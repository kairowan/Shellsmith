#!/usr/bin/env bash

# 对同签名标准/内存 APK 采集日常冷启动、内存整理前后数据和候选阶段日志。

set -euo pipefail

SELF_TEST=0
if [[ "${1:-}" == "--self-test" ]]; then
    SELF_TEST=1
    STANDARD_APK="self-test"
    MEMORY_APK="self-test"
    PACKAGE_NAME="dev.mocika.selftest"
    COMPONENT="dev.mocika.selftest/.Main"
else
    STANDARD_APK="${1:?请提供标准模式已签名 APK}"
    MEMORY_APK="${2:?请提供内存模式已签名 APK}"
    PACKAGE_NAME="${3:?请提供应用包名}"
    COMPONENT="${4:?请提供启动组件}"
fi
SAMPLE_COUNT="${SAMPLE_COUNT:-3}"
SETTLE_SECONDS="${SETTLE_SECONDS:-15}"
OUTPUT_DIR="${PROFILE_OUTPUT_DIR:-$(pwd)/target/test-results/memory-runtime-profile}"

if [[ "$SELF_TEST" -eq 0 ]]; then
    for command in adb awk sed; do
        command -v "$command" >/dev/null || { echo "缺少命令：$command" >&2; exit 1; }
    done
    for apk in "$STANDARD_APK" "$MEMORY_APK"; do
        [[ -f "$apk" ]] || { echo "APK 不存在：$apk" >&2; exit 1; }
    done
    if ! [[ "$SAMPLE_COUNT" =~ ^[0-9]+$ ]] || (( SAMPLE_COUNT < 1 )); then
        echo "SAMPLE_COUNT 必须是正整数" >&2
        exit 1
    fi
fi

ADB=(adb)
if [[ -n "${ANDROID_SERIAL:-}" ]]; then
    ADB+=(-s "$ANDROID_SERIAL")
fi
if [[ "$SELF_TEST" -eq 1 ]]; then
    OUTPUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mocika-profile-selftest.XXXXXX")"
    SELF_TEST_DIR="$OUTPUT_DIR"
else
    "${ADB[@]}" get-state >/dev/null
    mkdir -p "$OUTPUT_DIR"
fi
SUMMARY="$OUTPUT_DIR/summary.tsv"
printf '形态\t轮次\t启动毫秒\t计时来源\t窗口\tPSS_KB\tRSS_KB\t匿名映射_KB\t私有脏页_KB\t进程数\t崩溃\n' > "$SUMMARY"

process_ids() {
    "${ADB[@]}" shell ps -A -o PID,NAME | awk -v package="$PACKAGE_NAME" '
        $2 == package || index($2, package ":") == 1 { print $1 }
    ' | tr -d '\r'
}

meminfo_value() {
    local file="$1"
    local pattern="$2"
    awk -v pattern="$pattern" '
        index($0, pattern) {
            value = substr($0, index($0, pattern) + length(pattern))
            if (match(value, /[0-9]+/)) print substr(value, RSTART, RLENGTH)
            exit
        }
    ' "$file" | tr -d '\r '
}

rollup_value() {
    local file="$1"
    local field="$2"
    awk -v field="$field" '
        $1 == field ":" { print $2; exit }
    ' "$file" | tr -d '\r '
}

snapshot() {
    local variant="$1"
    local iteration="$2"
    local phase="$3"
    local launch_time="$4"
    local timing_source="$5"
    local total_pss=0 total_rss=0 total_anon=0 total_private_dirty=0 process_count=0
    local pss_missing=0 rss_missing=0 anon_missing=0 private_dirty_missing=0
    local pid pss rss anon private_dirty
    local meminfo_file smaps_file
    local raw_dir="$OUTPUT_DIR/$variant-$iteration-$phase"
    mkdir -p "$raw_dir"

    while read -r pid; do
        [[ -n "$pid" ]] || continue
        process_count=$((process_count + 1))

        # 每个 PID、每个快照只执行一次 meminfo；PSS/RSS 从同一份原始输出解析。
        meminfo_file="$raw_dir/meminfo-$pid.txt"
        if ! "${ADB[@]}" shell dumpsys meminfo "$pid" > "$meminfo_file" 2>/dev/null; then
            pss_missing=1
            rss_missing=1
        else
            pss="$(meminfo_value "$meminfo_file" "TOTAL PSS:")"
            rss="$(meminfo_value "$meminfo_file" "TOTAL RSS:")"
            if [[ "$pss" =~ ^[0-9]+$ ]]; then
                total_pss=$((total_pss + pss))
            else
                pss_missing=1
            fi
            if [[ "$rss" =~ ^[0-9]+$ ]]; then
                total_rss=$((total_rss + rss))
            else
                rss_missing=1
            fi
        fi

        # 同样只读取一次 smaps_rollup，再从保存文件解析匿名映射和私有脏页。
        smaps_file="$raw_dir/smaps-rollup-$pid.txt"
        if "${ADB[@]}" shell "cat /proc/$pid/smaps_rollup" > "$smaps_file" 2>/dev/null; then
            anon="$(rollup_value "$smaps_file" Anonymous)"
            private_dirty="$(rollup_value "$smaps_file" Private_Dirty)"
            if [[ "$anon" =~ ^[0-9]+$ ]]; then
                total_anon=$((total_anon + anon))
            else
                anon_missing=1
            fi
            if [[ "$private_dirty" =~ ^[0-9]+$ ]]; then
                total_private_dirty=$((total_private_dirty + private_dirty))
            else
                private_dirty_missing=1
            fi
        else
            anon_missing=1
            private_dirty_missing=1
        fi
    done < <(process_ids)

    if [[ "$process_count" -eq 0 ]]; then
        pss_missing=1
        rss_missing=1
        anon_missing=1
        private_dirty_missing=1
    fi
    [[ "$pss_missing" -eq 0 ]] || total_pss="不可用"
    [[ "$rss_missing" -eq 0 ]] || total_rss="不可用"
    [[ "$anon_missing" -eq 0 ]] || total_anon="不可用"
    [[ "$private_dirty_missing" -eq 0 ]] || total_private_dirty="不可用"

    local crashes
    crashes="$("${ADB[@]}" logcat -d -v brief | awk -v package="$PACKAGE_NAME" '
        /FATAL EXCEPTION/ { fatal++ }
        index($0, "Process: " package) { process++ }
        END { print fatal + process }
    ')"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$variant" "$iteration" "$launch_time" "$timing_source" "$phase" \
        "$total_pss" "$total_rss" "$total_anon" "$total_private_dirty" \
        "$process_count" "$crashes" >> "$SUMMARY"
}

self_test() {
    local work="$SELF_TEST_DIR"
    PACKAGE_NAME="dev.mocika.selftest"
    fake_meminfo_calls=0
    fake_smaps_calls=0
    fake_missing=0
    fake_adb() {
        case "$*" in
            *"ps -A -o PID,NAME"*)
                printf '123 %s\n' "$PACKAGE_NAME"
                ;;
            *"dumpsys meminfo 123"*)
                fake_meminfo_calls=$((fake_meminfo_calls + 1))
                if [[ "$fake_missing" -eq 1 ]]; then
                    printf 'No total lines\n'
                else
                    printf 'TOTAL PSS: 12345\nTOTAL RSS: 23456\n'
                fi
                ;;
            *"cat /proc/123/smaps_rollup"*)
                fake_smaps_calls=$((fake_smaps_calls + 1))
                if [[ "$fake_missing" -eq 1 ]]; then
                    printf 'Anonymous: not-a-number\n'
                else
                    printf 'Anonymous: 3456 kB\nPrivate_Dirty: 4567 kB\n'
                fi
                ;;
            *"logcat -d -v brief"*)
                :
                ;;
            *)
                :
                ;;
        esac
    }
    ADB=(fake_adb)

    snapshot standard 1 "自然窗口" 100 TotalTime
    local row pss rss anon private count
    row="$(tail -n 1 "$SUMMARY")"
    IFS=$'\t' read -r _ _ _ _ _ pss rss anon private count _ <<< "$row"
    [[ "$pss" == "12345" && "$rss" == "23456" && "$anon" == "3456" \
        && "$private" == "4567" && "$count" == "1" ]] \
        || { echo "自检失败：快照字段解析错误：$row" >&2; return 1; }
    [[ "$fake_meminfo_calls" -eq 1 && "$fake_smaps_calls" -eq 1 ]] \
        || { echo "自检失败：每个 PID 的快照采样次数不是 1" >&2; return 1; }

    fake_missing=1
    snapshot standard 2 "自然窗口" 100 TotalTime
    row="$(tail -n 1 "$SUMMARY")"
    IFS=$'\t' read -r _ _ _ _ _ pss rss anon private count _ <<< "$row"
    [[ "$pss" == "不可用" && "$rss" == "不可用" && "$anon" == "不可用" \
        && "$private" == "不可用" ]] \
        || { echo "自检失败：缺失字段未标记为不可用：$row" >&2; return 1; }
    echo "profile-memory-runtime-apk 自检通过：单次采样、字段解析与缺失字段标记"
}

if [[ "$SELF_TEST" -eq 1 ]]; then
    trap 'rm -rf "$SELF_TEST_DIR"' EXIT
    self_test
    exit 0
fi

measure_variant() {
    local variant="$1"
    local apk="$2"
    "${ADB[@]}" install -r "$apk" >/dev/null
    "${ADB[@]}" shell pm clear "$PACKAGE_NAME" >/dev/null
    "${ADB[@]}" shell am start -W -n "$COMPONENT" >/dev/null
    sleep 20

    for iteration in $(seq 1 "$SAMPLE_COUNT"); do
        local launch launch_time timing_source
        "${ADB[@]}" shell am force-stop "$PACKAGE_NAME" >/dev/null
        "${ADB[@]}" logcat -c
        launch="$("${ADB[@]}" shell am start -W -n "$COMPONENT")"
        launch_time="$(awk -F': ' '/^TotalTime:/ { gsub("\r", "", $2); print $2; exit }' <<< "$launch")"
        timing_source="TotalTime"
        if ! [[ "$launch_time" =~ ^[0-9]+$ ]]; then
            launch_time="$(awk -F': ' '/^WaitTime:/ { gsub("\r", "", $2); print $2; exit }' <<< "$launch")"
            timing_source="WaitTime"
        fi
        [[ "$launch_time" =~ ^[0-9]+$ ]] || { launch_time=0; timing_source="不可用"; }
        sleep "$SETTLE_SECONDS"
        snapshot "$variant" "$iteration" "自然窗口" "$launch_time" "$timing_source"
        "${ADB[@]}" shell am send-trim-memory "$PACKAGE_NAME" RUNNING_LOW >/dev/null
        sleep 3
        snapshot "$variant" "$iteration" "整理窗口" "$launch_time" "$timing_source"
        "${ADB[@]}" logcat -d -v threadtime -s mxp:I '*:S' \
            > "$OUTPUT_DIR/$variant-$iteration-runtime.log"
    done
}

measure_variant standard "$STANDARD_APK"
measure_variant memory "$MEMORY_APK"

echo "剖析完成：$SUMMARY"
