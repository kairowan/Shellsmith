#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ADB_BIN="${ADB_BIN:-${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}/platform-tools/adb}"
MODE="${MATRIX_MODE:-inventory}"
REPORT="${MATRIX_REPORT:-$ROOT/target/android-device-matrix.tsv}"

if [[ ! -x "$ADB_BIN" ]]; then
  ADB_BIN="$(command -v adb || true)"
fi
[[ -n "$ADB_BIN" && -x "$ADB_BIN" ]] || { echo "缺少 adb" >&2; exit 1; }

case "$MODE" in
  inventory|apk|apks|e2e) ;;
  *) echo "MATRIX_MODE 仅支持 inventory、apk、apks 或 e2e" >&2; exit 1 ;;
esac

if [[ "$MODE" == "apk" || "$MODE" == "apks" ]]; then
  [[ -f "${MATRIX_ARTIFACT:-}" ]] || { echo "MATRIX_ARTIFACT 不存在" >&2; exit 1; }
  [[ -n "${MATRIX_PACKAGE:-}" ]] || { echo "缺少 MATRIX_PACKAGE" >&2; exit 1; }
fi
if [[ "$MODE" == "apks" ]]; then
  [[ -f "${MATRIX_BUNDLETOOL:-}" ]] || { echo "缺少 MATRIX_BUNDLETOOL" >&2; exit 1; }
fi

mkdir -p "$(dirname "$REPORT")"
printf 'device\tstatus\tapi\trelease\tvendor\tmodel\tabis\tpage_size\tmode\tresult\n' > "$REPORT"

mapfile_compat() {
  local line
  DEVICES=()
  while IFS= read -r line; do
    [[ -n "$line" ]] && DEVICES+=("$line")
  done
}

mapfile_compat < <("$ADB_BIN" devices | awk 'NR > 1 && $2 == "device" { print $1 }')
[[ ${#DEVICES[@]} -gt 0 ]] || { echo "没有在线 Android 设备" >&2; exit 1; }

OBSERVED_APIS=()
OBSERVED_ABIS=()
OBSERVED_VENDORS=()
failures=0
index=0

for serial in "${DEVICES[@]}"; do
  index=$((index + 1))
  adb=("$ADB_BIN" -s "$serial")
  api="$("${adb[@]}" shell getprop ro.build.version.sdk | tr -d '\r')"
  release="$("${adb[@]}" shell getprop ro.build.version.release | tr -d '\r\t')"
  vendor="$("${adb[@]}" shell getprop ro.product.manufacturer | tr -d '\r\t')"
  model="$("${adb[@]}" shell getprop ro.product.model | tr -d '\r\t')"
  abis="$("${adb[@]}" shell getprop ro.product.cpu.abilist | tr -d '\r\t')"
  page_size="$("${adb[@]}" shell getconf PAGE_SIZE 2>/dev/null | tr -d '\r' || true)"
  [[ "$api" =~ ^[0-9]+$ ]] || { echo "设备 $index 返回无效 API" >&2; exit 1; }

  OBSERVED_APIS+=("$api")
  OBSERVED_VENDORS+=("$(printf '%s' "$vendor" | tr '[:upper:]' '[:lower:]')")
  IFS=',' read -r -a device_abis <<< "$abis"
  OBSERVED_ABIS+=("${device_abis[@]}")
  result="inventory-only"

  if [[ "$MODE" == "apk" ]]; then
    if "${adb[@]}" install -r -t "$MATRIX_ARTIFACT" >/dev/null \
        && "${adb[@]}" shell pm path "$MATRIX_PACKAGE" | grep -q '^package:'; then
      result="installed"
    else
      result="install-failed"
      failures=$((failures + 1))
    fi
  elif [[ "$MODE" == "apks" ]]; then
    if java -jar "$MATRIX_BUNDLETOOL" install-apks \
        --apks="$MATRIX_ARTIFACT" --device-id="$serial" >/dev/null \
        && "${adb[@]}" shell pm path "$MATRIX_PACKAGE" | grep -q '^package:'; then
      split_count="$("${adb[@]}" shell pm path "$MATRIX_PACKAGE" | grep -c '^package:')"
      result="installed-splits:$split_count"
    else
      result="install-failed"
      failures=$((failures + 1))
    fi
  elif [[ "$MODE" == "e2e" ]]; then
    if ANDROID_SERIAL="$serial" RUN_DEVICE_TEST=1 \
        PVM2_STRICT_TEST="${MATRIX_PVM2_STRICT_TEST:-0}" \
        bash "$ROOT/tests/scripts/run-protect-e2e.sh" >/dev/null; then
      result="apk-e2e-passed"
    else
      result="apk-e2e-failed"
      failures=$((failures + 1))
    fi
  fi

  if [[ "$result" == installed* && -n "${MATRIX_COMPONENT:-}" ]]; then
    if "${adb[@]}" shell am force-stop "$MATRIX_PACKAGE" >/dev/null 2>&1 \
        && "${adb[@]}" shell am start -W -n "$MATRIX_COMPONENT" >/dev/null; then
      sleep 1
      if "${adb[@]}" shell pidof "$MATRIX_PACKAGE" >/dev/null; then
        result="$result,launch-passed"
      else
        result="$result,launch-failed"
        failures=$((failures + 1))
      fi
    else
      result="$result,launch-failed"
      failures=$((failures + 1))
    fi
  fi

  printf 'device-%d\tonline\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$index" "$api" "$release" "$vendor" "$model" "$abis" "${page_size:-unknown}" \
    "$MODE" "$result" >> "$REPORT"
done

contains_exact() {
  local needle="$1"; shift
  local value
  for value in "$@"; do [[ "$value" == "$needle" ]] && return 0; done
  return 1
}

check_requirements() {
  local kind="$1" raw="$2"; shift 2
  local -a observed=("$@")
  [[ -n "$raw" ]] || return 0
  local required required_lower
  IFS=',' read -r -a required_values <<< "$raw"
  for required in "${required_values[@]}"; do
    required="${required//[[:space:]]/}"
    [[ -z "$required" ]] && continue
    required_lower="$(printf '%s' "$required" | tr '[:upper:]' '[:lower:]')"
    if ! contains_exact "$required_lower" "${observed[@]}"; then
      echo "矩阵缺少 $kind=$required" >&2
      failures=$((failures + 1))
    fi
  done
}

check_requirements API "${MATRIX_REQUIRED_APIS:-}" "${OBSERVED_APIS[@]}"
check_requirements ABI "${MATRIX_REQUIRED_ABIS:-}" "${OBSERVED_ABIS[@]}"
check_requirements vendor "${MATRIX_REQUIRED_VENDORS:-}" "${OBSERVED_VENDORS[@]}"

echo "设备矩阵报告: $REPORT"
[[ $failures -eq 0 ]] || exit 1
