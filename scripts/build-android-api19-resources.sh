#!/usr/bin/env bash

# 构建 Android 4.4 兼容资源包，不覆盖标准 resources.zip。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MAPPING_FILE="$PROJECT_ROOT/shield-stub/build/outputs/mapping/release/mapping.txt"
STANDARD_RESOURCES="$PROJECT_ROOT/shield-stub/build/outputs/resources/resources.zip"
API19_OUTPUT="$PROJECT_ROOT/shield-stub/build/experiments/api19"
LEGACY_RESOURCES="$PROJECT_ROOT/shield-stub/build/outputs/resources/resources-api19.zip"

if [[ "${SKIP_STANDARD_STUB_BUILD:-0}" != "1" ]]; then
    "$PROJECT_ROOT/scripts/build-stub.sh"
fi

ANDROID_SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
NDK_VERSION="${MOCIKA_API19_NDK_VERSION:-25.2.9519653}"
API19_RUST_TOOLCHAIN="${ANDROID_API19_RUST_TOOLCHAIN:-1.77.2}"
if [[ -z "$ANDROID_SDK" ]]; then
    echo "错误：未设置 ANDROID_HOME 或 ANDROID_SDK_ROOT"
    exit 1
fi
NDK_ROOT="${ANDROID_NDK_API19_ROOT:-$ANDROID_SDK/ndk/$NDK_VERSION}"
if [[ ! -f "$NDK_ROOT/source.properties" ]]; then
    echo "错误：未安装 Android 4.4 兼容构建所需的 NDK（${NDK_VERSION}）"
    echo "请先安装对应 NDK，或设置 ANDROID_NDK_API19_ROOT 指向已安装版本目录"
    exit 1
fi
if ! grep -q "Pkg.Revision = $NDK_VERSION" "$NDK_ROOT/source.properties"; then
    echo "错误：API19 NDK 路径与要求版本 $NDK_VERSION 不一致：$NDK_ROOT"
    echo "如果使用本地实验版本，请同时设置 MOCIKA_API19_NDK_VERSION"
    exit 1
fi
if ! rustup run "$API19_RUST_TOOLCHAIN" rustc --version >/dev/null 2>&1; then
    echo "错误：未安装 Android 4.4 兼容 Rust 工具链 $API19_RUST_TOOLCHAIN"
    echo "请先安装对应 Rust 工具链并添加 armv7-linux-androideabi target"
    exit 1
fi
if ! rustup target list --toolchain "$API19_RUST_TOOLCHAIN" --installed | grep -qx armv7-linux-androideabi; then
    echo "错误：Rust $API19_RUST_TOOLCHAIN 未安装 armv7-linux-androideabi target"
    echo "请先安装对应工具链并添加 armv7-linux-androideabi target"
    exit 1
fi

for required in "$MAPPING_FILE" "$STANDARD_RESOURCES"; do
    if [[ ! -f "$required" ]]; then
        echo "错误：缺少标准 Stub 构建产物：$required"
        exit 1
    fi
done

parse_mapping_class() {
    local original_class="$1"
    grep "^${original_class} ->" "$MAPPING_FILE" | sed 's/.*-> //' | tr -d ':'
}

parse_mapping_method() {
    local original_class="$1"
    local original_method="$2"
    awk "/^${original_class} ->/{found=1} found && / ${original_method}\\(/{print \$NF; exit}" \
        "$MAPPING_FILE"
}

ORIGINAL_LD="dev.mocika.shield.loader.Ld"
OBFUSCATED_LD="$(parse_mapping_class "$ORIGINAL_LD")"
OBFUSCATED_INJECT="$(parse_mapping_method "$ORIGINAL_LD" "p")"
OBFUSCATED_EXTRACT="$(parse_mapping_method "$ORIGINAL_LD" "q")"
OBFUSCATED_CHECK_ENV="$(parse_mapping_method "$ORIGINAL_LD" "r")"
OBFUSCATED_SIGNATURE="$(parse_mapping_method "$ORIGINAL_LD" "getSignatureSha256")"

if [[ -z "$OBFUSCATED_LD" ]]; then
    echo "错误：无法从 mapping.txt 解析 Ld 类名"
    exit 1
fi

STUB_BINLOADER_CLASS="${OBFUSCATED_LD//.//}" \
STUB_METHOD_INJECT_DEX="${OBFUSCATED_INJECT:-p}" \
STUB_METHOD_EXTRACT_DECRYPT="${OBFUSCATED_EXTRACT:-q}" \
STUB_METHOD_CHECK_ENV="${OBFUSCATED_CHECK_ENV:-r}" \
STUB_METHOD_GET_SIG="${OBFUSCATED_SIGNATURE:-getSignatureSha256}" \
    "$PROJECT_ROOT/scripts/verify-android-api19-native.sh"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mocika-api19-resources.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

unzip -q "$STANDARD_RESOURCES" -d "$WORK_DIR"
find "$WORK_DIR" -type f -name '.DS_Store' -delete
rm -rf "$WORK_DIR/__MACOSX"
# API 19 的验证产物只有 armeabi-v7a；不要把由现代 API 构建的其它 ABI
# 伪装进 legacy 包，否则旧设备可能选中无法加载的 Native 库。
rm -rf "$WORK_DIR/lib/arm64-v8a" "$WORK_DIR/lib/x86" "$WORK_DIR/lib/x86_64"
cp "$API19_OUTPUT/jniLibs/armeabi-v7a/libmocikashield.so" \
    "$WORK_DIR/lib/armeabi-v7a/libmocikashield.so"
perl -pi -e 's/"min_android_api": 21/"min_android_api": 19/' "$WORK_DIR/metadata.json"
perl -pi -e 's/"xop_pvm2": true/"xop_pvm2": false/' "$WORK_DIR/metadata.json"
perl -pi -e 's/"native_so_text": true/"native_so_text": false/' "$WORK_DIR/metadata.json"
perl -pi -e 's/"native_so_functions": true/"native_so_functions": false/' "$WORK_DIR/metadata.json"
perl -0pi -e 's/"supported_architectures":\s*\[[^\]]*\]/"supported_architectures": [\n    "armeabi-v7a"\n  ]/' "$WORK_DIR/metadata.json"
if ! grep -q '"min_android_api": 19' "$WORK_DIR/metadata.json"; then
    echo "错误：Android 4.4 兼容资源元数据未正确设置 min_android_api=19"
    exit 1
fi
if ! grep -q '"xop_pvm2": false' "$WORK_DIR/metadata.json"; then
    echo "错误：Android 4.4 兼容资源必须显式禁用 Xop PVM2"
    exit 1
fi
if ! grep -q '"armeabi-v7a"' "$WORK_DIR/metadata.json" \
    || grep -Eq '"(arm64-v8a|x86|x86_64)"' "$WORK_DIR/metadata.json"; then
    echo "错误：Android 4.4 兼容资源元数据只能声明 armeabi-v7a"
    exit 1
fi

mkdir -p "$API19_OUTPUT"
rm -f "$LEGACY_RESOURCES"
if [[ "${OS:-}" == "Windows_NT" ]]; then
    WINDOWS_WORK_DIR="$(cygpath -w "$WORK_DIR")"
    WINDOWS_RESOURCES="$(cygpath -w "$LEGACY_RESOURCES")"
    MOCIKA_WORK_DIR="$WINDOWS_WORK_DIR" \
    MOCIKA_RESOURCES="$WINDOWS_RESOURCES" \
        powershell.exe -NoProfile -NonInteractive -Command '
            $ErrorActionPreference = "Stop"
            $files = @(
                (Join-Path $env:MOCIKA_WORK_DIR "stub-classes.dex"),
                (Join-Path $env:MOCIKA_WORK_DIR "lib"),
                (Join-Path $env:MOCIKA_WORK_DIR "metadata.json")
            )
            Compress-Archive -Path $files -DestinationPath $env:MOCIKA_RESOURCES -Force
        '
else
    (
        cd "$WORK_DIR"
        zip -qr "$LEGACY_RESOURCES" stub-classes.dex lib metadata.json
    )
fi

if ! unzip -tq "$LEGACY_RESOURCES" >/dev/null; then
    echo "错误：Android 4.4 兼容资源包 ZIP 完整性校验失败"
    exit 1
fi
for required_entry in stub-classes.dex lib/armeabi-v7a/libmocikashield.so metadata.json; do
    if ! unzip -Z1 "$LEGACY_RESOURCES" \
        | awk -v required="$required_entry" '$0 == required { found = 1 } END { exit !found }'; then
        echo "错误：Android 4.4 兼容资源包缺少 $required_entry"
        exit 1
    fi
done
if unzip -Z1 "$LEGACY_RESOURCES" | grep -Eq '^lib/(arm64-v8a|x86|x86_64)/'; then
    echo "错误：API19 资源包意外包含非 armeabi-v7a Native 库"
    exit 1
fi

echo "Android API 19 兼容资源包构建完成：$LEGACY_RESOURCES"
