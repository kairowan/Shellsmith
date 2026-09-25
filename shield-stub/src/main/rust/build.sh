#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================"
echo "构建 Shellsmith Native 库 (Rust)"
echo "========================================"

if ! command -v cargo-ndk &> /dev/null; then
    echo "错误: 未找到 cargo-ndk"
    echo "请安装: cargo install cargo-ndk"
    exit 1
fi

if [ -z "$ANDROID_NDK_ROOT" ] && [ -z "$NDK_HOME" ]; then
    echo "错误: 未设置 ANDROID_NDK_ROOT 或 NDK_HOME"
    exit 1
fi

OUTPUT_DIR="../../../build/jniLibs"
mkdir -p "$OUTPUT_DIR"

# Android 15+ 16 KB page-size devices require every PT_LOAD segment to use
# at least 16 KB alignment; 32-bit lld targets still default to 4 KB.
export RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }-C link-arg=-Wl,-z,max-page-size=16384"

echo "构建目标: arm64-v8a, armeabi-v7a, x86, x86_64"
echo

# 本机可能同时存在 Homebrew Rust 与 rustup Rust。通过显式 toolchain 让
# Gradle/脚本复用已安装 Android target；CI 不设置时仍走默认 cargo。
CARGO_ARGS=(
    ndk
    --platform 21
    --target aarch64-linux-android
    --target armv7-linux-androideabi
    --target i686-linux-android
    --target x86_64-linux-android
    -o "$OUTPUT_DIR"
    build --release
)
RUST_TOOLCHAIN="${MOCIKA_RUST_TOOLCHAIN:-$(rustup show active-toolchain | awk '{print $1}')}"
RUST_TOOLCHAIN_BIN="$(dirname "$(rustup which cargo --toolchain "${RUST_TOOLCHAIN}")")"
PATH="${RUST_TOOLCHAIN_BIN}:${PATH}" rustup run "${RUST_TOOLCHAIN}" cargo "${CARGO_ARGS[@]}"

NDK_ROOT="${ANDROID_NDK_ROOT:-${NDK_HOME:-}}"
READELF_CANDIDATES=("$NDK_ROOT"/toolchains/llvm/prebuilt/*/bin/llvm-readelf)
READELF="${READELF_CANDIDATES[0]}"
if [ ! -x "$READELF" ]; then
    echo "错误: NDK 中未找到 llvm-readelf，无法验证 16 KB ELF 对齐"
    exit 1
fi
"$SCRIPT_DIR/../../../../scripts/verify-elf-load-alignment.sh" \
    "$READELF" 16384 \
    "$OUTPUT_DIR/arm64-v8a/libmocikashield.so" \
    "$OUTPUT_DIR/armeabi-v7a/libmocikashield.so" \
    "$OUTPUT_DIR/x86/libmocikashield.so" \
    "$OUTPUT_DIR/x86_64/libmocikashield.so"

for elf in "$OUTPUT_DIR"/*/libmocikashield.so; do
    unresolved_cxx="$($READELF --dyn-syms --wide "$elf" \
        | awk '$7 == "UND" { sub(/@.*/, "", $8); print $8 }' \
        | grep -E '^(_Z|__cxa_|__gxx|_Unwind)' \
        | grep -Ev '^__cxa_(atexit|finalize)$' || true)"
    if [ -n "$unresolved_cxx" ]; then
        echo "错误: $elf 仍依赖未解析的 C++ runtime 符号:"
        echo "$unresolved_cxx"
        exit 1
    fi
done

echo
echo "========================================"
echo "✓ 构建完成"
echo "========================================"
echo "产物位置:"
ls -lh "$OUTPUT_DIR"/*/libmocikashield.so
