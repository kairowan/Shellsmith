#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
llvm_config="${LLVM_CONFIG:-llvm-config}"
cmake_bin="${CMAKE:-cmake}"
build_root="${MOCIKA_VMP_TEST_BUILD:-${root_dir}/build/self-test}"
llvm_cmake_dir="$(${llvm_config} --cmakedir)"
clang_bin="$(dirname "${llvm_config}")/clang"
clangxx_bin="$(dirname "${llvm_config}")/clang++"

"${cmake_bin}" -S "${root_dir}" -B "${build_root}/pass" \
    -DLLVM_DIR="${llvm_cmake_dir}" \
    -DCMAKE_C_COMPILER="${clang_bin}" \
    -DCMAKE_CXX_COMPILER="${clangxx_bin}" \
    -DCMAKE_BUILD_TYPE=Release
"${cmake_bin}" --build "${build_root}/pass" --config Release

plugin="$(find "${build_root}/pass" -maxdepth 3 -type f \
    \( -name 'MocikaNativeVmpPass.so' -o -name 'MocikaNativeVmpPass.dylib' \
       -o -name 'MocikaNativeVmpPass.dll' \) -print -quit)"
test -n "${plugin}"

"${cmake_bin}" -S "${root_dir}/tests/fixture" -B "${build_root}/fixture" \
    -DCMAKE_C_COMPILER="${clang_bin}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DMOCIKA_NATIVE_VMP_PLUGIN="${plugin}" \
    -DMOCIKA_NATIVE_VMP_OPT="$(dirname "${llvm_config}")/opt"
"${cmake_bin}" --build "${build_root}/fixture" --config Release
"${build_root}/fixture/mocika-native-vmp-fixture"

"${clang_bin}" -O2 -fpass-plugin="${plugin}" \
    -I"${root_dir}/include" -S -emit-llvm \
    "${root_dir}/tests/fixture/main.c" -o "${build_root}/transformed.ll"
grep -q '@mocika_vmp_exec_i64' "${build_root}/transformed.ll"
grep -q '__mocika_vmp_program_protected_score' "${build_root}/transformed.ll"

if "${clang_bin}" -O2 -fpass-plugin="${plugin}" \
    -I"${root_dir}/include" -c "${root_dir}/tests/fixture/unsupported.c" \
    -o "${build_root}/unsupported.o" >"${build_root}/unsupported.log" 2>&1; then
    echo "unsupported annotated function unexpectedly compiled" >&2
    exit 1
fi
grep -q "Mocika Native VMP rejected function 'unsupported_pointer_load'" \
    "${build_root}/unsupported.log"

if command -v strings >/dev/null 2>&1; then
    strings "${build_root}/fixture/mocika-native-vmp-fixture" | grep -q 'MVMP'
fi
