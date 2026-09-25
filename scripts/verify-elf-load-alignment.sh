#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "用法：$0 <llvm-readelf> <最小对齐字节数> <ELF 文件...>" >&2
    exit 2
fi

READELF="$1"
MIN_ALIGNMENT="$2"
shift 2
if [[ ! -x "$READELF" || ! "$MIN_ALIGNMENT" =~ ^[0-9]+$ ]]; then
    echo "错误：readelf 路径或最小对齐值无效" >&2
    exit 2
fi

for elf in "$@"; do
    if [[ ! -f "$elf" ]]; then
        echo "错误：缺少 ELF 文件：$elf" >&2
        exit 1
    fi
    load_alignments=( $("$READELF" -lW "$elf" | awk '$1 == "LOAD" { print $NF }') )
    if [[ ${#load_alignments[@]} -eq 0 ]]; then
        echo "错误：$elf 没有可审计的 LOAD 段" >&2
        exit 1
    fi
    for alignment in "${load_alignments[@]}"; do
        if [[ ! "$alignment" =~ ^0x[[:xdigit:]]+$ ]] || (( alignment < MIN_ALIGNMENT )); then
            echo "错误：$elf 的 LOAD 段对齐 $alignment 小于 ${MIN_ALIGNMENT} 字节" >&2
            exit 1
        fi
    done
    echo "通过：$elf LOAD 段对齐均不小于 ${MIN_ALIGNMENT} 字节 (${load_alignments[*]})"
done
