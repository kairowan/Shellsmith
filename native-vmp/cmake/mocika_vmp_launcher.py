#!/usr/bin/env python3
"""CMake compiler launcher: source -> LLVM bitcode -> Mocika VMP -> object."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".m", ".mm"}


def parse_launcher_args(argv: list[str]) -> tuple[str, str, list[str]]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--opt", required=True)
    parser.add_argument("--plugin", required=True)
    known, remaining = parser.parse_known_args(argv)
    if not remaining:
        parser.error("compiler command is missing")
    return known.opt, known.plugin, remaining


def source_index(arguments: list[str]) -> int | None:
    for index, value in enumerate(arguments[1:], start=1):
        if not value.startswith("-") and Path(value).suffix.lower() in SOURCE_SUFFIXES:
            return index
    return None


def output_path(arguments: list[str]) -> Path | None:
    try:
        return Path(arguments[arguments.index("-o") + 1])
    except (ValueError, IndexError):
        return None


def replace_output(arguments: list[str], output: Path) -> list[str]:
    result = list(arguments)
    position = result.index("-o") + 1
    result[position] = str(output)
    return result


def remove_dependency_flags(arguments: list[str]) -> list[str]:
    result: list[str] = []
    skip_next = False
    options_with_value = {"-MF", "-MT", "-MQ"}
    standalone = {"-MD", "-MMD", "-MP"}
    for value in arguments:
        if skip_next:
            skip_next = False
            continue
        if value in options_with_value:
            skip_next = True
            continue
        if value in standalone:
            continue
        result.append(value)
    return result


def run(command: list[str]) -> None:
    completed = subprocess.run(command)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def main(argv: list[str]) -> int:
    llvm_opt, plugin, compiler_args = parse_launcher_args(argv)
    source_at = source_index(compiler_args)
    final_output = output_path(compiler_args)
    if "-c" not in compiler_args or source_at is None or final_output is None:
        run(compiler_args)
        return 0

    output_dir = final_output.resolve().parent
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mocika-vmp-", dir=output_dir) as temporary:
        temporary_dir = Path(temporary)
        original_bc = temporary_dir / "original.bc"
        transformed_bc = temporary_dir / "transformed.bc"

        emit_arguments = replace_output(compiler_args, original_bc)
        emit_arguments.append("-emit-llvm")
        run(emit_arguments)
        run([
            llvm_opt,
            "--strip-debug",
            f"-load-pass-plugin={plugin}",
            "-passes=mocika-native-vmp",
            str(original_bc),
            "-o",
            str(transformed_bc),
        ])

        object_arguments = remove_dependency_flags(compiler_args)
        source_at = source_index(object_arguments)
        if source_at is None:
            raise SystemExit("Mocika Native VMP launcher lost the source argument")
        object_arguments[source_at] = str(transformed_bc)
        object_arguments.append("-Wno-unused-command-line-argument")
        run(object_arguments)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
