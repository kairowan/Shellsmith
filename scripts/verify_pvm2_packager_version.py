#!/usr/bin/env python3
"""校验仓库内置的 PVM2 打包器 JAR 与壳运行时源码的镜像格式版本一致。

打包器把 `Pvm2Opcodes.VERSION` 写进每个 PVM2 镜像头部，壳运行时（静态链入的 Xop
解释器）按自身 `PVM2_VERSION_V*` 上限校验。两者取自不同 XopProtector 源码时，
运行时会拒绝镜像（`PVM2 unsupported version N`），被保护方法无法分派，应用在
启动阶段以 `VMP not ready` 崩溃——而这个失败只在用户设备上暴露。

发布工作流在钉住的 XOP_PROTECTOR_REF 检出后运行本脚本，把这类不匹配拦在打包之前。

用法：
    scripts/verify_pvm2_packager_version.py --jar tools/xop-pvm2-packer.jar \\
        --xop-root ../XopProtector
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
import zipfile
from pathlib import Path

OPCODES_CLASS = "com/yqsh/protector/packer/Pvm2Opcodes.class"
OPCODES_VERSION_FIELD = "VERSION"
HEADER_RELATIVE = Path("native/src/main/cpp/vm/pvm2_format.h")
VERSION_CONSTANT_RE = re.compile(r"PVM2_VERSION_V(\d+)\s*=\s*(\d+)")

# Java class 文件常量池标签。
CONSTANT_UTF8 = 1
CONSTANT_INTEGER = 3
CONSTANT_FLOAT = 4
CONSTANT_LONG = 5
CONSTANT_DOUBLE = 6
TWO_SLOT_TAGS = {CONSTANT_LONG, CONSTANT_DOUBLE}
TWO_BYTE_TAGS = {7, 8, 16, 19, 20}
FOUR_BYTE_TAGS = {9, 10, 11, 12, 17, 18}
METHOD_HANDLE_TAG = 15


class ClassFormatError(Exception):
    """class 文件结构不符合预期。"""


class Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, length: int) -> bytes:
        end = self.pos + length
        if end > len(self.data):
            raise ClassFormatError("class 文件被截断")
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk

    def u1(self) -> int:
        return self.take(1)[0]

    def u2(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u4(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def skip(self, length: int) -> None:
        self.take(length)


def parse_constant_pool(reader: Reader) -> tuple[list[str | None], list[int | None]]:
    count = reader.u2()
    utf8: list[str | None] = [None] * count
    integers: list[int | None] = [None] * count
    index = 1
    while index < count:
        tag = reader.u1()
        if tag == CONSTANT_UTF8:
            length = reader.u2()
            utf8[index] = reader.take(length).decode("utf-8", errors="replace")
        elif tag == CONSTANT_INTEGER:
            integers[index] = reader.u4()
        elif tag == CONSTANT_FLOAT:
            reader.skip(4)
        elif tag in TWO_SLOT_TAGS:
            reader.skip(8)
            index += 1  # Long / Double 占两个常量池槽位
        elif tag in TWO_BYTE_TAGS:
            reader.skip(2)
        elif tag in FOUR_BYTE_TAGS:
            reader.skip(4)
        elif tag == METHOD_HANDLE_TAG:
            reader.skip(3)
        else:
            raise ClassFormatError(f"未知常量池标签 {tag}")
        index += 1
    return utf8, integers


def static_int_constant(data: bytes, field: str) -> int | None:
    reader = Reader(data)
    if reader.u4() != 0xCAFEBABE:
        raise ClassFormatError("不是 Java class 文件")
    reader.skip(4)  # minor + major
    utf8, integers = parse_constant_pool(reader)
    reader.skip(2)  # access_flags
    reader.skip(2)  # this_class
    reader.skip(2)  # super_class
    reader.skip(reader.u2() * 2)  # interfaces
    for _ in range(reader.u2()):
        reader.skip(2)  # access_flags
        name_index = reader.u2()
        reader.skip(2)  # descriptor_index
        attributes = reader.u2()
        name = utf8[name_index] if name_index < len(utf8) else None
        value: int | None = None
        for _ in range(attributes):
            attribute_name_index = reader.u2()
            attribute_length = reader.u4()
            attribute_name = (
                utf8[attribute_name_index] if attribute_name_index < len(utf8) else None
            )
            if attribute_name == "ConstantValue" and attribute_length == 2:
                index = reader.u2()
                value = integers[index] if index < len(integers) else None
            else:
                reader.skip(attribute_length)
        if name == field:
            return value
    return None


def packer_format_version(jar: Path) -> int | None:
    with zipfile.ZipFile(jar) as archive:
        try:
            data = archive.read(OPCODES_CLASS)
        except KeyError:
            return None
    return static_int_constant(data, OPCODES_VERSION_FIELD)


def runtime_format_version(header: Path) -> int:
    text = header.read_text(encoding="utf-8")
    versions = [int(value) for _, value in VERSION_CONSTANT_RE.findall(text)]
    if not versions:
        raise SystemExit(f"未能从 {header} 解析出 PVM2_VERSION_V* 常量")
    return max(versions)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jar", type=Path, required=True, help="仓库内置的打包器 JAR")
    parser.add_argument("--xop-root", type=Path, required=True, help="XopProtector 源码根目录")
    args = parser.parse_args()

    if not args.jar.is_file():
        print(f"错误：PVM2 打包器 JAR 不存在：{args.jar}", file=sys.stderr)
        return 1

    header = args.xop_root / HEADER_RELATIVE
    if not header.is_file():
        print(
            f"警告：未找到 {header}，无法确定运行时支持的格式版本，跳过比对。"
            "发布工作流必须检出钉住的 XOP_PROTECTOR_REF 后再运行本脚本。",
            file=sys.stderr,
        )
        return 0

    runtime_version = runtime_format_version(header)
    packer_version = packer_format_version(args.jar)
    if packer_version is None:
        print(
            f"错误：{args.jar} 未声明 Pvm2Opcodes.VERSION，无法确认与运行时兼容。",
            file=sys.stderr,
        )
        return 1

    if packer_version > runtime_version:
        print(
            f"错误：PVM2 格式版本不一致——内置打包器产出 v{packer_version}，"
            f"而钉住的 XopProtector 运行时最高只支持 v{runtime_version}。\n"
            f"      继续发布会产出在设备上启动即崩的安装包"
            f"（运行时报 PVM2 unsupported version {packer_version}）。\n"
            f"      修复方式：用与 XOP_PROTECTOR_REF 相同的提交重建 "
            f"tools/xop-pvm2-packer.jar，或把 XOP_PROTECTOR_REF 提升到支持 "
            f"v{packer_version} 的提交后重建运行时。",
            file=sys.stderr,
        )
        return 1

    print(f"✓ PVM2 格式版本一致：打包器 v{packer_version}，运行时最高支持 v{runtime_version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
