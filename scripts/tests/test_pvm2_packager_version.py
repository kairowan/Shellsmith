from __future__ import annotations

import importlib.util
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify_pvm2_packager_version.py"
WORKFLOW = ROOT / ".github/workflows/release.yml"

spec = importlib.util.spec_from_file_location("verify_pvm2_packager_version", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def synthetic_class_file(value: int, field: str = "VERSION", pad_long: bool = False) -> bytes:
    """组装一个只含 `public static final int <field> = value` 的最小 class 文件。"""
    out = bytearray()
    out += struct.pack(">I", 0xCAFEBABE)
    out += struct.pack(">HH", 0, 52)
    out += struct.pack(">H", 6 if pad_long else 5)
    out += b"\x01" + struct.pack(">H", len(field)) + field.encode()
    out += b"\x01" + struct.pack(">H", 1) + b"I"
    out += b"\x01" + struct.pack(">H", 13) + b"ConstantValue"
    out += b"\x03" + struct.pack(">I", value)
    if pad_long:
        out += b"\x05" + struct.pack(">Q", 0)
    out += struct.pack(">HHH", 0x0019, 0, 0)
    out += struct.pack(">H", 0)  # interfaces
    out += struct.pack(">H", 1)  # fields
    out += struct.pack(">HHHH", 0x0019, 1, 2, 1)
    out += struct.pack(">HI", 3, 2)
    out += struct.pack(">H", 4)
    return bytes(out)


def write_packer_jar(path: Path, value: int | None, pad_long: bool = False) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        if value is not None:
            archive.writestr(
                "com/yqsh/protector/packer/Pvm2Opcodes.class",
                synthetic_class_file(value, pad_long=pad_long),
            )
        archive.writestr("other.txt", "x")


def write_header(root: Path, versions: list[int]) -> Path:
    header = root / module.HEADER_RELATIVE
    header.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(
        f"constexpr uint16_t PVM2_VERSION_V{value} = {value};\n" for value in versions
    )
    header.write_text(body, encoding="utf-8")
    return header


class Pvm2PackagerVersionTests(unittest.TestCase):
    def test_解析打包器声明与运行时上限(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "packer.jar"
            write_packer_jar(jar, 6)
            self.assertEqual(module.packer_format_version(jar), 6)
            # Long 常量占两个槽位，不能让后续索引错位。
            jar_long = Path(tmp) / "packer-long.jar"
            write_packer_jar(jar_long, 7, pad_long=True)
            self.assertEqual(module.packer_format_version(jar_long), 7)
            # 缺少该字段时按未知处理。
            jar_none = Path(tmp) / "packer-none.jar"
            write_packer_jar(jar_none, None)
            self.assertIsNone(module.packer_format_version(jar_none))

            header = write_header(Path(tmp) / "xop", [1, 2, 3, 4, 5])
            self.assertEqual(module.runtime_format_version(header), 5)

    def run_script(self, jar: Path, xop_root: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--jar",
                str(jar),
                "--xop-root",
                str(xop_root),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_版本一致时通过(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "packer.jar"
            write_packer_jar(jar, 5)
            root = Path(tmp) / "xop"
            write_header(root, [1, 2, 3, 4, 5])
            result = self.run_script(jar, root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("v5", result.stdout)

    def test_运行时更新于打包器时放行(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "packer.jar"
            write_packer_jar(jar, 5)
            root = Path(tmp) / "xop"
            write_header(root, [1, 2, 3, 4, 5, 6])
            self.assertEqual(self.run_script(jar, root).returncode, 0)

    def test_打包器更新于运行时必须拒绝并给出建议(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "packer.jar"
            write_packer_jar(jar, 6)
            root = Path(tmp) / "xop"
            write_header(root, [1, 2, 3, 4, 5])
            result = self.run_script(jar, root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("v6", result.stderr)
            self.assertIn("v5", result.stderr)
            self.assertIn("XOP_PROTECTOR_REF", result.stderr)
            self.assertIn("PVM2 unsupported version 6", result.stderr)

    def test_缺少运行时源码时跳过而不是误报(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "packer.jar"
            write_packer_jar(jar, 6)
            result = self.run_script(jar, Path(tmp) / "missing-xop")
            self.assertEqual(result.returncode, 0)
            self.assertIn("跳过", result.stderr)

    def test_打包器未声明版本或缺失时拒绝(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "xop"
            write_header(root, [1, 2, 3, 4, 5])
            jar_none = Path(tmp) / "packer-none.jar"
            write_packer_jar(jar_none, None)
            self.assertEqual(self.run_script(jar_none, root).returncode, 1)
            self.assertEqual(
                self.run_script(Path(tmp) / "missing.jar", root).returncode, 1
            )

    def test_发布工作流在钉住的检出后执行该检查(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("verify_pvm2_packager_version.py", workflow)
        self.assertIn("--xop-root", workflow)


if __name__ == "__main__":
    unittest.main()
