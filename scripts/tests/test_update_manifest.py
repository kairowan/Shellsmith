import base64
import copy
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from generate_update_manifest import generate_manifest


class UpdateManifestTests(unittest.TestCase):
    def test_三平台齐全且签名绑定版本才发布(self):
        version = "1.4.5"
        with tempfile.TemporaryDirectory() as directory:
            signatures = Path(directory)
            assets = []
            names = [f"Shellsmith_{version}_{suffix}" for suffix in (
                "macos_universal.app.tar.gz", "windows_x64_setup.exe", "linux_amd64.AppImage",
            )]
            # 结构测试使用假签名，不替代客户端公钥验签。
            signature = base64.b64encode(
                f"untrusted comment: 测试\n占位\ntrusted comment: file:test\tversion:{version}\n占位\n".encode()
            ).decode()
            for name in names:
                (signatures / (name + ".sig")).write_text(signature, encoding="utf-8")
                for filename in [name, name + ".sig"]:
                    assets.append({"name": filename, "size": 123, "state": "uploaded",
                                   "url": f"https://github.com/kairowan/Shellsmith/releases/download/v{version}/{filename}"})
            manifest = generate_manifest(version, assets, signatures, "更新说明")
            self.assertEqual(len(manifest["platforms"]), 4)
            self.assertEqual(manifest["platforms"]["darwin-aarch64"], manifest["platforms"]["darwin-x86_64"])
            self.assertEqual(manifest["platforms"]["linux-x86_64"]["signature"], signature)
            for index in range(len(assets)):
                with self.assertRaises(ValueError):
                    generate_manifest(version, assets[:index] + assets[index + 1:], signatures, "")
            for key, value in [("size", 0), ("state", "new"), ("url", "https://example.com/wrong.exe")]:
                invalid = copy.deepcopy(assets)
                invalid[0][key] = value
                with self.assertRaises(ValueError):
                    generate_manifest(version, invalid, signatures, "")
            wrong_version = base64.b64decode(signature).replace(b"version:1.4.5", b"version:1.4.4")
            (signatures / (names[0] + ".sig")).write_text(base64.b64encode(wrong_version).decode())
            with self.assertRaisesRegex(ValueError, "版本"):
                generate_manifest(version, assets, signatures, "")


if __name__ == "__main__":
    unittest.main()
