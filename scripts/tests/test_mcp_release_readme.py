import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "render-mcp-release-readme.sh"


class RenderMcpReleaseReadmeTests(unittest.TestCase):
    def test_发布脚本的说明模板使用带引号_heredoc(self) -> None:
        for name in ("release-cli.sh", "release-linux.sh", "release-macos.sh"):
            path = ROOT / "scripts" / name
            text = path.read_text(encoding="utf-8")
            heredocs = [
                line
                for line in text.splitlines()
                if "README.md" in line and "<<" in line
            ]
            self.assertTrue(heredocs, name)
            for line in heredocs:
                self.assertIn("<< '", line, f"{name} 的 README heredoc 未加引号: {line}")

    def test_发布工作流使用安全的说明渲染脚本(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "cli-release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/render-mcp-release-readme.sh", workflow)
        self.assertNotIn("cat > bundle/README.md", workflow)

    def test_说明文字不会被命令替换执行(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            marker = root / "executed"
            fake_bin = root / "bin"
            fake_bin.mkdir()
            shield = fake_bin / "shield"
            shield.write_text(
                "#!/bin/sh\n"
                f"printf 'executed' > '{marker}'\n",
                encoding="utf-8",
            )
            shield.chmod(0o755)

            output = root / "README.md"
            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}{os.pathsep}{env.get('PATH', '')}"
            subprocess.run(
                ["bash", str(SCRIPT), str(output), "1.10.2", "macos-universal"],
                check=True,
                env=env,
            )

            text = output.read_text(encoding="utf-8")
            self.assertFalse(marker.exists(), "反引号被 shell 执行了")
            self.assertIn("# Shellsmith CLI + MCP 1.10.2", text)
            self.assertIn("Platform: macos-universal", text)
            self.assertIn("`shield`", text)
            self.assertIn("`--cli /path/to/shield`", text)
            self.assertFalse((root / "README.md.tmp").exists())


if __name__ == "__main__":
    unittest.main()
