import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/release.yml"


class ReleaseDirectUploadTests(unittest.TestCase):
    def test_版本同步允许冷启动获取索引且草稿更新目标提交(self):
        script = (WORKFLOW.parents[2] / "scripts/bump-version.sh").read_text(encoding="utf-8")
        self.assertIn('--precise "$VERSION"', script)
        self.assertNotIn("--offline", script)
        self.assertIn('gh release edit "$tag" --repo "$GITHUB_REPOSITORY" --target "$(git rev-parse HEAD)"', WORKFLOW.read_text(encoding="utf-8"))

    def test_release_does_not_depend_on_actions_artifact_quota(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("actions/upload-artifact@", workflow)
        self.assertNotIn("actions/download-artifact@", workflow)
        self.assertEqual(workflow.count("gh release upload"), 4)
        self.assertIn("generate_update_manifest.py", workflow)
        self.assertLess(workflow.index("generate_update_manifest.py"), workflow.index("--draft=false"))
        self.assertIn("secrets.TAURI_SIGNING_PRIVATE_KEY", workflow)
        self.assertIn("禁止覆盖已公开的 Release", workflow)
        self.assertIn("--draft=false", workflow)
        self.assertIn("needs: prepare", workflow)


if __name__ == "__main__":
    unittest.main()
