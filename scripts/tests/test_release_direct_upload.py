import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/release.yml"


class ReleaseDirectUploadTests(unittest.TestCase):
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
