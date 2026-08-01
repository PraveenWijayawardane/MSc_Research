import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from research_preflight import PreflightSettings, ResearchPreflight  # noqa: E402


class ResearchPreflightTests(unittest.TestCase):
    def create_profile(self, root: Path) -> None:
        profile = root / "config" / "environments" / "healthcare-lab"
        profile.mkdir(parents=True, exist_ok=True)
        (profile / "asset_context.yaml").write_text("assets: {}\n", encoding="utf-8")
        (profile / "active_version.json").write_text(
            json.dumps({"version_id": "v-test"}),
            encoding="utf-8",
        )

    def test_local_checks_pass_and_repair_stale_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.create_profile(root)

            checker = ResearchPreflight(
                project_root=root,
                settings=PreflightSettings(
                    environment_id="healthcare-lab",
                    repair_stale_lock=True,
                    skip_opensearch=True,
                    skip_zeek=True,
                ),
                environment={},
            )
            checker.paths.ensure_directories()
            checker.paths.pipeline_lock_file.write_text(
                json.dumps({"pid": 99999999}),
                encoding="utf-8",
            )

            profile_result = checker.check_profile()
            directory_result = checker.check_directories()
            lock_result = checker.check_lock()

            self.assertEqual(profile_result.status, "PASS")
            self.assertEqual(directory_result.status, "PASS")
            self.assertEqual(lock_result.status, "PASS")
            self.assertFalse(checker.paths.pipeline_lock_file.exists())

    def test_missing_profile_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            checker = ResearchPreflight(
                project_root=Path(directory),
                settings=PreflightSettings(
                    environment_id="healthcare-lab",
                    skip_opensearch=True,
                    skip_zeek=True,
                ),
                environment={},
            )
            result = checker.check_profile()
            self.assertEqual(result.status, "FAIL")
            self.assertFalse(result.passed)

    def test_live_lock_is_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.create_profile(root)
            checker = ResearchPreflight(
                project_root=root,
                settings=PreflightSettings(
                    environment_id="healthcare-lab",
                    skip_opensearch=True,
                    skip_zeek=True,
                ),
                environment={},
            )
            checker.paths.ensure_directories()
            checker.paths.pipeline_lock_file.write_text(
                json.dumps({"pid": os.getpid()}),
                encoding="utf-8",
            )
            result = checker.check_lock()
            self.assertEqual(result.status, "WARN")
            self.assertTrue(result.passed)


if __name__ == "__main__":
    unittest.main()
