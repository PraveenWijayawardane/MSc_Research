import sys
import tempfile
import unittest
from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "src"),
)

sys.path.insert(
    0,
    str(PROJECT_ROOT / "scripts"),
)


from onboard_environment import (  # noqa: E402
    onboard_profile,
)
from profile_version_manager import (  # noqa: E402
    ProfileVersionManager,
)
from test_profile_validator import (  # noqa: E402
    valid_profile,
)


class EnvironmentOnboardingTests(unittest.TestCase):

    def write_profile(
        self,
        directory: Path,
    ) -> Path:
        profile_path = (
            directory
            / "hospital-profile.yaml"
        )

        profile_path.write_text(
            yaml.safe_dump(
                valid_profile(),
                sort_keys=False,
            ),
            encoding="utf-8",
        )

        return profile_path

    def test_dry_run_does_not_create_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile_path = self.write_profile(
                root
            )
            config_root = (
                root / "config"
            )

            result = onboard_profile(
                profile_path=profile_path,
                config_root=config_root,
                dry_run=True,
                archive=False,
            )

            self.assertTrue(
                result["dry_run"]
            )

            self.assertFalse(
                Path(
                    result[
                        "version_directory"
                    ]
                ).exists()
            )

    def test_onboarding_creates_inactive_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile_path = self.write_profile(
                root
            )
            config_root = (
                root / "config"
            )

            result = onboard_profile(
                profile_path=profile_path,
                config_root=config_root,
                archive=False,
                version_id=(
                    "20260727T100000Z"
                ),
            )

            self.assertFalse(
                result["activated"]
            )

            self.assertTrue(
                Path(
                    result[
                        "version_environment_file"
                    ]
                ).exists()
            )

            self.assertFalse(
                (
                    config_root
                    / "environments"
                    / "healthcare-lab"
                ).exists()
            )

    def test_onboarding_can_activate_new_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile_path = self.write_profile(
                root
            )
            config_root = (
                root / "config"
            )

            result = onboard_profile(
                profile_path=profile_path,
                config_root=config_root,
                archive=False,
                activate=True,
                version_id=(
                    "20260727T100000Z"
                ),
            )

            self.assertTrue(
                result["activated"]
            )

            manager = ProfileVersionManager(
                config_root
            )

            current = manager.current_version(
                "healthcare-lab",
                required=True,
            )

            self.assertEqual(
                current["active_version"],
                "20260727T100000Z",
            )

    def test_multiple_onboarding_versions_are_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile_path = self.write_profile(
                root
            )
            config_root = (
                root / "config"
            )

            first = onboard_profile(
                profile_path=profile_path,
                config_root=config_root,
                archive=False,
                version_id=(
                    "20260727T100000Z"
                ),
            )

            second = onboard_profile(
                profile_path=profile_path,
                config_root=config_root,
                archive=False,
                version_id=(
                    "20260727T110000Z"
                ),
            )

            self.assertNotEqual(
                first["version_id"],
                second["version_id"],
            )

            manager = ProfileVersionManager(
                config_root
            )

            self.assertEqual(
                len(
                    manager.list_versions(
                        "healthcare-lab"
                    )
                ),
                2,
            )


if __name__ == "__main__":
    unittest.main()