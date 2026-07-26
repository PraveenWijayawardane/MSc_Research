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
    EnvironmentOnboardingError,
    onboard_profile,
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

    def test_dry_run_does_not_create_environment(self):
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
            )

            self.assertTrue(
                result["dry_run"]
            )

            self.assertFalse(
                (
                    config_root
                    / "environments"
                    / "healthcare-lab"
                ).exists()
            )

    def test_onboarding_creates_split_files(self):
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
            )

            environment_file = Path(
                result["environment_file"]
            )

            asset_context_file = Path(
                result["asset_context_file"]
            )

            self.assertTrue(
                environment_file.exists()
            )

            self.assertTrue(
                asset_context_file.exists()
            )

            environment_data = yaml.safe_load(
                environment_file.read_text(
                    encoding="utf-8"
                )
            )

            asset_data = yaml.safe_load(
                asset_context_file.read_text(
                    encoding="utf-8"
                )
            )

            self.assertEqual(
                environment_data[
                    "environment"
                ]["id"],
                "healthcare-lab",
            )

            self.assertEqual(
                asset_data[
                    "critical_assets"
                ][
                    "192.168.100.40"
                ]["role"],
                "database",
            )

    def test_existing_environment_requires_force(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile_path = self.write_profile(
                root
            )
            config_root = (
                root / "config"
            )

            onboard_profile(
                profile_path=profile_path,
                config_root=config_root,
                archive=False,
            )

            with self.assertRaises(
                EnvironmentOnboardingError
            ):
                onboard_profile(
                    profile_path=profile_path,
                    config_root=config_root,
                    archive=False,
                )

    def test_force_creates_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile_path = self.write_profile(
                root
            )
            config_root = (
                root / "config"
            )

            onboard_profile(
                profile_path=profile_path,
                config_root=config_root,
                archive=False,
            )

            result = onboard_profile(
                profile_path=profile_path,
                config_root=config_root,
                force=True,
                archive=False,
            )

            backup_directory = Path(
                result[
                    "backup_directory"
                ]
            )

            self.assertTrue(
                backup_directory.exists()
            )

            self.assertTrue(
                (
                    backup_directory
                    / "environment.yaml"
                ).exists()
            )


if __name__ == "__main__":
    unittest.main()