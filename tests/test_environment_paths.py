import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "src"),
)


from environment_paths import EnvironmentPaths  # noqa: E402


class EnvironmentPathsTests(unittest.TestCase):

    def test_pipeline_files_are_environment_specific(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = EnvironmentPaths(
                project_root=Path(directory),
                environment_id=(
                    "healthcare-lab"
                ),
            )

            self.assertEqual(
                paths.pipeline_state_file,
                (
                    Path(directory).resolve()
                    / "logs"
                    / "healthcare-lab"
                    / "live_pipeline_state.json"
                ),
            )

            self.assertEqual(
                paths.pipeline_lock_file,
                (
                    Path(directory).resolve()
                    / "logs"
                    / "healthcare-lab"
                    / "live_pipeline.lock"
                ),
            )

    def test_ensure_directories_creates_all_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = EnvironmentPaths(
                project_root=Path(directory),
                environment_id=(
                    "healthcare-lab"
                ),
            )

            paths.ensure_directories()

            self.assertTrue(
                paths.data_directory.is_dir()
            )
            self.assertTrue(
                paths.output_directory.is_dir()
            )
            self.assertTrue(
                paths.logs_directory.is_dir()
            )


if __name__ == "__main__":
    unittest.main()