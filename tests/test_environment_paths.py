import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "src"),
)


from environment_paths import EnvironmentPaths  # noqa: E402


class EnvironmentPathsTests(unittest.TestCase):

    def test_environment_paths_are_isolated(self):
        paths = EnvironmentPaths(
            project_root=PROJECT_ROOT,
            environment_id="hospital-a-prod",
        )

        self.assertEqual(
            paths.wazuh_events_file,
            (
                PROJECT_ROOT.resolve()
                / "data"
                / "hospital-a-prod"
                / "live_wazuh_events.json"
            ),
        )

        self.assertEqual(
            paths.zeek_conn_log_file,
            (
                PROJECT_ROOT.resolve()
                / "data"
                / "hospital-a-prod"
                / "live_zeek_conn.log"
            ),
        )

        self.assertEqual(
            paths.zeek_conn_json_file,
            (
                PROJECT_ROOT.resolve()
                / "data"
                / "hospital-a-prod"
                / "live_zeek_conn.json"
            ),
        )

        self.assertEqual(
            paths.scored_events_file,
            (
                PROJECT_ROOT.resolve()
                / "output"
                / "hospital-a-prod"
                / "scored_events.json"
            ),
        )

    def test_different_environments_use_different_paths(self):
        lab_paths = EnvironmentPaths(
            project_root=PROJECT_ROOT,
            environment_id="healthcare-lab",
        )

        hospital_paths = EnvironmentPaths(
            project_root=PROJECT_ROOT,
            environment_id="hospital-a-prod",
        )

        self.assertNotEqual(
            lab_paths.wazuh_events_file,
            hospital_paths.wazuh_events_file,
        )

        self.assertNotEqual(
            lab_paths.zeek_conn_json_file,
            hospital_paths.zeek_conn_json_file,
        )

        self.assertNotEqual(
            lab_paths.scored_events_file,
            hospital_paths.scored_events_file,
        )

        self.assertNotEqual(
            lab_paths.pipeline_log_file,
            hospital_paths.pipeline_log_file,
        )

    def test_directories_are_created(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = EnvironmentPaths(
                project_root=Path(directory),
                environment_id="test-hospital",
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

    def test_environment_id_is_normalised(self):
        paths = EnvironmentPaths(
            project_root=PROJECT_ROOT,
            environment_id=" Hospital-A-Prod ",
        )

        self.assertEqual(
            paths.environment_id,
            "hospital-a-prod",
        )


if __name__ == "__main__":
    unittest.main()