import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from pipeline_health_check import PipelineHealthChecker  # noqa: E402


class PipelineHealthCheckTests(unittest.TestCase):
    def create_runtime(self, root: Path, completed_at: datetime) -> PipelineHealthChecker:
        checker = PipelineHealthChecker(
            project_root=root,
            environment_id="healthcare-lab",
            max_cycle_age_seconds=180,
            max_input_age_seconds=300,
            max_output_age_seconds=300,
            skip_opensearch=True,
        )
        checker.paths.ensure_directories()

        checker.paths.pipeline_lock_file.write_text(
            json.dumps({"pid": os.getpid()}),
            encoding="utf-8",
        )
        checker.paths.pipeline_state_file.write_text(
            json.dumps(
                {
                    "status": "success",
                    "last_completed_at": completed_at.isoformat().replace("+00:00", "Z"),
                    "steps": [
                        {"name": "collect_wazuh", "status": "success"},
                        {"name": "collect_zeek_log", "status": "success"},
                        {"name": "publish", "status": "success"},
                    ],
                }
            ),
            encoding="utf-8",
        )

        for path in (
            checker.paths.wazuh_events_file,
            checker.paths.zeek_conn_log_file,
            checker.paths.scored_events_file,
        ):
            path.write_text("{}\n", encoding="utf-8")

        return checker

    def test_recent_successful_pipeline_is_healthy(self):
        with tempfile.TemporaryDirectory() as directory:
            checker = self.create_runtime(
                Path(directory),
                datetime.now(timezone.utc),
            )
            results = checker.run()
            self.assertTrue(all(result.healthy for result in results))
            self.assertEqual(results[0].status, "HEALTHY")
            self.assertEqual(results[1].status, "HEALTHY")

    def test_stale_cycle_is_unhealthy(self):
        with tempfile.TemporaryDirectory() as directory:
            checker = self.create_runtime(
                Path(directory),
                datetime.now(timezone.utc) - timedelta(minutes=10),
            )
            result = checker.check_state()
            self.assertEqual(result.status, "UNHEALTHY")
            self.assertFalse(result.healthy)

    def test_stale_input_is_unhealthy(self):
        with tempfile.TemporaryDirectory() as directory:
            checker = self.create_runtime(
                Path(directory),
                datetime.now(timezone.utc),
            )
            old = time.time() - 1000
            os.utime(checker.paths.zeek_conn_log_file, (old, old))
            result = checker.check_file(
                "Zeek input",
                checker.paths.zeek_conn_log_file,
                300,
            )
            self.assertEqual(result.status, "UNHEALTHY")


if __name__ == "__main__":
    unittest.main()
