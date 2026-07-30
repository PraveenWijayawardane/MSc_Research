import json
import os
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

sys.path.insert(
    0,
    str(PROJECT_ROOT / "scripts"),
)


from live_pipeline import (  # noqa: E402
    CommandResult,
    LivePipeline,
    PipelineLock,
    PipelineLockError,
    PipelineOptions,
    process_is_running,
    scored_output_counts,
)


class FakeRunner:

    def __init__(self):
        self.commands = []

    def run(
        self,
        command,
        *,
        cwd,
        environment,
        timeout_seconds,
    ):
        self.commands.append(
            list(command)
        )

        script_name = Path(
            command[1]
        ).name

        environment_id = (
            environment[
                "ENVIRONMENT_ID"
            ]
        )

        data_directory = (
            Path(cwd)
            / "data"
            / environment_id
        )

        output_directory = (
            Path(cwd)
            / "output"
            / environment_id
        )

        data_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        if script_name == (
            "wazuh_live_collector.py"
        ):
            (
                data_directory
                / "live_wazuh_events.json"
            ).write_text(
                json.dumps(
                    [
                        {
                            "event_id": "w1",
                            "environment_id": (
                                environment_id
                            ),
                        }
                    ]
                ),
                encoding="utf-8",
            )

        elif script_name == (
            "zeek_log_parser.py"
        ):
            (
                data_directory
                / "live_zeek_conn.json"
            ).write_text(
                json.dumps(
                    [
                        {
                            "event_id": "z1",
                            "environment_id": (
                                environment_id
                            ),
                        }
                    ]
                ),
                encoding="utf-8",
            )

        elif script_name == (
            "risk_engine.py"
        ):
            (
                output_directory
                / "scored_events.json"
            ).write_text(
                json.dumps(
                    {
                        "environment": {
                            "environment_id": (
                                environment_id
                            ),
                        },
                        "wazuh_results": [
                            {
                                "event_id": "w1",
                            }
                        ],
                        "zeek_results": [
                            {
                                "event_id": "z1",
                            }
                        ],
                        "correlated_results": [
                            {
                                "event_id": "z1",
                                "correlated": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

        return CommandResult(
            command=list(command),
            return_code=0,
            stdout="ok",
            stderr="",
            duration_seconds=0.01,
        )


class LivePipelineTests(unittest.TestCase):

    def test_one_cycle_runs_all_python_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            zeek_log = (
                root / "sample_conn.log"
            )

            zeek_log.write_text(
                "#separator \\x09\n",
                encoding="utf-8",
            )

            runner = FakeRunner()

            pipeline = LivePipeline(
                project_root=root,
                environment_id=(
                    "healthcare-lab"
                ),
                python_executable=(
                    "python"
                ),
                runner=runner,
                environment={},
            )

            state = pipeline.run_cycle(
                PipelineOptions(
                    zeek_local_source=(
                        zeek_log
                    ),
                    dry_run=True,
                )
            )

            scripts = [
                Path(command[1]).name
                for command in (
                    runner.commands
                )
            ]

            self.assertEqual(
                scripts,
                [
                    "wazuh_live_collector.py",
                    "zeek_log_parser.py",
                    "risk_engine.py",
                    "push_scored_events.py",
                ],
            )

            self.assertEqual(
                state["status"],
                "success",
            )

            self.assertEqual(
                state[
                    "correlated_events"
                ],
                1,
            )

            self.assertEqual(
                state[
                    "published_documents"
                ],
                2,
            )

            self.assertTrue(
                pipeline.paths
                .pipeline_state_file
                .is_file()
            )

    def test_skip_flags_use_existing_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FakeRunner()

            pipeline = LivePipeline(
                project_root=root,
                environment_id=(
                    "healthcare-lab"
                ),
                python_executable=(
                    "python"
                ),
                runner=runner,
                environment={},
            )

            pipeline.paths.wazuh_events_file.write_text(
                "[]",
                encoding="utf-8",
            )

            pipeline.paths.zeek_conn_json_file.write_text(
                "[]",
                encoding="utf-8",
            )

            state = pipeline.run_cycle(
                PipelineOptions(
                    skip_wazuh=True,
                    skip_zeek=True,
                    skip_publish=True,
                )
            )

            scripts = [
                Path(command[1]).name
                for command in (
                    runner.commands
                )
            ]

            self.assertEqual(
                scripts,
                [
                    "risk_engine.py",
                ],
            )

            self.assertEqual(
                state["status"],
                "success",
            )

    def test_current_process_is_detected_without_interrupt(self):
        self.assertTrue(
            process_is_running(
                os.getpid()
            )
        )

    def test_nonexistent_process_is_not_running(self):
        self.assertFalse(
            process_is_running(
                99999999
            )
        )

    def test_lock_rejects_live_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = (
                Path(directory)
                / "live_pipeline.lock"
            )

            lock_path.write_text(
                json.dumps(
                    {
                        "pid": os.getpid(),
                    }
                ),
                encoding="utf-8",
            )

            lock = PipelineLock(
                lock_path,
                "healthcare-lab",
            )

            with self.assertRaises(
                PipelineLockError
            ):
                lock.acquire()

    def test_stale_lock_is_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = (
                Path(directory)
                / "live_pipeline.lock"
            )

            lock_path.write_text(
                json.dumps(
                    {
                        "pid": 99999999,
                    }
                ),
                encoding="utf-8",
            )

            with PipelineLock(
                lock_path,
                "healthcare-lab",
            ):
                metadata = json.loads(
                    lock_path.read_text(
                        encoding="utf-8"
                    )
                )

                self.assertEqual(
                    metadata["pid"],
                    os.getpid(),
                )

            self.assertFalse(
                lock_path.exists()
            )

    def test_scored_output_count_replaces_zeek_with_correlated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = (
                Path(directory)
                / "scored_events.json"
            )

            path.write_text(
                json.dumps(
                    {
                        "wazuh_results": [
                            {
                                "event_id": "w1",
                            }
                        ],
                        "zeek_results": [
                            {
                                "event_id": "z1",
                            },
                            {
                                "event_id": "z2",
                            },
                        ],
                        "correlated_results": [
                            {
                                "event_id": "z1",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            counts = scored_output_counts(
                path
            )

            self.assertEqual(
                counts[
                    "published_documents"
                ],
                3,
            )


if __name__ == "__main__":
    unittest.main()