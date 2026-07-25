import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "src"),
)

from behavior_analyzer import BehaviorAnalyzer  # noqa: E402


class BehaviorAnalyzerTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.analyzer = BehaviorAnalyzer.from_file(
            PROJECT_ROOT
            / "config"
            / "risk_rules.yaml"
        )

    @staticmethod
    def make_event(
        uid,
        timestamp,
        destination_ip="192.168.100.30",
        destination_port=5000,
        service="http",
        conn_state="SF",
        source_ip="192.168.100.25",
        source_role="workstation",
        destination_role="ehr_app",
        orig_bytes=100,
        resp_bytes=100,
        duration=1,
    ):
        return {
            "uid": uid,
            "ts": timestamp,
            "id.orig_h": source_ip,
            "id.orig_p": 45000,
            "id.resp_h": destination_ip,
            "id.resp_p": destination_port,
            "proto": "tcp",
            "service": service,
            "conn_state": conn_state,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "duration": duration,
            "source_role": source_role,
            "destination_role": destination_role,
        }

    def test_duplicate_event_is_analyzed_once(self):
        event = self.make_event(
            uid="C-duplicate",
            timestamp="2026-07-22T04:30:00Z",
        )

        results = self.analyzer.analyze(
            [
                event,
                dict(event),
                dict(event),
            ]
        )

        self.assertEqual(len(results), 1)

    def test_repeated_connections_reach_medium_threshold(self):
        events = []

        # Ten connections occur within 4 minutes and 30 seconds.
        # Therefore, all events remain inside the configured 5-minute window.
        for index in range(10):
            minute = 30 + (index // 2)
            second = 30 if index % 2 else 0

            events.append(
                self.make_event(
                    uid=f"C-frequency-{index}",
                    timestamp=(
                        f"2026-07-22T04:"
                        f"{minute:02d}:{second:02d}Z"
                    ),
                )
            )

        results = self.analyzer.analyze(events)

        latest = results["zeek:C-frequency-9"]

        self.assertEqual(
            latest["behavior_metrics"][
                "connection_frequency"
            ],
            10,
        )

        self.assertGreaterEqual(
            latest["behavior_score"],
            2,
        )

    def test_port_fanout_is_detected(self):
        events = []

        for index in range(10):
            events.append(
                self.make_event(
                    uid=f"C-port-{index}",
                    timestamp="2026-07-22T04:30:00Z",
                    destination_port=10000 + index,
                    service="unknown",
                )
            )

        results = self.analyzer.analyze(events)

        latest = results["zeek:C-port-9"]

        self.assertEqual(
            latest["behavior_metrics"][
                "distinct_destination_ports"
            ],
            10,
        )

        self.assertGreaterEqual(
            latest["behavior_score"],
            7,
        )

    def test_rejected_connection_burst_is_detected(self):
        events = []

        for index in range(5):
            events.append(
                self.make_event(
                    uid=f"C-rejected-{index}",
                    timestamp="2026-07-22T04:30:00Z",
                    destination_port=10000 + index,
                    service="unknown",
                    conn_state="S0",
                )
            )

        results = self.analyzer.analyze(events)

        latest = results[
            "zeek:C-rejected-4"
        ]

        self.assertEqual(
            latest["behavior_metrics"][
                "rejected_connections"
            ],
            5,
        )

        self.assertGreaterEqual(
            latest["behavior_score"],
            3,
        )

    def test_off_hours_activity_is_detected(self):
        event = self.make_event(
            uid="C-off-hours",
            # 20:30 in Sri Lanka.
            timestamp="2026-07-22T15:00:00Z",
        )

        result = self.analyzer.analyze(
            [event]
        )["zeek:C-off-hours"]

        self.assertTrue(
            result["behavior_metrics"][
                "is_off_hours"
            ]
        )

        self.assertIn(
            (
                "Activity occurred outside "
                "configured working hours"
            ),
            result["behavior_reasons"],
        )

    def test_weekend_activity_is_detected(self):
        event = self.make_event(
            uid="C-weekend",
            # Saturday, 10:00 in Sri Lanka.
            timestamp="2026-07-25T04:30:00Z",
        )

        result = self.analyzer.analyze(
            [event]
        )["zeek:C-weekend"]

        self.assertTrue(
            result["behavior_metrics"][
                "is_weekend"
            ]
        )

    def test_same_snapshot_produces_same_result(self):
        event = self.make_event(
            uid="C-deterministic",
            timestamp="2026-07-22T04:30:00Z",
            destination_port=445,
            service="smb",
        )

        first = self.analyzer.analyze(
            [event]
        )["zeek:C-deterministic"]

        second = self.analyzer.analyze(
            [event]
        )["zeek:C-deterministic"]

        self.assertEqual(
            first["behavior_score"],
            second["behavior_score"],
        )

        self.assertEqual(
            first["behavior_metrics"],
            second["behavior_metrics"],
        )

        self.assertEqual(
            first["behavior_reasons"],
            second["behavior_reasons"],
        )


if __name__ == "__main__":
    unittest.main()