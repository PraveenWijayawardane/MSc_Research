import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from push_scored_events import (  # noqa: E402
    build_final_documents,
    sanitize_document,
)


class PushScoredEventsTests(unittest.TestCase):

    def test_correlated_result_replaces_standalone_zeek_result(self):
        scored_output = {
            "wazuh_results": [],
            "zeek_results": [
                {
                    "event_id": "zeek:C-1",
                    "timestamp": "2026-07-22T04:30:00Z",
                    "event_source": "zeek",
                    "event_type": "network_connection",
                    "correlated": False,
                    "risk_score": 5,
                }
            ],
            "correlated_results": [
                {
                    "event_id": "zeek:C-1",
                    "timestamp": "2026-07-22T04:30:00Z",
                    "event_source": "zeek+wazuh",
                    "event_type": (
                        "correlated_network_activity"
                    ),
                    "correlated": True,
                    "risk_score": 14,
                }
            ],
        }

        documents = build_final_documents(
            scored_output
        )

        self.assertEqual(len(documents), 1)
        self.assertTrue(
            documents[0]["correlated"]
        )
        self.assertEqual(
            documents[0]["risk_score"],
            14,
        )

    def test_wazuh_and_zeek_documents_are_both_retained(self):
        scored_output = {
            "wazuh_results": [
                {
                    "event_id": "wazuh:1",
                    "timestamp": "2026-07-22T04:29:00Z",
                    "event_type": "host_activity",
                }
            ],
            "zeek_results": [
                {
                    "event_id": "zeek:C-1",
                    "timestamp": "2026-07-22T04:30:00Z",
                    "event_type": "network_connection",
                }
            ],
            "correlated_results": [],
        }

        documents = build_final_documents(
            scored_output
        )

        self.assertEqual(len(documents), 2)

        self.assertEqual(
            {
                document["event_id"]
                for document in documents
            },
            {
                "wazuh:1",
                "zeek:C-1",
            },
        )

    def test_timestamp_is_copied_to_at_timestamp(self):
        document = sanitize_document(
            {
                "event_id": "zeek:C-1",
                "timestamp": "2026-07-22T04:30:00Z",
                "event_type": "network_connection",
            }
        )

        self.assertEqual(
            document["@timestamp"],
            "2026-07-22T04:30:00Z",
        )

    def test_invalid_ip_fields_are_removed(self):
        document = sanitize_document(
            {
                "event_id": "zeek:C-1",
                "timestamp": "2026-07-22T04:30:00Z",
                "event_type": "network_connection",
                "source_ip": "unknown",
                "destination_ip": "not-an-ip",
                "ip": "",
                "behavior_metrics": {
                    "source_ip": "unknown",
                },
            }
        )

        self.assertNotIn(
            "source_ip",
            document,
        )
        self.assertNotIn(
            "destination_ip",
            document,
        )
        self.assertNotIn(
            "ip",
            document,
        )
        self.assertNotIn(
            "source_ip",
            document["behavior_metrics"],
        )

    def test_raw_zeek_dot_fields_are_removed(self):
        document = sanitize_document(
            {
                "event_id": "zeek:C-1",
                "timestamp": "2026-07-22T04:30:00Z",
                "event_type": "network_connection",
                "uid": "C-1",
                "id.orig_h": "192.168.100.25",
                "id.resp_h": "192.168.100.30",
            }
        )

        self.assertEqual(
            document["zeek_uid"],
            "C-1",
        )
        self.assertNotIn(
            "id.orig_h",
            document,
        )
        self.assertNotIn(
            "id.resp_h",
            document,
        )
        self.assertNotIn(
            "uid",
            document,
        )

    def test_duplicate_ids_are_deduplicated(self):
        scored_output = {
            "wazuh_results": [
                {
                    "event_id": "wazuh:1",
                    "timestamp": "2026-07-22T04:29:00Z",
                    "event_type": "host_activity",
                    "risk_score": 2,
                },
                {
                    "event_id": "wazuh:1",
                    "timestamp": "2026-07-22T04:29:00Z",
                    "event_type": "host_activity",
                    "risk_score": 6,
                },
            ],
            "zeek_results": [],
            "correlated_results": [],
        }

        documents = build_final_documents(
            scored_output
        )

        self.assertEqual(len(documents), 1)
        self.assertEqual(
            documents[0]["risk_score"],
            6,
        )


if __name__ == "__main__":
    unittest.main()