import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]

sys.path.insert(
    0,
    str(
        PROJECT_ROOT / "src"
    ),
)


from push_scored_events import (  # noqa: E402
    PushConfigurationError,
    build_final_documents,
    sanitize_document,
)


def sample_output():
    return {
        "environment": {
            "environment_id": (
                "healthcare-lab"
            ),
            "environment_name": (
                "Healthcare Security Research Lab"
            ),
            "site_id": "research-lab",
            "environment_type": "lab",
            "infrastructure_type": (
                "bare-metal"
            ),
        },
        "wazuh_results": [
            {
                "event_id": "wazuh:w1",
                "environment_id": (
                    "healthcare-lab"
                ),
                "timestamp": (
                    "2026-07-27T10:00:00Z"
                ),
                "event_type": (
                    "host_activity"
                ),
                "event_source": "wazuh",
                "risk_score": 4,
            }
        ],
        "zeek_results": [
            {
                "event_id": "zeek:z1",
                "environment_id": (
                    "healthcare-lab"
                ),
                "timestamp": (
                    "2026-07-27T10:00:01Z"
                ),
                "event_type": (
                    "network_connection"
                ),
                "event_source": "zeek",
                "risk_score": 5,
                "uid": "z1",
                "source_ip": (
                    "192.168.100.20"
                ),
                "destination_ip": (
                    "192.168.100.30"
                ),
            }
        ],
        "correlated_results": [
            {
                "event_id": "zeek:z1",
                "environment_id": (
                    "healthcare-lab"
                ),
                "timestamp": (
                    "2026-07-27T10:00:01Z"
                ),
                "event_type": (
                    "correlated_network_activity"
                ),
                "event_source": (
                    "zeek+wazuh"
                ),
                "correlated": True,
                "risk_score": 12,
                "uid": "z1",
                "source_ip": (
                    "192.168.100.20"
                ),
                "destination_ip": (
                    "192.168.100.30"
                ),
            }
        ],
    }


class PushScoredEventsTests(
    unittest.TestCase
):

    def test_correlated_event_replaces_standalone(self):
        documents = build_final_documents(
            sample_output(),
            "healthcare-lab",
        )

        self.assertEqual(
            len(documents),
            2,
        )

        by_id = {
            document["event_id"]:
            document
            for document in documents
        }

        self.assertTrue(
            by_id["zeek:z1"][
                "correlated"
            ]
        )

        self.assertEqual(
            by_id["zeek:z1"][
                "risk_score"
            ],
            12,
        )

    def test_all_documents_include_environment(self):
        documents = build_final_documents(
            sample_output(),
            "healthcare-lab",
        )

        for document in documents:
            self.assertEqual(
                document[
                    "environment_id"
                ],
                "healthcare-lab",
            )

            self.assertEqual(
                document[
                    "site_id"
                ],
                "research-lab",
            )

    def test_wrong_top_level_environment_is_rejected(self):
        output = sample_output()

        output["environment"][
            "environment_id"
        ] = "hospital-a-prod"

        with self.assertRaises(
            PushConfigurationError
        ):
            build_final_documents(
                output,
                "healthcare-lab",
            )

    def test_wrong_event_environment_is_rejected(self):
        output = sample_output()

        output["wazuh_results"][0][
            "environment_id"
        ] = "hospital-a-prod"

        with self.assertRaises(
            PushConfigurationError
        ):
            build_final_documents(
                output,
                "healthcare-lab",
            )

    def test_invalid_ip_is_removed(self):
        document = sanitize_document(
            {
                "event_id": "zeek:test",
                "event_type": (
                    "network_connection"
                ),
                "source_ip": "invalid",
                "destination_ip": (
                    "192.168.100.30"
                ),
            }
        )

        self.assertNotIn(
            "source_ip",
            document,
        )

        self.assertEqual(
            document[
                "destination_ip"
            ],
            "192.168.100.30",
        )

    def test_cross_source_id_collision_is_rejected(self):
        output = sample_output()

        output["wazuh_results"][0][
            "event_id"
        ] = "zeek:z1"

        with self.assertRaises(
            PushConfigurationError
        ):
            build_final_documents(
                output,
                "healthcare-lab",
            )


if __name__ == "__main__":
    unittest.main()