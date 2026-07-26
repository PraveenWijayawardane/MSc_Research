import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "src"),
)


from event_environment import (  # noqa: E402
    EventEnvironmentError,
    attach_environment,
    get_event_environment,
    resolve_environment_id,
)


class EventEnvironmentTests(unittest.TestCase):

    def test_explicit_environment_is_normalised(self):
        self.assertEqual(
            resolve_environment_id(
                " Hospital-A-Prod "
            ),
            "hospital-a-prod",
        )

    def test_environment_variable_is_supported(self):
        with patch.dict(
            os.environ,
            {
                "ENVIRONMENT_ID": (
                    "healthcare-lab"
                )
            },
            clear=False,
        ):
            self.assertEqual(
                resolve_environment_id(),
                "healthcare-lab",
            )

    def test_missing_environment_is_rejected(self):
        with patch.dict(
            os.environ,
            {},
            clear=True,
        ):
            with self.assertRaises(
                EventEnvironmentError
            ):
                resolve_environment_id()

    def test_zeek_event_is_tagged(self):
        event = {
            "uid": "C-test"
        }

        tagged = attach_environment(
            event,
            "hospital-a-prod",
        )

        self.assertEqual(
            tagged["environment_id"],
            "hospital-a-prod",
        )

        self.assertNotIn(
            "environment_id",
            event,
        )

    def test_wazuh_source_is_tagged(self):
        event = {
            "_id": "w1",
            "_source": {
                "timestamp": (
                    "2026-07-27T01:00:00Z"
                )
            },
        }

        tagged = attach_environment(
            event,
            "hospital-a-prod",
        )

        self.assertEqual(
            tagged["_source"][
                "environment_id"
            ],
            "hospital-a-prod",
        )

        self.assertEqual(
            get_event_environment(
                tagged
            ),
            "hospital-a-prod",
        )

    def test_retagging_another_environment_is_rejected(self):
        event = {
            "environment_id": (
                "healthcare-lab"
            )
        }

        with self.assertRaises(
            EventEnvironmentError
        ):
            attach_environment(
                event,
                "hospital-a-prod",
            )


if __name__ == "__main__":
    unittest.main()