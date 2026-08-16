import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "src"),
)


from risk_engine import ContextualRiskEngine  # noqa: E402


class RiskFilteringIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = ContextualRiskEngine.from_environment(
            environment_id="healthcare-lab",
            config_root=PROJECT_ROOT / "config",
        )

    @staticmethod
    def zeek_event(
        uid: str,
        destination_ip: str,
        destination_port: int,
        proto: str = "tcp",
        service: str = "unknown",
    ) -> dict:
        return {
            "uid": uid,
            "ts": "2026-07-22T04:30:00Z",
            "id.orig_h": "192.168.100.20",
            "id.orig_p": 45000,
            "id.resp_h": destination_ip,
            "id.resp_p": destination_port,
            "proto": proto,
            "service": service,
            "conn_state": "SF",
            "orig_bytes": 100,
            "resp_bytes": 100,
            "duration": 1,
        }

    def test_mdns_is_retained_as_input_but_not_scored(self):
        output = self.engine.build_output(
            wazuh_data=[],
            zeek_data=[
                self.zeek_event(
                    uid="C-mdns-noise",
                    destination_ip="224.0.0.251",
                    destination_port=5353,
                    proto="udp",
                    service="dns",
                )
            ],
        )

        self.assertEqual(
            output["summary"]["raw_zeek_event_count"],
            1,
        )
        self.assertEqual(
            output["summary"]["unique_zeek_input_count"],
            1,
        )
        self.assertEqual(
            output["summary"]["risk_eligible_zeek_event_count"],
            0,
        )
        self.assertEqual(
            output["summary"]["excluded_zeek_event_count"],
            1,
        )
        self.assertEqual(output["zeek_results"], [])
        self.assertEqual(output["correlated_results"], [])
        self.assertEqual(
            output["summary"]["final_document_count"],
            0,
        )

    def test_normal_ehr_connection_remains_scored(self):
        output = self.engine.build_output(
            wazuh_data=[],
            zeek_data=[
                self.zeek_event(
                    uid="C-normal-ehr",
                    destination_ip="192.168.100.30",
                    destination_port=5000,
                    proto="tcp",
                    service="http",
                )
            ],
        )

        self.assertEqual(
            output["summary"]["risk_eligible_zeek_event_count"],
            1,
        )
        self.assertEqual(
            output["summary"]["excluded_zeek_event_count"],
            0,
        )
        self.assertEqual(len(output["zeek_results"]), 1)


if __name__ == "__main__":
    unittest.main()