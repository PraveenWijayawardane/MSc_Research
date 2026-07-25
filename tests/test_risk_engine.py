import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from risk_engine import ContextualRiskEngine  # noqa: E402


class ContextualRiskEngineTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = ContextualRiskEngine.from_files(
            asset_context_file=(
                PROJECT_ROOT
                / "config"
                / "asset_context.yaml"
            ),
            role_policies_file=(
                PROJECT_ROOT
                / "config"
                / "role_policies.yaml"
            ),
            risk_rules_file=(
                PROJECT_ROOT
                / "config"
                / "risk_rules.yaml"
            ),
        )

    @staticmethod
    def zeek_event(
        uid="C-test",
        source_ip="192.168.100.25",
        destination_ip="192.168.100.30",
        destination_port=5000,
        service="http",
        timestamp="2026-07-22T04:30:00Z",
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
            "conn_state": "SF",
            "orig_bytes": 100,
            "resp_bytes": 100,
            "duration": 1,
        }

    @staticmethod
    def wazuh_event(
        event_id,
        description,
        source_ip="192.168.100.25",
        timestamp="2026-07-22T04:29:59Z",
        rule_level=7,
    ):
        return {
            "_id": event_id,
            "_source": {
                "timestamp": timestamp,
                "agent": {
                    "ip": source_ip,
                    "name": "user-pc-25",
                },
                "rule": {
                    "id": "5503",
                    "level": rule_level,
                    "description": description,
                },
                "full_log": description,
            },
        }

    def test_unlisted_workstation_is_resolved_by_network_zone(self):
        output = self.engine.build_output(
            wazuh_data=[],
            zeek_data=[self.zeek_event()],
        )

        result = output["zeek_results"][0]

        self.assertEqual(
            result["source_role"],
            "workstation",
        )
        self.assertEqual(
            result["source_zone"],
            "healthcare_lab",
        )
        self.assertEqual(
            result["policy_name"],
            "workstation_to_ehr_application",
        )
        self.assertEqual(
            result["policy_action"],
            "allow",
        )

    def test_duplicate_zeek_event_is_scored_once(self):
        event = self.zeek_event(uid="C-duplicate")

        output = self.engine.build_output(
            wazuh_data=[],
            zeek_data=[
                event,
                dict(event),
                dict(event),
            ],
        )

        self.assertEqual(
            output["summary"]["raw_zeek_event_count"],
            3,
        )
        self.assertEqual(
            output["summary"]["unique_zeek_result_count"],
            1,
        )

    def test_workstation_direct_database_access_is_high_risk(self):
        output = self.engine.build_output(
            wazuh_data=[],
            zeek_data=[
                self.zeek_event(
                    uid="C-database",
                    destination_ip="192.168.100.40",
                    destination_port=5432,
                    service="postgresql",
                )
            ],
        )

        result = output["zeek_results"][0]

        self.assertEqual(
            result["policy_name"],
            "workstation_direct_database_access",
        )
        self.assertEqual(
            result["policy_action"],
            "deny",
        )
        self.assertGreaterEqual(result["risk_score"], 18)
        self.assertEqual(
            result["classification"],
            "Likely Malicious",
        )

    def test_multiple_wazuh_events_create_one_correlated_result(self):
        output = self.engine.build_output(
            wazuh_data=[
                self.wazuh_event(
                    "w1",
                    "authentication failure",
                ),
                self.wazuh_event(
                    "w2",
                    "failed password",
                ),
            ],
            zeek_data=[
                self.zeek_event(
                    uid="C-correlation",
                    destination_port=445,
                    destination_ip="192.168.100.50",
                    service="smb",
                )
            ],
        )

        self.assertEqual(
            len(output["correlated_results"]),
            1,
        )

        result = output["correlated_results"][0]

        self.assertEqual(
            result["matched_wazuh_count"],
            2,
        )
        self.assertEqual(
            len(result["matched_wazuh_event_ids"]),
            2,
        )

    def test_correlated_result_uses_same_id_as_zeek_event(self):
        output = self.engine.build_output(
            wazuh_data=[
                self.wazuh_event(
                    "w1",
                    "authentication failure",
                )
            ],
            zeek_data=[
                self.zeek_event(
                    uid="C-stable-id",
                    destination_port=445,
                    destination_ip="192.168.100.50",
                    service="smb",
                )
            ],
        )

        zeek_result = output["zeek_results"][0]
        correlated_result = output["correlated_results"][0]

        self.assertEqual(
            zeek_result["event_id"],
            correlated_result["event_id"],
        )
        self.assertEqual(
            correlated_result["event_id"],
            "zeek:C-stable-id",
        )

    def test_same_input_produces_same_score_and_classification(self):
        event = self.zeek_event(uid="C-deterministic")

        first = self.engine.build_output(
            wazuh_data=[],
            zeek_data=[event],
        )["zeek_results"][0]

        second = self.engine.build_output(
            wazuh_data=[],
            zeek_data=[event],
        )["zeek_results"][0]

        self.assertEqual(
            first["event_id"],
            second["event_id"],
        )
        self.assertEqual(
            first["risk_score"],
            second["risk_score"],
        )
        self.assertEqual(
            first["classification"],
            second["classification"],
        )
        self.assertEqual(
            first["reasons"],
            second["reasons"],
        )


if __name__ == "__main__":
    unittest.main()