import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "src"),
)


from asset_resolver import AssetResolver  # noqa: E402
from environment_registry import EnvironmentRegistry  # noqa: E402
from risk_engine import ContextualRiskEngine  # noqa: E402


class MultiEnvironmentTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.registry = EnvironmentRegistry(
            PROJECT_ROOT / "config"
        )

        cls.hospital_engine = (
            ContextualRiskEngine.from_environment(
                environment_id="hospital-a-prod",
                config_root=PROJECT_ROOT / "config",
            )
        )

    @staticmethod
    def zeek_event(
        uid,
        source_ip,
        destination_ip,
        destination_port,
        service,
    ):
        return {
            "uid": uid,
            "ts": "2026-07-27T04:30:00Z",
            "id.orig_h": source_ip,
            "id.orig_p": 45000,
            "id.resp_h": destination_ip,
            "id.resp_p": destination_port,
            "proto": "tcp",
            "service": service,
            "conn_state": "SF",
            "orig_bytes": 100,
            "resp_bytes": 200,
            "duration": 1,
        }

    def test_both_environments_are_registered(self):
        environments = self.registry.list_environments()

        self.assertIn(
            "healthcare-lab",
            environments,
        )

        self.assertIn(
            "hospital-a-prod",
            environments,
        )

    def test_hospital_asset_roles_are_resolved(self):
        configuration = self.registry.load(
            "hospital-a-prod"
        )

        resolver = (
            AssetResolver
            .from_environment_configuration(
                configuration
            )
        )

        workstation = resolver.resolve(
            "10.50.10.25"
        )

        ehr_application = resolver.resolve(
            "10.50.30.15"
        )

        database = resolver.resolve(
            "10.50.40.10"
        )

        administrator = resolver.resolve(
            "10.50.20.21"
        )

        self.assertEqual(
            workstation["role"],
            "workstation",
        )

        self.assertEqual(
            ehr_application["role"],
            "ehr_app",
        )

        self.assertEqual(
            database["role"],
            "database",
        )

        self.assertEqual(
            administrator["role"],
            "admin_workstation",
        )

    def test_hospital_workstation_to_ehr_is_allowed(self):
        output = self.hospital_engine.build_output(
            wazuh_data=[],
            zeek_data=[
                self.zeek_event(
                    uid="hospital-a-ehr-test",
                    source_ip="10.50.10.25",
                    destination_ip="10.50.30.15",
                    destination_port=5000,
                    service="http",
                )
            ],
        )

        result = output["zeek_results"][0]

        self.assertEqual(
            result["environment_id"],
            "hospital-a-prod",
        )

        self.assertEqual(
            result["source_role"],
            "workstation",
        )

        self.assertEqual(
            result["destination_role"],
            "ehr_app",
        )

        self.assertEqual(
            result["policy_name"],
            "workstation_to_ehr_application",
        )

        self.assertEqual(
            result["policy_action"],
            "allow",
        )

    def test_hospital_workstation_database_access_is_denied(self):
        output = self.hospital_engine.build_output(
            wazuh_data=[],
            zeek_data=[
                self.zeek_event(
                    uid="hospital-a-db-test",
                    source_ip="10.50.10.25",
                    destination_ip="10.50.40.10",
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


if __name__ == "__main__":
    unittest.main()