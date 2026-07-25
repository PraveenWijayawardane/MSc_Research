import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from asset_resolver import AssetResolver  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402


class PolicyEngineTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.asset_resolver = AssetResolver.from_file(
            PROJECT_ROOT
            / "config"
            / "asset_context.yaml"
        )

        cls.policy_engine = PolicyEngine.from_file(
            PROJECT_ROOT
            / "config"
            / "role_policies.yaml"
        )

    def evaluate(
        self,
        source_ip,
        destination_ip,
        port,
        protocol="tcp",
        service="",
    ):
        source_context = self.asset_resolver.resolve(
            source_ip
        )

        destination_context = self.asset_resolver.resolve(
            destination_ip
        )

        return self.policy_engine.evaluate(
            source_context=source_context,
            destination_context=destination_context,
            destination_port=port,
            protocol=protocol,
            service=service,
        )

    def test_workstation_to_ehr_is_allowed(self):
        result = self.evaluate(
            source_ip="192.168.100.25",
            destination_ip="192.168.100.30",
            port=5000,
            service="http",
        )

        self.assertTrue(result["matched"])
        self.assertEqual(
            result["policy_name"],
            "workstation_to_ehr_application",
        )
        self.assertEqual(result["action"], "allow")
        self.assertEqual(result["risk_points"], -2)

    def test_workstation_direct_database_is_denied(self):
        result = self.evaluate(
            source_ip="192.168.100.25",
            destination_ip="192.168.100.40",
            port=5432,
            service="postgresql",
        )

        self.assertTrue(result["matched"])
        self.assertEqual(
            result["policy_name"],
            "workstation_direct_database_access",
        )
        self.assertEqual(result["action"], "deny")
        self.assertEqual(result["risk_points"], 10)

    def test_admin_database_access_is_allowed(self):
        result = self.evaluate(
            source_ip="192.168.100.21",
            destination_ip="192.168.100.40",
            port=5432,
            service="postgresql",
        )

        self.assertEqual(
            result["policy_name"],
            "administrator_database_management",
        )
        self.assertEqual(result["action"], "allow")

    def test_attacker_to_internal_asset_is_denied(self):
        result = self.evaluate(
            source_ip="192.168.100.10",
            destination_ip="192.168.100.30",
            port=5000,
            service="http",
        )

        self.assertEqual(
            result["policy_name"],
            "attacker_to_internal_asset",
        )
        self.assertEqual(result["action"], "deny")
        self.assertEqual(result["risk_points"], 12)

    def test_unknown_connection_uses_default_policy(self):
        result = self.evaluate(
            source_ip="192.168.100.25",
            destination_ip="192.168.100.50",
            port=9999,
            service="unknown",
        )

        self.assertFalse(result["matched"])
        self.assertEqual(
            result["policy_name"],
            "default_policy",
        )
        self.assertEqual(result["action"], "observe")
        self.assertEqual(result["risk_points"], 3)

    def test_udp_dns_policy_is_allowed(self):
        result = self.evaluate(
            source_ip="192.168.100.25",
            destination_ip="192.168.100.30",
            port=53,
            protocol="udp",
            service="dns",
        )

        self.assertEqual(
            result["policy_name"],
            "internal_dns",
        )
        self.assertEqual(result["action"], "allow")
        self.assertEqual(result["risk_points"], 0)


if __name__ == "__main__":
    unittest.main()