import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "src"),
)


from asset_resolver import AssetResolver  # noqa: E402
from environment_registry import (  # noqa: E402
    EnvironmentRegistry,
)


class AssetResolverTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Keep the original loading method to preserve backward
        # compatibility during the refactor.
        cls.resolver = AssetResolver.from_file(
            PROJECT_ROOT
            / "config"
            / "asset_context.yaml"
        )

    def test_normal_workstation_from_network_zone(self):
        result = self.resolver.resolve(
            "192.168.100.25"
        )

        self.assertEqual(
            result["role"],
            "workstation",
        )
        self.assertEqual(
            result["zone"],
            "healthcare_lab",
        )
        self.assertEqual(
            result["resolution_source"],
            "network_zone",
        )
        self.assertTrue(
            result["is_internal"]
        )
        self.assertFalse(
            result["is_critical"]
        )

    def test_critical_database_asset(self):
        result = self.resolver.resolve(
            "192.168.100.40"
        )

        self.assertEqual(
            result["role"],
            "database",
        )
        self.assertEqual(
            result["hostname"],
            "ehr-db-server-01",
        )
        self.assertEqual(
            result["resolution_source"],
            "critical_asset",
        )
        self.assertTrue(
            result["is_critical"]
        )

    def test_admin_workstation_override(self):
        result = self.resolver.resolve(
            "192.168.100.21"
        )

        self.assertEqual(
            result["role"],
            "admin_workstation",
        )
        self.assertEqual(
            result["resolution_source"],
            "asset_override",
        )
        self.assertTrue(
            result["trusted"]
        )

    def test_external_address(self):
        result = self.resolver.resolve(
            "8.8.8.8"
        )

        self.assertEqual(
            result["role"],
            "external",
        )
        self.assertEqual(
            result["resolution_source"],
            "external_fallback",
        )
        self.assertFalse(
            result["is_internal"]
        )

    def test_invalid_address(self):
        result = self.resolver.resolve(
            "invalid-ip"
        )

        self.assertEqual(
            result["resolution_source"],
            "invalid_ip",
        )
        self.assertEqual(
            result["role"],
            "unknown",
        )

    def test_resolver_loads_selected_environment(self):
        registry = EnvironmentRegistry(
            PROJECT_ROOT / "config"
        )

        configuration = registry.load(
            "healthcare-lab"
        )

        resolver = (
            AssetResolver
            .from_environment_configuration(
                configuration
            )
        )

        user_context = resolver.resolve(
            "192.168.100.20"
        )

        ehr_context = resolver.resolve(
            "192.168.100.30"
        )

        self.assertEqual(
            user_context["role"],
            "workstation",
        )

        self.assertEqual(
            user_context["hostname"],
            "user-pc-01",
        )

        self.assertEqual(
            ehr_context["role"],
            "ehr_app",
        )

    def test_missing_environment_asset_path_is_rejected(
        self,
    ):
        with self.assertRaises(ValueError):
            (
                AssetResolver
                .from_environment_configuration({})
            )

    def test_resolve_many(self):
        results = self.resolver.resolve_many(
            [
                "192.168.100.21",
                "192.168.100.40",
            ]
        )

        self.assertEqual(
            len(results),
            2,
        )
        self.assertEqual(
            results[0]["role"],
            "admin_workstation",
        )
        self.assertEqual(
            results[1]["role"],
            "database",
        )


if __name__ == "__main__":
    unittest.main()