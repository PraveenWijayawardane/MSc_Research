import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "src"),
)


from environment_registry import (  # noqa: E402
    EnvironmentNotFoundError,
    EnvironmentRegistry,
)


class EnvironmentRegistryTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.registry = EnvironmentRegistry(
            PROJECT_ROOT / "config"
        )

    def test_healthcare_lab_is_listed(self):
        environments = (
            self.registry.list_environments()
        )

        self.assertIn(
            "healthcare-lab",
            environments,
        )

    def test_healthcare_lab_can_be_loaded(self):
        configuration = self.registry.load(
            "healthcare-lab"
        )

        self.assertEqual(
            configuration["environment_id"],
            "healthcare-lab",
        )

        self.assertEqual(
            configuration["environment"]["id"],
            "healthcare-lab",
        )

        self.assertEqual(
            configuration["environment"]["name"],
            "Healthcare Security Research Lab",
        )

    def test_common_rules_are_loaded(self):
        configuration = self.registry.load(
            "healthcare-lab"
        )

        self.assertTrue(
            configuration["risk_rules"]
        )

        self.assertTrue(
            configuration["role_policies"]
        )

    def test_asset_context_is_loaded(self):
        configuration = self.registry.load(
            "healthcare-lab"
        )

        self.assertTrue(
            configuration["asset_context"]
        )

    def test_unknown_environment_is_rejected(self):
        with self.assertRaises(
            EnvironmentNotFoundError
        ):
            self.registry.load(
                "unknown-hospital"
            )

    def test_reload_returns_environment(self):
        configuration = self.registry.reload(
            "healthcare-lab"
        )

        self.assertEqual(
            configuration["environment_id"],
            "healthcare-lab",
        )


if __name__ == "__main__":
    unittest.main()