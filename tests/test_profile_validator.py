import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "src"),
)


from profile_validator import (  # noqa: E402
    ProfileValidationError,
    load_profile_file,
    validate_profile,
)


def valid_profile():
    return {
        "schema_version": "1.0",
        "environment": {
            "id": "healthcare-lab",
            "name": (
                "Healthcare Security Research Lab"
            ),
            "site_id": "research-lab",
            "environment_type": "lab",
            "infrastructure_type": (
                "bare-metal"
            ),
            "timezone": "Asia/Colombo",
        },
        "business_hours": {
            "start": "08:00",
            "end": "18:00",
            "working_days": [
                "Monday",
                "Tuesday",
                "Wednesday",
                "Thursday",
                "Friday",
            ],
        },
        "data_sources": {
            "wazuh": {
                "enabled": True,
            },
            "zeek": {
                "enabled": True,
            },
        },
        "output": {
            "index": (
                "healthcare-risk-events"
            ),
        },
        "network_zones": {
            "healthcare_lab": {
                "subnets": [
                    "192.168.100.0/24",
                ],
                "default_role": (
                    "workstation"
                ),
                "trust_level": "standard",
                "sensitivity": "normal",
                "managed": True,
                "trusted": False,
                "criticality": "normal",
                "tags": [
                    "healthcare-lab",
                ],
            },
        },
        "critical_assets": {
            "192.168.100.30": {
                "hostname": (
                    "ehr-app-server-01"
                ),
                "role": "ehr_app",
                "zone": "healthcare_lab",
                "asset_type": (
                    "application_server"
                ),
                "trust_level": "protected",
                "sensitivity": "high",
                "managed": True,
                "trusted": False,
                "criticality": "high",
                "tags": [
                    "ehr",
                    "application",
                ],
            },
            "192.168.100.40": {
                "hostname": (
                    "ehr-db-server-01"
                ),
                "role": "database",
                "zone": "healthcare_lab",
                "asset_type": (
                    "database_server"
                ),
                "trust_level": "protected",
                "sensitivity": "critical",
                "managed": True,
                "trusted": False,
                "criticality": "critical",
                "tags": [
                    "ehr",
                    "database",
                ],
            },
        },
        "asset_overrides": {
            "192.168.100.21": {
                "hostname": "admin-pc-01",
                "role": (
                    "admin_workstation"
                ),
                "zone": "healthcare_lab",
                "asset_type": (
                    "admin_workstation"
                ),
                "trust_level": "elevated",
                "sensitivity": "high",
                "managed": True,
                "trusted": True,
                "criticality": "high",
                "tags": [
                    "administrator",
                ],
            },
        },
        "fallback_context": {
            "internal": {
                "role": (
                    "internal_unknown"
                ),
                "trust_level": "internal",
                "sensitivity": "unknown",
                "managed": False,
                "trusted": False,
                "criticality": "unknown",
                "tags": [
                    "unknown-internal",
                ],
            },
            "external": {
                "role": "external",
                "trust_level": "untrusted",
                "sensitivity": "unknown",
                "managed": False,
                "trusted": False,
                "criticality": "unknown",
                "tags": [
                    "external",
                ],
            },
        },
        "services": {
            "ehr_web": {
                "protocol": "tcp",
                "ports": [
                    80,
                    443,
                    5000,
                ],
            },
            "postgresql": {
                "protocol": "tcp",
                "ports": [
                    5432,
                ],
            },
        },
    }


class ProfileValidatorTests(unittest.TestCase):

    def test_valid_profile_passes(self):
        result = validate_profile(
            valid_profile()
        )

        self.assertTrue(
            result.is_valid,
            result.errors,
        )

        self.assertEqual(
            result.statistics[
                "critical_asset_count"
            ],
            2,
        )

    def test_overlapping_networks_are_rejected(self):
        profile = valid_profile()

        profile["network_zones"][
            "admin_network"
        ] = {
            "subnets": [
                "192.168.100.16/28",
            ],
            "default_role": (
                "admin_workstation"
            ),
            "trust_level": "elevated",
            "sensitivity": "high",
            "managed": True,
            "trusted": True,
            "criticality": "high",
            "tags": [
                "admin",
            ],
        }

        result = validate_profile(
            profile
        )

        self.assertFalse(
            result.is_valid
        )

        self.assertTrue(
            any(
                "overlaps" in error
                for error in result.errors
            )
        )

    def test_invalid_role_is_rejected(self):
        profile = valid_profile()

        profile["critical_assets"][
            "192.168.100.30"
        ]["role"] = "super_secret_role"

        result = validate_profile(
            profile
        )

        self.assertFalse(
            result.is_valid
        )

        self.assertTrue(
            any(
                "invalid value" in error
                for error in result.errors
            )
        )

    def test_invalid_service_port_is_rejected(self):
        profile = valid_profile()

        profile["services"][
            "ehr_web"
        ]["ports"] = [
            70000,
        ]

        result = validate_profile(
            profile
        )

        self.assertFalse(
            result.is_valid
        )

        self.assertTrue(
            any(
                "65535" in error
                for error in result.errors
            )
        )

    def test_asset_zone_mismatch_is_rejected(self):
        profile = valid_profile()

        profile["network_zones"][
            "database_network"
        ] = {
            "subnets": [
                "10.50.40.0/24",
            ],
            "default_role": "database",
            "trust_level": "protected",
            "sensitivity": "critical",
            "managed": True,
            "trusted": False,
            "criticality": "critical",
            "tags": [
                "database",
            ],
        }

        profile["critical_assets"][
            "192.168.100.40"
        ]["zone"] = "database_network"

        result = validate_profile(
            profile
        )

        self.assertFalse(
            result.is_valid
        )

        self.assertTrue(
            any(
                "is not inside" in error
                for error in result.errors
            )
        )

    def test_duplicate_yaml_keys_are_rejected(self):
        content = """
schema_version: "1.0"
environment:
  id: healthcare-lab
  id: duplicate-id
"""

        with tempfile.TemporaryDirectory() as directory:
            profile_path = (
                Path(directory)
                / "duplicate.yaml"
            )

            profile_path.write_text(
                content,
                encoding="utf-8",
            )

            with self.assertRaises(
                ProfileValidationError
            ):
                load_profile_file(
                    profile_path
                )


if __name__ == "__main__":
    unittest.main()