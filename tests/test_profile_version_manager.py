import json
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "src"),
)


from profile_version_manager import (  # noqa: E402
    ProfileVersionManager,
    RollbackUnavailableError,
    VersionIntegrityError,
)


def environment_document(
    name="Healthcare Security Research Lab",
):
    return {
        "schema_version": "1.0",
        "environment": {
            "id": "healthcare-lab",
            "name": name,
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
    }


def asset_context_document(
    database_hostname="ehr-db-server-01",
):
    return {
        "organization": {
            "name": (
                "Healthcare Security Research Lab"
            ),
            "site_id": "research-lab",
            "environment": "lab",
            "infrastructure_type": (
                "bare-metal"
            ),
            "timezone": "Asia/Colombo",
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
            "192.168.100.40": {
                "hostname": (
                    database_hostname
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
                    "database",
                ],
            },
        },
        "asset_overrides": {},
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
                "tags": [],
            },
            "external": {
                "role": "external",
                "trust_level": "untrusted",
                "sensitivity": "unknown",
                "managed": False,
                "trusted": False,
                "criticality": "unknown",
                "tags": [],
            },
        },
    }


class ProfileVersionManagerTests(unittest.TestCase):

    def create_manager(self, directory):
        return ProfileVersionManager(
            Path(directory) / "config"
        )

    def create_version(
        self,
        manager,
        version_id,
        name="Healthcare Security Research Lab",
        database_hostname="ehr-db-server-01",
    ):
        return manager.create_version(
            environment_id="healthcare-lab",
            environment_document=(
                environment_document(name)
            ),
            asset_context_document=(
                asset_context_document(
                    database_hostname
                )
            ),
            version_id=version_id,
            validation={
                "valid": True,
            },
        )

    def test_create_version_writes_metadata_and_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = self.create_manager(
                directory
            )

            version = self.create_version(
                manager,
                "20260727T100000Z",
            )

            self.assertTrue(
                Path(
                    version[
                        "environment_file"
                    ]
                ).exists()
            )

            self.assertTrue(
                Path(
                    version[
                        "asset_context_file"
                    ]
                ).exists()
            )

            self.assertEqual(
                len(
                    version[
                        "configuration_sha256"
                    ]
                ),
                64,
            )

            verification = (
                manager.verify_version(
                    "healthcare-lab",
                    "20260727T100000Z",
                )
            )

            self.assertTrue(
                verification["valid"]
            )

    def test_activation_writes_active_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = self.create_manager(
                directory
            )

            self.create_version(
                manager,
                "20260727T100000Z",
            )

            result = manager.activate_version(
                "healthcare-lab",
                "20260727T100000Z",
            )

            self.assertEqual(
                result["active_version"],
                "20260727T100000Z",
            )

            active_directory = (
                manager.active_directory(
                    "healthcare-lab"
                )
            )

            self.assertTrue(
                (
                    active_directory
                    / "environment.yaml"
                ).exists()
            )

            pointer = json.loads(
                (
                    active_directory
                    / "active_version.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            self.assertEqual(
                pointer["active_version"],
                "20260727T100000Z",
            )

    def test_second_activation_and_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = self.create_manager(
                directory
            )

            self.create_version(
                manager,
                "20260727T100000Z",
                database_hostname=(
                    "ehr-db-server-01"
                ),
            )

            self.create_version(
                manager,
                "20260727T110000Z",
                database_hostname=(
                    "ehr-db-server-02"
                ),
            )

            manager.activate_version(
                "healthcare-lab",
                "20260727T100000Z",
            )

            manager.activate_version(
                "healthcare-lab",
                "20260727T110000Z",
            )

            rollback = manager.rollback(
                "healthcare-lab"
            )

            self.assertEqual(
                rollback["rollback_from"],
                "20260727T110000Z",
            )

            self.assertEqual(
                rollback["rollback_to"],
                "20260727T100000Z",
            )

            current = manager.current_version(
                "healthcare-lab",
                required=True,
            )

            self.assertEqual(
                current["active_version"],
                "20260727T100000Z",
            )

    def test_first_active_version_cannot_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = self.create_manager(
                directory
            )

            self.create_version(
                manager,
                "20260727T100000Z",
            )

            manager.activate_version(
                "healthcare-lab",
                "20260727T100000Z",
            )

            with self.assertRaises(
                RollbackUnavailableError
            ):
                manager.rollback(
                    "healthcare-lab"
                )

    def test_tampered_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = self.create_manager(
                directory
            )

            version = self.create_version(
                manager,
                "20260727T100000Z",
            )

            Path(
                version[
                    "asset_context_file"
                ]
            ).write_text(
                "tampered: true\n",
                encoding="utf-8",
            )

            verification = (
                manager.verify_version(
                    "healthcare-lab",
                    "20260727T100000Z",
                )
            )

            self.assertFalse(
                verification["valid"]
            )

            with self.assertRaises(
                VersionIntegrityError
            ):
                manager.activate_version(
                    "healthcare-lab",
                    "20260727T100000Z",
                )

    def test_list_versions_marks_active_version(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = self.create_manager(
                directory
            )

            self.create_version(
                manager,
                "20260727T100000Z",
            )

            self.create_version(
                manager,
                "20260727T110000Z",
            )

            manager.activate_version(
                "healthcare-lab",
                "20260727T110000Z",
            )

            versions = manager.list_versions(
                "healthcare-lab"
            )

            active = [
                version
                for version in versions
                if version.get(
                    "is_active"
                )
            ]

            self.assertEqual(
                len(active),
                1,
            )

            self.assertEqual(
                active[0]["version_id"],
                "20260727T110000Z",
            )


    def test_existing_active_environment_is_imported_before_first_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = self.create_manager(
                directory
            )

            active_directory = (
                manager.active_directory(
                    "healthcare-lab"
                )
            )

            active_directory.mkdir(
                parents=True,
                exist_ok=True,
            )

            import yaml

            (
                active_directory
                / "environment.yaml"
            ).write_text(
                yaml.safe_dump(
                    environment_document(
                        "Legacy Active Environment"
                    ),
                    sort_keys=False,
                ),
                encoding="utf-8",
            )

            (
                active_directory
                / "asset_context.yaml"
            ).write_text(
                yaml.safe_dump(
                    asset_context_document(
                        "legacy-db-server"
                    ),
                    sort_keys=False,
                ),
                encoding="utf-8",
            )

            self.create_version(
                manager,
                "20260727T120000Z",
                name="New Reviewed Environment",
                database_hostname=(
                    "new-db-server"
                ),
            )

            activated = manager.activate_version(
                "healthcare-lab",
                "20260727T120000Z",
            )

            imported_version = activated[
                "previous_version"
            ]

            self.assertIsNotNone(
                imported_version
            )

            imported = manager.read_version(
                "healthcare-lab",
                imported_version,
            )

            self.assertTrue(
                imported.get(
                    "legacy_import"
                )
            )

            rollback = manager.rollback(
                "healthcare-lab"
            )

            self.assertEqual(
                rollback["rollback_to"],
                imported_version,
            )


if __name__ == "__main__":
    unittest.main()