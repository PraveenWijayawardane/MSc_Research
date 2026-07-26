#!/usr/bin/env python3
"""
Version management for hospital environment configurations.

A validated hospital profile is converted into an immutable version containing:

- environment.yaml
- asset_context.yaml
- version.json

A version must be explicitly activated before it replaces the active files under
config/environments/<environment-id>. Activation verifies SHA-256 hashes and
records the previous version, allowing a one-command rollback.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from event_environment import resolve_environment_id


VERSION_ID_PATTERN = re.compile(
    r"^\d{8}T\d{6}Z(?:-\d{2})?$"
)


class ProfileVersionError(RuntimeError):
    """Base error for profile version-management operations."""


class VersionNotFoundError(ProfileVersionError):
    """Raised when a requested configuration version does not exist."""


class VersionIntegrityError(ProfileVersionError):
    """Raised when version files fail integrity verification."""


class NoActiveVersionError(ProfileVersionError):
    """Raised when an environment has no active version."""


class RollbackUnavailableError(ProfileVersionError):
    """Raised when an active version has no previous version."""


def utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def utc_iso() -> str:
    """Return a UTC timestamp suitable for metadata."""
    return (
        utc_now()
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def timestamp_version_id() -> str:
    """Return the base version ID format."""
    return utc_now().strftime(
        "%Y%m%dT%H%M%SZ"
    )


def sha256_file(path: Path) -> str:
    """Calculate the SHA-256 digest of a file."""
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(
            lambda: file.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def configuration_sha256(
    environment_sha256: str,
    asset_context_sha256: str,
) -> str:
    """Calculate one digest representing both configuration files."""
    digest = hashlib.sha256()

    digest.update(
        environment_sha256.encode("ascii")
    )
    digest.update(b"\n")
    digest.update(
        asset_context_sha256.encode("ascii")
    )

    return digest.hexdigest()


def _atomic_write_json(
    path: Path,
    value: Any,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = path.with_suffix(
        path.suffix + ".tmp"
    )

    with temporary.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        json.dump(
            value,
            file,
            indent=4,
            ensure_ascii=False,
            sort_keys=False,
        )
        file.write("\n")

    temporary.replace(path)


def _atomic_write_yaml(
    path: Path,
    value: dict[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = path.with_suffix(
        path.suffix + ".tmp"
    )

    with temporary.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        yaml.safe_dump(
            value,
            file,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )

    temporary.replace(path)


def _load_json_object(
    path: Path,
) -> dict[str, Any]:
    try:
        with path.open(
            "r",
            encoding="utf-8-sig",
        ) as file:
            value = json.load(file)
    except FileNotFoundError as exc:
        raise VersionNotFoundError(
            f"Metadata file was not found: {path}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ProfileVersionError(
            f"Invalid JSON in {path}: {exc}"
        ) from exc

    if not isinstance(value, dict):
        raise ProfileVersionError(
            f"JSON root must be an object: {path}"
        )

    return value


class ProfileVersionManager:
    """Create, verify, activate, list, and roll back profile versions."""

    def __init__(
        self,
        config_root: str | Path,
    ) -> None:
        self.config_root = Path(
            config_root
        ).resolve()

        self.versions_root = (
            self.config_root / "versions"
        )

        self.environments_root = (
            self.config_root / "environments"
        )

    def versions_directory(
        self,
        environment_id: str,
    ) -> Path:
        environment_id = resolve_environment_id(
            environment_id
        )

        return (
            self.versions_root
            / environment_id
        )

    def active_directory(
        self,
        environment_id: str,
    ) -> Path:
        environment_id = resolve_environment_id(
            environment_id
        )

        return (
            self.environments_root
            / environment_id
        )

    def active_metadata_file(
        self,
        environment_id: str,
    ) -> Path:
        return (
            self.active_directory(
                environment_id
            )
            / "active_version.json"
        )

    def activation_history_file(
        self,
        environment_id: str,
    ) -> Path:
        return (
            self.versions_directory(
                environment_id
            )
            / "activation_history.json"
        )

    def version_directory(
        self,
        environment_id: str,
        version_id: str,
    ) -> Path:
        environment_id = resolve_environment_id(
            environment_id
        )

        self.validate_version_id(
            version_id
        )

        return (
            self.versions_directory(
                environment_id
            )
            / version_id
        )

    @staticmethod
    def validate_version_id(
        version_id: str,
    ) -> str:
        normalized = str(
            version_id or ""
        ).strip()

        if not VERSION_ID_PATTERN.fullmatch(
            normalized
        ):
            raise ProfileVersionError(
                "Invalid version ID. Expected "
                "YYYYMMDDTHHMMSSZ or "
                "YYYYMMDDTHHMMSSZ-01."
            )

        return normalized

    def next_version_id(
        self,
        environment_id: str,
    ) -> str:
        environment_id = resolve_environment_id(
            environment_id
        )

        base = timestamp_version_id()
        versions_directory = (
            self.versions_directory(
                environment_id
            )
        )

        candidate = base

        if not (
            versions_directory / candidate
        ).exists():
            return candidate

        for sequence in range(1, 100):
            candidate = (
                f"{base}-{sequence:02d}"
            )

            if not (
                versions_directory / candidate
            ).exists():
                return candidate

        raise ProfileVersionError(
            "Unable to allocate a unique version ID"
        )

    def current_version(
        self,
        environment_id: str,
        *,
        required: bool = False,
    ) -> dict[str, Any] | None:
        environment_id = resolve_environment_id(
            environment_id
        )

        metadata_file = (
            self.active_metadata_file(
                environment_id
            )
        )

        if not metadata_file.exists():
            if required:
                raise NoActiveVersionError(
                    "No active version exists for "
                    f"{environment_id}"
                )

            return None

        metadata = _load_json_object(
            metadata_file
        )

        if (
            metadata.get("environment_id")
            != environment_id
        ):
            raise ProfileVersionError(
                "Active-version metadata environment "
                "does not match its directory"
            )

        active_version = metadata.get(
            "active_version"
        )

        if not isinstance(
            active_version,
            str,
        ):
            raise ProfileVersionError(
                "active_version.json is missing "
                "active_version"
            )

        self.validate_version_id(
            active_version
        )

        return metadata

    def create_version(
        self,
        *,
        environment_id: str,
        environment_document: dict[str, Any],
        asset_context_document: dict[str, Any],
        source_profile: str | Path | None = None,
        validation: dict[str, Any] | None = None,
        version_id: str | None = None,
    ) -> dict[str, Any]:
        """Create an immutable inactive configuration version."""
        environment_id = resolve_environment_id(
            environment_id
        )

        if not isinstance(
            environment_document,
            dict,
        ):
            raise ProfileVersionError(
                "environment_document must be a dictionary"
            )

        if not isinstance(
            asset_context_document,
            dict,
        ):
            raise ProfileVersionError(
                "asset_context_document must be a dictionary"
            )

        configured_environment = (
            environment_document.get(
                "environment"
            )
        )

        if not isinstance(
            configured_environment,
            dict,
        ):
            raise ProfileVersionError(
                "environment_document.environment "
                "must be a dictionary"
            )

        configured_environment_id = (
            resolve_environment_id(
                configured_environment.get(
                    "id"
                )
            )
        )

        if (
            configured_environment_id
            != environment_id
        ):
            raise ProfileVersionError(
                "Environment ID in environment.yaml "
                "does not match the requested environment"
            )

        if version_id is None:
            version_id = (
                self.next_version_id(
                    environment_id
                )
            )
        else:
            version_id = (
                self.validate_version_id(
                    version_id
                )
            )

        target_directory = (
            self.version_directory(
                environment_id,
                version_id,
            )
        )

        if target_directory.exists():
            raise ProfileVersionError(
                "Version already exists: "
                f"{target_directory}"
            )

        versions_directory = (
            self.versions_directory(
                environment_id
            )
        )

        versions_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        staging_directory = (
            versions_directory
            / (
                f".staging-{version_id}-"
                f"{uuid.uuid4().hex}"
            )
        )

        staging_directory.mkdir(
            parents=False,
            exist_ok=False,
        )

        try:
            environment_file = (
                staging_directory
                / "environment.yaml"
            )

            asset_context_file = (
                staging_directory
                / "asset_context.yaml"
            )

            _atomic_write_yaml(
                environment_file,
                environment_document,
            )

            _atomic_write_yaml(
                asset_context_file,
                asset_context_document,
            )

            environment_digest = (
                sha256_file(
                    environment_file
                )
            )

            asset_context_digest = (
                sha256_file(
                    asset_context_file
                )
            )

            configuration_digest = (
                configuration_sha256(
                    environment_digest,
                    asset_context_digest,
                )
            )

            source_path = (
                Path(source_profile).resolve()
                if source_profile
                else None
            )

            source_profile_name = (
                source_path.name
                if source_path
                else None
            )

            profile_digest = (
                sha256_file(source_path)
                if (
                    source_path
                    and source_path.is_file()
                )
                else None
            )

            active = self.current_version(
                environment_id
            )

            previous_version = (
                active.get(
                    "active_version"
                )
                if active
                else None
            )

            metadata = {
                "schema_version": "1.0",
                "version_id": version_id,
                "environment_id": (
                    environment_id
                ),
                "created_at": utc_iso(),
                "source_profile": (
                    source_profile_name
                ),
                "source_profile_path": (
                    str(source_path)
                    if source_path
                    else None
                ),
                "profile_sha256": (
                    profile_digest
                ),
                "environment_sha256": (
                    environment_digest
                ),
                "asset_context_sha256": (
                    asset_context_digest
                ),
                "configuration_sha256": (
                    configuration_digest
                ),
                "status": "inactive",
                "previous_version": (
                    previous_version
                ),
                "activated_at": None,
                "last_activated_at": None,
                "activation_count": 0,
                "validation": (
                    validation
                    if isinstance(
                        validation,
                        dict,
                    )
                    else {}
                ),
            }

            _atomic_write_json(
                staging_directory
                / "version.json",
                metadata,
            )

            staging_directory.rename(
                target_directory
            )
        except Exception:
            if staging_directory.exists():
                shutil.rmtree(
                    staging_directory,
                    ignore_errors=True,
                )

            raise

        return self.read_version(
            environment_id,
            version_id,
        )

    def read_version(
        self,
        environment_id: str,
        version_id: str,
    ) -> dict[str, Any]:
        """Read one version's metadata and file paths."""
        environment_id = resolve_environment_id(
            environment_id
        )

        version_id = self.validate_version_id(
            version_id
        )

        version_directory = (
            self.version_directory(
                environment_id,
                version_id,
            )
        )

        if not version_directory.is_dir():
            raise VersionNotFoundError(
                "Version was not found: "
                f"{environment_id}/{version_id}"
            )

        metadata = _load_json_object(
            version_directory
            / "version.json"
        )

        if (
            metadata.get("environment_id")
            != environment_id
            or metadata.get("version_id")
            != version_id
        ):
            raise ProfileVersionError(
                "Version metadata does not match "
                "its directory"
            )

        active = self.current_version(
            environment_id
        )

        metadata = dict(metadata)
        metadata["is_active"] = bool(
            active
            and active.get(
                "active_version"
            )
            == version_id
        )
        metadata["version_directory"] = str(
            version_directory
        )
        metadata["environment_file"] = str(
            version_directory
            / "environment.yaml"
        )
        metadata["asset_context_file"] = str(
            version_directory
            / "asset_context.yaml"
        )

        return metadata

    def list_versions(
        self,
        environment_id: str,
    ) -> list[dict[str, Any]]:
        """List available versions, newest first."""
        environment_id = resolve_environment_id(
            environment_id
        )

        versions_directory = (
            self.versions_directory(
                environment_id
            )
        )

        if not versions_directory.exists():
            return []

        results: list[
            dict[str, Any]
        ] = []

        for child in versions_directory.iterdir():
            if (
                not child.is_dir()
                or not VERSION_ID_PATTERN.fullmatch(
                    child.name
                )
            ):
                continue

            try:
                results.append(
                    self.read_version(
                        environment_id,
                        child.name,
                    )
                )
            except ProfileVersionError as exc:
                results.append(
                    {
                        "environment_id": (
                            environment_id
                        ),
                        "version_id": (
                            child.name
                        ),
                        "status": "invalid",
                        "is_active": False,
                        "error": str(exc),
                        "version_directory": str(
                            child
                        ),
                    }
                )

        return sorted(
            results,
            key=lambda item: str(
                item.get(
                    "version_id",
                    "",
                )
            ),
            reverse=True,
        )

    def verify_version(
        self,
        environment_id: str,
        version_id: str,
        *,
        raise_on_error: bool = False,
    ) -> dict[str, Any]:
        """Verify version files against their stored SHA-256 digests."""
        version = self.read_version(
            environment_id,
            version_id,
        )

        environment_file = Path(
            version["environment_file"]
        )

        asset_context_file = Path(
            version[
                "asset_context_file"
            ]
        )

        errors: list[str] = []

        if not environment_file.is_file():
            errors.append(
                f"Missing file: {environment_file}"
            )

        if not asset_context_file.is_file():
            errors.append(
                f"Missing file: {asset_context_file}"
            )

        actual_environment_digest = None
        actual_asset_context_digest = None
        actual_configuration_digest = None

        if environment_file.is_file():
            actual_environment_digest = (
                sha256_file(
                    environment_file
                )
            )

            if (
                actual_environment_digest
                != version.get(
                    "environment_sha256"
                )
            ):
                errors.append(
                    "environment.yaml SHA-256 "
                    "does not match version metadata"
                )

        if asset_context_file.is_file():
            actual_asset_context_digest = (
                sha256_file(
                    asset_context_file
                )
            )

            if (
                actual_asset_context_digest
                != version.get(
                    "asset_context_sha256"
                )
            ):
                errors.append(
                    "asset_context.yaml SHA-256 "
                    "does not match version metadata"
                )

        if (
            actual_environment_digest
            and actual_asset_context_digest
        ):
            actual_configuration_digest = (
                configuration_sha256(
                    actual_environment_digest,
                    actual_asset_context_digest,
                )
            )

            if (
                actual_configuration_digest
                != version.get(
                    "configuration_sha256"
                )
            ):
                errors.append(
                    "Combined configuration SHA-256 "
                    "does not match version metadata"
                )

        result = {
            "valid": not errors,
            "environment_id": (
                environment_id
            ),
            "version_id": version_id,
            "errors": errors,
            "environment_sha256": (
                actual_environment_digest
            ),
            "asset_context_sha256": (
                actual_asset_context_digest
            ),
            "configuration_sha256": (
                actual_configuration_digest
            ),
        }

        if errors and raise_on_error:
            raise VersionIntegrityError(
                "Version integrity verification "
                f"failed for {environment_id}/"
                f"{version_id}:\n- "
                + "\n- ".join(errors)
            )

        return result

    def _write_version_metadata(
        self,
        environment_id: str,
        version_id: str,
        metadata: dict[str, Any],
    ) -> None:
        version_directory = (
            self.version_directory(
                environment_id,
                version_id,
            )
        )

        _atomic_write_json(
            version_directory
            / "version.json",
            metadata,
        )

    def _read_history(
        self,
        environment_id: str,
    ) -> dict[str, Any]:
        history_file = (
            self.activation_history_file(
                environment_id
            )
        )

        if not history_file.exists():
            return {
                "schema_version": "1.0",
                "environment_id": (
                    resolve_environment_id(
                        environment_id
                    )
                ),
                "activations": [],
            }

        history = _load_json_object(
            history_file
        )

        if not isinstance(
            history.get("activations"),
            list,
        ):
            raise ProfileVersionError(
                "activation_history.json has "
                "an invalid activations field"
            )

        return history

    def _append_history(
        self,
        environment_id: str,
        record: dict[str, Any],
    ) -> None:
        history = self._read_history(
            environment_id
        )

        history["activations"].append(
            record
        )

        _atomic_write_json(
            self.activation_history_file(
                environment_id
            ),
            history,
        )


    def _bootstrap_existing_active_environment(
        self,
        environment_id: str,
    ) -> dict[str, Any] | None:
        """
        Import a pre-versioning active environment as the first version.

        This protects existing installations that already have environment.yaml
        and asset_context.yaml but do not yet have active_version.json. The
        imported version becomes the current version, so the first new
        activation can roll back to the previously working configuration.
        """
        environment_id = resolve_environment_id(
            environment_id
        )

        current = self.current_version(
            environment_id
        )

        if current is not None:
            return current

        active_directory = (
            self.active_directory(
                environment_id
            )
        )

        environment_file = (
            active_directory
            / "environment.yaml"
        )

        asset_context_file = (
            active_directory
            / "asset_context.yaml"
        )

        if not (
            environment_file.is_file()
            and asset_context_file.is_file()
        ):
            return None

        try:
            environment_document = yaml.safe_load(
                environment_file.read_text(
                    encoding="utf-8-sig"
                )
            )

            asset_context_document = yaml.safe_load(
                asset_context_file.read_text(
                    encoding="utf-8-sig"
                )
            )
        except yaml.YAMLError as exc:
            raise ProfileVersionError(
                "Existing active configuration cannot be "
                f"imported: {exc}"
            ) from exc

        if not isinstance(
            environment_document,
            dict,
        ) or not isinstance(
            asset_context_document,
            dict,
        ):
            raise ProfileVersionError(
                "Existing active configuration must contain "
                "YAML objects before it can be imported"
            )

        imported = self.create_version(
            environment_id=environment_id,
            environment_document=(
                environment_document
            ),
            asset_context_document=(
                asset_context_document
            ),
            validation={
                "valid": True,
                "legacy_import": True,
            },
        )

        activated_at = utc_iso()

        pointer = {
            "schema_version": "1.0",
            "environment_id": (
                environment_id
            ),
            "active_version": (
                imported["version_id"]
            ),
            "previous_version": None,
            "activated_at": activated_at,
            "configuration_sha256": (
                imported[
                    "configuration_sha256"
                ]
            ),
            "imported_from_legacy": True,
        }

        _atomic_write_json(
            active_directory
            / "active_version.json",
            pointer,
        )

        imported_metadata = _load_json_object(
            self.version_directory(
                environment_id,
                imported["version_id"],
            )
            / "version.json"
        )

        imported_metadata["status"] = "active"
        imported_metadata["activated_at"] = activated_at
        imported_metadata["last_activated_at"] = activated_at
        imported_metadata["activation_count"] = 1
        imported_metadata["legacy_import"] = True

        self._write_version_metadata(
            environment_id,
            imported["version_id"],
            imported_metadata,
        )

        self._append_history(
            environment_id,
            {
                "activated_at": activated_at,
                "environment_id": (
                    environment_id
                ),
                "from_version": None,
                "to_version": (
                    imported["version_id"]
                ),
                "reason": "legacy_bootstrap",
                "configuration_sha256": (
                    imported[
                        "configuration_sha256"
                    ]
                ),
            },
        )

        return pointer

    def activate_version(
        self,
        environment_id: str,
        version_id: str,
        *,
        reason: str = "manual_activation",
    ) -> dict[str, Any]:
        """Verify and activate one stored version."""
        environment_id = resolve_environment_id(
            environment_id
        )

        version_id = self.validate_version_id(
            version_id
        )

        self.verify_version(
            environment_id,
            version_id,
            raise_on_error=True,
        )

        version = self.read_version(
            environment_id,
            version_id,
        )

        current = self.current_version(
            environment_id
        )

        if current is None:
            current = (
                self._bootstrap_existing_active_environment(
                    environment_id
                )
            )

        current_version_id = (
            current.get(
                "active_version"
            )
            if current
            else None
        )

        if current_version_id == version_id:
            return {
                **version,
                "activation_changed": False,
                "active_version": version_id,
                "previous_version": (
                    current.get(
                        "previous_version"
                    )
                    if current
                    else None
                ),
            }

        active_directory = (
            self.active_directory(
                environment_id
            )
        )

        active_parent = (
            active_directory.parent
        )

        active_parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        operation_id = uuid.uuid4().hex

        staging_directory = (
            active_parent
            / (
                f".{environment_id}-"
                f"staging-{operation_id}"
            )
        )

        previous_directory = (
            active_parent
            / (
                f".{environment_id}-"
                f"previous-{operation_id}"
            )
        )

        staging_directory.mkdir(
            parents=False,
            exist_ok=False,
        )

        activated_at = utc_iso()

        pointer = {
            "schema_version": "1.0",
            "environment_id": (
                environment_id
            ),
            "active_version": (
                version_id
            ),
            "previous_version": (
                current_version_id
            ),
            "activated_at": (
                activated_at
            ),
            "configuration_sha256": (
                version.get(
                    "configuration_sha256"
                )
            ),
        }

        version_directory = (
            self.version_directory(
                environment_id,
                version_id,
            )
        )

        try:
            shutil.copy2(
                version_directory
                / "environment.yaml",
                staging_directory
                / "environment.yaml",
            )

            shutil.copy2(
                version_directory
                / "asset_context.yaml",
                staging_directory
                / "asset_context.yaml",
            )

            _atomic_write_json(
                staging_directory
                / "active_version.json",
                pointer,
            )

            if active_directory.exists():
                active_directory.rename(
                    previous_directory
                )

            staging_directory.rename(
                active_directory
            )
        except Exception:
            if (
                not active_directory.exists()
                and previous_directory.exists()
            ):
                previous_directory.rename(
                    active_directory
                )

            if staging_directory.exists():
                shutil.rmtree(
                    staging_directory,
                    ignore_errors=True,
                )

            raise

        if previous_directory.exists():
            shutil.rmtree(
                previous_directory,
                ignore_errors=True,
            )

        target_metadata = _load_json_object(
            version_directory
            / "version.json"
        )

        target_metadata[
            "status"
        ] = "active"
        target_metadata[
            "previous_version"
        ] = current_version_id
        target_metadata[
            "activated_at"
        ] = (
            target_metadata.get(
                "activated_at"
            )
            or activated_at
        )
        target_metadata[
            "last_activated_at"
        ] = activated_at
        target_metadata[
            "activation_count"
        ] = (
            int(
                target_metadata.get(
                    "activation_count",
                    0,
                )
            )
            + 1
        )

        self._write_version_metadata(
            environment_id,
            version_id,
            target_metadata,
        )

        if current_version_id:
            previous_metadata = (
                self.read_version(
                    environment_id,
                    current_version_id,
                )
            )

            previous_metadata.pop(
                "is_active",
                None,
            )
            previous_metadata.pop(
                "version_directory",
                None,
            )
            previous_metadata.pop(
                "environment_file",
                None,
            )
            previous_metadata.pop(
                "asset_context_file",
                None,
            )
            previous_metadata[
                "status"
            ] = "inactive"

            self._write_version_metadata(
                environment_id,
                current_version_id,
                previous_metadata,
            )

        history_record = {
            "activated_at": activated_at,
            "environment_id": (
                environment_id
            ),
            "from_version": (
                current_version_id
            ),
            "to_version": version_id,
            "reason": str(
                reason or "manual_activation"
            ),
            "configuration_sha256": (
                version.get(
                    "configuration_sha256"
                )
            ),
        }

        self._append_history(
            environment_id,
            history_record,
        )

        activated = self.read_version(
            environment_id,
            version_id,
        )

        return {
            **activated,
            "activation_changed": True,
            "active_version": version_id,
            "previous_version": (
                current_version_id
            ),
        }

    def rollback(
        self,
        environment_id: str,
    ) -> dict[str, Any]:
        """Activate the previous version recorded by the active pointer."""
        environment_id = resolve_environment_id(
            environment_id
        )

        current = self.current_version(
            environment_id,
            required=True,
        )

        assert current is not None

        current_version_id = str(
            current["active_version"]
        )

        previous_version_id = (
            current.get(
                "previous_version"
            )
        )

        if not previous_version_id:
            raise RollbackUnavailableError(
                "No previous version is available "
                f"for {environment_id}"
            )

        result = self.activate_version(
            environment_id,
            str(previous_version_id),
            reason=(
                f"rollback_from_{current_version_id}"
            ),
        )

        result[
            "rollback_from"
        ] = current_version_id
        result[
            "rollback_to"
        ] = str(
            previous_version_id
        )

        return result

    def activation_history(
        self,
        environment_id: str,
    ) -> list[dict[str, Any]]:
        """Return activation audit records."""
        return list(
            self._read_history(
                environment_id
            )["activations"]
        )