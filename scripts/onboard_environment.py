#!/usr/bin/env python3
"""
Validate and create a versioned hospital environment configuration.

Onboarding no longer overwrites the active environment directly. It creates an
immutable version under:

config/versions/<environment-id>/<version-id>/

The new version remains inactive unless --activate is explicitly supplied.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(SRC_ROOT),
    )


from profile_validator import (  # noqa: E402
    ProfileValidationError,
    ProfileValidationResult,
    load_profile_file,
    validate_profile,
)
from profile_version_manager import (  # noqa: E402
    ProfileVersionError,
    ProfileVersionManager,
)


DEFAULT_CONFIG_ROOT = (
    PROJECT_ROOT / "config"
)


class EnvironmentOnboardingError(RuntimeError):
    """Raised when a validated profile cannot be onboarded."""


def _timestamp() -> str:
    return (
        datetime.now(
            timezone.utc
        )
        .strftime(
            "%Y%m%dT%H%M%SZ"
        )
    )


def _archive_profile(
    profile_path: Path,
    destination_directory: Path,
    environment_id: str,
    suffix: str = "",
) -> Path:
    destination_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    suffix_part = (
        f"-{suffix}"
        if suffix
        else ""
    )

    destination = (
        destination_directory
        / (
            f"{environment_id}-"
            f"{_timestamp()}"
            f"{suffix_part}.yaml"
        )
    )

    sequence = 1

    while destination.exists():
        destination = (
            destination_directory
            / (
                f"{environment_id}-"
                f"{_timestamp()}"
                f"{suffix_part}-"
                f"{sequence:02d}.yaml"
            )
        )
        sequence += 1

    shutil.copy2(
        profile_path,
        destination,
    )

    return destination


def _write_rejection_report(
    archived_profile: Path,
    validation: ProfileValidationResult,
) -> Path:
    report_path = archived_profile.with_suffix(
        ".errors.txt"
    )

    lines = [
        "Hospital profile validation failed",
        "",
    ]

    lines.extend(
        f"- {error}"
        for error in validation.errors
    )

    if validation.warnings:
        lines.extend(
            [
                "",
                "Warnings:",
            ]
        )

        lines.extend(
            f"- {warning}"
            for warning in validation.warnings
        )

    report_path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    return report_path


def build_environment_document(
    profile: dict[str, Any],
) -> dict[str, Any]:
    """Extract the environment-level YAML document."""
    return {
        "schema_version": str(
            profile.get(
                "schema_version",
                "1.0",
            )
        ),
        "environment": dict(
            profile["environment"]
        ),
        "business_hours": dict(
            profile["business_hours"]
        ),
        "data_sources": dict(
            profile.get(
                "data_sources",
                {
                    "wazuh": {
                        "enabled": True,
                    },
                    "zeek": {
                        "enabled": True,
                    },
                },
            )
        ),
        "output": dict(
            profile.get(
                "output",
                {
                    "index": (
                        "healthcare-risk-events"
                    ),
                },
            )
        ),
    }


def build_asset_context_document(
    profile: dict[str, Any],
) -> dict[str, Any]:
    """Extract the network and asset YAML document."""
    environment = profile[
        "environment"
    ]

    asset_context = {
        "organization": {
            "name": environment.get(
                "name"
            ),
            "site_id": environment.get(
                "site_id"
            ),
            "environment": environment.get(
                "environment_type"
            ),
            "infrastructure_type": environment.get(
                "infrastructure_type"
            ),
            "timezone": environment.get(
                "timezone"
            ),
        },
        "network_zones": dict(
            profile[
                "network_zones"
            ]
        ),
        "critical_assets": dict(
            profile.get(
                "critical_assets",
                {},
            )
        ),
        "asset_overrides": dict(
            profile.get(
                "asset_overrides",
                {},
            )
        ),
        "fallback_context": dict(
            profile.get(
                "fallback_context",
                {},
            )
        ),
    }

    services = profile.get(
        "services"
    )

    if isinstance(services, dict):
        asset_context[
            "services"
        ] = dict(services)

    return asset_context


def onboard_profile(
    profile_path: str | Path,
    config_root: str | Path = DEFAULT_CONFIG_ROOT,
    *,
    dry_run: bool = False,
    activate: bool = False,
    archive: bool = True,
    version_id: str | None = None,
) -> dict[str, Any]:
    """
    Validate a hospital profile and create an immutable version.

    The version is inactive by default. Set activate=True only after review.
    """
    source_path = Path(
        profile_path
    ).resolve()

    config_root_path = Path(
        config_root
    ).resolve()

    profile = load_profile_file(
        source_path
    )

    validation = validate_profile(
        profile
    )

    environment = profile.get(
        "environment",
        {},
    )

    environment_id = str(
        environment.get(
            "id",
            "unknown",
        )
    ).strip().lower()

    uploads_root = (
        config_root_path
        / "uploads"
    )

    if not validation.is_valid:
        archived_rejected = None
        rejection_report = None

        if archive and not dry_run:
            archived_rejected = (
                _archive_profile(
                    source_path,
                    uploads_root
                    / "rejected",
                    environment_id,
                    suffix="rejected",
                )
            )

            rejection_report = (
                _write_rejection_report(
                    archived_rejected,
                    validation,
                )
            )

        error_lines = "\n".join(
            f"- {error}"
            for error in validation.errors
        )

        raise ProfileValidationError(
            "Hospital profile validation failed:\n"
            f"{error_lines}"
            + (
                "\nRejected profile: "
                f"{archived_rejected}"
                if archived_rejected
                else ""
            )
            + (
                "\nValidation report: "
                f"{rejection_report}"
                if rejection_report
                else ""
            )
        )

    environment_document = (
        build_environment_document(
            profile
        )
    )

    asset_context_document = (
        build_asset_context_document(
            profile
        )
    )

    manager = ProfileVersionManager(
        config_root_path
    )

    preview_version_id = (
        version_id
        or manager.next_version_id(
            environment_id
        )
    )

    version_directory = (
        manager.version_directory(
            environment_id,
            preview_version_id,
        )
    )

    summary: dict[str, Any] = {
        "environment_id": environment_id,
        "version_id": (
            preview_version_id
        ),
        "version_directory": str(
            version_directory
        ),
        "version_environment_file": str(
            version_directory
            / "environment.yaml"
        ),
        "version_asset_context_file": str(
            version_directory
            / "asset_context.yaml"
        ),
        "active_environment_directory": str(
            manager.active_directory(
                environment_id
            )
        ),
        "dry_run": dry_run,
        "activate": activate,
        "activated": False,
        "archived_profile": None,
        "validation": (
            validation.as_dict()
        ),
    }

    if dry_run:
        return summary

    created = manager.create_version(
        environment_id=environment_id,
        environment_document=(
            environment_document
        ),
        asset_context_document=(
            asset_context_document
        ),
        source_profile=source_path,
        validation=(
            validation.as_dict()
        ),
        version_id=version_id,
    )

    summary.update(
        {
            "version_id": (
                created["version_id"]
            ),
            "version_directory": (
                created[
                    "version_directory"
                ]
            ),
            "version_environment_file": (
                created[
                    "environment_file"
                ]
            ),
            "version_asset_context_file": (
                created[
                    "asset_context_file"
                ]
            ),
            "configuration_sha256": (
                created[
                    "configuration_sha256"
                ]
            ),
        }
    )

    if activate:
        activated = manager.activate_version(
            environment_id,
            created["version_id"],
            reason=(
                "onboarding_activation"
            ),
        )

        summary["activated"] = True
        summary["active_version"] = (
            activated["active_version"]
        )
        summary["previous_version"] = (
            activated.get(
                "previous_version"
            )
        )

    if archive:
        archived_profile = (
            _archive_profile(
                source_path,
                uploads_root
                / "accepted",
                environment_id,
                suffix="accepted",
            )
        )

        summary[
            "archived_profile"
        ] = str(
            archived_profile
        )

    return summary


def _print_validation_statistics(
    validation: dict[str, Any],
) -> None:
    statistics = validation.get(
        "statistics",
        {},
    )

    for name, value in statistics.items():
        label = name.replace(
            "_",
            " ",
        ).title()

        print(
            f"{label}: {value}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate and create a versioned hospital "
            "environment profile"
        )
    )

    parser.add_argument(
        "--profile",
        required=True,
        help=(
            "Path to the combined hospital profile YAML"
        ),
    )

    parser.add_argument(
        "--config-root",
        default=str(
            DEFAULT_CONFIG_ROOT
        ),
        help="Configuration root directory",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Validate and show the target version "
            "without writing files"
        ),
    )

    action_group = (
        parser.add_mutually_exclusive_group()
    )

    action_group.add_argument(
        "--create-version",
        action="store_true",
        help=(
            "Create an inactive version. This is "
            "the default behaviour."
        ),
    )

    action_group.add_argument(
        "--activate",
        action="store_true",
        help=(
            "Create and immediately activate the "
            "new version"
        ),
    )

    parser.add_argument(
        "--version-id",
        help=(
            "Optional explicit version ID using "
            "YYYYMMDDTHHMMSSZ format"
        ),
    )

    parser.add_argument(
        "--no-archive",
        action="store_true",
        help=(
            "Do not archive the uploaded profile"
        ),
    )

    args = parser.parse_args()

    try:
        summary = onboard_profile(
            profile_path=args.profile,
            config_root=args.config_root,
            dry_run=args.dry_run,
            activate=args.activate,
            archive=not args.no_archive,
            version_id=args.version_id,
        )
    except (
        FileNotFoundError,
        ProfileValidationError,
        ProfileVersionError,
        EnvironmentOnboardingError,
    ) as exc:
        print(
            "Environment onboarding failed"
        )
        print()
        print(exc)
        return 2

    if summary["dry_run"]:
        print(
            "Profile validation passed"
        )
        print(
            "Dry run completed; no files were changed"
        )
    else:
        print(
            "Configuration version created"
        )

    print()
    print(
        "Environment ID: "
        f"{summary['environment_id']}"
    )
    print(
        "Version ID: "
        f"{summary['version_id']}"
    )

    _print_validation_statistics(
        summary["validation"]
    )

    print()
    print(
        "Version directory: "
        f"{summary['version_directory']}"
    )

    if summary.get(
        "configuration_sha256"
    ):
        print(
            "Configuration SHA-256: "
            f"{summary['configuration_sha256']}"
        )

    if summary.get("activated"):
        print(
            "Status: active"
        )
        print(
            "Previous version: "
            f"{summary.get('previous_version') or 'none'}"
        )
    elif not summary["dry_run"]:
        print(
            "Status: inactive"
        )
        print(
            "Review and activate this version using "
            "manage_environment_versions.py"
        )

    if summary.get(
        "archived_profile"
    ):
        print(
            "Archived profile: "
            f"{summary['archived_profile']}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())