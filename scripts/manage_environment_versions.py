#!/usr/bin/env python3
"""
Command-line management for hospital configuration versions.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(SRC_ROOT),
    )


from profile_version_manager import (  # noqa: E402
    NoActiveVersionError,
    ProfileVersionError,
    ProfileVersionManager,
    RollbackUnavailableError,
    VersionIntegrityError,
    VersionNotFoundError,
)


DEFAULT_CONFIG_ROOT = (
    PROJECT_ROOT / "config"
)


def _print_versions(
    versions: list[dict],
) -> None:
    if not versions:
        print("No versions found")
        return

    print(
        f"{'VERSION':<22} "
        f"{'STATUS':<10} "
        f"{'ACTIVE':<7} "
        f"{'CREATED'}"
    )

    for version in versions:
        print(
            f"{str(version.get('version_id', '')):<22} "
            f"{str(version.get('status', 'unknown')):<10} "
            f"{str(bool(version.get('is_active'))):<7} "
            f"{str(version.get('created_at', ''))}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "List, verify, activate, and roll back "
            "hospital configuration versions"
        )
    )

    parser.add_argument(
        "--environment",
        required=True,
        help="Hospital environment ID",
    )

    parser.add_argument(
        "--config-root",
        default=str(
            DEFAULT_CONFIG_ROOT
        ),
        help="Configuration root directory",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON",
    )

    actions = (
        parser.add_mutually_exclusive_group(
            required=True
        )
    )

    actions.add_argument(
        "--list",
        action="store_true",
        help="List available versions",
    )

    actions.add_argument(
        "--current",
        action="store_true",
        help="Show the active version",
    )

    actions.add_argument(
        "--show",
        metavar="VERSION_ID",
        help="Show one version",
    )

    actions.add_argument(
        "--verify",
        metavar="VERSION_ID",
        help="Verify one version's SHA-256 hashes",
    )

    actions.add_argument(
        "--activate",
        metavar="VERSION_ID",
        help="Activate a reviewed version",
    )

    actions.add_argument(
        "--rollback",
        action="store_true",
        help="Roll back to the previous active version",
    )

    actions.add_argument(
        "--history",
        action="store_true",
        help="Show activation history",
    )

    args = parser.parse_args()

    manager = ProfileVersionManager(
        args.config_root
    )

    try:
        if args.list:
            result = manager.list_versions(
                args.environment
            )

            if args.json:
                print(
                    json.dumps(
                        result,
                        indent=4,
                        ensure_ascii=False,
                    )
                )
            else:
                _print_versions(result)

            return 0

        if args.current:
            result = manager.current_version(
                args.environment,
                required=True,
            )

        elif args.show:
            result = manager.read_version(
                args.environment,
                args.show,
            )

        elif args.verify:
            result = manager.verify_version(
                args.environment,
                args.verify,
            )

        elif args.activate:
            result = manager.activate_version(
                args.environment,
                args.activate,
            )

        elif args.rollback:
            result = manager.rollback(
                args.environment
            )

        elif args.history:
            result = manager.activation_history(
                args.environment
            )

        else:
            parser.error(
                "No action was selected"
            )
            return 2

    except (
        ProfileVersionError,
        VersionNotFoundError,
        VersionIntegrityError,
        NoActiveVersionError,
        RollbackUnavailableError,
    ) as exc:
        if args.json:
            print(
                json.dumps(
                    {
                        "success": False,
                        "error": str(exc),
                    },
                    indent=4,
                )
            )
        else:
            print(
                "Version operation failed"
            )
            print()
            print(exc)

        return 2

    if args.json:
        print(
            json.dumps(
                result,
                indent=4,
                ensure_ascii=False,
            )
        )
    else:
        if args.current:
            print(
                "Active version: "
                f"{result['active_version']}"
            )
            print(
                "Previous version: "
                f"{result.get('previous_version') or 'none'}"
            )

        elif args.show:
            print(
                "Version: "
                f"{result['version_id']}"
            )
            print(
                "Status: "
                f"{result.get('status')}"
            )
            print(
                "Active: "
                f"{result.get('is_active')}"
            )
            print(
                "Created: "
                f"{result.get('created_at')}"
            )
            print(
                "Configuration SHA-256: "
                f"{result.get('configuration_sha256')}"
            )

        elif args.verify:
            if result["valid"]:
                print(
                    "Version integrity verification passed"
                )
            else:
                print(
                    "Version integrity verification failed"
                )

                for error in result["errors"]:
                    print(f"- {error}")

        elif args.activate:
            print(
                "Version activated"
            )
            print(
                "Active version: "
                f"{result['active_version']}"
            )
            print(
                "Previous version: "
                f"{result.get('previous_version') or 'none'}"
            )

        elif args.rollback:
            print(
                "Rollback completed"
            )
            print(
                "Rolled back from: "
                f"{result['rollback_from']}"
            )
            print(
                "Rolled back to: "
                f"{result['rollback_to']}"
            )

        elif args.history:
            if not result:
                print(
                    "No activation history found"
                )
            else:
                for record in result:
                    print(
                        f"{record.get('activated_at')} "
                        f"{record.get('from_version') or 'none'} "
                        f"-> {record.get('to_version')} "
                        f"({record.get('reason')})"
                    )

    if args.verify and not result["valid"]:
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())