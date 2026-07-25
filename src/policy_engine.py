#!/usr/bin/env python3
"""
Role-based communication policy engine.

The policy engine evaluates communication using organizational roles and
network context instead of individual source and destination IP allowlists.

Example:

    workstation -> ehr_app -> TCP/5000

matches the role policy:

    workstation_to_ehr_application

The first matching policy is selected according to configured priority.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

import yaml

from asset_resolver import AssetResolver


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_POLICY_FILE = (
    PROJECT_ROOT / "config" / "role_policies.yaml"
)

DEFAULT_ASSET_CONTEXT_FILE = (
    PROJECT_ROOT / "config" / "asset_context.yaml"
)


VALID_ACTIONS = {
    "allow",
    "monitor",
    "deny",
    "observe",
}


class PolicyConfigurationError(RuntimeError):
    """Raised when the role-policy configuration is invalid."""


class PolicyEngine:
    """
    Match network communication against role-based policies.

    Supported policy conditions:

    - source_roles
    - destination_roles
    - source_zones
    - destination_zones
    - source_trust_levels
    - destination_trust_levels
    - destination_sensitivities
    - ports
    - protocols
    - services

    Missing or empty condition lists behave as wildcards.
    """

    def __init__(
        self,
        configuration: dict[str, Any],
    ) -> None:
        self.configuration = configuration

        self.settings = configuration.get(
            "policy_settings",
            {},
        )

        self.raw_policies = configuration.get(
            "role_policies",
            [],
        )

        self._validate_configuration()
        self.policies = self._compile_policies()

    @classmethod
    def from_file(
        cls,
        file_path: str | Path = DEFAULT_POLICY_FILE,
    ) -> "PolicyEngine":
        """Create a policy engine from a YAML file."""

        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Role-policy file was not found: {path}"
            )

        try:
            with path.open(
                "r",
                encoding="utf-8-sig",
            ) as file:
                configuration = yaml.safe_load(file)

        except yaml.YAMLError as exc:
            raise PolicyConfigurationError(
                f"Invalid YAML in {path}: {exc}"
            ) from exc

        if not isinstance(configuration, dict):
            raise PolicyConfigurationError(
                f"The YAML root must be an object: {path}"
            )

        return cls(configuration)

    @staticmethod
    def _normalize_string_list(
        value: Any,
        lowercase: bool = True,
    ) -> list[str]:
        """Normalize a scalar or list into unique strings."""

        if value in (None, ""):
            return []

        if isinstance(value, str):
            values = [value]
        elif isinstance(value, (list, tuple, set)):
            values = list(value)
        else:
            raise PolicyConfigurationError(
                f"Expected a string or list, received: {value!r}"
            )

        normalized_values: list[str] = []
        seen: set[str] = set()

        for item in values:
            normalized = str(item).strip()

            if lowercase:
                normalized = normalized.lower()

            if normalized and normalized not in seen:
                seen.add(normalized)
                normalized_values.append(normalized)

        return normalized_values

    @staticmethod
    def _normalize_ports(
        value: Any,
    ) -> list[int]:
        """Normalize one or more destination ports."""

        if value in (None, ""):
            return []

        if isinstance(value, int):
            values = [value]
        elif isinstance(value, (list, tuple, set)):
            values = list(value)
        else:
            raise PolicyConfigurationError(
                f"Ports must be an integer or list: {value!r}"
            )

        normalized_ports: list[int] = []

        for port_value in values:
            try:
                port = int(port_value)
            except (TypeError, ValueError) as exc:
                raise PolicyConfigurationError(
                    f"Invalid destination port: {port_value!r}"
                ) from exc

            if port < 1 or port > 65535:
                raise PolicyConfigurationError(
                    f"Port is outside the valid range: {port}"
                )

            if port not in normalized_ports:
                normalized_ports.append(port)

        return normalized_ports

    @staticmethod
    def _normalize_risk_points(
        value: Any,
    ) -> int:
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise PolicyConfigurationError(
                f"risk_points must be an integer: {value!r}"
            ) from exc

    def _validate_configuration(self) -> None:
        """Validate settings and raw policy entries."""

        if not isinstance(self.settings, dict):
            raise PolicyConfigurationError(
                "policy_settings must be a YAML object"
            )

        if not isinstance(self.raw_policies, list):
            raise PolicyConfigurationError(
                "role_policies must be a YAML list"
            )

        priority_order = str(
            self.settings.get(
                "priority_order",
                "descending",
            )
        ).lower()

        if priority_order not in {
            "ascending",
            "descending",
        }:
            raise PolicyConfigurationError(
                "priority_order must be ascending or descending"
            )

        match_strategy = str(
            self.settings.get(
                "match_strategy",
                "first_match",
            )
        ).lower()

        if match_strategy != "first_match":
            raise PolicyConfigurationError(
                "Only first_match is currently supported"
            )

        default_action = str(
            self.settings.get(
                "default_action",
                "observe",
            )
        ).lower()

        if default_action not in VALID_ACTIONS:
            raise PolicyConfigurationError(
                f"Invalid default action: {default_action}"
            )

        self._normalize_risk_points(
            self.settings.get(
                "default_risk_points",
                0,
            )
        )

        policy_names: set[str] = set()

        for index, policy in enumerate(
            self.raw_policies,
            start=1,
        ):
            if not isinstance(policy, dict):
                raise PolicyConfigurationError(
                    f"Policy #{index} must be a YAML object"
                )

            name = str(
                policy.get("name") or ""
            ).strip()

            if not name:
                raise PolicyConfigurationError(
                    f"Policy #{index} does not contain a name"
                )

            if name in policy_names:
                raise PolicyConfigurationError(
                    f"Duplicate policy name: {name}"
                )

            policy_names.add(name)

            action = str(
                policy.get("action") or ""
            ).strip().lower()

            if action not in VALID_ACTIONS:
                raise PolicyConfigurationError(
                    f"Policy {name} has invalid action: {action}"
                )

            try:
                int(policy.get("priority", 0))
            except (TypeError, ValueError) as exc:
                raise PolicyConfigurationError(
                    f"Policy {name} has invalid priority"
                ) from exc

            self._normalize_risk_points(
                policy.get("risk_points", 0)
            )

            self._normalize_ports(
                policy.get("ports", [])
            )

            for condition_name in (
                "source_roles",
                "destination_roles",
                "source_zones",
                "destination_zones",
                "source_trust_levels",
                "destination_trust_levels",
                "destination_sensitivities",
                "protocols",
                "services",
            ):
                self._normalize_string_list(
                    policy.get(condition_name, [])
                )

    def _compile_policy(
        self,
        policy: dict[str, Any],
    ) -> dict[str, Any]:
        """Normalize one policy for efficient evaluation."""

        return {
            "name": str(policy["name"]).strip(),
            "description": str(
                policy.get("description") or ""
            ).strip(),
            "priority": int(
                policy.get("priority", 0)
            ),
            "source_roles": self._normalize_string_list(
                policy.get("source_roles", [])
            ),
            "destination_roles": self._normalize_string_list(
                policy.get("destination_roles", [])
            ),
            "source_zones": self._normalize_string_list(
                policy.get("source_zones", [])
            ),
            "destination_zones": self._normalize_string_list(
                policy.get("destination_zones", [])
            ),
            "source_trust_levels": self._normalize_string_list(
                policy.get("source_trust_levels", [])
            ),
            "destination_trust_levels": (
                self._normalize_string_list(
                    policy.get(
                        "destination_trust_levels",
                        [],
                    )
                )
            ),
            "destination_sensitivities": (
                self._normalize_string_list(
                    policy.get(
                        "destination_sensitivities",
                        [],
                    )
                )
            ),
            "ports": self._normalize_ports(
                policy.get("ports", [])
            ),
            "protocols": self._normalize_string_list(
                policy.get("protocols", [])
            ),
            "services": self._normalize_string_list(
                policy.get("services", [])
            ),
            "action": str(
                policy["action"]
            ).strip().lower(),
            "risk_points": self._normalize_risk_points(
                policy.get("risk_points", 0)
            ),
            "reason": str(
                policy.get("reason")
                or policy.get("description")
                or f"Matched policy {policy['name']}"
            ).strip(),
        }

    def _compile_policies(
        self,
    ) -> list[dict[str, Any]]:
        """Normalize and sort policy definitions."""

        compiled = [
            self._compile_policy(policy)
            for policy in self.raw_policies
        ]

        priority_order = str(
            self.settings.get(
                "priority_order",
                "descending",
            )
        ).lower()

        reverse = priority_order == "descending"

        compiled.sort(
            key=lambda policy: (
                policy["priority"],
                policy["name"],
            ),
            reverse=reverse,
        )

        return compiled

    @staticmethod
    def _context_value(
        context: dict[str, Any],
        field_name: str,
    ) -> str:
        return str(
            context.get(field_name) or "unknown"
        ).strip().lower()

    @staticmethod
    def _matches_value(
        actual_value: str,
        configured_values: list[str],
    ) -> bool:
        """
        Match a value against a condition list.

        Empty lists and the wildcard "*" match every value.
        """

        if not configured_values:
            return True

        if "*" in configured_values:
            return True

        return actual_value in configured_values

    @staticmethod
    def _matches_port(
        destination_port: int,
        configured_ports: list[int],
    ) -> bool:
        if not configured_ports:
            return True

        return destination_port in configured_ports

    def policy_matches(
        self,
        policy: dict[str, Any],
        source_context: dict[str, Any],
        destination_context: dict[str, Any],
        destination_port: int,
        protocol: str,
        service: str,
    ) -> tuple[bool, dict[str, bool]]:
        """
        Check whether all configured policy conditions match.

        Returns:
            matched:
                True only when every condition matches.

            condition_results:
                Per-condition results for explanation and testing.
        """

        source_role = self._context_value(
            source_context,
            "role",
        )
        destination_role = self._context_value(
            destination_context,
            "role",
        )
        source_zone = self._context_value(
            source_context,
            "zone",
        )
        destination_zone = self._context_value(
            destination_context,
            "zone",
        )
        source_trust_level = self._context_value(
            source_context,
            "trust_level",
        )
        destination_trust_level = self._context_value(
            destination_context,
            "trust_level",
        )
        destination_sensitivity = self._context_value(
            destination_context,
            "sensitivity",
        )

        normalized_protocol = str(
            protocol or "unknown"
        ).strip().lower()

        normalized_service = str(
            service or "unknown"
        ).strip().lower()

        condition_results = {
            "source_role": self._matches_value(
                source_role,
                policy["source_roles"],
            ),
            "destination_role": self._matches_value(
                destination_role,
                policy["destination_roles"],
            ),
            "source_zone": self._matches_value(
                source_zone,
                policy["source_zones"],
            ),
            "destination_zone": self._matches_value(
                destination_zone,
                policy["destination_zones"],
            ),
            "source_trust_level": self._matches_value(
                source_trust_level,
                policy["source_trust_levels"],
            ),
            "destination_trust_level": self._matches_value(
                destination_trust_level,
                policy["destination_trust_levels"],
            ),
            "destination_sensitivity": self._matches_value(
                destination_sensitivity,
                policy["destination_sensitivities"],
            ),
            "destination_port": self._matches_port(
                destination_port,
                policy["ports"],
            ),
            "protocol": self._matches_value(
                normalized_protocol,
                policy["protocols"],
            ),
            "service": self._matches_value(
                normalized_service,
                policy["services"],
            ),
        }

        return (
            all(condition_results.values()),
            condition_results,
        )

    def evaluate(
        self,
        source_context: dict[str, Any],
        destination_context: dict[str, Any],
        destination_port: int,
        protocol: str,
        service: str | None = None,
    ) -> dict[str, Any]:
        """
        Evaluate one network connection.

        The result is always structured, even when no explicit policy
        matches.
        """

        try:
            normalized_port = int(destination_port)
        except (TypeError, ValueError):
            normalized_port = 0

        normalized_protocol = str(
            protocol or "unknown"
        ).strip().lower()

        normalized_service = str(
            service or "unknown"
        ).strip().lower()

        evaluated_policy_count = 0

        for policy in self.policies:
            evaluated_policy_count += 1

            matched, condition_results = self.policy_matches(
                policy=policy,
                source_context=source_context,
                destination_context=destination_context,
                destination_port=normalized_port,
                protocol=normalized_protocol,
                service=normalized_service,
            )

            if not matched:
                continue

            return {
                "matched": True,
                "resolution": "explicit_policy",
                "policy_name": policy["name"],
                "policy_description": policy["description"],
                "policy_priority": policy["priority"],
                "action": policy["action"],
                "risk_points": policy["risk_points"],
                "reason": policy["reason"],
                "evaluated_policy_count": (
                    evaluated_policy_count
                ),
                "condition_results": condition_results,
                "source_role": self._context_value(
                    source_context,
                    "role",
                ),
                "destination_role": self._context_value(
                    destination_context,
                    "role",
                ),
                "source_zone": self._context_value(
                    source_context,
                    "zone",
                ),
                "destination_zone": self._context_value(
                    destination_context,
                    "zone",
                ),
                "destination_port": normalized_port,
                "protocol": normalized_protocol,
                "service": normalized_service,
            }

        default_action = str(
            self.settings.get(
                "default_action",
                "observe",
            )
        ).lower()

        default_risk_points = self._normalize_risk_points(
            self.settings.get(
                "default_risk_points",
                0,
            )
        )

        default_reason = str(
            self.settings.get(
                "default_reason",
                "Communication does not match a known role policy",
            )
        )

        return {
            "matched": False,
            "resolution": "default_policy",
            "policy_name": "default_policy",
            "policy_description": (
                "Default result used because no explicit policy matched"
            ),
            "policy_priority": None,
            "action": default_action,
            "risk_points": default_risk_points,
            "reason": default_reason,
            "evaluated_policy_count": evaluated_policy_count,
            "condition_results": {},
            "source_role": self._context_value(
                source_context,
                "role",
            ),
            "destination_role": self._context_value(
                destination_context,
                "role",
            ),
            "source_zone": self._context_value(
                source_context,
                "zone",
            ),
            "destination_zone": self._context_value(
                destination_context,
                "zone",
            ),
            "destination_port": normalized_port,
            "protocol": normalized_protocol,
            "service": normalized_service,
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve two assets and evaluate communication "
            "against role_policies.yaml"
        )
    )

    parser.add_argument(
        "--source-ip",
        required=True,
        help="Connection source IP",
    )

    parser.add_argument(
        "--destination-ip",
        required=True,
        help="Connection destination IP",
    )

    parser.add_argument(
        "--port",
        required=True,
        type=int,
        help="Destination port",
    )

    parser.add_argument(
        "--protocol",
        default="tcp",
        help="Network protocol, for example tcp or udp",
    )

    parser.add_argument(
        "--service",
        default="",
        help="Optional service such as http, smb, ssh, or dns",
    )

    parser.add_argument(
        "--policy-config",
        default=str(DEFAULT_POLICY_FILE),
        help="Path to role_policies.yaml",
    )

    parser.add_argument(
        "--asset-config",
        default=str(DEFAULT_ASSET_CONTEXT_FILE),
        help="Path to asset_context.yaml",
    )

    args = parser.parse_args()

    asset_resolver = AssetResolver.from_file(
        args.asset_config
    )

    policy_engine = PolicyEngine.from_file(
        args.policy_config
    )

    source_context = asset_resolver.resolve(
        args.source_ip
    )

    destination_context = asset_resolver.resolve(
        args.destination_ip
    )

    result = policy_engine.evaluate(
        source_context=source_context,
        destination_context=destination_context,
        destination_port=args.port,
        protocol=args.protocol,
        service=args.service,
    )

    output = {
        "source_context": source_context,
        "destination_context": destination_context,
        "policy_result": result,
    }

    print(
        json.dumps(
            output,
            indent=4,
            ensure_ascii=False,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())