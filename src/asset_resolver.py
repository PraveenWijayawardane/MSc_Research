#!/usr/bin/env python3
"""
Asset context resolver for the healthcare contextual risk engine.

Resolution priority:

1. Exact asset override
2. Exact critical asset
3. Supplied Wazuh/agent metadata
4. Network zone/subnet classification
5. Internal or external fallback

Normal workstations do not need individual inventory entries.
"""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_ASSET_CONTEXT_FILE = (
    PROJECT_ROOT / "config" / "asset_context.yaml"
)


class AssetConfigurationError(RuntimeError):
    """Raised when the asset-context configuration is invalid."""


class AssetResolver:
    """
    Resolve an IP address into organizational context.

    The returned context contains fields such as:

    - ip
    - hostname
    - role
    - zone
    - trust_level
    - sensitivity
    - managed
    - trusted
    - criticality
    - tags
    - resolution_source
    - is_internal
    - is_critical
    """

    def __init__(self, configuration: dict[str, Any]) -> None:
        self.configuration = configuration

        self.organization = configuration.get("organization", {})
        self.network_zones = configuration.get("network_zones", {})
        self.critical_assets = configuration.get("critical_assets", {})
        self.asset_overrides = configuration.get("asset_overrides", {})
        self.fallback_context = configuration.get("fallback_context", {})

        self._validate_configuration()
        self._compiled_zones = self._compile_network_zones()

    @classmethod
    def from_file(
        cls,
        file_path: str | Path = DEFAULT_ASSET_CONTEXT_FILE,
    ) -> "AssetResolver":
        """Create a resolver from a YAML configuration file."""

        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Asset context file was not found: {path}"
            )

        try:
            with path.open("r", encoding="utf-8-sig") as file:
                configuration = yaml.safe_load(file)
        except yaml.YAMLError as exc:
            raise AssetConfigurationError(
                f"Invalid YAML in {path}: {exc}"
            ) from exc

        if not isinstance(configuration, dict):
            raise AssetConfigurationError(
                f"The YAML root must be an object: {path}"
            )

        return cls(configuration)

    def _validate_configuration(self) -> None:
        """Validate important configuration sections."""

        for section_name, section_value in (
            ("network_zones", self.network_zones),
            ("critical_assets", self.critical_assets),
            ("asset_overrides", self.asset_overrides),
            ("fallback_context", self.fallback_context),
        ):
            if not isinstance(section_value, dict):
                raise AssetConfigurationError(
                    f"{section_name} must be a YAML object"
                )

        for ip_value in list(self.critical_assets) + list(
            self.asset_overrides
        ):
            try:
                ip_address(ip_value)
            except ValueError as exc:
                raise AssetConfigurationError(
                    f"Invalid asset IP address: {ip_value}"
                ) from exc

        for zone_name, zone_config in self.network_zones.items():
            if not isinstance(zone_config, dict):
                raise AssetConfigurationError(
                    f"Network zone {zone_name} must be an object"
                )

            subnets = zone_config.get("subnets", [])

            if not isinstance(subnets, list):
                raise AssetConfigurationError(
                    f"subnets for zone {zone_name} must be a list"
                )

            for subnet in subnets:
                try:
                    ip_network(str(subnet), strict=False)
                except ValueError as exc:
                    raise AssetConfigurationError(
                        f"Invalid subnet {subnet} in zone {zone_name}"
                    ) from exc

    def _compile_network_zones(
        self,
    ) -> list[
        tuple[
            str,
            dict[str, Any],
            Any,
        ]
    ]:
        """
        Precompile network definitions.

        More-specific subnets are checked first. For example, /28 is
        evaluated before /24.
        """

        compiled = []

        for zone_name, zone_config in self.network_zones.items():
            for subnet_value in zone_config.get("subnets", []):
                network = ip_network(
                    str(subnet_value),
                    strict=False,
                )

                compiled.append(
                    (
                        zone_name,
                        zone_config,
                        network,
                    )
                )

        compiled.sort(
            key=lambda item: item[2].prefixlen,
            reverse=True,
        )

        return compiled

    def _find_zone(
        self,
        address: IPv4Address | IPv6Address,
    ) -> tuple[str | None, dict[str, Any] | None]:
        """Find the most-specific network zone for an address."""

        for zone_name, zone_config, network in self._compiled_zones:
            if address.version != network.version:
                continue

            if address in network:
                return zone_name, zone_config

        return None, None

    @staticmethod
    def _normalise_tags(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []

        unique_tags = []
        seen = set()

        for tag in value:
            normalized = str(tag).strip()

            if normalized and normalized not in seen:
                seen.add(normalized)
                unique_tags.append(normalized)

        return unique_tags

    def _base_context(
        self,
        ip_value: str,
        address: IPv4Address | IPv6Address,
    ) -> dict[str, Any]:
        """Create the common result structure."""

        zone_name, zone_config = self._find_zone(address)
        is_internal = zone_name is not None or address.is_private

        return {
            "ip": ip_value,
            "hostname": "unknown",
            "role": "unknown",
            "zone": zone_name or "unknown",
            "trust_level": "unknown",
            "sensitivity": "unknown",
            "managed": False,
            "trusted": False,
            "criticality": "unknown",
            "tags": [],
            "resolution_source": "unresolved",
            "is_internal": is_internal,
            "is_critical": False,
        }

    def _apply_zone_context(
        self,
        context: dict[str, Any],
        zone_name: str,
        zone_config: dict[str, Any],
    ) -> dict[str, Any]:
        """Apply network-zone defaults to an asset context."""

        result = deepcopy(context)

        result.update(
            {
                "role": zone_config.get(
                    "default_role",
                    result["role"],
                ),
                "zone": zone_name,
                "trust_level": zone_config.get(
                    "trust_level",
                    result["trust_level"],
                ),
                "sensitivity": zone_config.get(
                    "sensitivity",
                    result["sensitivity"],
                ),
                "managed": bool(
                    zone_config.get(
                        "managed",
                        result["managed"],
                    )
                ),
                "trusted": bool(
                    zone_config.get(
                        "trusted",
                        result["trusted"],
                    )
                ),
                "criticality": zone_config.get(
                    "criticality",
                    result["criticality"],
                ),
                "tags": self._normalise_tags(
                    zone_config.get("tags", [])
                ),
                "resolution_source": "network_zone",
                "is_internal": True,
            }
        )

        return result

    def _apply_asset_context(
        self,
        context: dict[str, Any],
        asset_data: dict[str, Any],
        resolution_source: str,
        is_critical: bool,
    ) -> dict[str, Any]:
        """
        Apply exact asset information.

        Existing zone information is preserved unless explicitly overridden
        by the exact asset entry.
        """

        result = deepcopy(context)

        for field in (
            "hostname",
            "role",
            "zone",
            "trust_level",
            "sensitivity",
            "criticality",
            "asset_type",
        ):
            if field in asset_data:
                result[field] = asset_data[field]

        if "managed" in asset_data:
            result["managed"] = bool(asset_data["managed"])

        if "trusted" in asset_data:
            result["trusted"] = bool(asset_data["trusted"])

        result["tags"] = self._normalise_tags(
            asset_data.get("tags", result.get("tags", []))
        )

        result["resolution_source"] = resolution_source
        result["is_critical"] = is_critical

        return result

    def _apply_metadata_context(
        self,
        context: dict[str, Any],
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Apply trusted metadata supplied by Wazuh or another asset source.

        Metadata is used only when there is no exact critical asset or
        asset override.
        """

        result = deepcopy(context)

        allowed_metadata_fields = (
            "hostname",
            "role",
            "zone",
            "trust_level",
            "sensitivity",
            "criticality",
            "asset_type",
        )

        metadata_applied = False

        for field in allowed_metadata_fields:
            value = metadata.get(field)

            if value not in (None, ""):
                result[field] = value
                metadata_applied = True

        if "managed" in metadata:
            result["managed"] = bool(metadata["managed"])
            metadata_applied = True

        if "trusted" in metadata:
            result["trusted"] = bool(metadata["trusted"])
            metadata_applied = True

        if isinstance(metadata.get("tags"), list):
            result["tags"] = self._normalise_tags(
                list(result.get("tags", []))
                + list(metadata["tags"])
            )
            metadata_applied = True

        if metadata_applied:
            result["resolution_source"] = "agent_metadata"

        return result

    def _apply_fallback(
        self,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Apply internal or external fallback context."""

        fallback_type = (
            "internal"
            if context["is_internal"]
            else "external"
        )

        fallback = self.fallback_context.get(fallback_type, {})

        if not isinstance(fallback, dict):
            fallback = {}

        result = deepcopy(context)

        result.update(
            {
                "role": fallback.get(
                    "role",
                    (
                        "internal_unknown"
                        if context["is_internal"]
                        else "external"
                    ),
                ),
                "trust_level": fallback.get(
                    "trust_level",
                    (
                        "internal"
                        if context["is_internal"]
                        else "untrusted"
                    ),
                ),
                "sensitivity": fallback.get(
                    "sensitivity",
                    "unknown",
                ),
                "managed": bool(
                    fallback.get("managed", False)
                ),
                "trusted": bool(
                    fallback.get("trusted", False)
                ),
                "criticality": fallback.get(
                    "criticality",
                    "unknown",
                ),
                "tags": self._normalise_tags(
                    fallback.get("tags", [])
                ),
                "resolution_source": (
                    "internal_fallback"
                    if context["is_internal"]
                    else "external_fallback"
                ),
            }
        )

        return result

    def resolve(
        self,
        ip_value: str,
        hostname: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Resolve one IP address into organizational context.

        Args:
            ip_value:
                IPv4 or IPv6 address.

            hostname:
                Optional hostname collected from Wazuh, DNS, DHCP, or Zeek.

            metadata:
                Optional trusted metadata, for example:

                {
                    "role": "workstation",
                    "managed": True,
                    "tags": ["wazuh-agent"]
                }
        """

        normalized_ip = str(ip_value or "").strip()

        try:
            address = ip_address(normalized_ip)
        except ValueError:
            return {
                "ip": normalized_ip or "unknown",
                "hostname": hostname or "unknown",
                "role": "unknown",
                "zone": "unknown",
                "trust_level": "unknown",
                "sensitivity": "unknown",
                "managed": False,
                "trusted": False,
                "criticality": "unknown",
                "tags": [],
                "resolution_source": "invalid_ip",
                "is_internal": False,
                "is_critical": False,
            }

        context = self._base_context(
            normalized_ip,
            address,
        )

        zone_name, zone_config = self._find_zone(address)

        if zone_name and zone_config:
            context = self._apply_zone_context(
                context,
                zone_name,
                zone_config,
            )

        # Exact exceptional device definitions have the highest priority.
        override = self.asset_overrides.get(normalized_ip)

        if isinstance(override, dict):
            context = self._apply_asset_context(
                context,
                override,
                resolution_source="asset_override",
                is_critical=False,
            )

        else:
            critical_asset = self.critical_assets.get(
                normalized_ip
            )

            if isinstance(critical_asset, dict):
                context = self._apply_asset_context(
                    context,
                    critical_asset,
                    resolution_source="critical_asset",
                    is_critical=True,
                )

            elif metadata and isinstance(metadata, dict):
                context = self._apply_metadata_context(
                    context,
                    metadata,
                )

            elif zone_name is None:
                context = self._apply_fallback(context)

        if hostname and context.get("hostname") in (
            None,
            "",
            "unknown",
        ):
            context["hostname"] = hostname

        return context

    def resolve_many(
        self,
        ip_values: Iterable[str],
    ) -> list[dict[str, Any]]:
        """Resolve multiple IP addresses."""

        return [
            self.resolve(ip_value)
            for ip_value in ip_values
        ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Resolve an IP address using asset_context.yaml"
    )

    parser.add_argument(
        "--ip",
        required=True,
        help="IP address to resolve",
    )

    parser.add_argument(
        "--hostname",
        help="Optional hostname",
    )

    parser.add_argument(
        "--config",
        default=str(DEFAULT_ASSET_CONTEXT_FILE),
        help="Path to asset_context.yaml",
    )

    args = parser.parse_args()

    resolver = AssetResolver.from_file(args.config)

    result = resolver.resolve(
        ip_value=args.ip,
        hostname=args.hostname,
    )

    print(
        json.dumps(
            result,
            indent=4,
            ensure_ascii=False,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())