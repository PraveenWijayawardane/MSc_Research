#!/usr/bin/env python3
"""
Hospital environment profile validation.

A hospital administrator can provide one combined YAML profile containing
environment details, network zones, assets, business hours, and optional
service definitions. This module validates the profile before onboarding.

The validator checks:

- duplicate YAML keys;
- environment ID safety;
- required environment fields;
- timezone and business-hour formats;
- invalid or overlapping CIDR ranges;
- invalid asset IP addresses;
- duplicate assets across sections;
- unknown roles, trust levels, sensitivity, and criticality;
- asset-to-zone consistency;
- invalid service ports and protocols.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import (
    IPv4Address,
    IPv6Address,
    IPv4Network,
    IPv6Network,
    ip_address,
    ip_network,
)
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from yaml.constructor import ConstructorError

from event_environment import (
    EventEnvironmentError,
    resolve_environment_id,
)


SUPPORTED_SCHEMA_VERSIONS = {
    "1.0",
}

RESERVED_ENVIRONMENT_IDS = {
    "base",
    "templates",
    "uploads",
    "accepted",
    "rejected",
    "pending",
}

ALLOWED_ROLES = {
    "attacker",
    "workstation",
    "admin_workstation",
    "application_server",
    "ehr_app",
    "database",
    "file_server",
    "monitoring_server",
    "security_server",
    "zeek_sensor",
    "wazuh_manager",
    "domain_controller",
    "directory_server",
    "backup_server",
    "jump_server",
    "load_balancer",
    "api_gateway",
    "medical_device",
    "network_device",
    "internal_unknown",
    "external",
    "unknown",
}

ALLOWED_TRUST_LEVELS = {
    "unknown",
    "untrusted",
    "internal",
    "standard",
    "elevated",
    "protected",
    "trusted",
}

ALLOWED_SENSITIVITY_LEVELS = {
    "unknown",
    "normal",
    "low",
    "medium",
    "high",
    "critical",
}

ALLOWED_CRITICALITY_LEVELS = {
    "unknown",
    "normal",
    "low",
    "medium",
    "high",
    "critical",
}

ALLOWED_PROTOCOLS = {
    "tcp",
    "udp",
    "sctp",
    "icmp",
    "any",
}

ALLOWED_WORKING_DAYS = {
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
}

INDEX_NAME_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9._-]{0,254}$"
)

HOSTNAME_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$"
)

ZONE_NAME_PATTERN = re.compile(
    r"^[a-z][a-z0-9_]{0,62}$"
)

SERVICE_NAME_PATTERN = re.compile(
    r"^[a-z][a-z0-9_-]{0,62}$"
)


class ProfileValidationError(ValueError):
    """Raised when a profile cannot be loaded or validated."""


class DuplicateKeyLoader(yaml.SafeLoader):
    """YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: DuplicateKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}

    for key_node, value_node in node.value:
        key = loader.construct_object(
            key_node,
            deep=deep,
        )

        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key found: {key!r}",
                key_node.start_mark,
            )

        mapping[key] = loader.construct_object(
            value_node,
            deep=deep,
        )

    return mapping


DuplicateKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass
class ProfileValidationResult:
    """Detailed result returned by the hospital profile validator."""

    profile: dict[str, Any] | None = None
    errors: list[str] = field(
        default_factory=list
    )
    warnings: list[str] = field(
        default_factory=list
    )
    statistics: dict[str, int] = field(
        default_factory=dict
    )

    @property
    def is_valid(self) -> bool:
        return not self.errors

    def add_error(
        self,
        path: str,
        message: str,
    ) -> None:
        self.errors.append(
            f"{path}: {message}"
        )

    def add_warning(
        self,
        path: str,
        message: str,
    ) -> None:
        self.warnings.append(
            f"{path}: {message}"
        )

    def as_dict(self) -> dict[str, Any]:
        environment_id = None

        if isinstance(self.profile, dict):
            environment = self.profile.get(
                "environment"
            )

            if isinstance(environment, dict):
                environment_id = (
                    environment.get("id")
                )

        return {
            "valid": self.is_valid,
            "environment_id": environment_id,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "statistics": dict(
                self.statistics
            ),
        }


def load_profile_file(
    profile_path: str | Path,
) -> dict[str, Any]:
    """Load a combined hospital profile and reject duplicate YAML keys."""
    path = Path(profile_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Hospital profile was not found: {path}"
        )

    if not path.is_file():
        raise ProfileValidationError(
            f"Hospital profile path is not a file: {path}"
        )

    try:
        with path.open(
            "r",
            encoding="utf-8-sig",
        ) as file:
            profile = yaml.load(
                file,
                Loader=DuplicateKeyLoader,
            )
    except ConstructorError as exc:
        raise ProfileValidationError(
            f"Duplicate YAML key in {path}: {exc}"
        ) from exc
    except yaml.YAMLError as exc:
        raise ProfileValidationError(
            f"Invalid YAML in {path}: {exc}"
        ) from exc

    if not isinstance(profile, dict):
        raise ProfileValidationError(
            "Hospital profile root must be a YAML object"
        )

    return profile


def _is_mapping(
    result: ProfileValidationResult,
    value: Any,
    path: str,
    required: bool = True,
) -> bool:
    if value is None and not required:
        return False

    if not isinstance(value, dict):
        result.add_error(
            path,
            "must be a YAML object",
        )
        return False

    return True


def _is_non_empty_string(
    result: ProfileValidationResult,
    value: Any,
    path: str,
) -> bool:
    if not isinstance(value, str) or not value.strip():
        result.add_error(
            path,
            "must be a non-empty string",
        )
        return False

    return True


def _validate_choice(
    result: ProfileValidationResult,
    value: Any,
    path: str,
    allowed_values: set[str],
    required: bool = True,
) -> None:
    if value is None and not required:
        return

    if not isinstance(value, str):
        result.add_error(
            path,
            "must be a string",
        )
        return

    normalized = value.strip().lower()

    if normalized not in allowed_values:
        result.add_error(
            path,
            "invalid value "
            f"{value!r}; allowed values are "
            + ", ".join(
                sorted(allowed_values)
            ),
        )


def _parse_time(
    result: ProfileValidationResult,
    value: Any,
    path: str,
) -> tuple[int, int] | None:
    if not isinstance(value, str):
        result.add_error(
            path,
            "must use HH:MM format",
        )
        return None

    try:
        parsed = datetime.strptime(
            value.strip(),
            "%H:%M",
        )
    except ValueError:
        result.add_error(
            path,
            "must use 24-hour HH:MM format",
        )
        return None

    return parsed.hour, parsed.minute


def _parse_port(
    result: ProfileValidationResult,
    value: Any,
    path: str,
) -> list[int]:
    if isinstance(value, bool):
        result.add_error(
            path,
            "must be a port number or port range",
        )
        return []

    if isinstance(value, int):
        if 1 <= value <= 65535:
            return [value]

        result.add_error(
            path,
            "port must be between 1 and 65535",
        )
        return []

    if isinstance(value, str):
        text = value.strip()

        if text.isdigit():
            port = int(text)

            if 1 <= port <= 65535:
                return [port]

            result.add_error(
                path,
                "port must be between 1 and 65535",
            )
            return []

        if "-" in text:
            start_text, end_text = text.split(
                "-",
                1,
            )

            if (
                start_text.strip().isdigit()
                and end_text.strip().isdigit()
            ):
                start = int(
                    start_text.strip()
                )
                end = int(
                    end_text.strip()
                )

                if (
                    1 <= start <= 65535
                    and 1 <= end <= 65535
                    and start <= end
                ):
                    return list(
                        range(start, end + 1)
                    )

        result.add_error(
            path,
            "invalid port or port range",
        )
        return []

    result.add_error(
        path,
        "must be a port number or port range",
    )
    return []


def _validate_environment(
    result: ProfileValidationResult,
    profile: dict[str, Any],
) -> str | None:
    schema_version = str(
        profile.get(
            "schema_version",
            "",
        )
    ).strip()

    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        result.add_error(
            "schema_version",
            "unsupported schema version "
            f"{schema_version!r}; supported versions: "
            + ", ".join(
                sorted(
                    SUPPORTED_SCHEMA_VERSIONS
                )
            ),
        )

    environment = profile.get(
        "environment"
    )

    if not _is_mapping(
        result,
        environment,
        "environment",
    ):
        return None

    assert isinstance(environment, dict)

    environment_id_raw = environment.get(
        "id"
    )

    try:
        environment_id = resolve_environment_id(
            str(
                environment_id_raw
                or ""
            )
        )
    except EventEnvironmentError as exc:
        result.add_error(
            "environment.id",
            str(exc),
        )
        environment_id = None

    if (
        environment_id
        in RESERVED_ENVIRONMENT_IDS
    ):
        result.add_error(
            "environment.id",
            f"{environment_id!r} is reserved",
        )

    for field_name in (
        "name",
        "site_id",
        "environment_type",
        "infrastructure_type",
        "timezone",
    ):
        _is_non_empty_string(
            result,
            environment.get(
                field_name
            ),
            f"environment.{field_name}",
        )

    timezone_name = environment.get(
        "timezone"
    )

    if isinstance(
        timezone_name,
        str,
    ) and timezone_name.strip():
        try:
            ZoneInfo(
                timezone_name.strip()
            )
        except ZoneInfoNotFoundError:
            result.add_warning(
                "environment.timezone",
                "timezone data is unavailable on this "
                "machine; install the Python tzdata "
                "package if the runtime cannot load it",
            )

    return environment_id


def _validate_business_hours(
    result: ProfileValidationResult,
    profile: dict[str, Any],
) -> None:
    business_hours = profile.get(
        "business_hours"
    )

    if not _is_mapping(
        result,
        business_hours,
        "business_hours",
    ):
        return

    assert isinstance(
        business_hours,
        dict,
    )

    start = _parse_time(
        result,
        business_hours.get(
            "start"
        ),
        "business_hours.start",
    )

    end = _parse_time(
        result,
        business_hours.get(
            "end"
        ),
        "business_hours.end",
    )

    if start and end and start >= end:
        result.add_error(
            "business_hours",
            "start time must be earlier than end time",
        )

    working_days = business_hours.get(
        "working_days"
    )

    if not isinstance(
        working_days,
        list,
    ) or not working_days:
        result.add_error(
            "business_hours.working_days",
            "must be a non-empty list",
        )
        return

    seen: set[str] = set()

    for index, day in enumerate(
        working_days
    ):
        path = (
            "business_hours."
            f"working_days[{index}]"
        )

        if day not in ALLOWED_WORKING_DAYS:
            result.add_error(
                path,
                "invalid working day",
            )
            continue

        if day in seen:
            result.add_error(
                path,
                f"duplicate working day {day}",
            )

        seen.add(day)


def _validate_network_zones(
    result: ProfileValidationResult,
    profile: dict[str, Any],
) -> dict[
    str,
    list[
        IPv4Network | IPv6Network
    ],
]:
    network_zones = profile.get(
        "network_zones"
    )

    if not _is_mapping(
        result,
        network_zones,
        "network_zones",
    ):
        return {}

    assert isinstance(
        network_zones,
        dict,
    )

    if not network_zones:
        result.add_error(
            "network_zones",
            "at least one network zone is required",
        )
        return {}

    compiled: dict[
        str,
        list[
            IPv4Network | IPv6Network
        ],
    ] = {}

    all_networks: list[
        tuple[
            str,
            IPv4Network | IPv6Network,
        ]
    ] = []

    for zone_name, zone in network_zones.items():
        zone_path = (
            f"network_zones.{zone_name}"
        )

        if (
            not isinstance(zone_name, str)
            or not ZONE_NAME_PATTERN.fullmatch(
                zone_name
            )
        ):
            result.add_error(
                "network_zones",
                f"invalid zone name {zone_name!r}; "
                "use lowercase letters, numbers, "
                "and underscores",
            )
            continue

        if not _is_mapping(
            result,
            zone,
            zone_path,
        ):
            continue

        assert isinstance(zone, dict)

        subnets = zone.get(
            "subnets"
        )

        if not isinstance(
            subnets,
            list,
        ) or not subnets:
            result.add_error(
                f"{zone_path}.subnets",
                "must be a non-empty list",
            )
            continue

        compiled[zone_name] = []

        for index, subnet_value in enumerate(
            subnets
        ):
            subnet_path = (
                f"{zone_path}.subnets[{index}]"
            )

            try:
                network = ip_network(
                    str(subnet_value),
                    strict=False,
                )
            except ValueError:
                result.add_error(
                    subnet_path,
                    f"invalid CIDR {subnet_value!r}",
                )
                continue

            duplicate = any(
                network == existing_network
                for _, existing_network
                in all_networks
            )

            if duplicate:
                result.add_error(
                    subnet_path,
                    f"duplicate subnet {network}",
                )
                continue

            compiled[
                zone_name
            ].append(network)

            all_networks.append(
                (
                    zone_name,
                    network,
                )
            )

        _validate_choice(
            result,
            zone.get(
                "default_role"
            ),
            f"{zone_path}.default_role",
            ALLOWED_ROLES,
        )

        _validate_choice(
            result,
            zone.get(
                "trust_level"
            ),
            f"{zone_path}.trust_level",
            ALLOWED_TRUST_LEVELS,
        )

        _validate_choice(
            result,
            zone.get(
                "sensitivity"
            ),
            f"{zone_path}.sensitivity",
            ALLOWED_SENSITIVITY_LEVELS,
        )

        _validate_choice(
            result,
            zone.get(
                "criticality"
            ),
            f"{zone_path}.criticality",
            ALLOWED_CRITICALITY_LEVELS,
        )

        for boolean_field in (
            "managed",
            "trusted",
        ):
            if not isinstance(
                zone.get(boolean_field),
                bool,
            ):
                result.add_error(
                    f"{zone_path}.{boolean_field}",
                    "must be true or false",
                )

        tags = zone.get(
            "tags",
            [],
        )

        if not isinstance(tags, list):
            result.add_error(
                f"{zone_path}.tags",
                "must be a list",
            )

    for index, (
        first_zone,
        first_network,
    ) in enumerate(all_networks):
        for (
            second_zone,
            second_network,
        ) in all_networks[
            index + 1:
        ]:
            if (
                first_network.version
                != second_network.version
            ):
                continue

            if first_network.overlaps(
                second_network
            ):
                result.add_error(
                    "network_zones",
                    f"{first_zone} {first_network} overlaps "
                    f"{second_zone} {second_network}",
                )

    return compiled


def _validate_asset_entry(
    result: ProfileValidationResult,
    section_name: str,
    ip_value: Any,
    asset: Any,
    zones: dict[
        str,
        list[
            IPv4Network | IPv6Network
        ],
    ],
) -> IPv4Address | IPv6Address | None:
    asset_path = (
        f"{section_name}.{ip_value}"
    )

    try:
        address = ip_address(
            str(ip_value)
        )
    except ValueError:
        result.add_error(
            asset_path,
            "invalid IP address",
        )
        return None

    if not _is_mapping(
        result,
        asset,
        asset_path,
    ):
        return address

    assert isinstance(asset, dict)

    hostname = asset.get(
        "hostname"
    )

    if _is_non_empty_string(
        result,
        hostname,
        f"{asset_path}.hostname",
    ):
        assert isinstance(
            hostname,
            str,
        )

        if not HOSTNAME_PATTERN.fullmatch(
            hostname.strip()
        ):
            result.add_error(
                f"{asset_path}.hostname",
                "invalid hostname format",
            )

    _validate_choice(
        result,
        asset.get("role"),
        f"{asset_path}.role",
        ALLOWED_ROLES,
    )

    _validate_choice(
        result,
        asset.get(
            "trust_level"
        ),
        f"{asset_path}.trust_level",
        ALLOWED_TRUST_LEVELS,
        required=False,
    )

    _validate_choice(
        result,
        asset.get(
            "sensitivity"
        ),
        f"{asset_path}.sensitivity",
        ALLOWED_SENSITIVITY_LEVELS,
        required=False,
    )

    _validate_choice(
        result,
        asset.get(
            "criticality"
        ),
        f"{asset_path}.criticality",
        ALLOWED_CRITICALITY_LEVELS,
        required=False,
    )

    for boolean_field in (
        "managed",
        "trusted",
    ):
        if (
            boolean_field in asset
            and not isinstance(
                asset.get(boolean_field),
                bool,
            )
        ):
            result.add_error(
                f"{asset_path}.{boolean_field}",
                "must be true or false",
            )

    zone_name = asset.get(
        "zone"
    )

    if zone_name is not None:
        if (
            not isinstance(zone_name, str)
            or zone_name not in zones
        ):
            result.add_error(
                f"{asset_path}.zone",
                f"unknown network zone {zone_name!r}",
            )
        else:
            matching_zone = any(
                (
                    address.version
                    == network.version
                    and address in network
                )
                for network in zones[
                    zone_name
                ]
            )

            if not matching_zone:
                result.add_error(
                    f"{asset_path}.zone",
                    f"IP {address} is not inside any "
                    f"subnet configured for {zone_name}",
                )
    else:
        inside_any_zone = any(
            (
                address.version
                == network.version
                and address in network
            )
            for networks in zones.values()
            for network in networks
        )

        if not inside_any_zone:
            result.add_warning(
                asset_path,
                "asset is not inside any configured "
                "network zone",
            )

    tags = asset.get(
        "tags",
        [],
    )

    if not isinstance(tags, list):
        result.add_error(
            f"{asset_path}.tags",
            "must be a list",
        )

    return address


def _validate_assets(
    result: ProfileValidationResult,
    profile: dict[str, Any],
    zones: dict[
        str,
        list[
            IPv4Network | IPv6Network
        ],
    ],
) -> None:
    addresses: dict[
        str,
        str,
    ] = {}

    for section_name in (
        "critical_assets",
        "asset_overrides",
    ):
        section = profile.get(
            section_name,
            {},
        )

        if not _is_mapping(
            result,
            section,
            section_name,
            required=False,
        ):
            continue

        assert isinstance(section, dict)

        for ip_value, asset in section.items():
            normalized_ip = str(
                ip_value
            ).strip()

            if normalized_ip in addresses:
                result.add_error(
                    f"{section_name}.{ip_value}",
                    "asset is already defined in "
                    f"{addresses[normalized_ip]}",
                )
                continue

            addresses[
                normalized_ip
            ] = section_name

            _validate_asset_entry(
                result,
                section_name,
                ip_value,
                asset,
                zones,
            )


def _validate_fallback_context(
    result: ProfileValidationResult,
    profile: dict[str, Any],
) -> None:
    fallback_context = profile.get(
        "fallback_context",
        {},
    )

    if not _is_mapping(
        result,
        fallback_context,
        "fallback_context",
        required=False,
    ):
        return

    assert isinstance(
        fallback_context,
        dict,
    )

    for context_name in (
        "internal",
        "external",
    ):
        context = fallback_context.get(
            context_name
        )

        if context is None:
            result.add_warning(
                f"fallback_context.{context_name}",
                "fallback context is not defined",
            )
            continue

        if not _is_mapping(
            result,
            context,
            f"fallback_context.{context_name}",
        ):
            continue

        assert isinstance(context, dict)

        _validate_choice(
            result,
            context.get("role"),
            f"fallback_context.{context_name}.role",
            ALLOWED_ROLES,
        )

        _validate_choice(
            result,
            context.get(
                "trust_level"
            ),
            (
                f"fallback_context.{context_name}."
                "trust_level"
            ),
            ALLOWED_TRUST_LEVELS,
        )

        _validate_choice(
            result,
            context.get(
                "sensitivity"
            ),
            (
                f"fallback_context.{context_name}."
                "sensitivity"
            ),
            ALLOWED_SENSITIVITY_LEVELS,
        )

        _validate_choice(
            result,
            context.get(
                "criticality"
            ),
            (
                f"fallback_context.{context_name}."
                "criticality"
            ),
            ALLOWED_CRITICALITY_LEVELS,
        )


def _validate_services(
    result: ProfileValidationResult,
    profile: dict[str, Any],
) -> None:
    services = profile.get(
        "services",
        {},
    )

    if not _is_mapping(
        result,
        services,
        "services",
        required=False,
    ):
        return

    assert isinstance(services, dict)

    for service_name, service in services.items():
        service_path = (
            f"services.{service_name}"
        )

        if (
            not isinstance(service_name, str)
            or not SERVICE_NAME_PATTERN.fullmatch(
                service_name
            )
        ):
            result.add_error(
                "services",
                f"invalid service name {service_name!r}",
            )
            continue

        if not _is_mapping(
            result,
            service,
            service_path,
        ):
            continue

        assert isinstance(service, dict)

        protocol = service.get(
            "protocol",
            "tcp",
        )

        _validate_choice(
            result,
            protocol,
            f"{service_path}.protocol",
            ALLOWED_PROTOCOLS,
        )

        ports = service.get(
            "ports"
        )

        if not isinstance(
            ports,
            list,
        ) or not ports:
            result.add_error(
                f"{service_path}.ports",
                "must be a non-empty list",
            )
            continue

        parsed_ports: set[int] = set()

        for index, port_value in enumerate(
            ports
        ):
            port_path = (
                f"{service_path}.ports[{index}]"
            )

            for port in _parse_port(
                result,
                port_value,
                port_path,
            ):
                if port in parsed_ports:
                    result.add_error(
                        port_path,
                        f"duplicate port {port}",
                    )

                parsed_ports.add(port)


def _validate_data_sources_and_output(
    result: ProfileValidationResult,
    profile: dict[str, Any],
) -> None:
    data_sources = profile.get(
        "data_sources",
        {},
    )

    if _is_mapping(
        result,
        data_sources,
        "data_sources",
        required=False,
    ):
        assert isinstance(
            data_sources,
            dict,
        )

        for source_name in (
            "wazuh",
            "zeek",
        ):
            source = data_sources.get(
                source_name
            )

            if source is None:
                continue

            if not _is_mapping(
                result,
                source,
                f"data_sources.{source_name}",
            ):
                continue

            assert isinstance(source, dict)

            if not isinstance(
                source.get("enabled"),
                bool,
            ):
                result.add_error(
                    (
                        f"data_sources.{source_name}."
                        "enabled"
                    ),
                    "must be true or false",
                )

    output = profile.get(
        "output",
        {},
    )

    if _is_mapping(
        result,
        output,
        "output",
        required=False,
    ):
        assert isinstance(output, dict)

        index_name = output.get(
            "index"
        )

        if index_name is not None:
            if (
                not isinstance(index_name, str)
                or not INDEX_NAME_PATTERN.fullmatch(
                    index_name.strip()
                )
            ):
                result.add_error(
                    "output.index",
                    "invalid OpenSearch index name",
                )


def validate_profile(
    profile: dict[str, Any],
) -> ProfileValidationResult:
    """Validate one already-loaded hospital profile."""
    result = ProfileValidationResult(
        profile=profile
        if isinstance(profile, dict)
        else None
    )

    if not isinstance(profile, dict):
        result.add_error(
            "profile",
            "must be a YAML object",
        )
        return result

    _validate_environment(
        result,
        profile,
    )

    _validate_business_hours(
        result,
        profile,
    )

    zones = _validate_network_zones(
        result,
        profile,
    )

    _validate_assets(
        result,
        profile,
        zones,
    )

    _validate_fallback_context(
        result,
        profile,
    )

    _validate_services(
        result,
        profile,
    )

    _validate_data_sources_and_output(
        result,
        profile,
    )

    critical_assets = profile.get(
        "critical_assets",
        {},
    )

    asset_overrides = profile.get(
        "asset_overrides",
        {},
    )

    services = profile.get(
        "services",
        {},
    )

    result.statistics = {
        "network_zone_count": len(
            profile.get(
                "network_zones",
                {},
            )
        )
        if isinstance(
            profile.get(
                "network_zones"
            ),
            dict,
        )
        else 0,
        "critical_asset_count": len(
            critical_assets
        )
        if isinstance(
            critical_assets,
            dict,
        )
        else 0,
        "asset_override_count": len(
            asset_overrides
        )
        if isinstance(
            asset_overrides,
            dict,
        )
        else 0,
        "service_count": len(
            services
        )
        if isinstance(
            services,
            dict,
        )
        else 0,
    }

    return result


def validate_profile_file(
    profile_path: str | Path,
) -> ProfileValidationResult:
    """Load and validate a hospital profile file."""
    profile = load_profile_file(
        profile_path
    )

    return validate_profile(
        profile
    )


def _print_human_result(
    result: ProfileValidationResult,
) -> None:
    environment_id = (
        result.as_dict().get(
            "environment_id"
        )
        or "unknown"
    )

    if result.is_valid:
        print(
            "Profile validation passed"
        )
    else:
        print(
            "Profile validation failed"
        )

    print()
    print(
        f"Environment ID: {environment_id}"
    )

    for name, value in (
        result.statistics.items()
    ):
        label = name.replace(
            "_",
            " ",
        ).title()

        print(
            f"{label}: {value}"
        )

    if result.errors:
        print()
        print("Errors:")

        for error in result.errors:
            print(f"- {error}")

    if result.warnings:
        print()
        print("Warnings:")

        for warning in result.warnings:
            print(f"- {warning}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a hospital environment profile"
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
        "--json",
        action="store_true",
        help=(
            "Print the validation result as JSON"
        ),
    )

    args = parser.parse_args()

    try:
        result = validate_profile_file(
            args.profile
        )
    except (
        FileNotFoundError,
        ProfileValidationError,
    ) as exc:
        if args.json:
            print(
                json.dumps(
                    {
                        "valid": False,
                        "errors": [
                            str(exc)
                        ],
                        "warnings": [],
                        "statistics": {},
                    },
                    indent=4,
                )
            )
        else:
            print(
                "Profile validation failed"
            )
            print()
            print(f"- {exc}")

        return 2

    if args.json:
        print(
            json.dumps(
                result.as_dict(),
                indent=4,
                ensure_ascii=False,
            )
        )
    else:
        _print_human_result(
            result
        )

    return 0 if result.is_valid else 2


if __name__ == "__main__":
    raise SystemExit(main())