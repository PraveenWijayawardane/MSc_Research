#!/usr/bin/env python3
"""
Scalable contextual risk engine for Wazuh and Zeek telemetry.

This module combines:

- environment-specific configuration loading;
- asset context resolution;
- role-based communication policies;
- fixed-window behavioural analysis;
- Wazuh host-event scoring;
- Wazuh/Zeek correlation;
- deterministic event IDs and deduplication.

The same Python code can run for different hospital environments by selecting
an environment profile under config/environments/<environment-id>.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from asset_resolver import AssetResolver
from behavior_analyzer import BehaviorAnalyzer
from environment_registry import EnvironmentRegistry
from event_environment import get_event_environment
from environment_paths import EnvironmentPaths
from policy_engine import PolicyEngine


LOGGER = logging.getLogger("risk_engine")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_ROOT = PROJECT_ROOT / "config"
DEFAULT_ENVIRONMENT_ID = "healthcare-lab"

# Legacy paths remain available while the project is migrated.
ASSET_CONTEXT_FILE = CONFIG_ROOT / "asset_context.yaml"
ROLE_POLICIES_FILE = CONFIG_ROOT / "role_policies.yaml"
RISK_RULES_FILE = CONFIG_ROOT / "risk_rules.yaml"

WAZUH_INPUT_FILE = PROJECT_ROOT / "data" / "live_wazuh_events.json"
ZEEK_INPUT_FILE = PROJECT_ROOT / "data" / "live_zeek_conn.json"
OUTPUT_FILE = PROJECT_ROOT / "output" / "scored_events.json"


class RiskConfigurationError(RuntimeError):
    """Raised when risk-engine configuration is invalid."""


def safe_int(value: Any, default: int = 0) -> int:
    """Convert a value to int without raising for telemetry placeholders."""
    try:
        if value in (None, "", "-"):
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    """Convert a value to float without raising for telemetry placeholders."""
    try:
        if value in (None, "", "-"):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def parse_timestamp(value: Any) -> datetime | None:
    """Parse epoch or ISO timestamps and normalise them to UTC."""
    if value in (None, "", "-"):
        return None

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)

    text = str(value).strip()

    try:
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    except ValueError:
        pass

    normalised = text.replace("Z", "+00:00")

    if (
        len(normalised) >= 5
        and normalised[-5] in {"+", "-"}
        and normalised[-3] != ":"
    ):
        normalised = normalised[:-2] + ":" + normalised[-2:]

    try:
        parsed = datetime.fromisoformat(normalised)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def format_timestamp(value: Any) -> str:
    """Return a UTC ISO-8601 timestamp."""
    parsed = parse_timestamp(value)

    if parsed is None:
        return ""

    return (
        parsed.isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def stable_hash(
    prefix: str,
    value: dict[str, Any],
) -> str:
    """Build a deterministic identifier from a JSON-compatible object."""
    serialised = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )

    digest = hashlib.sha256(
        serialised.encode("utf-8")
    ).hexdigest()

    return f"{prefix}:{digest}"


def unique_strings(
    values: Iterable[Any],
) -> list[str]:
    """Return unique, non-empty strings while preserving order."""
    result: list[str] = []
    seen: set[str] = set()

    for value in values:
        text = str(value or "").strip()

        if text and text not in seen:
            seen.add(text)
            result.append(text)

    return result


def clamp(
    value: int,
    minimum: int,
    maximum: int,
) -> int:
    """Restrict an integer to a configured range."""
    return max(
        minimum,
        min(safe_int(value), maximum),
    )


def load_json(path: Path) -> Any:
    """Load JSON from disk."""
    try:
        with path.open(
            "r",
            encoding="utf-8-sig",
        ) as file:
            return json.load(file)
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"Required JSON file was not found: {path}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in {path}: {exc}"
        ) from exc


def load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML object from disk."""
    try:
        with path.open(
            "r",
            encoding="utf-8-sig",
        ) as file:
            value = yaml.safe_load(file)
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"Required YAML file was not found: {path}"
        ) from exc
    except yaml.YAMLError as exc:
        raise RiskConfigurationError(
            f"Invalid YAML in {path}: {exc}"
        ) from exc

    if not isinstance(value, dict):
        raise RiskConfigurationError(
            f"YAML root must be an object: {path}"
        )

    return value


def atomic_write_json(
    path: Path,
    value: Any,
) -> None:
    """Write JSON through a temporary file to avoid partial output."""
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
    ) as file:
        json.dump(
            value,
            file,
            indent=4,
            ensure_ascii=False,
        )

    temporary.replace(path)


def normalize_wazuh_input(
    value: Any,
) -> list[dict[str, Any]]:
    """Support hit lists, OpenSearch responses, or an events object."""
    if isinstance(value, list):
        return [
            event
            for event in value
            if isinstance(event, dict)
        ]

    if isinstance(value, dict):
        hits = value.get("hits")

        if (
            isinstance(hits, dict)
            and isinstance(
                hits.get("hits"),
                list,
            )
        ):
            return [
                event
                for event in hits["hits"]
                if isinstance(event, dict)
            ]

        events = value.get("events")

        if isinstance(events, list):
            return [
                event
                for event in events
                if isinstance(event, dict)
            ]

        return [value]

    return []


def normalize_zeek_input(
    value: Any,
) -> list[dict[str, Any]]:
    """Support a Zeek event list or an object containing events."""
    if isinstance(value, list):
        return [
            event
            for event in value
            if isinstance(event, dict)
        ]

    if isinstance(value, dict):
        events = value.get("events")

        if isinstance(events, list):
            return [
                event
                for event in events
                if isinstance(event, dict)
            ]

        return [value]

    return []


class ContextualRiskEngine:
    """Combine asset, policy, behaviour, Wazuh, and correlation evidence."""

    def __init__(
        self,
        asset_resolver: AssetResolver,
        policy_engine: PolicyEngine,
        behavior_analyzer: BehaviorAnalyzer,
        risk_rules: dict[str, Any],
        environment_id: str = "legacy",
        environment: dict[str, Any] | None = None,
    ) -> None:
        self.asset_resolver = asset_resolver
        self.policy_engine = policy_engine
        self.behavior_analyzer = behavior_analyzer
        self.risk_rules = risk_rules

        self.environment_id = str(
            environment_id or "legacy"
        )

        self.environment = (
            dict(environment)
            if isinstance(environment, dict)
            else {}
        )

        self.classification_rules = (
            risk_rules.get(
                "classification",
                {},
            )
        )

        self.limits = risk_rules.get(
            "limits",
            {},
        )

        self.asset_rules = risk_rules.get(
            "asset_scoring",
            {},
        )

        self.wazuh_rules = risk_rules.get(
            "wazuh",
            {},
        )

        self.correlation_rules = risk_rules.get(
            "correlation",
            {},
        )

        self.working_hours = risk_rules.get(
            "working_hours",
            {},
        )

        self._validate_configuration()
        self.local_timezone = self._load_timezone()

    @classmethod
    def from_files(
        cls,
        asset_context_file: str | Path = ASSET_CONTEXT_FILE,
        role_policies_file: str | Path = ROLE_POLICIES_FILE,
        risk_rules_file: str | Path = RISK_RULES_FILE,
    ) -> "ContextualRiskEngine":
        """
        Build an engine from the original single-environment files.

        This method remains available during migration and for older tests.
        """
        risk_rules_path = Path(
            risk_rules_file
        )

        risk_rules = load_yaml(
            risk_rules_path
        )

        return cls(
            asset_resolver=(
                AssetResolver.from_file(
                    asset_context_file
                )
            ),
            policy_engine=(
                PolicyEngine.from_file(
                    role_policies_file
                )
            ),
            behavior_analyzer=BehaviorAnalyzer(
                risk_rules=risk_rules,
            ),
            risk_rules=risk_rules,
            environment_id="legacy",
            environment={
                "id": "legacy",
                "name": "Legacy single environment",
                "site_id": "legacy",
                "environment_type": "legacy",
                "infrastructure_type": "unknown",
            },
        )

    @classmethod
    def from_environment(
        cls,
        environment_id: str,
        config_root: str | Path = CONFIG_ROOT,
    ) -> "ContextualRiskEngine":
        """
        Build an engine for a selected hospital environment.

        Common scoring and policy files are loaded from config/base. Hospital
        asset and network details are loaded from
        config/environments/<environment-id>.
        """
        registry = EnvironmentRegistry(
            config_root
        )

        configuration = registry.load(
            environment_id
        )

        risk_rules = dict(
            configuration["risk_rules"]
        )

        environment = dict(
            configuration.get(
                "environment",
                {},
            )
        )

        business_hours = configuration.get(
            "business_hours",
            {},
        )

        working_hours = dict(
            risk_rules.get(
                "working_hours",
                {},
            )
        )

        timezone_name = environment.get(
            "timezone"
        )

        if timezone_name:
            working_hours["timezone"] = (
                timezone_name
            )

        start_time = str(
            business_hours.get(
                "start",
                "",
            )
        )

        end_time = str(
            business_hours.get(
                "end",
                "",
            )
        )

        if ":" in start_time:
            try:
                working_hours["start_hour"] = int(
                    start_time.split(
                        ":",
                        1,
                    )[0]
                )
            except ValueError:
                LOGGER.warning(
                    "Invalid business-hours start value: %s",
                    start_time,
                )

        if ":" in end_time:
            try:
                working_hours["end_hour"] = int(
                    end_time.split(
                        ":",
                        1,
                    )[0]
                )
            except ValueError:
                LOGGER.warning(
                    "Invalid business-hours end value: %s",
                    end_time,
                )

        risk_rules["working_hours"] = (
            working_hours
        )

        return cls(
            asset_resolver=(
                AssetResolver
                .from_environment_configuration(
                    configuration
                )
            ),
            policy_engine=PolicyEngine.from_file(
                configuration["paths"][
                    "role_policies_file"
                ]
            ),
            behavior_analyzer=BehaviorAnalyzer(
                risk_rules=risk_rules,
            ),
            risk_rules=risk_rules,
            environment_id=environment_id,
            environment=environment,
        )

    def _environment_fields(
        self,
    ) -> dict[str, Any]:
        """Return environment metadata included in every result."""
        return {
            "environment_id": (
                self.environment_id
            ),
            "environment_name": (
                self.environment.get(
                    "name",
                    self.environment_id,
                )
            ),
            "site_id": (
                self.environment.get(
                    "site_id",
                    "unknown",
                )
            ),
            "environment_type": (
                self.environment.get(
                    "environment_type",
                    "unknown",
                )
            ),
            "infrastructure_type": (
                self.environment.get(
                    "infrastructure_type",
                    "unknown",
                )
            ),
        }


    def _validate_input_environments(
        self,
        events: list[dict[str, Any]],
        source_name: str,
    ) -> None:
        """
        Reject telemetry explicitly tagged for another environment.

        Untagged events remain accepted temporarily for backwards
        compatibility. The Wazuh collector and Zeek parser generated in this
        step tag all newly collected events.
        """
        mismatched: set[str] = set()

        for event in events:
            event_environment = (
                get_event_environment(
                    event
                )
            )

            if event_environment is None:
                continue

            if (
                event_environment
                != self.environment_id
            ):
                mismatched.add(
                    event_environment
                )

        if mismatched:
            environments = ", ".join(
                sorted(mismatched)
            )

            raise ValueError(
                f"{source_name} input contains event(s) from "
                f"environment(s) {environments}, but the "
                f"selected environment is "
                f"{self.environment_id}."
            )

    def _validate_configuration(
        self,
    ) -> None:
        """Validate required scoring configuration sections."""
        required_sections = (
            "classification",
            "limits",
            "asset_scoring",
            "behavior",
            "wazuh",
            "correlation",
        )

        for section_name in required_sections:
            if not isinstance(
                self.risk_rules.get(
                    section_name
                ),
                dict,
            ):
                raise RiskConfigurationError(
                    f"risk_rules.{section_name} "
                    "must be an object"
                )

        required_classification_fields = (
            "legitimate_max",
            "low_suspicion_max",
            "suspicious_max",
        )

        for field in required_classification_fields:
            if field not in self.classification_rules:
                raise RiskConfigurationError(
                    f"classification.{field} "
                    "is required"
                )

    def _load_timezone(
        self,
    ) -> ZoneInfo:
        """Load the configured timezone, falling back to UTC."""
        timezone_name = str(
            self.working_hours.get(
                "timezone",
                "UTC",
            )
        )

        try:
            return ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError:
            LOGGER.warning(
                "Timezone %s is unavailable. "
                "Falling back to UTC.",
                timezone_name,
            )

            return timezone.utc

    def classify(
        self,
        score: int,
    ) -> str:
        """Convert a risk score into a configured classification."""
        normalised = max(
            0,
            safe_int(score),
        )

        if normalised <= safe_int(
            self.classification_rules[
                "legitimate_max"
            ]
        ):
            return "Legitimate"

        if normalised <= safe_int(
            self.classification_rules[
                "low_suspicion_max"
            ]
        ):
            return "Low Suspicion"

        if normalised <= safe_int(
            self.classification_rules[
                "suspicious_max"
            ]
        ):
            return "Suspicious"

        return "Likely Malicious"

    def _is_off_hours(
        self,
        timestamp: Any,
    ) -> bool:
        """Return True when an event is outside configured working hours."""
        event_time = parse_timestamp(
            timestamp
        )

        if event_time is None:
            return False

        local_time = event_time.astimezone(
            self.local_timezone
        )

        start_hour = safe_int(
            self.working_hours.get(
                "start_hour"
            ),
            8,
        )

        end_hour = safe_int(
            self.working_hours.get(
                "end_hour"
            ),
            18,
        )

        return (
            local_time.hour < start_hour
            or local_time.hour >= end_hour
        )

    def _deduplicate(
        self,
        events: Iterable[dict[str, Any]],
        timestamp_field: str = "timestamp",
    ) -> list[dict[str, Any]]:
        """Deduplicate by deterministic event ID."""
        unique: dict[
            str,
            dict[str, Any],
        ] = {}

        for event in events:
            event_id = str(
                event.get("event_id") or ""
            ).strip()

            if event_id:
                unique[event_id] = event

        return sorted(
            unique.values(),
            key=lambda event: (
                parse_timestamp(
                    event.get(timestamp_field)
                )
                or datetime.min.replace(
                    tzinfo=timezone.utc
                ),
                event["event_id"],
            ),
        )

    def _normalize_wazuh_event(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        """Convert Wazuh/OpenSearch data to a common event structure."""
        source = event.get(
            "_source",
            event,
        )

        if not isinstance(source, dict):
            source = {}

        agent = (
            source.get("agent")
            if isinstance(
                source.get("agent"),
                dict,
            )
            else {}
        )

        rule = (
            source.get("rule")
            if isinstance(
                source.get("rule"),
                dict,
            )
            else {}
        )

        data = (
            source.get("data")
            if isinstance(
                source.get("data"),
                dict,
            )
            else {}
        )

        predecoder = (
            source.get("predecoder")
            if isinstance(
                source.get("predecoder"),
                dict,
            )
            else {}
        )

        timestamp = format_timestamp(
            source.get("timestamp")
            or source.get("@timestamp")
        )

        agent_ip = str(
            agent.get("ip")
            or source.get("agent_ip")
            or source.get("ip")
            or "unknown"
        ).strip()

        hostname = str(
            agent.get("name")
            or source.get("host")
            or "unknown"
        ).strip()

        rule_id = str(
            rule.get("id")
            or source.get("rule_id")
            or ""
        ).strip()

        rule_level = safe_int(
            rule.get("level")
            or source.get("rule_level")
        )

        description = str(
            rule.get("description")
            or source.get("description")
            or ""
        )

        full_log = str(
            source.get("full_log") or ""
        )

        program_name = str(
            predecoder.get("program_name")
            or source.get("program_name")
            or ""
        )

        groups = (
            rule.get("groups")
            if isinstance(
                rule.get("groups"),
                list,
            )
            else []
        )

        raw_event_id = str(
            event.get("_id")
            or source.get("event_id")
            or ""
        ).strip()

        if raw_event_id:
            event_id = (
                f"wazuh:{raw_event_id}"
            )
        else:
            event_id = stable_hash(
                "wazuh",
                {
                    "timestamp": timestamp,
                    "agent_ip": agent_ip,
                    "hostname": hostname,
                    "rule_id": rule_id,
                    "description": description,
                    "full_log": full_log,
                    "program_name": program_name,
                    "data": data,
                },
            )

        asset_context = (
            self.asset_resolver.resolve(
                ip_value=agent_ip,
                hostname=hostname,
            )
        )

        return {
            **self._environment_fields(),
            "event_id": event_id,
            "event_source": "wazuh",
            "event_type": "host_activity",
            "timestamp": timestamp,
            "host": hostname,
            "ip": agent_ip,
            "role": asset_context.get(
                "role",
                "unknown",
            ),
            "zone": asset_context.get(
                "zone",
                "unknown",
            ),
            "trust_level": asset_context.get(
                "trust_level",
                "unknown",
            ),
            "sensitivity": asset_context.get(
                "sensitivity",
                "unknown",
            ),
            "trusted": bool(
                asset_context.get(
                    "trusted",
                    False,
                )
            ),
            "resolution_source": (
                asset_context.get(
                    "resolution_source",
                    "unknown",
                )
            ),
            "rule_id": rule_id,
            "rule_level": rule_level,
            "rule_groups": groups,
            "description": description,
            "program_name": program_name,
            "full_log": full_log,
            "data": data,
            "asset_context": asset_context,
        }

    def _score_wazuh_event(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        """Calculate the host-event contribution from a Wazuh alert."""
        reasons: list[str] = []
        indicator_codes: list[str] = []

        rule_level_score = 0
        indicator_score = 0
        context_score = 0

        level = safe_int(
            event.get("rule_level")
        )

        level_rules = self.wazuh_rules.get(
            "rule_level",
            {},
        )

        if level >= safe_int(
            level_rules.get(
                "critical_minimum"
            ),
            12,
        ):
            rule_level_score = safe_int(
                level_rules.get(
                    "critical_points"
                ),
                7,
            )

            reasons.append(
                "Critical Wazuh rule level "
                f"detected ({level})"
            )

        elif level >= safe_int(
            level_rules.get(
                "high_minimum"
            ),
            8,
        ):
            rule_level_score = safe_int(
                level_rules.get(
                    "high_points"
                ),
                4,
            )

            reasons.append(
                "High Wazuh rule level "
                f"detected ({level})"
            )

        elif level >= safe_int(
            level_rules.get(
                "medium_minimum"
            ),
            5,
        ):
            rule_level_score = safe_int(
                level_rules.get(
                    "medium_points"
                ),
                2,
            )

            reasons.append(
                "Medium Wazuh rule level "
                f"detected ({level})"
            )

        combined_text = " ".join(
            [
                str(
                    event.get(
                        "description"
                    )
                    or ""
                ),
                str(
                    event.get(
                        "full_log"
                    )
                    or ""
                ),
                str(
                    event.get(
                        "program_name"
                    )
                    or ""
                ),
                " ".join(
                    str(value)
                    for value in event.get(
                        "rule_groups",
                        [],
                    )
                ),
                json.dumps(
                    event.get(
                        "data",
                        {},
                    ),
                    ensure_ascii=False,
                    default=str,
                ),
            ]
        ).lower()

        indicators = self.wazuh_rules.get(
            "indicators",
            {},
        )

        for (
            indicator_name,
            configuration,
        ) in indicators.items():
            if not isinstance(
                configuration,
                dict,
            ):
                continue

            phrases = [
                str(phrase).strip().lower()
                for phrase in configuration.get(
                    "phrases",
                    [],
                )
                if str(phrase).strip()
            ]

            if not phrases:
                continue

            if any(
                phrase in combined_text
                for phrase in phrases
            ):
                points = safe_int(
                    configuration.get(
                        "points"
                    )
                )

                indicator_score += points
                indicator_codes.append(
                    str(indicator_name)
                )

                readable_name = (
                    str(indicator_name)
                    .replace("_", " ")
                )

                reasons.append(
                    "Wazuh indicator detected: "
                    f"{readable_name}"
                )

        if self._is_off_hours(
            event.get("timestamp")
        ):
            context_score += safe_int(
                self.wazuh_rules.get(
                    "off_hours_points"
                ),
                2,
            )

            reasons.append(
                "Wazuh activity occurred outside "
                "configured working hours"
            )

        if event.get("trusted") is True:
            reduction = safe_int(
                self.wazuh_rules.get(
                    "trusted_admin_reduction"
                ),
                -2,
            )

            context_score += reduction

            reasons.append(
                "Trusted administrator or monitoring "
                "context reduced risk"
            )

        maximum = safe_int(
            self.limits.get(
                "max_wazuh_score"
            ),
            20,
        )

        total = clamp(
            (
                rule_level_score
                + indicator_score
                + context_score
            ),
            0,
            maximum,
        )

        return {
            **event,
            "rule_level_score": (
                rule_level_score
            ),
            "indicator_score": (
                indicator_score
            ),
            "context_score": (
                context_score
            ),
            "wazuh_score": total,
            "risk_score": total,
            "classification": (
                self.classify(total)
            ),
            "indicator_codes": (
                unique_strings(
                    indicator_codes
                )
            ),
            "reasons": unique_strings(
                reasons
            ),
        }

    def _normalize_zeek_event(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        """Convert a Zeek connection event and enrich both endpoints."""
        normalized = (
            BehaviorAnalyzer.normalize_event(
                event
            )
        )

        if not normalized.get(
            "event_id"
        ):
            uid = str(
                normalized.get("uid")
                or event.get("uid")
                or ""
            ).strip()

            normalized["event_id"] = (
                f"zeek:{uid}"
                if uid
                else stable_hash(
                    "zeek",
                    normalized,
                )
            )

        source_context = (
            self.asset_resolver.resolve(
                normalized["source_ip"]
            )
        )

        destination_context = (
            self.asset_resolver.resolve(
                normalized[
                    "destination_ip"
                ]
            )
        )

        normalized.update(
            {
                **self._environment_fields(),
                "event_source": "zeek",
                "event_type": (
                    "network_connection"
                ),
                "source_host": (
                    source_context.get(
                        "hostname",
                        "unknown",
                    )
                ),
                "source_role": (
                    source_context.get(
                        "role",
                        "unknown",
                    )
                ),
                "source_zone": (
                    source_context.get(
                        "zone",
                        "unknown",
                    )
                ),
                "source_trust_level": (
                    source_context.get(
                        "trust_level",
                        "unknown",
                    )
                ),
                "source_resolution_source": (
                    source_context.get(
                        "resolution_source",
                        "unknown",
                    )
                ),
                "destination_host": (
                    destination_context.get(
                        "hostname",
                        "unknown",
                    )
                ),
                "destination_role": (
                    destination_context.get(
                        "role",
                        "unknown",
                    )
                ),
                "destination_zone": (
                    destination_context.get(
                        "zone",
                        "unknown",
                    )
                ),
                "destination_trust_level": (
                    destination_context.get(
                        "trust_level",
                        "unknown",
                    )
                ),
                "destination_sensitivity": (
                    destination_context.get(
                        "sensitivity",
                        "unknown",
                    )
                ),
                "destination_criticality": (
                    destination_context.get(
                        "criticality",
                        "unknown",
                    )
                ),
                "destination_is_critical": bool(
                    destination_context.get(
                        "is_critical",
                        False,
                    )
                ),
                "source_context": (
                    source_context
                ),
                "destination_context": (
                    destination_context
                ),
            }
        )

        policy_result = (
            self.policy_engine.evaluate(
                source_context=source_context,
                destination_context=(
                    destination_context
                ),
                destination_port=(
                    normalized[
                        "destination_port"
                    ]
                ),
                protocol=normalized[
                    "protocol"
                ],
                service=normalized[
                    "service"
                ],
            )
        )

        normalized[
            "policy_result"
        ] = policy_result

        # Internal timestamp helper is useful during behaviour analysis but
        # must not be written to JSON output.
        normalized.pop(
            "_parsed_timestamp",
            None,
        )

        return normalized

    def _score_asset_context(
        self,
        event: dict[str, Any],
    ) -> tuple[
        int,
        list[str],
        dict[str, int],
    ]:
        """Calculate destination and source-context risk."""
        reasons: list[str] = []
        breakdown: dict[str, int] = {}

        sensitivity = str(
            event.get(
                "destination_sensitivity"
            )
            or "unknown"
        ).lower()

        destination_role = str(
            event.get(
                "destination_role"
            )
            or "unknown"
        ).lower()

        source_trust_level = str(
            event.get(
                "source_trust_level"
            )
            or "unknown"
        ).lower()

        source_role = str(
            event.get(
                "source_role"
            )
            or "unknown"
        ).lower()

        sensitivity_points = safe_int(
            self.asset_rules.get(
                "sensitivity",
                {},
            ).get(
                sensitivity,
                0,
            )
        )

        destination_role_points = safe_int(
            self.asset_rules.get(
                "destination_role",
                {},
            ).get(
                destination_role,
                0,
            )
        )

        source_trust_points = safe_int(
            self.asset_rules.get(
                "trust_level",
                {},
            ).get(
                source_trust_level,
                0,
            )
        )

        breakdown[
            "destination_sensitivity"
        ] = sensitivity_points

        breakdown[
            "destination_role"
        ] = destination_role_points

        breakdown[
            "source_trust_level"
        ] = source_trust_points

        if sensitivity_points:
            reasons.append(
                "Destination sensitivity is "
                f"{sensitivity}"
            )

        if destination_role_points:
            reasons.append(
                "Protected destination role: "
                f"{destination_role}"
            )

        if source_trust_points > 0:
            reasons.append(
                "Source trust level is "
                f"{source_trust_level}"
            )

        elif source_trust_points < 0:
            reasons.append(
                "Trusted source context "
                "reduced asset risk"
            )

        external_internal_points = 0

        destination_context = event.get(
            "destination_context",
            {},
        )

        if (
            source_role == "external"
            and isinstance(
                destination_context,
                dict,
            )
            and bool(
                destination_context.get(
                    "is_internal"
                )
            )
        ):
            external_internal_points = (
                safe_int(
                    self.asset_rules.get(
                        "external_source_to_"
                        "internal_destination"
                    ),
                    4,
                )
            )

            reasons.append(
                "External source communicated "
                "with an internal destination"
            )

        breakdown[
            "external_source_to_"
            "internal_destination"
        ] = external_internal_points

        unknown_critical_points = 0

        if (
            source_role
            in {
                "unknown",
                "internal_unknown",
            }
            and event.get(
                "destination_is_critical"
            )
            is True
        ):
            unknown_critical_points = (
                safe_int(
                    self.asset_rules.get(
                        "unknown_source_to_"
                        "critical_destination"
                    ),
                    3,
                )
            )

            reasons.append(
                "Unknown source communicated "
                "with a critical destination"
            )

        breakdown[
            "unknown_source_to_"
            "critical_destination"
        ] = unknown_critical_points

        maximum = safe_int(
            self.limits.get(
                "max_asset_score"
            ),
            10,
        )

        total = clamp(
            sum(breakdown.values()),
            0,
            maximum,
        )

        return (
            total,
            unique_strings(reasons),
            breakdown,
        )

    def _score_network_event(
        self,
        event: dict[str, Any],
        behavior_result: dict[str, Any],
    ) -> dict[str, Any]:
        """Combine asset, policy, and behaviour scores for one connection."""
        (
            asset_score,
            asset_reasons,
            asset_breakdown,
        ) = self._score_asset_context(
            event
        )

        policy_result = event.get(
            "policy_result",
            {},
        )

        raw_policy_score = safe_int(
            policy_result.get(
                "risk_points"
            )
        )

        maximum_policy_score = safe_int(
            self.limits.get(
                "max_policy_score"
            ),
            15,
        )

        policy_score = clamp(
            raw_policy_score,
            -maximum_policy_score,
            maximum_policy_score,
        )

        behavior_score = safe_int(
            behavior_result.get(
                "behavior_score"
            )
        )

        maximum_behavior_score = safe_int(
            self.limits.get(
                "max_behavior_score"
            ),
            20,
        )

        behavior_score = clamp(
            behavior_score,
            0,
            maximum_behavior_score,
        )

        reasons = list(
            asset_reasons
        )

        policy_reason = str(
            policy_result.get(
                "reason"
            )
            or ""
        ).strip()

        if policy_reason:
            reasons.append(
                policy_reason
            )

        reasons.extend(
            behavior_result.get(
                "behavior_reasons",
                [],
            )
        )

        maximum_total = safe_int(
            self.limits.get(
                "max_total_score"
            ),
            30,
        )

        total = clamp(
            (
                asset_score
                + policy_score
                + behavior_score
            ),
            0,
            maximum_total,
        )

        clean_event = {
            key: value
            for key, value in event.items()
            if not str(key).startswith("_")
        }

        return {
            **clean_event,
            "correlated": False,
            "asset_score": asset_score,
            "asset_score_breakdown": (
                asset_breakdown
            ),
            "policy_score": policy_score,
            "policy_name": (
                policy_result.get(
                    "policy_name",
                    "default_policy",
                )
            ),
            "policy_action": (
                policy_result.get(
                    "action",
                    "observe",
                )
            ),
            "policy_matched": bool(
                policy_result.get(
                    "matched",
                    False,
                )
            ),
            "policy_priority": (
                policy_result.get(
                    "policy_priority"
                )
            ),
            "behavior_score": (
                behavior_score
            ),
            "behavior_metrics": (
                behavior_result.get(
                    "behavior_metrics",
                    {},
                )
            ),
            "wazuh_score": 0,
            "correlation_score": 0,
            "risk_score": total,
            "classification": (
                self.classify(total)
            ),
            "reasons": unique_strings(
                reasons
            ),
        }

    def _correlate_network_events(
        self,
        network_results: list[
            dict[str, Any]
        ],
        wazuh_results: list[
            dict[str, Any]
        ],
    ) -> list[dict[str, Any]]:
        """Correlate Wazuh host evidence with nearby Zeek connections."""
        window_minutes = safe_float(
            self.correlation_rules.get(
                "window_minutes"
            ),
            5.0,
        )

        minimum_wazuh_score = safe_int(
            self.correlation_rules.get(
                "minimum_wazuh_score"
            ),
            1,
        )

        maximum_wazuh_contribution = (
            safe_int(
                self.correlation_rules.get(
                    "max_wazuh_contribution"
                ),
                8,
            )
        )

        maximum_correlation_score = (
            safe_int(
                self.limits.get(
                    "max_correlation_score"
                ),
                15,
            )
        )

        maximum_total = safe_int(
            self.limits.get(
                "max_total_score"
            ),
            30,
        )

        correlated_results: list[
            dict[str, Any]
        ] = []

        for network_event in network_results:
            network_time = parse_timestamp(
                network_event.get(
                    "timestamp"
                )
            )

            if network_time is None:
                continue

            source_ip = str(
                network_event.get(
                    "source_ip"
                )
                or ""
            )

            destination_ip = str(
                network_event.get(
                    "destination_ip"
                )
                or ""
            )

            matches: list[
                dict[str, Any]
            ] = []

            for wazuh_event in wazuh_results:
                if safe_int(
                    wazuh_event.get(
                        "risk_score"
                    )
                ) < minimum_wazuh_score:
                    continue

                wazuh_ip = str(
                    wazuh_event.get(
                        "ip"
                    )
                    or ""
                )

                if wazuh_ip not in {
                    source_ip,
                    destination_ip,
                }:
                    continue

                wazuh_time = parse_timestamp(
                    wazuh_event.get(
                        "timestamp"
                    )
                )

                if wazuh_time is None:
                    continue

                difference = abs(
                    (
                        network_time
                        - wazuh_time
                    ).total_seconds()
                ) / 60.0

                if difference > window_minutes:
                    continue

                matches.append(
                    {
                        **wazuh_event,
                        "_time_difference_"
                        "minutes": (
                            difference
                        ),
                        "_matched_side": (
                            "source"
                            if wazuh_ip
                            == source_ip
                            else "destination"
                        ),
                    }
                )

            if not matches:
                continue

            matches.sort(
                key=lambda matched: (
                    -safe_int(
                        matched.get(
                            "risk_score"
                        )
                    ),
                    safe_float(
                        matched.get(
                            "_time_difference_"
                            "minutes"
                        )
                    ),
                    str(
                        matched.get(
                            "event_id"
                        )
                        or ""
                    ),
                )
            )

            strongest = matches[0]

            wazuh_contribution = min(
                safe_int(
                    strongest.get(
                        "risk_score"
                    )
                ),
                maximum_wazuh_contribution,
            )

            correlation_score = safe_int(
                self.correlation_rules.get(
                    "base_points"
                ),
                2,
            )

            correlation_reasons = [
                (
                    f"{len(matches)} Wazuh event(s) "
                    f"were aggregated within "
                    f"{window_minutes:g} minutes"
                )
            ]

            indicator_codes = {
                code
                for match in matches
                for code in match.get(
                    "indicator_codes",
                    [],
                )
            }

            destination_role = str(
                network_event.get(
                    "destination_role"
                )
                or ""
            ).lower()

            destination_port = safe_int(
                network_event.get(
                    "destination_port"
                )
            )

            service = str(
                network_event.get(
                    "service"
                )
                or ""
            ).lower()

            if (
                "privilege_activity"
                in indicator_codes
                and (
                    destination_role
                    == "database"
                    or destination_port
                    in {
                        5432,
                        3306,
                        1433,
                        1521,
                    }
                )
            ):
                points = safe_int(
                    self.correlation_rules.get(
                        "privilege_and_"
                        "database_access",
                        {},
                    ).get(
                        "points"
                    ),
                    5,
                )

                correlation_score += points

                correlation_reasons.append(
                    "Privilege activity correlated "
                    "with database access"
                )

            if (
                "privilege_activity"
                in indicator_codes
                and (
                    destination_port == 445
                    or "smb" in service
                )
            ):
                points = safe_int(
                    self.correlation_rules.get(
                        "privilege_and_"
                        "smb_activity",
                        {},
                    ).get(
                        "points"
                    ),
                    4,
                )

                correlation_score += points

                correlation_reasons.append(
                    "Privilege activity correlated "
                    "with SMB activity"
                )

            failed_authentication_config = (
                self.correlation_rules.get(
                    "failed_authentication_"
                    "and_remote_service",
                    {},
                )
            )

            remote_ports = {
                safe_int(port)
                for port
                in failed_authentication_config.get(
                    "remote_ports",
                    [],
                )
            }

            if (
                "failed_authentication"
                in indicator_codes
                and destination_port
                in remote_ports
            ):
                points = safe_int(
                    failed_authentication_config.get(
                        "points"
                    ),
                    4,
                )

                correlation_score += points

                correlation_reasons.append(
                    "Failed authentication correlated "
                    "with remote-service traffic"
                )

            if (
                "malware_indicator"
                in indicator_codes
                and (
                    destination_port == 445
                    or "smb" in service
                )
            ):
                points = safe_int(
                    self.correlation_rules.get(
                        "malware_and_"
                        "smb_activity",
                        {},
                    ).get(
                        "points"
                    ),
                    7,
                )

                correlation_score += points

                correlation_reasons.append(
                    "Malware indicator correlated "
                    "with SMB activity"
                )

            correlation_score = clamp(
                correlation_score,
                0,
                maximum_correlation_score,
            )

            total = clamp(
                (
                    safe_int(
                        network_event.get(
                            "risk_score"
                        )
                    )
                    + wazuh_contribution
                    + correlation_score
                ),
                0,
                maximum_total,
            )

            matched_event_ids = sorted(
                {
                    str(
                        match.get(
                            "event_id"
                        )
                    )
                    for match in matches
                    if match.get(
                        "event_id"
                    )
                }
            )

            matched_rule_ids = sorted(
                {
                    str(
                        match.get(
                            "rule_id"
                        )
                    )
                    for match in matches
                    if match.get(
                        "rule_id"
                    )
                }
            )

            matched_host_sides = sorted(
                {
                    str(
                        match.get(
                            "_matched_side"
                        )
                    )
                    for match in matches
                }
            )

            all_wazuh_reasons = unique_strings(
                reason
                for match in matches
                for reason in match.get(
                    "reasons",
                    [],
                )
            )

            correlated_results.append(
                {
                    **network_event,
                    # Keep the Zeek event ID so the publisher can replace the
                    # standalone network result rather than create a duplicate.
                    "event_id": (
                        network_event[
                            "event_id"
                        ]
                    ),
                    "zeek_event_id": (
                        network_event[
                            "event_id"
                        ]
                    ),
                    "event_source": (
                        "zeek+wazuh"
                    ),
                    "event_type": (
                        "correlated_"
                        "network_activity"
                    ),
                    "correlated": True,
                    "wazuh_score": (
                        wazuh_contribution
                    ),
                    "strongest_wazuh_"
                    "raw_score": safe_int(
                        strongest.get(
                            "risk_score"
                        )
                    ),
                    "correlation_score": (
                        correlation_score
                    ),
                    "risk_score": total,
                    "classification": (
                        self.classify(total)
                    ),
                    "matched_wazuh_count": (
                        len(matches)
                    ),
                    "matched_wazuh_"
                    "event_ids": (
                        matched_event_ids
                    ),
                    "matched_wazuh_"
                    "rule_ids": (
                        matched_rule_ids
                    ),
                    "matched_host_sides": (
                        matched_host_sides
                    ),
                    "strongest_wazuh_"
                    "event_id": (
                        strongest.get(
                            "event_id"
                        )
                    ),
                    "time_difference_"
                    "minutes": round(
                        min(
                            safe_float(
                                match.get(
                                    "_time_difference_"
                                    "minutes"
                                )
                            )
                            for match in matches
                        ),
                        3,
                    ),
                    "reasons": unique_strings(
                        list(
                            network_event.get(
                                "reasons",
                                [],
                            )
                        )
                        + all_wazuh_reasons
                        + correlation_reasons
                    ),
                }
            )

        return self._deduplicate(
            correlated_results
        )

    def build_output(
        self,
        wazuh_data: Any,
        zeek_data: Any,
    ) -> dict[str, Any]:
        """Score and correlate all supplied Wazuh and Zeek events."""
        raw_wazuh_events = (
            normalize_wazuh_input(
                wazuh_data
            )
        )

        raw_zeek_events = (
            normalize_zeek_input(
                zeek_data
            )
        )

        self._validate_input_environments(
            raw_wazuh_events,
            "Wazuh",
        )

        self._validate_input_environments(
            raw_zeek_events,
            "Zeek",
        )

        normalised_wazuh = [
            self._normalize_wazuh_event(
                event
            )
            for event
            in raw_wazuh_events
        ]

        normalised_wazuh = (
            self._deduplicate(
                normalised_wazuh
            )
        )

        wazuh_results = [
            self._score_wazuh_event(
                event
            )
            for event
            in normalised_wazuh
        ]

        normalised_zeek = [
            self._normalize_zeek_event(
                event
            )
            for event
            in raw_zeek_events
        ]

        normalised_zeek = (
            self._deduplicate(
                normalised_zeek
            )
        )

        behavior_results = (
            self.behavior_analyzer.analyze(
                normalised_zeek
            )
        )

        zeek_results = [
            self._score_network_event(
                event=event,
                behavior_result=(
                    behavior_results.get(
                        event["event_id"],
                        {
                            "behavior_score": 0,
                            "behavior_reasons": [],
                            "behavior_metrics": {},
                        },
                    )
                ),
            )
            for event in normalised_zeek
        ]

        correlated_results = (
            self._correlate_network_events(
                network_results=(
                    zeek_results
                ),
                wazuh_results=(
                    wazuh_results
                ),
            )
        )

        classification_counts: dict[
            str,
            int,
        ] = {}

        final_network_by_id = {
            event["event_id"]: event
            for event in zeek_results
        }

        final_network_by_id.update(
            {
                event["event_id"]: event
                for event
                in correlated_results
            }
        )

        for event in (
            list(wazuh_results)
            + list(
                final_network_by_id.values()
            )
        ):
            classification = str(
                event.get(
                    "classification"
                )
                or "Unknown"
            )

            classification_counts[
                classification
            ] = (
                classification_counts.get(
                    classification,
                    0,
                )
                + 1
            )

        return {
            "environment": (
                self._environment_fields()
            ),
            "generated_at": (
                datetime.now(
                    timezone.utc
                )
                .isoformat(
                    timespec="seconds"
                )
                .replace(
                    "+00:00",
                    "Z",
                )
            ),
            "wazuh_results": (
                wazuh_results
            ),
            "zeek_results": (
                zeek_results
            ),
            "correlated_results": (
                correlated_results
            ),
            "summary": {
                "raw_wazuh_event_count": len(
                    raw_wazuh_events
                ),
                "raw_zeek_event_count": len(
                    raw_zeek_events
                ),
                "unique_wazuh_"
                "result_count": len(
                    wazuh_results
                ),
                "unique_zeek_"
                "result_count": len(
                    zeek_results
                ),
                "correlated_result_count": len(
                    correlated_results
                ),
                "final_document_count": (
                    len(wazuh_results)
                    + len(
                        final_network_by_id
                    )
                ),
                "classification_counts": (
                    classification_counts
                ),
            },
        }


def main() -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(
        description=(
            "Run contextual risk analysis for "
            "a selected hospital environment"
        )
    )

    parser.add_argument(
        "--environment",
        default=os.environ.get(
            "ENVIRONMENT_ID",
            DEFAULT_ENVIRONMENT_ID,
        ),
        help=(
            "Environment ID under "
            "config/environments"
        ),
    )

    parser.add_argument(
        "--config-root",
        default=str(
            CONFIG_ROOT
        ),
        help=(
            "Root configuration directory"
        ),
    )

    parser.add_argument(
        "--wazuh-input",
        default=None,
        help=(
            "Optional Wazuh input file. By default, "
            "data/<environment-id>/live_wazuh_events.json "
            "is used."
        ),
    )

    parser.add_argument(
        "--zeek-input",
        default=None,
        help=(
            "Optional Zeek input file. By default, "
            "data/<environment-id>/live_zeek_conn.json "
            "is used."
        ),
    )

    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Optional output file. By default, "
            "output/<environment-id>/scored_events.json "
            "is used."
        ),
    )

    args = parser.parse_args()

    environment_paths = EnvironmentPaths(
        project_root=PROJECT_ROOT,
        environment_id=args.environment,
    )

    environment_paths.ensure_directories()

    wazuh_input_path = (
        Path(args.wazuh_input).resolve()
        if args.wazuh_input
        else environment_paths.wazuh_events_file
    )

    zeek_input_path = (
        Path(args.zeek_input).resolve()
        if args.zeek_input
        else environment_paths.zeek_conn_json_file
    )

    output_path = (
        Path(args.output).resolve()
        if args.output
        else environment_paths.scored_events_file
    )

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s %(levelname)s "
            "%(name)s: %(message)s"
        ),
    )

    engine = (
        ContextualRiskEngine
        .from_environment(
            environment_id=(
                args.environment
            ),
            config_root=(
                args.config_root
            ),
        )
    )

    wazuh_data = load_json(
        wazuh_input_path
    )

    zeek_data = load_json(
        zeek_input_path
    )

    output = engine.build_output(
        wazuh_data=wazuh_data,
        zeek_data=zeek_data,
    )

    atomic_write_json(
        output_path,
        output,
    )

    LOGGER.info(
        (
            "Risk analysis completed for "
            "environment %s: "
            "%s Wazuh result(s), "
            "%s Zeek result(s), "
            "%s correlated result(s)."
        ),
        args.environment,
        output["summary"][
            "unique_wazuh_result_count"
        ],
        output["summary"][
            "unique_zeek_result_count"
        ],
        output["summary"][
            "correlated_result_count"
        ],
    )

    LOGGER.info(
        "Results saved to %s",
        output_path,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())