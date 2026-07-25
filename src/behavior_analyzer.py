#!/usr/bin/env python3
"""
Behavioral analyzer for normalized or raw Zeek connection events.

The analyzer uses a sliding time window for each source IP. It calculates
behavioral metrics without modifying counters inside the scoring function.

Important properties:

1. Input events are deduplicated before analysis.
2. Events are processed chronologically.
3. Events with the same timestamp are evaluated using the same snapshot.
4. Future events are not included in an older event's behavior context.
5. One event ID always produces one behavior result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from asset_resolver import AssetResolver


LOGGER = logging.getLogger("behavior_analyzer")

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_RISK_RULES_FILE = (
    PROJECT_ROOT / "config" / "risk_rules.yaml"
)

DEFAULT_ASSET_CONTEXT_FILE = (
    PROJECT_ROOT / "config" / "asset_context.yaml"
)

DEFAULT_ZEEK_FILE = (
    PROJECT_ROOT / "data" / "live_zeek_conn.json"
)

DEFAULT_OUTPUT_FILE = (
    PROJECT_ROOT / "output" / "behavior_results.json"
)


class BehaviorConfigurationError(RuntimeError):
    """Raised when the behavior configuration is invalid."""


def safe_int(
    value: Any,
    default: int = 0,
) -> int:
    try:
        if value in (None, "", "-"):
            return default

        return int(float(value))

    except (TypeError, ValueError):
        return default


def safe_float(
    value: Any,
    default: float = 0.0,
) -> float:
    try:
        if value in (None, "", "-"):
            return default

        return float(value)

    except (TypeError, ValueError):
        return default


def parse_timestamp(
    value: Any,
) -> datetime | None:
    """
    Parse Zeek epoch timestamps and ISO timestamps.

    Returned values are normalized to UTC.
    """

    if value in (None, "", "-"):
        return None

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(
            float(value),
            tz=timezone.utc,
        )

    text = str(value).strip()

    try:
        return datetime.fromtimestamp(
            float(text),
            tz=timezone.utc,
        )
    except ValueError:
        pass

    normalized = text.replace("Z", "+00:00")

    # Convert timezone offsets such as +0530 to +05:30.
    if (
        len(normalized) >= 5
        and normalized[-5] in {"+", "-"}
        and normalized[-3] != ":"
    ):
        normalized = (
            normalized[:-2]
            + ":"
            + normalized[-2:]
        )

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def format_timestamp(
    value: Any,
) -> str:
    parsed = parse_timestamp(value)

    if parsed is None:
        return ""

    return (
        parsed.isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def stable_event_id(
    event: dict[str, Any],
) -> str:
    """
    Return the Zeek UID when available, otherwise create a deterministic ID.
    """

    existing_event_id = str(
        event.get("event_id") or ""
    ).strip()

    if existing_event_id:
        return existing_event_id

    zeek_uid = str(
        event.get("uid")
        or event.get("zeek_uid")
        or ""
    ).strip()

    if zeek_uid:
        return f"zeek:{zeek_uid}"

    identity = {
        "timestamp": format_timestamp(
            event.get("timestamp")
            or event.get("ts")
            or event.get("@timestamp")
        ),
        "source_ip": (
            event.get("source_ip")
            or event.get("id.orig_h")
        ),
        "source_port": (
            event.get("source_port")
            or event.get("id.orig_p")
        ),
        "destination_ip": (
            event.get("destination_ip")
            or event.get("id.resp_h")
        ),
        "destination_port": (
            event.get("destination_port")
            or event.get("id.resp_p")
        ),
        "protocol": (
            event.get("protocol")
            or event.get("proto")
        ),
        "service": event.get("service"),
        "duration": event.get("duration"),
        "orig_bytes": event.get("orig_bytes"),
        "resp_bytes": event.get("resp_bytes"),
        "conn_state": event.get("conn_state"),
    }

    serialized = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )

    digest = hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()

    return f"zeek:{digest}"


def unique_strings(
    values: Iterable[Any],
) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()

    for value in values:
        text = str(value or "").strip()

        if text and text not in seen:
            seen.add(text)
            result.append(text)

    return result


def atomic_write_json(
    file_path: Path,
    value: Any,
) -> None:
    file_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_file = file_path.with_suffix(
        file_path.suffix + ".tmp"
    )

    with temporary_file.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            value,
            file,
            indent=4,
            ensure_ascii=False,
        )

    temporary_file.replace(file_path)


class BehaviorAnalyzer:
    """
    Analyze Zeek events using a source-based sliding time window.

    Optional baseline format:

    {
        "known_services_by_source_role": {
            "workstation": ["http", "https", "smb"]
        },
        "known_role_pairs": [
            ["workstation", "ehr_app"],
            ["workstation", "file_server"]
        ]
    }
    """

    def __init__(
        self,
        risk_rules: dict[str, Any],
        baseline: dict[str, Any] | None = None,
    ) -> None:
        self.risk_rules = risk_rules
        self.behavior_rules = risk_rules.get(
            "behavior",
            {},
        )
        self.working_hours = risk_rules.get(
            "working_hours",
            {},
        )
        self.limits = risk_rules.get(
            "limits",
            {},
        )
        self.baseline = baseline or {}

        self._validate_configuration()

        self.window_minutes = safe_int(
            self.behavior_rules.get(
                "window_minutes",
                5,
            ),
            5,
        )

        self.window_duration = timedelta(
            minutes=self.window_minutes
        )

        self.rejected_states = {
            str(value).upper()
            for value in self.behavior_rules.get(
                "rejected_connections",
                {},
            ).get("states", [])
        }

        self.known_services_by_source_role = (
            self._normalize_known_services(
                self.baseline.get(
                    "known_services_by_source_role",
                    {},
                )
            )
        )

        self.known_role_pairs = (
            self._normalize_known_role_pairs(
                self.baseline.get(
                    "known_role_pairs",
                    [],
                )
            )
        )

        self.local_timezone = (
            self._load_local_timezone()
        )

    @classmethod
    def from_file(
        cls,
        file_path: str | Path = DEFAULT_RISK_RULES_FILE,
        baseline: dict[str, Any] | None = None,
    ) -> "BehaviorAnalyzer":
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Risk-rule file was not found: {path}"
            )

        try:
            with path.open(
                "r",
                encoding="utf-8-sig",
            ) as file:
                risk_rules = yaml.safe_load(file)

        except yaml.YAMLError as exc:
            raise BehaviorConfigurationError(
                f"Invalid YAML in {path}: {exc}"
            ) from exc

        if not isinstance(risk_rules, dict):
            raise BehaviorConfigurationError(
                f"The YAML root must be an object: {path}"
            )

        return cls(
            risk_rules=risk_rules,
            baseline=baseline,
        )

    def _validate_configuration(self) -> None:
        if not isinstance(
            self.behavior_rules,
            dict,
        ):
            raise BehaviorConfigurationError(
                "behavior must be a YAML object"
            )

        window_minutes = safe_int(
            self.behavior_rules.get(
                "window_minutes",
                5,
            )
        )

        if window_minutes <= 0:
            raise BehaviorConfigurationError(
                "behavior.window_minutes must be greater than zero"
            )

        required_sections = (
            "connection_frequency",
            "destination_fanout",
            "port_fanout",
            "rejected_connections",
            "data_transfer",
            "connection_duration",
            "off_hours",
            "weekend_activity",
            "rare_service",
            "new_role_pair",
            "suspicious_services",
        )

        for section_name in required_sections:
            section = self.behavior_rules.get(
                section_name
            )

            if not isinstance(section, dict):
                raise BehaviorConfigurationError(
                    f"behavior.{section_name} must be an object"
                )

    def _load_local_timezone(self) -> ZoneInfo:
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
                "Timezone %s is unavailable. Falling back to UTC.",
                timezone_name,
            )

            return timezone.utc

    @staticmethod
    def _normalize_known_services(
        value: Any,
    ) -> dict[str, set[str]]:
        if not isinstance(value, dict):
            return {}

        normalized: dict[str, set[str]] = {}

        for role, services in value.items():
            if not isinstance(
                services,
                (list, tuple, set),
            ):
                continue

            normalized[
                str(role).strip().lower()
            ] = {
                str(service).strip().lower()
                for service in services
                if str(service).strip()
            }

        return normalized

    @staticmethod
    def _normalize_known_role_pairs(
        value: Any,
    ) -> set[tuple[str, str]]:
        result: set[tuple[str, str]] = set()

        if not isinstance(value, list):
            return result

        for pair in value:
            if (
                isinstance(pair, (list, tuple))
                and len(pair) == 2
            ):
                result.add(
                    (
                        str(pair[0]).strip().lower(),
                        str(pair[1]).strip().lower(),
                    )
                )

        return result

    @staticmethod
    def normalize_event(
        event: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Normalize a raw Zeek event or an already-normalized network event.
        """

        timestamp = format_timestamp(
            event.get("timestamp")
            or event.get("ts")
            or event.get("@timestamp")
        )

        source_ip = str(
            event.get("source_ip")
            or event.get("id.orig_h")
            or "unknown"
        )

        destination_ip = str(
            event.get("destination_ip")
            or event.get("id.resp_h")
            or "unknown"
        )

        source_port = safe_int(
            event.get("source_port")
            or event.get("id.orig_p")
        )

        destination_port = safe_int(
            event.get("destination_port")
            or event.get("id.resp_p")
        )

        protocol = str(
            event.get("protocol")
            or event.get("proto")
            or "unknown"
        ).strip().lower()

        service = str(
            event.get("service")
            or "unknown"
        ).strip().lower()

        source_role = str(
            event.get("source_role")
            or "unknown"
        ).strip().lower()

        destination_role = str(
            event.get("destination_role")
            or "unknown"
        ).strip().lower()

        normalized = {
            **event,
            "event_id": stable_event_id(event),
            "timestamp": timestamp,
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "protocol": protocol,
            "service": service,
            "source_role": source_role,
            "destination_role": destination_role,
            "conn_state": str(
                event.get("conn_state")
                or ""
            ).strip().upper(),
            "duration": safe_float(
                event.get("duration")
            ),
            "orig_bytes": safe_int(
                event.get("orig_bytes")
            ),
            "resp_bytes": safe_int(
                event.get("resp_bytes")
            ),
        }

        normalized["total_bytes"] = (
            normalized["orig_bytes"]
            + normalized["resp_bytes"]
        )

        normalized["_parsed_timestamp"] = (
            parse_timestamp(timestamp)
        )

        return normalized

    @staticmethod
    def deduplicate_events(
        events: Iterable[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        unique_events: dict[str, dict[str, Any]] = {}

        for event in events:
            if not isinstance(event, dict):
                continue

            normalized = (
                BehaviorAnalyzer.normalize_event(
                    event
                )
            )

            event_id = normalized["event_id"]

            # The latest identical event representation replaces the
            # previous one, but it remains one logical event.
            unique_events[event_id] = normalized

        return sorted(
            unique_events.values(),
            key=lambda event: (
                event.get("_parsed_timestamp")
                or datetime.min.replace(
                    tzinfo=timezone.utc
                ),
                event["event_id"],
            ),
        )

    def _is_off_hours(
        self,
        event_time: datetime,
    ) -> bool:
        local_time = event_time.astimezone(
            self.local_timezone
        )

        start_hour = safe_int(
            self.working_hours.get(
                "start_hour",
                8,
            ),
            8,
        )

        end_hour = safe_int(
            self.working_hours.get(
                "end_hour",
                18,
            ),
            18,
        )

        return (
            local_time.hour < start_hour
            or local_time.hour >= end_hour
        )

    def _is_weekend(
        self,
        event_time: datetime,
    ) -> bool:
        local_time = event_time.astimezone(
            self.local_timezone
        )

        weekend_days = {
            safe_int(value)
            for value in self.working_hours.get(
                "weekend_days",
                [5, 6],
            )
        }

        return local_time.weekday() in weekend_days

    @staticmethod
    def _threshold_score(
        value: int | float,
        configuration: dict[str, Any],
    ) -> tuple[int, str | None]:
        high_threshold = safe_float(
            configuration.get(
                "high_threshold"
            ),
            float("inf"),
        )

        medium_threshold = safe_float(
            configuration.get(
                "medium_threshold"
            ),
            float("inf"),
        )

        if value >= high_threshold:
            return (
                safe_int(
                    configuration.get(
                        "high_points"
                    )
                ),
                "high",
            )

        if value >= medium_threshold:
            return (
                safe_int(
                    configuration.get(
                        "medium_points"
                    )
                ),
                "medium",
            )

        return 0, None

    def _is_rare_service(
        self,
        event: dict[str, Any],
        source_window_size: int,
        service_count: int,
    ) -> bool:
        service = str(
            event.get("service")
            or "unknown"
        ).lower()

        source_role = str(
            event.get("source_role")
            or "unknown"
        ).lower()

        if service in {"", "-", "unknown"}:
            return False

        known_services = (
            self.known_services_by_source_role.get(
                source_role
            )
        )

        # An explicit baseline is the preferred method.
        if known_services is not None:
            return service not in known_services

        configuration = self.behavior_rules.get(
            "rare_service",
            {},
        )

        minimum_observations = safe_int(
            configuration.get(
                "minimum_observations",
                20,
            ),
            20,
        )

        maximum_occurrences = safe_int(
            configuration.get(
                "maximum_occurrences",
                1,
            ),
            1,
        )

        # Avoid marking the first few lab events as rare.
        if source_window_size < minimum_observations:
            return False

        return service_count <= maximum_occurrences

    def _is_new_role_pair(
        self,
        event: dict[str, Any],
        source_window_size: int,
        role_pair_count: int,
    ) -> bool:
        source_role = str(
            event.get("source_role")
            or "unknown"
        ).lower()

        destination_role = str(
            event.get("destination_role")
            or "unknown"
        ).lower()

        if "unknown" in {
            source_role,
            destination_role,
        }:
            return False

        role_pair = (
            source_role,
            destination_role,
        )

        if self.known_role_pairs:
            return role_pair not in self.known_role_pairs

        configuration = self.behavior_rules.get(
            "new_role_pair",
            {},
        )

        minimum_observations = safe_int(
            configuration.get(
                "minimum_observations",
                20,
            ),
            20,
        )

        if source_window_size < minimum_observations:
            return False

        return role_pair_count <= 1

    def _suspicious_service_score(
        self,
        event: dict[str, Any],
    ) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []

        destination_port = safe_int(
            event.get("destination_port")
        )

        configured_services = (
            self.behavior_rules.get(
                "suspicious_services",
                {},
            )
        )

        for service_name, configuration in (
            configured_services.items()
        ):
            if not isinstance(
                configuration,
                dict,
            ):
                continue

            configured_ports = {
                safe_int(port)
                for port in configuration.get(
                    "ports",
                    [],
                )
            }

            if destination_port not in configured_ports:
                continue

            points = safe_int(
                configuration.get(
                    "points"
                )
            )

            score += points

            reasons.append(
                (
                    f"Sensitive {service_name.upper()} "
                    f"service activity detected on port "
                    f"{destination_port}"
                )
            )

        return score, reasons

    def _score_event(
        self,
        event: dict[str, Any],
        metrics: dict[str, Any],
    ) -> dict[str, Any]:
        score = 0
        reasons: list[str] = []

        frequency_points, frequency_level = (
            self._threshold_score(
                metrics["connection_frequency"],
                self.behavior_rules[
                    "connection_frequency"
                ],
            )
        )

        if frequency_points:
            score += frequency_points
            reasons.append(
                (
                    f"{frequency_level.capitalize()} repeated "
                    f"connection frequency detected "
                    f"({metrics['connection_frequency']} "
                    f"connections in {self.window_minutes} minutes)"
                )
            )

        destination_points, destination_level = (
            self._threshold_score(
                metrics["distinct_destinations"],
                self.behavior_rules[
                    "destination_fanout"
                ],
            )
        )

        if destination_points:
            score += destination_points
            reasons.append(
                (
                    f"{destination_level.capitalize()} destination "
                    f"fan-out detected "
                    f"({metrics['distinct_destinations']} destinations)"
                )
            )

        port_points, port_level = (
            self._threshold_score(
                metrics["distinct_destination_ports"],
                self.behavior_rules[
                    "port_fanout"
                ],
            )
        )

        if port_points:
            score += port_points
            reasons.append(
                (
                    f"{port_level.capitalize()} destination-port "
                    f"fan-out detected "
                    f"({metrics['distinct_destination_ports']} ports)"
                )
            )

        rejected_points, rejected_level = (
            self._threshold_score(
                metrics["rejected_connections"],
                self.behavior_rules[
                    "rejected_connections"
                ],
            )
        )

        if rejected_points:
            score += rejected_points
            reasons.append(
                (
                    f"{rejected_level.capitalize()} rejected "
                    f"connection burst detected "
                    f"({metrics['rejected_connections']} events)"
                )
            )

        transfer_rules = self.behavior_rules[
            "data_transfer"
        ]

        if (
            metrics["event_total_bytes"]
            >= safe_int(
                transfer_rules.get(
                    "high_bytes"
                )
            )
        ):
            points = safe_int(
                transfer_rules.get(
                    "high_points"
                )
            )

            score += points

            reasons.append(
                (
                    "High-volume data transfer detected "
                    f"({metrics['event_total_bytes']} bytes)"
                )
            )

        elif (
            metrics["event_total_bytes"]
            >= safe_int(
                transfer_rules.get(
                    "medium_bytes"
                )
            )
        ):
            points = safe_int(
                transfer_rules.get(
                    "medium_points"
                )
            )

            score += points

            reasons.append(
                (
                    "Elevated data transfer detected "
                    f"({metrics['event_total_bytes']} bytes)"
                )
            )

        duration_rules = self.behavior_rules[
            "connection_duration"
        ]

        if (
            metrics["duration_seconds"]
            >= safe_float(
                duration_rules.get(
                    "very_long_seconds"
                )
            )
        ):
            points = safe_int(
                duration_rules.get(
                    "very_long_points"
                )
            )

            score += points
            reasons.append(
                (
                    "Very long connection duration detected "
                    f"({metrics['duration_seconds']} seconds)"
                )
            )

        elif (
            metrics["duration_seconds"]
            >= safe_float(
                duration_rules.get(
                    "long_seconds"
                )
            )
        ):
            points = safe_int(
                duration_rules.get(
                    "long_points"
                )
            )

            score += points
            reasons.append(
                (
                    "Long connection duration detected "
                    f"({metrics['duration_seconds']} seconds)"
                )
            )

        if metrics["is_off_hours"]:
            points = safe_int(
                self.behavior_rules[
                    "off_hours"
                ].get("points")
            )

            score += points

            reasons.append(
                "Activity occurred outside configured working hours"
            )

        if metrics["is_weekend"]:
            points = safe_int(
                self.behavior_rules[
                    "weekend_activity"
                ].get("points")
            )

            score += points

            reasons.append(
                "Activity occurred during a configured weekend day"
            )

        if metrics["rare_service"]:
            points = safe_int(
                self.behavior_rules[
                    "rare_service"
                ].get("points")
            )

            score += points

            reasons.append(
                (
                    "Service is rare for the source role: "
                    f"{event.get('service')}"
                )
            )

        if metrics["new_role_pair"]:
            points = safe_int(
                self.behavior_rules[
                    "new_role_pair"
                ].get("points")
            )

            score += points

            reasons.append(
                (
                    "New source-to-destination role relationship: "
                    f"{event.get('source_role')} -> "
                    f"{event.get('destination_role')}"
                )
            )

        (
            suspicious_service_points,
            suspicious_service_reasons,
        ) = self._suspicious_service_score(event)

        score += suspicious_service_points
        reasons.extend(
            suspicious_service_reasons
        )

        maximum_score = safe_int(
            self.limits.get(
                "max_behavior_score",
                20,
            ),
            20,
        )

        final_score = max(
            0,
            min(score, maximum_score),
        )

        return {
            "event_id": event["event_id"],
            "timestamp": event["timestamp"],
            "behavior_score": final_score,
            "behavior_reasons": unique_strings(
                reasons
            ),
            "behavior_metrics": metrics,
        }

    def analyze(
        self,
        events: Iterable[dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        """
        Analyze all events.

        Returns a dictionary keyed by event_id.
        """

        normalized_events = (
            self.deduplicate_events(events)
        )

        events_by_source: dict[
            str,
            list[dict[str, Any]],
        ] = defaultdict(list)

        results: dict[
            str,
            dict[str, Any],
        ] = {}

        for event in normalized_events:
            if event["_parsed_timestamp"] is None:
                results[event["event_id"]] = {
                    "event_id": event["event_id"],
                    "timestamp": event["timestamp"],
                    "behavior_score": 0,
                    "behavior_reasons": [
                        (
                            "Behavior analysis skipped because "
                            "the event timestamp is invalid"
                        )
                    ],
                    "behavior_metrics": {
                        "analysis_skipped": True,
                        "skip_reason": "invalid_timestamp",
                    },
                }

                continue

            events_by_source[
                event["source_ip"]
            ].append(event)

        for source_ip, source_events in (
            events_by_source.items()
        ):
            source_events.sort(
                key=lambda event: (
                    event["_parsed_timestamp"],
                    event["event_id"],
                )
            )

            window: deque[
                dict[str, Any]
            ] = deque()

            connection_counter: Counter[
                tuple[str, int, str]
            ] = Counter()

            destination_counter: Counter[
                str
            ] = Counter()

            port_counter: Counter[
                int
            ] = Counter()

            service_counter: Counter[
                str
            ] = Counter()

            role_pair_counter: Counter[
                tuple[str, str]
            ] = Counter()

            rejected_count = 0
            source_window_total_bytes = 0

            def add_to_window(
                window_event: dict[str, Any],
            ) -> None:
                nonlocal rejected_count
                nonlocal source_window_total_bytes

                window.append(window_event)

                connection_key = (
                    window_event["destination_ip"],
                    window_event["destination_port"],
                    window_event["protocol"],
                )

                connection_counter[
                    connection_key
                ] += 1

                destination_counter[
                    window_event["destination_ip"]
                ] += 1

                port_counter[
                    window_event["destination_port"]
                ] += 1

                service_counter[
                    window_event["service"]
                ] += 1

                role_pair_counter[
                    (
                        window_event["source_role"],
                        window_event[
                            "destination_role"
                        ],
                    )
                ] += 1

                if (
                    window_event["conn_state"]
                    in self.rejected_states
                ):
                    rejected_count += 1

                source_window_total_bytes += (
                    window_event["total_bytes"]
                )

            def remove_from_window(
                window_event: dict[str, Any],
            ) -> None:
                nonlocal rejected_count
                nonlocal source_window_total_bytes

                connection_key = (
                    window_event["destination_ip"],
                    window_event["destination_port"],
                    window_event["protocol"],
                )

                connection_counter[
                    connection_key
                ] -= 1

                if (
                    connection_counter[
                        connection_key
                    ]
                    <= 0
                ):
                    del connection_counter[
                        connection_key
                    ]

                destination_ip = (
                    window_event["destination_ip"]
                )

                destination_counter[
                    destination_ip
                ] -= 1

                if (
                    destination_counter[
                        destination_ip
                    ]
                    <= 0
                ):
                    del destination_counter[
                        destination_ip
                    ]

                destination_port = (
                    window_event[
                        "destination_port"
                    ]
                )

                port_counter[
                    destination_port
                ] -= 1

                if (
                    port_counter[
                        destination_port
                    ]
                    <= 0
                ):
                    del port_counter[
                        destination_port
                    ]

                service = window_event["service"]

                service_counter[service] -= 1

                if service_counter[service] <= 0:
                    del service_counter[service]

                role_pair = (
                    window_event["source_role"],
                    window_event[
                        "destination_role"
                    ],
                )

                role_pair_counter[
                    role_pair
                ] -= 1

                if (
                    role_pair_counter[
                        role_pair
                    ]
                    <= 0
                ):
                    del role_pair_counter[
                        role_pair
                    ]

                if (
                    window_event["conn_state"]
                    in self.rejected_states
                ):
                    rejected_count -= 1

                source_window_total_bytes -= (
                    window_event["total_bytes"]
                )

            # Events sharing an exact timestamp are added as one batch.
            # This prevents processing order from changing their metrics.
            current_index = 0

            while current_index < len(
                source_events
            ):
                current_time = source_events[
                    current_index
                ]["_parsed_timestamp"]

                batch_end = current_index

                while (
                    batch_end < len(source_events)
                    and source_events[
                        batch_end
                    ]["_parsed_timestamp"]
                    == current_time
                ):
                    batch_end += 1

                minimum_time = (
                    current_time
                    - self.window_duration
                )

                while (
                    window
                    and window[0][
                        "_parsed_timestamp"
                    ] < minimum_time
                ):
                    expired_event = (
                        window.popleft()
                    )

                    remove_from_window(
                        expired_event
                    )

                current_batch = source_events[
                    current_index:batch_end
                ]

                for event in current_batch:
                    add_to_window(event)

                for event in current_batch:
                    connection_key = (
                        event["destination_ip"],
                        event["destination_port"],
                        event["protocol"],
                    )

                    role_pair = (
                        event["source_role"],
                        event["destination_role"],
                    )

                    metrics = {
                        "window_minutes": (
                            self.window_minutes
                        ),
                        "window_start": (
                            minimum_time
                            .isoformat(
                                timespec="milliseconds"
                            )
                            .replace("+00:00", "Z")
                        ),
                        "window_end": (
                            current_time
                            .isoformat(
                                timespec="milliseconds"
                            )
                            .replace("+00:00", "Z")
                        ),
                        "source_ip": source_ip,
                        "source_window_event_count": (
                            len(window)
                        ),
                        "connection_frequency": (
                            connection_counter[
                                connection_key
                            ]
                        ),
                        "distinct_destinations": (
                            len(destination_counter)
                        ),
                        "distinct_destination_ports": (
                            len(port_counter)
                        ),
                        "rejected_connections": (
                            rejected_count
                        ),
                        "event_total_bytes": (
                            event["total_bytes"]
                        ),
                        "source_window_total_bytes": (
                            source_window_total_bytes
                        ),
                        "duration_seconds": (
                            event["duration"]
                        ),
                        "service_window_count": (
                            service_counter[
                                event["service"]
                            ]
                        ),
                        "role_pair_window_count": (
                            role_pair_counter[
                                role_pair
                            ]
                        ),
                        "is_off_hours": (
                            self._is_off_hours(
                                current_time
                            )
                        ),
                        "is_weekend": (
                            self._is_weekend(
                                current_time
                            )
                        ),
                    }

                    metrics["rare_service"] = (
                        self._is_rare_service(
                            event=event,
                            source_window_size=(
                                len(window)
                            ),
                            service_count=(
                                metrics[
                                    "service_window_count"
                                ]
                            ),
                        )
                    )

                    metrics["new_role_pair"] = (
                        self._is_new_role_pair(
                            event=event,
                            source_window_size=(
                                len(window)
                            ),
                            role_pair_count=(
                                metrics[
                                    "role_pair_window_count"
                                ]
                            ),
                        )
                    )

                    results[event["event_id"]] = (
                        self._score_event(
                            event=event,
                            metrics=metrics,
                        )
                    )

                current_index = batch_end

        return results


def load_zeek_events(
    file_path: Path,
) -> list[dict[str, Any]]:
    with file_path.open(
        "r",
        encoding="utf-8-sig",
    ) as file:
        value = json.load(file)

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

    raise ValueError(
        f"Unsupported Zeek JSON structure: {file_path}"
    )


def enrich_events_with_asset_context(
    events: Iterable[dict[str, Any]],
    resolver: AssetResolver,
) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []

    for event in events:
        normalized = (
            BehaviorAnalyzer.normalize_event(event)
        )

        source_context = resolver.resolve(
            normalized["source_ip"]
        )

        destination_context = resolver.resolve(
            normalized["destination_ip"]
        )

        enriched.append(
            {
                **normalized,
                "source_role": source_context[
                    "role"
                ],
                "source_zone": source_context[
                    "zone"
                ],
                "destination_role": (
                    destination_context["role"]
                ),
                "destination_zone": (
                    destination_context["zone"]
                ),
            }
        )

    return enriched


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze Zeek connections using "
            "risk_rules.yaml"
        )
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_ZEEK_FILE,
        help="Zeek JSON input file",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_FILE,
        help="Behavior result JSON file",
    )

    parser.add_argument(
        "--risk-rules",
        type=Path,
        default=DEFAULT_RISK_RULES_FILE,
        help="Risk-rule YAML file",
    )

    parser.add_argument(
        "--asset-context",
        type=Path,
        default=DEFAULT_ASSET_CONTEXT_FILE,
        help="Asset-context YAML file",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s %(levelname)s "
            "%(name)s: %(message)s"
        ),
    )

    zeek_events = load_zeek_events(
        args.input
    )

    asset_resolver = AssetResolver.from_file(
        args.asset_context
    )

    enriched_events = (
        enrich_events_with_asset_context(
            events=zeek_events,
            resolver=asset_resolver,
        )
    )

    analyzer = BehaviorAnalyzer.from_file(
        args.risk_rules
    )

    results = analyzer.analyze(
        enriched_events
    )

    output = {
        "event_count": len(results),
        "results": list(results.values()),
    }

    atomic_write_json(
        args.output,
        output,
    )

    LOGGER.info(
        "Behavior analysis completed for %s event(s).",
        len(results),
    )

    LOGGER.info(
        "Results saved to %s",
        args.output,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())