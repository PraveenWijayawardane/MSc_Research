#!/usr/bin/env python3
"""
Parse a Zeek conn.log file and tag each event with a hospital environment ID.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from event_environment import (
    attach_environment,
    resolve_environment_id,
)
from environment_paths import EnvironmentPaths


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_ZEEK_CONN_LOG_FILE = (
    PROJECT_ROOT
    / "data"
    / "live_zeek_conn.log"
)

DEFAULT_OUTPUT_JSON_FILE = (
    PROJECT_ROOT
    / "data"
    / "live_zeek_conn.json"
)


def convert_zeek_timestamp(
    value: Any,
) -> str:
    """Convert a Zeek epoch timestamp to UTC ISO-8601."""
    try:
        return (
            datetime.fromtimestamp(
                float(value),
                tz=timezone.utc,
            )
            .isoformat(
                timespec="milliseconds"
            )
            .replace(
                "+00:00",
                "Z",
            )
        )
    except (
        TypeError,
        ValueError,
        OSError,
    ):
        return ""


def convert_value(
    value: str,
) -> str | None:
    """Convert Zeek null placeholders to None."""
    if value in {
        "-",
        "(empty)",
        "",
    }:
        return None

    return value


def convert_numeric_fields(
    event: dict[str, Any],
) -> None:
    """Convert known Zeek numeric fields in place."""
    integer_fields = {
        "id.orig_p",
        "id.resp_p",
        "ip_proto",
    }

    floating_fields = {
        "duration",
        "orig_bytes",
        "resp_bytes",
        "missed_bytes",
        "orig_pkts",
        "orig_ip_bytes",
        "resp_pkts",
        "resp_ip_bytes",
    }

    for field in integer_fields:
        value = event.get(field)

        if value is None:
            continue

        try:
            event[field] = int(
                float(value)
            )
        except (
            TypeError,
            ValueError,
        ):
            pass

    for field in floating_fields:
        value = event.get(field)

        if value is None:
            continue

        try:
            event[field] = float(value)
        except (
            TypeError,
            ValueError,
        ):
            pass


def parse_zeek_conn_log(
    file_path: str | Path,
    environment_id: str,
) -> list[dict[str, Any]]:
    """Parse one Zeek conn.log file."""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Zeek conn.log file was not found: {path}"
        )

    validated_environment_id = (
        resolve_environment_id(
            environment_id
        )
    )

    fields: list[str] = []
    events: list[dict[str, Any]] = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line_number, raw_line in enumerate(
            file,
            start=1,
        ):
            line = raw_line.rstrip(
                "\r\n"
            )

            if not line:
                continue

            if line.startswith("#fields"):
                fields = line.split(
                    "\t"
                )[1:]
                continue

            if line.startswith("#"):
                continue

            if not fields:
                continue

            values = line.split("\t")

            if len(values) != len(fields):
                print(
                    "Skipping malformed Zeek line "
                    f"{line_number}: expected "
                    f"{len(fields)} values, received "
                    f"{len(values)}"
                )
                continue

            event = {
                field: convert_value(value)
                for field, value in zip(
                    fields,
                    values,
                )
            }

            convert_numeric_fields(event)

            event["ts"] = (
                convert_zeek_timestamp(
                    event.get("ts")
                )
            )

            events.append(
                attach_environment(
                    event,
                    validated_environment_id,
                )
            )

    return events


def write_json(
    path: Path,
    value: Any,
) -> None:
    """Write JSON safely to the selected output path."""
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = path.with_suffix(
        path.suffix + ".tmp"
    )

    with temporary_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            value,
            file,
            indent=4,
            ensure_ascii=False,
        )

    temporary_path.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Parse Zeek conn.log data for a selected "
            "hospital environment"
        )
    )

    parser.add_argument(
        "--environment",
        default=None,
        help=(
            "Hospital environment ID. It can also be "
            "provided using ENVIRONMENT_ID."
        ),
    )

    parser.add_argument(
        "--input",
        default=None,
        help=(
            "Optional Zeek conn.log file. By default, "
            "data/<environment-id>/live_zeek_conn.log "
            "is used."
        ),
    )

    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Optional output JSON file. By default, "
            "data/<environment-id>/live_zeek_conn.json "
            "is used."
        ),
    )

    args = parser.parse_args()

    environment_id = resolve_environment_id(
        args.environment
    )

    environment_paths = EnvironmentPaths(
        project_root=PROJECT_ROOT,
        environment_id=environment_id,
    )

    environment_paths.ensure_directories()

    input_path = (
        Path(args.input).resolve()
        if args.input
        else environment_paths.zeek_conn_log_file
    )

    output_path = (
        Path(args.output).resolve()
        if args.output
        else environment_paths.zeek_conn_json_file
    )

    events = parse_zeek_conn_log(
        file_path=input_path,
        environment_id=environment_id,
    )

    write_json(
        output_path,
        events,
    )

    print(
        f"Environment: {environment_id}"
    )
    print(
        f"Parsed {len(events)} Zeek conn events"
    )
    print(
        f"Saved to {output_path}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())