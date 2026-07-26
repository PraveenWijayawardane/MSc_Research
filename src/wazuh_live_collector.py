#!/usr/bin/env python3
"""
Collect recent Wazuh alerts and tag them with a hospital environment ID.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

import requests
import urllib3
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

from event_environment import (
    attach_environment,
    resolve_environment_id,
)
from environment_paths import EnvironmentPaths


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "live_wazuh_events.json"
)

load_dotenv()

WAZUH_INDEXER_URL = os.getenv(
    "WAZUH_INDEXER_URL",
    "https://localhost:9200",
)
WAZUH_INDEX = os.getenv(
    "WAZUH_INDEX",
    "wazuh-alerts-*",
)
USERNAME = os.getenv(
    "WAZUH_USERNAME",
    "readall",
)
PASSWORD = os.getenv("WAZUH_PASSWORD")


def environment_flag(
    name: str,
    default: bool = False,
) -> bool:
    """Read a boolean environment variable."""
    raw_value = os.getenv(name)

    if raw_value is None:
        return default

    return raw_value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def fetch_latest_wazuh_alerts(
    size: int = 100,
    verify_tls: bool = False,
    timeout_seconds: int = 30,
) -> list[dict[str, Any]]:
    """Fetch the latest Wazuh alerts from the configured indexer."""
    if not PASSWORD:
        raise ValueError(
            "WAZUH_PASSWORD is missing. Add it to the .env file."
        )

    if size < 1:
        raise ValueError(
            "size must be greater than zero"
        )

    url = (
        f"{WAZUH_INDEXER_URL.rstrip('/')}/"
        f"{WAZUH_INDEX}/_search"
    )

    query = {
        "size": size,
        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ],
        "_source": [
            "timestamp",
            "@timestamp",
            "agent.ip",
            "agent.name",
            "rule.id",
            "rule.level",
            "rule.description",
            "rule.groups",
            "data.srcuser",
            "data.dstuser",
            "data.uid",
            "data.srcip",
            "data.dstip",
            "predecoder.program_name",
            "full_log",
        ],
    }

    if not verify_tls:
        urllib3.disable_warnings(
            urllib3.exceptions.InsecureRequestWarning
        )

    response = requests.get(
        url,
        auth=HTTPBasicAuth(
            USERNAME,
            PASSWORD,
        ),
        headers={
            "Content-Type": "application/json"
        },
        json=query,
        verify=verify_tls,
        timeout=timeout_seconds,
    )

    response.raise_for_status()

    data = response.json()
    hits = data.get(
        "hits",
        {},
    ).get(
        "hits",
        [],
    )

    return [
        event
        for event in hits
        if isinstance(event, dict)
    ]


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
            "Collect recent Wazuh alerts for a selected "
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
        "--size",
        type=int,
        default=100,
        help="Maximum number of recent alerts to collect",
    )

    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Optional output JSON file. By default, "
            "data/<environment-id>/live_wazuh_events.json "
            "is used."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Indexer request timeout in seconds",
    )

    parser.add_argument(
        "--verify-tls",
        action="store_true",
        default=environment_flag(
            "WAZUH_VERIFY_TLS",
            False,
        ),
        help=(
            "Verify the Wazuh indexer TLS certificate. "
            "WAZUH_VERIFY_TLS may also enable this."
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

    alerts = fetch_latest_wazuh_alerts(
        size=args.size,
        verify_tls=args.verify_tls,
        timeout_seconds=args.timeout,
    )

    tagged_alerts = [
        attach_environment(
            alert,
            environment_id,
        )
        for alert in alerts
    ]

    output_path = (
        Path(args.output).resolve()
        if args.output
        else environment_paths.wazuh_events_file
    )

    write_json(
        output_path,
        tagged_alerts,
    )

    print(
        f"Environment: {environment_id}"
    )
    print(
        f"Fetched {len(tagged_alerts)} Wazuh alerts"
    )
    print(
        f"Saved to {output_path}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())