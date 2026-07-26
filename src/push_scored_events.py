#!/usr/bin/env python3
"""
Idempotently publish environment-isolated healthcare-risk events.

Important behaviour:

1. Reads output/<environment-id>/scored_events.json by default.
2. Rejects output belonging to a different hospital environment.
3. Uses event_id as the OpenSearch document _id.
4. Replaces standalone Zeek documents with correlated versions.
5. Keeps Wazuh host events as separate documents.
6. Publishes through the environment-specific write alias.
7. Automatically ensures the backing index and aliases exist.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
from pathlib import Path
from typing import Any, Iterable

from dotenv import load_dotenv

from environment_paths import EnvironmentPaths
from event_environment import (
    get_event_environment,
    resolve_environment_id,
)
from opensearch_index_manager import (
    DEFAULT_CONFIG_ROOT,
    DEFAULT_MAPPING_FILE,
    OpenSearchClient,
    OpenSearchConfigurationError,
    OpenSearchConnectionSettings,
    OpenSearchIndexManager,
    OpenSearchRequestError,
    build_index_names,
    load_environment_base_index,
    load_json_object,
    validate_index_name,
)


LOGGER = logging.getLogger(
    "push_scored_events"
)

PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]


class PushConfigurationError(
    RuntimeError
):
    """Raised when publisher input or configuration is invalid."""


class BulkIndexError(
    RuntimeError
):
    """Raised when one or more OpenSearch bulk operations fail."""


def load_json(
    path: str | Path,
) -> Any:
    """Load JSON from disk."""
    resolved = Path(
        path
    ).resolve()

    try:
        with resolved.open(
            "r",
            encoding="utf-8-sig",
        ) as file:
            return json.load(file)
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"JSON file was not found: {resolved}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in {resolved}: {exc}"
        ) from exc


def valid_ip_or_none(
    value: Any,
) -> str | None:
    """Return a normalized IP address or None."""
    if value in (
        None,
        "",
        "-",
        "unknown",
    ):
        return None

    try:
        return str(
            ipaddress.ip_address(
                str(value).strip()
            )
        )
    except ValueError:
        return None


def valid_timestamp_or_none(
    value: Any,
) -> str | int | float | None:
    """Return an OpenSearch-compatible date value or None."""
    if value in (
        None,
        "",
        "-",
        "unknown",
    ):
        return None

    if isinstance(
        value,
        (int, float),
    ):
        return value

    text = str(
        value
    ).strip()

    return text or None


def clean_private_fields(
    value: Any,
) -> Any:
    """Recursively remove internal fields beginning with an underscore."""
    if isinstance(value, dict):
        return {
            key: clean_private_fields(
                item
            )
            for key, item in value.items()
            if not str(
                key
            ).startswith("_")
        }

    if isinstance(value, list):
        return [
            clean_private_fields(item)
            for item in value
        ]

    return value


def sanitize_document(
    source_document: dict[str, Any],
) -> dict[str, Any]:
    """Prepare one risk event for the strict index mapping."""
    document = clean_private_fields(
        dict(source_document)
    )

    event_id = str(
        document.get(
            "event_id"
        )
        or ""
    ).strip()

    if not event_id:
        raise PushConfigurationError(
            "Every scored event must contain event_id"
        )

    document["event_id"] = event_id

    timestamp = (
        valid_timestamp_or_none(
            document.get(
                "timestamp"
            )
            or document.get(
                "@timestamp"
            )
        )
    )

    if timestamp is None:
        document.pop(
            "timestamp",
            None,
        )
        document.pop(
            "@timestamp",
            None,
        )
    else:
        document[
            "timestamp"
        ] = timestamp
        document[
            "@timestamp"
        ] = timestamp

    for field_name in (
        "ip",
        "source_ip",
        "destination_ip",
    ):
        normalized_ip = (
            valid_ip_or_none(
                document.get(
                    field_name
                )
            )
        )

        if normalized_ip is None:
            document.pop(
                field_name,
                None,
            )
        else:
            document[
                field_name
            ] = normalized_ip

    behavior_metrics = (
        document.get(
            "behavior_metrics"
        )
    )

    if isinstance(
        behavior_metrics,
        dict,
    ):
        behavior_ip = (
            valid_ip_or_none(
                behavior_metrics.get(
                    "source_ip"
                )
            )
        )

        if behavior_ip is None:
            behavior_metrics.pop(
                "source_ip",
                None,
            )
        else:
            behavior_metrics[
                "source_ip"
            ] = behavior_ip

        for date_field in (
            "window_start",
            "window_end",
        ):
            normalized_date = (
                valid_timestamp_or_none(
                    behavior_metrics.get(
                        date_field
                    )
                )
            )

            if normalized_date is None:
                behavior_metrics.pop(
                    date_field,
                    None,
                )
            else:
                behavior_metrics[
                    date_field
                ] = normalized_date

    if not document.get(
        "event_type"
    ):
        document[
            "event_type"
        ] = "unknown_activity"

    document[
        "detection_type"
    ] = document[
        "event_type"
    ]

    zeek_uid = str(
        document.get(
            "zeek_uid"
        )
        or document.get("uid")
        or ""
    ).strip()

    if zeek_uid:
        document[
            "zeek_uid"
        ] = zeek_uid

    for redundant_field in (
        "uid",
        "ts",
        "proto",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
    ):
        document.pop(
            redundant_field,
            None,
        )

    return document


def _environment_metadata(
    scored_output: dict[str, Any],
) -> dict[str, Any]:
    environment = scored_output.get(
        "environment",
        {},
    )

    if not isinstance(
        environment,
        dict,
    ):
        raise PushConfigurationError(
            "scored_events.environment "
            "must be an object"
        )

    return environment


def validate_scored_environment(
    scored_output: dict[str, Any],
    environment_id: str,
) -> dict[str, Any]:
    """
    Validate top-level and event-level environment identities.

    Missing event fields are filled from the selected environment. Explicit
    mismatches are rejected.
    """
    environment_id = resolve_environment_id(
        environment_id
    )

    if not isinstance(
        scored_output,
        dict,
    ):
        raise PushConfigurationError(
            "scored_events.json must "
            "contain a JSON object"
        )

    metadata = _environment_metadata(
        scored_output
    )

    configured_environment = str(
        metadata.get(
            "environment_id",
            "",
        )
    ).strip().lower()

    if not configured_environment:
        raise PushConfigurationError(
            "scored_events.environment."
            "environment_id is required"
        )

    if (
        configured_environment
        != environment_id
    ):
        raise PushConfigurationError(
            "Scored output belongs to "
            f"environment "
            f"{configured_environment}, "
            "but the selected environment is "
            f"{environment_id}"
        )

    return {
        "environment_id": (
            environment_id
        ),
        "environment_name": (
            metadata.get(
                "environment_name",
                environment_id,
            )
        ),
        "site_id": (
            metadata.get(
                "site_id",
                "unknown",
            )
        ),
        "environment_type": (
            metadata.get(
                "environment_type",
                "unknown",
            )
        ),
        "infrastructure_type": (
            metadata.get(
                "infrastructure_type",
                "unknown",
            )
        ),
    }


def _prepare_event(
    event: dict[str, Any],
    environment_fields: dict[str, Any],
) -> dict[str, Any]:
    event_environment = (
        get_event_environment(
            event
        )
    )

    selected_environment = str(
        environment_fields[
            "environment_id"
        ]
    )

    if (
        event_environment
        and event_environment
        != selected_environment
    ):
        raise PushConfigurationError(
            "Event "
            f"{event.get('event_id', 'unknown')} "
            "belongs to environment "
            f"{event_environment}, but the "
            "selected environment is "
            f"{selected_environment}"
        )

    prepared_source = {
        **event,
        **environment_fields,
    }

    return sanitize_document(
        prepared_source
    )


def build_final_documents(
    scored_output: dict[str, Any],
    environment_id: str,
) -> list[dict[str, Any]]:
    """
    Build the final environment-isolated OpenSearch snapshot.

    Correlated Zeek results replace standalone Zeek results with the same
    event_id. Wazuh results remain separate.
    """
    environment_fields = (
        validate_scored_environment(
            scored_output,
            environment_id,
        )
    )

    wazuh_results = (
        scored_output.get(
            "wazuh_results",
            [],
        )
    )

    zeek_results = (
        scored_output.get(
            "zeek_results",
            [],
        )
    )

    correlated_results = (
        scored_output.get(
            "correlated_results",
            [],
        )
    )

    for section_name, section in (
        (
            "wazuh_results",
            wazuh_results,
        ),
        (
            "zeek_results",
            zeek_results,
        ),
        (
            "correlated_results",
            correlated_results,
        ),
    ):
        if not isinstance(
            section,
            list,
        ):
            raise PushConfigurationError(
                f"{section_name} must "
                "be a JSON list"
            )

    wazuh_by_id: dict[
        str,
        dict[str, Any],
    ] = {}

    network_by_id: dict[
        str,
        dict[str, Any],
    ] = {}

    for event in wazuh_results:
        if not isinstance(
            event,
            dict,
        ):
            continue

        prepared = _prepare_event(
            event,
            environment_fields,
        )

        wazuh_by_id[
            prepared["event_id"]
        ] = prepared

    for event in zeek_results:
        if not isinstance(
            event,
            dict,
        ):
            continue

        prepared = _prepare_event(
            event,
            environment_fields,
        )

        network_by_id[
            prepared["event_id"]
        ] = prepared

    for event in correlated_results:
        if not isinstance(
            event,
            dict,
        ):
            continue

        prepared = _prepare_event(
            event,
            environment_fields,
        )

        network_by_id[
            prepared["event_id"]
        ] = prepared

    collisions = set(
        wazuh_by_id
    ).intersection(
        network_by_id
    )

    if collisions:
        raise PushConfigurationError(
            "Wazuh and network events share "
            "the same event_id: "
            + ", ".join(
                sorted(collisions)
            )
        )

    combined = {
        **wazuh_by_id,
        **network_by_id,
    }

    return [
        combined[event_id]
        for event_id in sorted(
            combined
        )
    ]


def chunked(
    values: list[dict[str, Any]],
    chunk_size: int,
) -> Iterable[
    list[dict[str, Any]]
]:
    """Yield fixed-size batches."""
    if chunk_size <= 0:
        raise ValueError(
            "chunk_size must be "
            "greater than zero"
        )

    for start in range(
        0,
        len(values),
        chunk_size,
    ):
        yield values[
            start:
            start + chunk_size
        ]


class OpenSearchPublisher:
    """Bulk publisher using deterministic event IDs."""

    def __init__(
        self,
        client: OpenSearchClient,
    ) -> None:
        self.client = client

    def bulk_index(
        self,
        target: str,
        documents: list[
            dict[str, Any]
        ],
        batch_size: int = 500,
    ) -> dict[str, int]:
        counters = {
            "submitted": 0,
            "created": 0,
            "updated": 0,
            "noop": 0,
            "failed": 0,
        }

        failures: list[
            dict[str, Any]
        ] = []

        for batch in chunked(
            documents,
            batch_size,
        ):
            lines: list[str] = []

            for document in batch:
                event_id = str(
                    document["event_id"]
                )

                lines.append(
                    json.dumps(
                        {
                            "index": {
                                "_index": (
                                    target
                                ),
                                "_id": (
                                    event_id
                                ),
                            }
                        },
                        separators=(
                            ",",
                            ":",
                        ),
                        ensure_ascii=False,
                    )
                )

                lines.append(
                    json.dumps(
                        document,
                        separators=(
                            ",",
                            ":",
                        ),
                        ensure_ascii=False,
                        default=str,
                    )
                )

            payload = (
                "\n".join(lines)
                + "\n"
            )

            response = (
                self.client.request(
                    "POST",
                    "_bulk",
                    expected_statuses={
                        200,
                    },
                    data=payload.encode(
                        "utf-8"
                    ),
                    headers={
                        "Content-Type": (
                            "application/x-ndjson"
                        )
                    },
                )
            )

            result = response.json()
            items = result.get(
                "items",
                [],
            )

            counters[
                "submitted"
            ] += len(batch)

            if len(items) != len(batch):
                raise BulkIndexError(
                    "OpenSearch bulk response "
                    "item count does not match "
                    "the submitted document count"
                )

            for item in items:
                operation = item.get(
                    "index",
                    {},
                )

                status = int(
                    operation.get(
                        "status",
                        0,
                    )
                )

                operation_result = str(
                    operation.get(
                        "result",
                        "",
                    )
                )

                if 200 <= status < 300:
                    if operation_result in (
                        "created",
                        "updated",
                        "noop",
                    ):
                        counters[
                            operation_result
                        ] += 1
                    else:
                        counters[
                            "updated"
                        ] += 1

                    continue

                counters["failed"] += 1

                if len(failures) < 10:
                    failures.append(
                        {
                            "id": operation.get(
                                "_id"
                            ),
                            "status": status,
                            "error": operation.get(
                                "error"
                            ),
                        }
                    )

        if counters["failed"]:
            raise BulkIndexError(
                f"{counters['failed']} bulk "
                "operation(s) failed. "
                "First failures: "
                + json.dumps(
                    failures,
                    indent=2,
                )
            )

        return counters


def build_argument_parser(
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Publish environment-isolated "
            "healthcare-risk events"
        )
    )

    parser.add_argument(
        "--environment",
        default=os.getenv(
            "ENVIRONMENT_ID"
        ),
        help=(
            "Hospital environment ID. "
            "ENVIRONMENT_ID may also be used."
        ),
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help=(
            "Optional scored-events file. "
            "Defaults to output/<environment-id>/"
            "scored_events.json."
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
        "--mapping",
        type=Path,
        default=DEFAULT_MAPPING_FILE,
        help=(
            "OpenSearch index mapping JSON"
        ),
    )

    parser.add_argument(
        "--base-index",
        default=None,
        help=(
            "Optional base index override. "
            "Defaults to environment output.index."
        ),
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="OpenSearch bulk batch size",
    )

    parser.add_argument(
        "--refresh",
        action="store_true",
        help=(
            "Refresh the read alias "
            "after publishing"
        ),
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Validate and prepare documents "
            "without contacting OpenSearch"
        ),
    )

    parser.add_argument(
        "--skip-ensure",
        action="store_true",
        help=(
            "Do not ensure the backing index "
            "and aliases before publishing"
        ),
    )

    return parser


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s %(levelname)s "
            "%(name)s: %(message)s"
        ),
    )

    load_dotenv(
        PROJECT_ROOT / ".env"
    )

    args = (
        build_argument_parser()
        .parse_args()
    )

    environment_id = (
        resolve_environment_id(
            args.environment
        )
    )

    environment_paths = (
        EnvironmentPaths(
            project_root=PROJECT_ROOT,
            environment_id=(
                environment_id
            ),
        )
    )

    environment_paths.ensure_directories()

    input_file = (
        args.input.resolve()
        if args.input
        else (
            environment_paths
            .scored_events_file
        )
    )

    scored_output = load_json(
        input_file
    )

    documents = (
        build_final_documents(
            scored_output,
            environment_id,
        )
    )

    LOGGER.info(
        "Prepared %s unique document(s) "
        "for environment %s.",
        len(documents),
        environment_id,
    )

    if args.dry_run:
        event_ids = [
            document["event_id"]
            for document in documents
        ]

        if len(event_ids) != len(
            set(event_ids)
        ):
            raise PushConfigurationError(
                "Duplicate event IDs remain "
                "after preparation"
            )

        LOGGER.info(
            "Dry run completed successfully."
        )

        return 0

    base_index = (
        validate_index_name(
            args.base_index,
            "base index",
        )
        if args.base_index
        else load_environment_base_index(
            environment_id,
            args.config_root,
        )
    )

    names = build_index_names(
        environment_id,
        base_index,
    )

    mapping = load_json_object(
        args.mapping
    )

    settings = (
        OpenSearchConnectionSettings
        .from_environment()
    )

    client = OpenSearchClient(
        settings
    )

    manager = (
        OpenSearchIndexManager(
            client=client,
            names=names,
            mapping=mapping,
        )
    )

    if not args.skip_ensure:
        ensure_result = (
            manager.ensure()
        )

        LOGGER.info(
            "OpenSearch index ready: %s",
            ensure_result[
                "write_index"
            ],
        )

    publisher = OpenSearchPublisher(
        client
    )

    counters = publisher.bulk_index(
        target=names.write_alias,
        documents=documents,
        batch_size=args.batch_size,
    )

    if args.refresh:
        client.refresh(
            names.read_alias
        )

    LOGGER.info(
        (
            "Published %s document(s): "
            "%s created, %s updated, "
            "%s no-op, %s failed."
        ),
        counters["submitted"],
        counters["created"],
        counters["updated"],
        counters["noop"],
        counters["failed"],
    )

    LOGGER.info(
        "Environment: %s",
        environment_id,
    )

    LOGGER.info(
        "Write alias: %s",
        names.write_alias,
    )

    LOGGER.info(
        "Dashboard read alias: %s",
        names.read_alias,
    )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        BulkIndexError,
        FileNotFoundError,
        OpenSearchConfigurationError,
        OpenSearchRequestError,
        PushConfigurationError,
        ValueError,
    ) as exc:
        LOGGER.error("%s", exc)
        raise SystemExit(1)