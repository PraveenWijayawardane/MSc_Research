#!/usr/bin/env python3
"""
Idempotently publish scored healthcare-risk events to OpenSearch.

Key behavior:

1. Uses event_id as the OpenSearch document _id.
2. Replaces a standalone Zeek document with its correlated version.
3. Keeps Wazuh host events as separate documents.
4. Creates the target index from healthcare-risk-events-mapping.json.
5. Uses the OpenSearch Bulk API for efficient indexing.
6. Sanitizes invalid IP/date values before indexing.

The same input can be pushed repeatedly without creating duplicate documents.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Iterable

import requests
import urllib3
from dotenv import load_dotenv
from requests import Response, Session
from requests.auth import HTTPBasicAuth


LOGGER = logging.getLogger("push_scored_events")

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_INPUT_FILE = (
    PROJECT_ROOT / "output" / "scored_events.json"
)

DEFAULT_MAPPING_FILE = (
    PROJECT_ROOT / "healthcare-risk-events-mapping.json"
)

DEFAULT_INDEX_NAME = "healthcare-risk-events-v2"


class PushConfigurationError(RuntimeError):
    """Raised when the publisher configuration is incomplete or invalid."""


class BulkIndexError(RuntimeError):
    """Raised when one or more OpenSearch bulk operations fail."""


def parse_boolean(
    value: Any,
    default: bool = False,
) -> bool:
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    normalized = str(value).strip().lower()

    if normalized in {
        "1",
        "true",
        "yes",
        "y",
        "on",
    }:
        return True

    if normalized in {
        "0",
        "false",
        "no",
        "n",
        "off",
    }:
        return False

    return default


def load_json(
    path: Path,
) -> Any:
    try:
        with path.open(
            "r",
            encoding="utf-8-sig",
        ) as file:
            return json.load(file)

    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"JSON file was not found: {path}"
        ) from exc

    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in {path}: {exc}"
        ) from exc


def valid_ip_or_none(
    value: Any,
) -> str | None:
    if value in (None, "", "-", "unknown"):
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
    if value in (None, "", "-", "unknown"):
        return None

    if isinstance(
        value,
        (int, float),
    ):
        return value

    text = str(value).strip()

    if not text:
        return None

    return text


def clean_private_fields(
    value: Any,
) -> Any:
    """
    Recursively remove internal keys beginning with an underscore.

    OpenSearch metadata such as _id is supplied separately through the
    Bulk API and must not be embedded in the document source.
    """

    if isinstance(value, dict):
        return {
            key: clean_private_fields(item)
            for key, item in value.items()
            if not str(key).startswith("_")
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
    """
    Prepare one event for the healthcare-risk-events-v2 mapping.
    """

    document = clean_private_fields(
        dict(source_document)
    )

    event_id = str(
        document.get("event_id") or ""
    ).strip()

    if not event_id:
        raise PushConfigurationError(
            "Every scored event must contain event_id"
        )

    document["event_id"] = event_id

    timestamp = valid_timestamp_or_none(
        document.get("timestamp")
        or document.get("@timestamp")
    )

    if timestamp is None:
        document.pop("timestamp", None)
        document.pop("@timestamp", None)
    else:
        document["timestamp"] = timestamp
        document["@timestamp"] = timestamp

    for field_name in (
        "ip",
        "source_ip",
        "destination_ip",
    ):
        normalized_ip = valid_ip_or_none(
            document.get(field_name)
        )

        if normalized_ip is None:
            document.pop(field_name, None)
        else:
            document[field_name] = normalized_ip

    behavior_metrics = document.get(
        "behavior_metrics"
    )

    if isinstance(
        behavior_metrics,
        dict,
    ):
        behavior_ip = valid_ip_or_none(
            behavior_metrics.get("source_ip")
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

    if not document.get("event_type"):
        document["event_type"] = (
            "unknown_activity"
        )

    document["detection_type"] = (
        document["event_type"]
    )

    zeek_uid = str(
        document.get("zeek_uid")
        or document.get("uid")
        or ""
    ).strip()

    if zeek_uid:
        document["zeek_uid"] = zeek_uid

    # These raw Zeek fields have canonical equivalents and contain dots,
    # which can create mapping conflicts in OpenSearch.
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


def build_final_documents(
    scored_output: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Build the final OpenSearch snapshot.

    Correlated Zeek results replace standalone Zeek results using the same
    event_id. Wazuh results remain independent host-event documents.
    """

    if not isinstance(
        scored_output,
        dict,
    ):
        raise PushConfigurationError(
            "scored_events.json must contain a JSON object"
        )

    wazuh_results = scored_output.get(
        "wazuh_results",
        [],
    )
    zeek_results = scored_output.get(
        "zeek_results",
        [],
    )
    correlated_results = scored_output.get(
        "correlated_results",
        [],
    )

    for section_name, section in (
        ("wazuh_results", wazuh_results),
        ("zeek_results", zeek_results),
        (
            "correlated_results",
            correlated_results,
        ),
    ):
        if not isinstance(section, list):
            raise PushConfigurationError(
                f"{section_name} must be a JSON list"
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
        if not isinstance(event, dict):
            continue

        prepared = sanitize_document(event)

        wazuh_by_id[
            prepared["event_id"]
        ] = prepared

    for event in zeek_results:
        if not isinstance(event, dict):
            continue

        prepared = sanitize_document(event)

        network_by_id[
            prepared["event_id"]
        ] = prepared

    # Correlated versions intentionally overwrite their standalone Zeek
    # document. This prevents two dashboard rows for the same connection.
    for event in correlated_results:
        if not isinstance(event, dict):
            continue

        prepared = sanitize_document(event)

        network_by_id[
            prepared["event_id"]
        ] = prepared

    combined: dict[
        str,
        dict[str, Any],
    ] = {}

    combined.update(wazuh_by_id)
    combined.update(network_by_id)

    return [
        combined[event_id]
        for event_id in sorted(combined)
    ]


def chunked(
    values: list[dict[str, Any]],
    chunk_size: int,
) -> Iterable[list[dict[str, Any]]]:
    if chunk_size <= 0:
        raise ValueError(
            "chunk_size must be greater than zero"
        )

    for start in range(
        0,
        len(values),
        chunk_size,
    ):
        yield values[
            start:start + chunk_size
        ]


class OpenSearchPublisher:
    """Minimal requests-based OpenSearch publisher."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_tls: bool | str,
        timeout_seconds: int = 30,
    ) -> None:
        self.base_url = (
            base_url.rstrip("/")
        )
        self.verify_tls = verify_tls
        self.timeout_seconds = (
            timeout_seconds
        )

        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(
            username,
            password,
        )
        self.session.headers.update(
            {
                "Accept": "application/json",
            }
        )

        if verify_tls is False:
            urllib3.disable_warnings(
                urllib3.exceptions
                .InsecureRequestWarning
            )

    def _url(
        self,
        path: str,
    ) -> str:
        return (
            f"{self.base_url}/"
            f"{path.lstrip('/')}"
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        expected_statuses: set[int],
        **kwargs: Any,
    ) -> Response:
        try:
            response = self.session.request(
                method=method,
                url=self._url(path),
                verify=self.verify_tls,
                timeout=self.timeout_seconds,
                **kwargs,
            )

        except requests.RequestException as exc:
            raise RuntimeError(
                (
                    "Unable to communicate with "
                    f"OpenSearch at {self.base_url}: "
                    f"{exc}"
                )
            ) from exc

        if response.status_code not in (
            expected_statuses
        ):
            body = response.text[:2000]

            raise RuntimeError(
                (
                    f"OpenSearch request failed: "
                    f"{method} {path} returned "
                    f"HTTP {response.status_code}: "
                    f"{body}"
                )
            )

        return response

    def index_exists(
        self,
        index_name: str,
    ) -> bool:
        response = self._request(
            "HEAD",
            index_name,
            expected_statuses={200, 404},
        )

        return response.status_code == 200

    def create_index(
        self,
        index_name: str,
        mapping: dict[str, Any],
    ) -> None:
        self._request(
            "PUT",
            index_name,
            expected_statuses={200},
            json=mapping,
        )

        LOGGER.info(
            "Created OpenSearch index %s",
            index_name,
        )

    def delete_index(
        self,
        index_name: str,
    ) -> None:
        self._request(
            "DELETE",
            index_name,
            expected_statuses={200, 404},
        )

        LOGGER.info(
            "Deleted OpenSearch index %s",
            index_name,
        )

    def ensure_index(
        self,
        index_name: str,
        mapping: dict[str, Any],
        recreate: bool = False,
    ) -> None:
        exists = self.index_exists(
            index_name
        )

        if recreate and exists:
            self.delete_index(index_name)
            exists = False

        if not exists:
            self.create_index(
                index_name=index_name,
                mapping=mapping,
            )
        else:
            LOGGER.info(
                "OpenSearch index already exists: %s",
                index_name,
            )

    def bulk_index(
        self,
        index_name: str,
        documents: list[dict[str, Any]],
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

                action = {
                    "index": {
                        "_index": index_name,
                        "_id": event_id,
                    }
                }

                lines.append(
                    json.dumps(
                        action,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    )
                )

                lines.append(
                    json.dumps(
                        document,
                        separators=(",", ":"),
                        ensure_ascii=False,
                        default=str,
                    )
                )

            payload = "\n".join(lines) + "\n"

            response = self._request(
                "POST",
                "_bulk",
                expected_statuses={200},
                data=payload.encode("utf-8"),
                headers={
                    "Content-Type":
                        "application/x-ndjson"
                },
            )

            result = response.json()
            items = result.get("items", [])

            counters["submitted"] += len(batch)

            for item in items:
                operation = item.get("index", {})
                status = int(
                    operation.get("status", 0)
                )
                operation_result = str(
                    operation.get("result", "")
                )

                if 200 <= status < 300:
                    if (
                        operation_result
                        in counters
                    ):
                        counters[
                            operation_result
                        ] += 1
                    else:
                        counters["updated"] += 1
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
                (
                    f"{counters['failed']} bulk "
                    f"operation(s) failed. "
                    f"First failures: "
                    f"{json.dumps(failures, indent=2)}"
                )
            )

        return counters

    def refresh_index(
        self,
        index_name: str,
    ) -> None:
        self._request(
            "POST",
            f"{index_name}/_refresh",
            expected_statuses={200},
        )


def resolve_tls_verification() -> bool | str:
    ca_certificate = str(
        os.getenv(
            "RISK_INDEXER_CA_CERT",
            "",
        )
    ).strip()

    if ca_certificate:
        ca_path = Path(ca_certificate)

        if not ca_path.exists():
            raise PushConfigurationError(
                (
                    "RISK_INDEXER_CA_CERT does "
                    f"not exist: {ca_path}"
                )
            )

        return str(ca_path)

    return parse_boolean(
        os.getenv(
            "RISK_INDEXER_VERIFY_TLS",
            "false",
        ),
        default=False,
    )


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Publish scored healthcare-risk "
            "events to OpenSearch"
        )
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_FILE,
        help=(
            "Path to output/scored_events.json"
        ),
    )

    parser.add_argument(
        "--mapping",
        type=Path,
        default=DEFAULT_MAPPING_FILE,
        help=(
            "Path to the OpenSearch index "
            "mapping JSON"
        ),
    )

    parser.add_argument(
        "--index",
        default=None,
        help=(
            "Target index. Defaults to "
            "RISK_OUTPUT_INDEX or "
            "healthcare-risk-events-v2"
        ),
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="OpenSearch bulk batch size",
    )

    parser.add_argument(
        "--recreate-index",
        action="store_true",
        help=(
            "Delete and recreate the target "
            "index before publishing"
        ),
    )

    parser.add_argument(
        "--refresh",
        action="store_true",
        help=(
            "Refresh the index after publishing"
        ),
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Prepare and validate documents "
            "without contacting OpenSearch"
        ),
    )

    return parser


def main() -> int:
    load_dotenv(
        PROJECT_ROOT / ".env"
    )

    parser = build_argument_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s %(levelname)s "
            "%(name)s: %(message)s"
        ),
    )

    scored_output = load_json(
        args.input
    )

    documents = build_final_documents(
        scored_output
    )

    LOGGER.info(
        "Prepared %s unique document(s).",
        len(documents),
    )

    if args.dry_run:
        event_ids = [
            document["event_id"]
            for document in documents
        ]

        if len(event_ids) != len(
            set(event_ids)
        ):
            raise RuntimeError(
                "Duplicate event IDs remain after preparation"
            )

        LOGGER.info(
            "Dry run completed successfully."
        )

        return 0

    mapping = load_json(
        args.mapping
    )

    base_url = str(
        os.getenv(
            "RISK_INDEXER_URL",
            os.getenv(
                "WAZUH_INDEXER_URL",
                "https://localhost:9200",
            ),
        )
    ).strip()

    username = str(
        os.getenv(
            "RISK_INDEXER_USERNAME",
            os.getenv(
                "WAZUH_USERNAME",
                "",
            ),
        )
    ).strip()

    password = str(
        os.getenv(
            "RISK_INDEXER_PASSWORD",
            os.getenv(
                "WAZUH_PASSWORD",
                "",
            ),
        )
    )

    index_name = str(
        args.index
        or os.getenv(
            "RISK_OUTPUT_INDEX",
            DEFAULT_INDEX_NAME,
        )
    ).strip()

    if not base_url:
        raise PushConfigurationError(
            "RISK_INDEXER_URL is empty"
        )

    if not username:
        raise PushConfigurationError(
            (
                "RISK_INDEXER_USERNAME or "
                "WAZUH_USERNAME is required"
            )
        )

    if not password:
        raise PushConfigurationError(
            (
                "RISK_INDEXER_PASSWORD or "
                "WAZUH_PASSWORD is required"
            )
        )

    if not index_name:
        raise PushConfigurationError(
            "Target index name is empty"
        )

    verify_tls = (
        resolve_tls_verification()
    )

    timeout_seconds = int(
        os.getenv(
            "RISK_INDEXER_TIMEOUT_SECONDS",
            "30",
        )
    )

    publisher = OpenSearchPublisher(
        base_url=base_url,
        username=username,
        password=password,
        verify_tls=verify_tls,
        timeout_seconds=timeout_seconds,
    )

    publisher.ensure_index(
        index_name=index_name,
        mapping=mapping,
        recreate=args.recreate_index,
    )

    counters = publisher.bulk_index(
        index_name=index_name,
        documents=documents,
        batch_size=args.batch_size,
    )

    if args.refresh:
        publisher.refresh_index(
            index_name
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
        "Target index: %s",
        index_name,
    )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())

    except (
        PushConfigurationError,
        BulkIndexError,
        FileNotFoundError,
        ValueError,
        RuntimeError,
    ) as exc:
        LOGGER.error("%s", exc)
        raise SystemExit(1)