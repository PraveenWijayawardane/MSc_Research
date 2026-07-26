#!/usr/bin/env python3
"""
Environment-isolated OpenSearch index and alias management.

For an environment such as ``healthcare-lab`` and a base index name such as
``healthcare-risk-events``, this module manages:

- read alias:  healthcare-risk-events-healthcare-lab
- write alias: healthcare-risk-events-healthcare-lab-write
- backing index: healthcare-risk-events-healthcare-lab-000001

Dashboards should use the read alias. Publishers should use the write alias.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
import urllib3
import yaml
from dotenv import load_dotenv
from requests import Response, Session
from requests.auth import HTTPBasicAuth

from event_environment import resolve_environment_id


LOGGER = logging.getLogger(
    "opensearch_index_manager"
)

PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]

DEFAULT_CONFIG_ROOT = (
    PROJECT_ROOT / "config"
)

DEFAULT_MAPPING_FILE = (
    DEFAULT_CONFIG_ROOT
    / "base"
    / "opensearch_index_mapping.json"
)

DEFAULT_BASE_INDEX = (
    "healthcare-risk-events"
)

INDEX_NAME_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9._-]{0,254}$"
)


class OpenSearchConfigurationError(
    RuntimeError
):
    """Raised when OpenSearch configuration is invalid."""


class OpenSearchRequestError(
    RuntimeError
):
    """Raised when an OpenSearch request fails."""


@dataclass(frozen=True)
class OpenSearchIndexNames:
    """Names used for one environment's index family."""

    environment_id: str
    base_index: str
    index_prefix: str
    read_alias: str
    write_alias: str
    first_backing_index: str


@dataclass(frozen=True)
class OpenSearchConnectionSettings:
    """Connection settings loaded from environment variables."""

    base_url: str
    username: str
    password: str
    verify_tls: bool | str
    timeout_seconds: int = 30

    @classmethod
    def from_environment(
        cls,
    ) -> "OpenSearchConnectionSettings":
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

        if not base_url:
            raise OpenSearchConfigurationError(
                "RISK_INDEXER_URL or "
                "WAZUH_INDEXER_URL is required"
            )

        if not username:
            raise OpenSearchConfigurationError(
                "RISK_INDEXER_USERNAME or "
                "WAZUH_USERNAME is required"
            )

        if not password:
            raise OpenSearchConfigurationError(
                "RISK_INDEXER_PASSWORD or "
                "WAZUH_PASSWORD is required"
            )

        timeout_raw = str(
            os.getenv(
                "RISK_INDEXER_TIMEOUT_SECONDS",
                "30",
            )
        ).strip()

        try:
            timeout_seconds = int(
                timeout_raw
            )
        except ValueError as exc:
            raise OpenSearchConfigurationError(
                "RISK_INDEXER_TIMEOUT_SECONDS "
                "must be an integer"
            ) from exc

        if timeout_seconds <= 0:
            raise OpenSearchConfigurationError(
                "RISK_INDEXER_TIMEOUT_SECONDS "
                "must be greater than zero"
            )

        return cls(
            base_url=base_url.rstrip("/"),
            username=username,
            password=password,
            verify_tls=(
                resolve_tls_verification()
            ),
            timeout_seconds=(
                timeout_seconds
            ),
        )


def parse_boolean(
    value: Any,
    default: bool = False,
) -> bool:
    """Parse common true and false values."""
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    normalized = str(
        value
    ).strip().lower()

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


def resolve_tls_verification(
) -> bool | str:
    """Resolve TLS verification or a custom CA certificate."""
    ca_certificate = str(
        os.getenv(
            "RISK_INDEXER_CA_CERT",
            "",
        )
    ).strip()

    if ca_certificate:
        ca_path = Path(
            ca_certificate
        ).resolve()

        if not ca_path.is_file():
            raise OpenSearchConfigurationError(
                "RISK_INDEXER_CA_CERT "
                f"does not exist: {ca_path}"
            )

        return str(ca_path)

    return parse_boolean(
        os.getenv(
            "RISK_INDEXER_VERIFY_TLS",
            "false",
        ),
        default=False,
    )


def validate_index_name(
    value: str,
    field_name: str = "index name",
) -> str:
    """Validate and normalize an OpenSearch index or alias name."""
    normalized = str(
        value or ""
    ).strip().lower()

    if not normalized:
        raise OpenSearchConfigurationError(
            f"{field_name} is empty"
        )

    if normalized in {
        ".",
        "..",
    }:
        raise OpenSearchConfigurationError(
            f"Invalid {field_name}: {normalized}"
        )

    if normalized[0] in {
        "_",
        "-",
        "+",
    }:
        raise OpenSearchConfigurationError(
            f"{field_name} cannot start with "
            f"{normalized[0]!r}"
        )

    if not INDEX_NAME_PATTERN.fullmatch(
        normalized
    ):
        raise OpenSearchConfigurationError(
            f"Invalid {field_name}: {normalized!r}"
        )

    return normalized


def build_index_names(
    environment_id: str,
    base_index: str = DEFAULT_BASE_INDEX,
) -> OpenSearchIndexNames:
    """Build deterministic index and alias names."""
    environment_id = resolve_environment_id(
        environment_id
    )

    base_index = validate_index_name(
        base_index,
        "base index",
    )

    suffix = f"-{environment_id}"

    if base_index.endswith(suffix):
        index_prefix = base_index
    else:
        index_prefix = (
            f"{base_index}{suffix}"
        )

    index_prefix = validate_index_name(
        index_prefix,
        "environment index prefix",
    )

    read_alias = index_prefix
    write_alias = validate_index_name(
        f"{index_prefix}-write",
        "write alias",
    )

    first_backing_index = (
        validate_index_name(
            f"{index_prefix}-000001",
            "backing index",
        )
    )

    return OpenSearchIndexNames(
        environment_id=(
            environment_id
        ),
        base_index=base_index,
        index_prefix=index_prefix,
        read_alias=read_alias,
        write_alias=write_alias,
        first_backing_index=(
            first_backing_index
        ),
    )


def load_json_object(
    path: str | Path,
) -> dict[str, Any]:
    """Load a JSON object."""
    resolved = Path(
        path
    ).resolve()

    try:
        with resolved.open(
            "r",
            encoding="utf-8-sig",
        ) as file:
            value = json.load(file)
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"JSON file was not found: {resolved}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise OpenSearchConfigurationError(
            f"Invalid JSON in {resolved}: {exc}"
        ) from exc

    if not isinstance(value, dict):
        raise OpenSearchConfigurationError(
            f"JSON root must be an object: {resolved}"
        )

    return value


def load_environment_base_index(
    environment_id: str,
    config_root: str | Path = DEFAULT_CONFIG_ROOT,
) -> str:
    """
    Read output.index from the active environment configuration.

    RISK_OUTPUT_INDEX_BASE takes priority when set.
    """
    environment_id = resolve_environment_id(
        environment_id
    )

    override = str(
        os.getenv(
            "RISK_OUTPUT_INDEX_BASE",
            "",
        )
    ).strip()

    if override:
        return validate_index_name(
            override,
            "RISK_OUTPUT_INDEX_BASE",
        )

    environment_file = (
        Path(config_root).resolve()
        / "environments"
        / environment_id
        / "environment.yaml"
    )

    if not environment_file.is_file():
        raise FileNotFoundError(
            "Active environment configuration "
            f"was not found: {environment_file}"
        )

    try:
        with environment_file.open(
            "r",
            encoding="utf-8-sig",
        ) as file:
            configuration = (
                yaml.safe_load(file)
            )
    except yaml.YAMLError as exc:
        raise OpenSearchConfigurationError(
            f"Invalid YAML in {environment_file}: "
            f"{exc}"
        ) from exc

    if not isinstance(
        configuration,
        dict,
    ):
        raise OpenSearchConfigurationError(
            "Environment YAML root must "
            f"be an object: {environment_file}"
        )

    output = configuration.get(
        "output",
        {},
    )

    if not isinstance(output, dict):
        raise OpenSearchConfigurationError(
            "environment.output must be an object"
        )

    base_index = str(
        output.get(
            "index",
            DEFAULT_BASE_INDEX,
        )
    ).strip()

    return validate_index_name(
        base_index,
        "environment output.index",
    )


class OpenSearchClient:
    """Small requests-based OpenSearch client."""

    def __init__(
        self,
        settings: OpenSearchConnectionSettings,
        session: Session | None = None,
    ) -> None:
        self.settings = settings
        self.session = (
            session
            if session is not None
            else requests.Session()
        )

        self.session.auth = (
            HTTPBasicAuth(
                settings.username,
                settings.password,
            )
        )

        self.session.headers.update(
            {
                "Accept": (
                    "application/json"
                ),
            }
        )

        if settings.verify_tls is False:
            urllib3.disable_warnings(
                urllib3.exceptions
                .InsecureRequestWarning
            )

    def url(
        self,
        path: str,
    ) -> str:
        return (
            f"{self.settings.base_url}/"
            f"{path.lstrip('/')}"
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        expected_statuses: set[int],
        **kwargs: Any,
    ) -> Response:
        try:
            response = (
                self.session.request(
                    method=method,
                    url=self.url(path),
                    verify=(
                        self.settings
                        .verify_tls
                    ),
                    timeout=(
                        self.settings
                        .timeout_seconds
                    ),
                    **kwargs,
                )
            )
        except requests.RequestException as exc:
            raise OpenSearchRequestError(
                "Unable to communicate with "
                f"OpenSearch at "
                f"{self.settings.base_url}: "
                f"{exc}"
            ) from exc

        if response.status_code not in (
            expected_statuses
        ):
            raise OpenSearchRequestError(
                "OpenSearch request failed: "
                f"{method} {path} returned "
                f"HTTP {response.status_code}: "
                f"{response.text[:2000]}"
            )

        return response

    def index_exists(
        self,
        index_name: str,
    ) -> bool:
        response = self.request(
            "HEAD",
            index_name,
            expected_statuses={
                200,
                404,
            },
        )

        return response.status_code == 200

    def create_index(
        self,
        index_name: str,
        mapping: dict[str, Any],
    ) -> None:
        self.request(
            "PUT",
            index_name,
            expected_statuses={200},
            json=mapping,
        )

    def get_alias(
        self,
        alias_name: str,
    ) -> dict[str, Any]:
        response = self.request(
            "GET",
            f"_alias/{alias_name}",
            expected_statuses={
                200,
                404,
            },
        )

        if response.status_code == 404:
            return {}

        value = response.json()

        if not isinstance(value, dict):
            raise OpenSearchRequestError(
                "Alias response must be an object"
            )

        return value

    def update_aliases(
        self,
        actions: list[dict[str, Any]],
    ) -> None:
        if not actions:
            return

        self.request(
            "POST",
            "_aliases",
            expected_statuses={200},
            json={
                "actions": actions,
            },
        )

    def refresh(
        self,
        target: str,
    ) -> None:
        self.request(
            "POST",
            f"{target}/_refresh",
            expected_statuses={200},
        )

    def count(
        self,
        target: str,
    ) -> int | None:
        response = self.request(
            "GET",
            f"{target}/_count",
            expected_statuses={
                200,
                404,
            },
        )

        if response.status_code == 404:
            return None

        value = response.json()

        try:
            return int(
                value.get("count", 0)
            )
        except (
            AttributeError,
            TypeError,
            ValueError,
        ):
            return None


class OpenSearchIndexManager:
    """Manage one environment's backing index and aliases."""

    def __init__(
        self,
        client: OpenSearchClient,
        names: OpenSearchIndexNames,
        mapping: dict[str, Any],
    ) -> None:
        self.client = client
        self.names = names
        self.mapping = mapping

        if not isinstance(mapping, dict):
            raise OpenSearchConfigurationError(
                "OpenSearch mapping must be an object"
            )

    @staticmethod
    def _indices_from_alias(
        alias_response: dict[str, Any],
    ) -> list[str]:
        return sorted(
            str(index_name)
            for index_name
            in alias_response
        )

    def _write_indices(
        self,
        alias_response: dict[str, Any],
    ) -> list[str]:
        write_indices: list[str] = []

        for index_name, index_data in (
            alias_response.items()
        ):
            aliases = (
                index_data.get(
                    "aliases",
                    {},
                )
                if isinstance(
                    index_data,
                    dict,
                )
                else {}
            )

            alias_settings = (
                aliases.get(
                    self.names.write_alias,
                    {},
                )
                if isinstance(
                    aliases,
                    dict,
                )
                else {}
            )

            if (
                isinstance(
                    alias_settings,
                    dict,
                )
                and alias_settings.get(
                    "is_write_index"
                )
                is True
            ):
                write_indices.append(
                    str(index_name)
                )

        if not write_indices and len(
            alias_response
        ) == 1:
            write_indices = (
                self._indices_from_alias(
                    alias_response
                )
            )

        return sorted(write_indices)

    def ensure(
        self,
    ) -> dict[str, Any]:
        """
        Ensure the first backing index and both aliases exist.

        The operation is idempotent.
        """
        read_response = (
            self.client.get_alias(
                self.names.read_alias
            )
        )

        write_response = (
            self.client.get_alias(
                self.names.write_alias
            )
        )

        read_indices = (
            self._indices_from_alias(
                read_response
            )
        )

        write_indices = (
            self._write_indices(
                write_response
            )
        )

        candidate_index = None

        if write_indices:
            candidate_index = (
                write_indices[-1]
            )
        elif read_indices:
            candidate_index = (
                read_indices[-1]
            )
        else:
            candidate_index = (
                self.names
                .first_backing_index
            )

        created_index = False

        if not self.client.index_exists(
            candidate_index
        ):
            self.client.create_index(
                candidate_index,
                self.mapping,
            )
            created_index = True

        actions: list[
            dict[str, Any]
        ] = []

        if candidate_index not in (
            read_indices
        ):
            actions.append(
                {
                    "add": {
                        "index": candidate_index,
                        "alias": (
                            self.names
                            .read_alias
                        ),
                    }
                }
            )

        if candidate_index not in (
            write_indices
        ):
            for old_write_index in (
                write_indices
            ):
                actions.append(
                    {
                        "add": {
                            "index": (
                                old_write_index
                            ),
                            "alias": (
                                self.names
                                .write_alias
                            ),
                            "is_write_index": (
                                False
                            ),
                        }
                    }
                )

            actions.append(
                {
                    "add": {
                        "index": candidate_index,
                        "alias": (
                            self.names
                            .write_alias
                        ),
                        "is_write_index": (
                            True
                        ),
                    }
                }
            )

        self.client.update_aliases(
            actions
        )

        return {
            "environment_id": (
                self.names
                .environment_id
            ),
            "base_index": (
                self.names.base_index
            ),
            "index_prefix": (
                self.names.index_prefix
            ),
            "read_alias": (
                self.names.read_alias
            ),
            "write_alias": (
                self.names.write_alias
            ),
            "write_index": (
                candidate_index
            ),
            "created_index": (
                created_index
            ),
            "alias_actions": actions,
        }

    def status(
        self,
        include_count: bool = True,
    ) -> dict[str, Any]:
        """Return current alias and backing-index status."""
        read_response = (
            self.client.get_alias(
                self.names.read_alias
            )
        )

        write_response = (
            self.client.get_alias(
                self.names.write_alias
            )
        )

        read_indices = (
            self._indices_from_alias(
                read_response
            )
        )

        write_indices = (
            self._write_indices(
                write_response
            )
        )

        document_count = None

        if (
            include_count
            and read_response
        ):
            document_count = (
                self.client.count(
                    self.names.read_alias
                )
            )

        return {
            "environment_id": (
                self.names.environment_id
            ),
            "base_index": (
                self.names.base_index
            ),
            "index_prefix": (
                self.names.index_prefix
            ),
            "read_alias": (
                self.names.read_alias
            ),
            "write_alias": (
                self.names.write_alias
            ),
            "read_alias_exists": bool(
                read_response
            ),
            "write_alias_exists": bool(
                write_response
            ),
            "read_indices": (
                read_indices
            ),
            "write_indices": (
                write_indices
            ),
            "document_count": (
                document_count
            ),
            "healthy": bool(
                read_response
                and write_response
                and len(write_indices) == 1
            ),
        }


def build_manager(
    environment_id: str,
    *,
    config_root: str | Path = DEFAULT_CONFIG_ROOT,
    mapping_file: str | Path = DEFAULT_MAPPING_FILE,
    base_index: str | None = None,
) -> OpenSearchIndexManager:
    """Create a configured index manager."""
    environment_id = resolve_environment_id(
        environment_id
    )

    resolved_base_index = (
        validate_index_name(
            base_index,
            "base index",
        )
        if base_index
        else load_environment_base_index(
            environment_id,
            config_root,
        )
    )

    names = build_index_names(
        environment_id,
        resolved_base_index,
    )

    mapping = load_json_object(
        mapping_file
    )

    settings = (
        OpenSearchConnectionSettings
        .from_environment()
    )

    client = OpenSearchClient(
        settings
    )

    return OpenSearchIndexManager(
        client=client,
        names=names,
        mapping=mapping,
    )


def build_argument_parser(
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Manage environment-specific "
            "OpenSearch indices and aliases"
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
        "--config-root",
        default=str(
            DEFAULT_CONFIG_ROOT
        ),
        help="Configuration root directory",
    )

    parser.add_argument(
        "--mapping",
        default=str(
            DEFAULT_MAPPING_FILE
        ),
        help="OpenSearch mapping JSON file",
    )

    parser.add_argument(
        "--base-index",
        default=None,
        help=(
            "Optional base index override. "
            "Defaults to environment output.index."
        ),
    )

    action = (
        parser.add_mutually_exclusive_group(
            required=True
        )
    )

    action.add_argument(
        "--ensure",
        action="store_true",
        help=(
            "Create the backing index and aliases "
            "when missing"
        ),
    )

    action.add_argument(
        "--status",
        action="store_true",
        help=(
            "Show index and alias status"
        ),
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON",
    )

    return parser


def main() -> int:
    load_dotenv(
        PROJECT_ROOT / ".env"
    )

    args = (
        build_argument_parser()
        .parse_args()
    )

    environment_id = resolve_environment_id(
        args.environment
    )

    manager = build_manager(
        environment_id,
        config_root=args.config_root,
        mapping_file=args.mapping,
        base_index=args.base_index,
    )

    if args.ensure:
        result = manager.ensure()
    else:
        result = manager.status()

    if args.json:
        print(
            json.dumps(
                result,
                indent=4,
                ensure_ascii=False,
            )
        )
    elif args.ensure:
        print(
            "OpenSearch environment index ensured"
        )
        print()
        print(
            "Environment: "
            f"{result['environment_id']}"
        )
        print(
            "Backing index: "
            f"{result['write_index']}"
        )
        print(
            "Read alias: "
            f"{result['read_alias']}"
        )
        print(
            "Write alias: "
            f"{result['write_alias']}"
        )
        print(
            "Index created: "
            f"{result['created_index']}"
        )
    else:
        print(
            "OpenSearch environment index status"
        )
        print()
        print(
            "Environment: "
            f"{result['environment_id']}"
        )
        print(
            "Read alias: "
            f"{result['read_alias']}"
        )
        print(
            "Write alias: "
            f"{result['write_alias']}"
        )
        print(
            "Read indices: "
            + (
                ", ".join(
                    result[
                        "read_indices"
                    ]
                )
                or "none"
            )
        )
        print(
            "Write indices: "
            + (
                ", ".join(
                    result[
                        "write_indices"
                    ]
                )
                or "none"
            )
        )
        print(
            "Document count: "
            f"{result['document_count']}"
        )
        print(
            "Healthy: "
            f"{result['healthy']}"
        )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        FileNotFoundError,
        OpenSearchConfigurationError,
        OpenSearchRequestError,
        ValueError,
    ) as exc:
        LOGGER.error("%s", exc)
        raise SystemExit(1)