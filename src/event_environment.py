#!/usr/bin/env python3
"""
Helpers for attaching and validating hospital environment identities.

Every Wazuh and Zeek event should contain an environment_id so telemetry from
different hospitals cannot be accidentally processed with the wrong profile.
"""

from __future__ import annotations

import os
import re
from copy import deepcopy
from typing import Any


ENVIRONMENT_ID_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


class EventEnvironmentError(ValueError):
    """Raised when event environment information is missing or invalid."""


def resolve_environment_id(
    value: str | None = None,
) -> str:
    """
    Resolve and validate an environment ID.

    An explicitly supplied value has priority over the ENVIRONMENT_ID
    environment variable.
    """
    environment_id = str(
        value
        or os.environ.get("ENVIRONMENT_ID")
        or ""
    ).strip().lower()

    if not environment_id:
        raise EventEnvironmentError(
            "Environment ID is required. Use --environment "
            "or set ENVIRONMENT_ID."
        )

    if not ENVIRONMENT_ID_PATTERN.fullmatch(
        environment_id
    ):
        raise EventEnvironmentError(
            "Environment ID may contain only lowercase letters, "
            "numbers and hyphens, must not start or end with a "
            "hyphen, and must be at most 63 characters."
        )

    return environment_id


def get_event_environment(
    event: dict[str, Any],
) -> str | None:
    """
    Read environment_id from a Wazuh/OpenSearch or Zeek event.

    Wazuh events normally keep fields inside _source. Zeek events keep fields
    at the top level.
    """
    if not isinstance(event, dict):
        return None

    source = event.get("_source")

    if isinstance(source, dict):
        value = source.get("environment_id")

        if value not in (None, ""):
            return str(value).strip().lower()

    value = event.get("environment_id")

    if value not in (None, ""):
        return str(value).strip().lower()

    return None


def attach_environment(
    event: dict[str, Any],
    environment_id: str,
) -> dict[str, Any]:
    """
    Return a copy of an event containing the selected environment_id.

    If an event is already tagged with another environment, it is rejected
    instead of silently overwriting the original identity.
    """
    if not isinstance(event, dict):
        raise EventEnvironmentError(
            "Event must be a dictionary"
        )

    validated_environment_id = (
        resolve_environment_id(
            environment_id
        )
    )

    existing_environment_id = (
        get_event_environment(event)
    )

    if (
        existing_environment_id
        and existing_environment_id
        != validated_environment_id
    ):
        raise EventEnvironmentError(
            "Event already belongs to environment "
            f"'{existing_environment_id}' and cannot be "
            f"retagged as '{validated_environment_id}'."
        )

    result = deepcopy(event)

    if isinstance(result.get("_source"), dict):
        result["_source"]["environment_id"] = (
            validated_environment_id
        )
    else:
        result["environment_id"] = (
            validated_environment_id
        )

    return result