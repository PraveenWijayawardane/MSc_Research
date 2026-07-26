#!/usr/bin/env python3
"""
Environment-specific file-path management.

Each hospital receives isolated input, output, and log directories so
telemetry from one environment cannot overwrite another environment's files.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from event_environment import resolve_environment_id


@dataclass(frozen=True)
class EnvironmentPaths:
    """Resolved file paths for one hospital environment."""

    project_root: Path
    environment_id: str

    def __post_init__(self) -> None:
        normalised_root = Path(
            self.project_root
        ).resolve()

        normalised_environment_id = (
            resolve_environment_id(
                self.environment_id
            )
        )

        object.__setattr__(
            self,
            "project_root",
            normalised_root,
        )

        object.__setattr__(
            self,
            "environment_id",
            normalised_environment_id,
        )

    @property
    def data_directory(self) -> Path:
        return (
            self.project_root
            / "data"
            / self.environment_id
        )

    @property
    def output_directory(self) -> Path:
        return (
            self.project_root
            / "output"
            / self.environment_id
        )

    @property
    def logs_directory(self) -> Path:
        return (
            self.project_root
            / "logs"
            / self.environment_id
        )

    @property
    def wazuh_events_file(self) -> Path:
        return (
            self.data_directory
            / "live_wazuh_events.json"
        )

    @property
    def zeek_conn_log_file(self) -> Path:
        return (
            self.data_directory
            / "live_zeek_conn.log"
        )

    @property
    def zeek_conn_json_file(self) -> Path:
        return (
            self.data_directory
            / "live_zeek_conn.json"
        )

    @property
    def scored_events_file(self) -> Path:
        return (
            self.output_directory
            / "scored_events.json"
        )

    @property
    def pipeline_log_file(self) -> Path:
        return (
            self.logs_directory
            / "live_pipeline.log"
        )

    def ensure_directories(self) -> None:
        """Create all environment-specific directories."""
        self.data_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.logs_directory.mkdir(
            parents=True,
            exist_ok=True,
        )