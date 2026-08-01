#!/usr/bin/env python3
"""Health check for the environment-aware healthcare risk pipeline."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import urllib3
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
SCRIPTS_ROOT = PROJECT_ROOT / "scripts"

for candidate in (SRC_ROOT, SCRIPTS_ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from environment_paths import EnvironmentPaths  # noqa: E402
from event_environment import resolve_environment_id  # noqa: E402
from live_pipeline import load_json_file, process_is_running  # noqa: E402


@dataclass(frozen=True)
class HealthResult:
    name: str
    status: str
    message: str

    @property
    def healthy(self) -> bool:
        return self.status in {"HEALTHY", "WARN"}


def parse_iso8601(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def age_seconds_from_datetime(value: datetime, now: datetime | None = None) -> int:
    reference = now or datetime.now(timezone.utc)
    return max(0, int((reference - value).total_seconds()))


def file_age_seconds(path: Path) -> int | None:
    if not path.is_file():
        return None
    return max(0, int(time.time() - path.stat().st_mtime))


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class PipelineHealthChecker:
    def __init__(
        self,
        *,
        project_root: Path,
        environment_id: str,
        max_cycle_age_seconds: int = 180,
        max_input_age_seconds: int = 300,
        max_output_age_seconds: int = 300,
        max_index_age_seconds: int = 900,
        skip_opensearch: bool = False,
        require_recent_index_event: bool = False,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.environment_id = resolve_environment_id(environment_id)
        self.paths = EnvironmentPaths(
            project_root=self.project_root,
            environment_id=self.environment_id,
        )
        self.max_cycle_age_seconds = max_cycle_age_seconds
        self.max_input_age_seconds = max_input_age_seconds
        self.max_output_age_seconds = max_output_age_seconds
        self.max_index_age_seconds = max_index_age_seconds
        self.skip_opensearch = skip_opensearch
        self.require_recent_index_event = require_recent_index_event

    def check_process(self) -> HealthResult:
        lock_path = self.paths.pipeline_lock_file
        if not lock_path.is_file():
            return HealthResult(
                "Pipeline process",
                "UNHEALTHY",
                "Pipeline lock is missing; continuous pipeline is not running",
            )

        metadata = load_json_file(lock_path, default={})
        try:
            pid = int(metadata.get("pid", 0)) if isinstance(metadata, dict) else 0
        except (TypeError, ValueError):
            pid = 0

        if not process_is_running(pid):
            return HealthResult(
                "Pipeline process",
                "UNHEALTHY",
                f"Pipeline lock references a stopped process (PID {pid})",
            )

        return HealthResult(
            "Pipeline process",
            "HEALTHY",
            f"Continuous pipeline process is running (PID {pid})",
        )

    def check_state(self) -> HealthResult:
        state_path = self.paths.pipeline_state_file
        if not state_path.is_file():
            return HealthResult(
                "Pipeline state",
                "UNHEALTHY",
                f"State file is missing: {state_path}",
            )

        state = load_json_file(state_path, default={})
        if not isinstance(state, dict):
            return HealthResult(
                "Pipeline state",
                "UNHEALTHY",
                "State file does not contain a JSON object",
            )

        status = str(state.get("status", "")).lower()
        completed = parse_iso8601(str(state.get("last_completed_at") or ""))
        if completed is None:
            return HealthResult(
                "Pipeline state",
                "UNHEALTHY",
                "last_completed_at is missing or invalid",
            )

        age = age_seconds_from_datetime(completed)
        if status != "success":
            return HealthResult(
                "Pipeline state",
                "UNHEALTHY",
                f"Latest cycle status is {status or 'unknown'}; error={state.get('error')}",
            )
        if age > self.max_cycle_age_seconds:
            return HealthResult(
                "Pipeline state",
                "UNHEALTHY",
                f"Latest successful cycle is stale ({age}s old)",
            )

        failed_steps = []
        for step in state.get("steps", []):
            if isinstance(step, dict) and step.get("status") == "failed":
                failed_steps.append(str(step.get("name", "unknown")))
        if failed_steps:
            return HealthResult(
                "Pipeline state",
                "UNHEALTHY",
                "Latest cycle contains failed steps: " + ", ".join(failed_steps),
            )

        return HealthResult(
            "Pipeline state",
            "HEALTHY",
            f"Latest successful cycle completed {age}s ago",
        )

    def check_file(self, name: str, path: Path, maximum_age: int) -> HealthResult:
        age = file_age_seconds(path)
        if age is None:
            return HealthResult(name, "UNHEALTHY", f"File is missing: {path}")
        if path.stat().st_size <= 0:
            return HealthResult(name, "UNHEALTHY", f"File is empty: {path}")
        if age > maximum_age:
            return HealthResult(name, "UNHEALTHY", f"File is stale ({age}s old): {path}")
        return HealthResult(
            name,
            "HEALTHY",
            f"File is {age}s old and {path.stat().st_size} bytes",
        )

    def check_opensearch(self) -> HealthResult:
        if self.skip_opensearch:
            return HealthResult(
                "OpenSearch latest event",
                "WARN",
                "OpenSearch freshness check was skipped",
            )

        url = (
            os.getenv("RISK_INDEXER_URL")
            or os.getenv("WAZUH_INDEXER_URL")
            or "https://127.0.0.1:9200"
        ).rstrip("/")
        username = (
            os.getenv("RISK_INDEXER_USERNAME")
            or os.getenv("WAZUH_USERNAME")
            or ""
        ).strip()
        password = (
            os.getenv("RISK_INDEXER_PASSWORD")
            or os.getenv("WAZUH_PASSWORD")
            or ""
        )
        if not username or not password:
            return HealthResult(
                "OpenSearch latest event",
                "UNHEALTHY",
                "Indexer credentials are missing",
            )

        verify_tls = parse_bool(
            os.getenv("RISK_INDEXER_VERIFY_TLS")
            or os.getenv("WAZUH_VERIFY_TLS"),
            default=False,
        )
        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        alias = f"healthcare-risk-events-{self.environment_id}"
        body = {
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "_source": ["@timestamp", "event_source", "environment_id"],
        }

        try:
            response = requests.get(
                f"{url}/{alias}/_search",
                auth=(username, password),
                verify=verify_tls,
                timeout=15,
                json=body,
            )
        except requests.RequestException as exc:
            return HealthResult(
                "OpenSearch latest event",
                "UNHEALTHY",
                f"OpenSearch query failed: {exc}",
            )

        if response.status_code != 200:
            return HealthResult(
                "OpenSearch latest event",
                "UNHEALTHY",
                f"OpenSearch returned HTTP {response.status_code}: {response.text[:200]}",
            )

        try:
            payload: dict[str, Any] = response.json()
            hits = payload.get("hits", {}).get("hits", [])
        except (ValueError, AttributeError):
            hits = []

        if not hits:
            status = "UNHEALTHY" if self.require_recent_index_event else "WARN"
            return HealthResult(
                "OpenSearch latest event",
                status,
                f"No documents are present in {alias}",
            )

        timestamp = parse_iso8601(str(hits[0].get("_source", {}).get("@timestamp") or ""))
        if timestamp is None:
            return HealthResult(
                "OpenSearch latest event",
                "UNHEALTHY",
                "Newest document has no valid @timestamp",
            )

        age = age_seconds_from_datetime(timestamp)
        if age > self.max_index_age_seconds:
            status = "UNHEALTHY" if self.require_recent_index_event else "WARN"
            return HealthResult(
                "OpenSearch latest event",
                status,
                f"Newest indexed event is {age}s old",
            )

        return HealthResult(
            "OpenSearch latest event",
            "HEALTHY",
            f"Newest indexed event is {age}s old",
        )

    def run(self) -> list[HealthResult]:
        return [
            self.check_process(),
            self.check_state(),
            self.check_file(
                "Wazuh input",
                self.paths.wazuh_events_file,
                self.max_input_age_seconds,
            ),
            self.check_file(
                "Zeek input",
                self.paths.zeek_conn_log_file,
                self.max_input_age_seconds,
            ),
            self.check_file(
                "Scored output",
                self.paths.scored_events_file,
                self.max_output_age_seconds,
            ),
            self.check_opensearch(),
        ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check live-pipeline health")
    parser.add_argument("--environment", default=os.getenv("ENVIRONMENT_ID", "healthcare-lab"))
    parser.add_argument("--max-cycle-age-seconds", type=int, default=180)
    parser.add_argument("--max-input-age-seconds", type=int, default=300)
    parser.add_argument("--max-output-age-seconds", type=int, default=300)
    parser.add_argument("--max-index-age-seconds", type=int, default=900)
    parser.add_argument("--skip-opensearch", action="store_true")
    parser.add_argument("--require-recent-index-event", action="store_true")
    parser.add_argument("--json", action="store_true", dest="json_output")
    return parser


def main() -> int:
    load_dotenv(PROJECT_ROOT / ".env")
    args = build_parser().parse_args()
    checker = PipelineHealthChecker(
        project_root=PROJECT_ROOT,
        environment_id=args.environment,
        max_cycle_age_seconds=max(1, args.max_cycle_age_seconds),
        max_input_age_seconds=max(1, args.max_input_age_seconds),
        max_output_age_seconds=max(1, args.max_output_age_seconds),
        max_index_age_seconds=max(1, args.max_index_age_seconds),
        skip_opensearch=args.skip_opensearch,
        require_recent_index_event=args.require_recent_index_event,
    )
    results = checker.run()

    if args.json_output:
        print(json.dumps([asdict(result) for result in results], indent=2))
    else:
        print(f"Pipeline health: {checker.environment_id}")
        for result in results:
            print(f"[{result.status}] {result.name}: {result.message}")

    return 0 if all(result.healthy for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
