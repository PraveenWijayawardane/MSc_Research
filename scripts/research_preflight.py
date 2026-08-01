#!/usr/bin/env python3
"""Preflight validation for the healthcare risk research pipeline."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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
class CheckResult:
    """Result of one preflight validation."""

    name: str
    status: str
    message: str

    @property
    def passed(self) -> bool:
        return self.status in {"PASS", "WARN"}


@dataclass(frozen=True)
class PreflightSettings:
    """Runtime settings for preflight checks."""

    environment_id: str
    timeout_seconds: int = 15
    max_zeek_age_seconds: int = 300
    repair_stale_lock: bool = False
    skip_opensearch: bool = False
    skip_zeek: bool = False


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def verify_tls_setting() -> bool:
    return parse_bool(
        os.getenv("RISK_INDEXER_VERIFY_TLS")
        or os.getenv("WAZUH_VERIFY_TLS"),
        default=False,
    )


def indexer_url() -> str:
    return (
        os.getenv("RISK_INDEXER_URL")
        or os.getenv("WAZUH_INDEXER_URL")
        or "https://127.0.0.1:9200"
    ).rstrip("/")


def indexer_auth() -> tuple[str, str] | None:
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
        return None
    return username, password


def tcp_reachable(host: str, port: int, timeout_seconds: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True
    except OSError:
        return False


class ResearchPreflight:
    """Validate dependencies required by one environment pipeline."""

    def __init__(
        self,
        *,
        project_root: Path,
        settings: PreflightSettings,
        environment: dict[str, str] | None = None,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.settings = settings
        self.environment_id = resolve_environment_id(settings.environment_id)
        self.environment = dict(os.environ if environment is None else environment)
        self.paths = EnvironmentPaths(
            project_root=self.project_root,
            environment_id=self.environment_id,
        )

    def check_profile(self) -> CheckResult:
        profile_directory = (
            self.project_root / "config" / "environments" / self.environment_id
        )
        required = [
            profile_directory / "asset_context.yaml",
        ]
        missing = [str(path) for path in required if not path.is_file()]
        if missing:
            return CheckResult(
                "Environment profile",
                "FAIL",
                "Missing profile file(s): " + ", ".join(missing),
            )

        active_version = profile_directory / "active_version.json"
        if active_version.is_file():
            try:
                value = load_json_file(active_version, default={})
            except Exception as exc:  # pragma: no cover - defensive
                return CheckResult(
                    "Environment profile",
                    "FAIL",
                    f"Unable to read active version metadata: {exc}",
                )
            version_id = ""
            if isinstance(value, dict):
                version_id = str(
                    value.get("version_id")
                    or value.get("active_version")
                    or ""
                ).strip()
            suffix = f"; active version: {version_id}" if version_id else ""
            return CheckResult(
                "Environment profile",
                "PASS",
                f"Profile exists for {self.environment_id}{suffix}",
            )

        return CheckResult(
            "Environment profile",
            "WARN",
            "Profile exists, but active_version.json is not present",
        )

    def check_directories(self) -> CheckResult:
        try:
            self.paths.ensure_directories()
            probe = self.paths.logs_directory / ".preflight-write-test"
            probe.write_text("ok\n", encoding="utf-8")
            probe.unlink(missing_ok=True)
        except OSError as exc:
            return CheckResult(
                "Pipeline directories",
                "FAIL",
                f"Runtime directories are not writable: {exc}",
            )

        return CheckResult(
            "Pipeline directories",
            "PASS",
            "Data, output, and log directories are ready",
        )

    def check_lock(self) -> CheckResult:
        lock_path = self.paths.pipeline_lock_file
        if not lock_path.is_file():
            return CheckResult(
                "Pipeline lock",
                "PASS",
                "No existing pipeline lock",
            )

        metadata = load_json_file(lock_path, default={})
        try:
            pid = int(metadata.get("pid", 0)) if isinstance(metadata, dict) else 0
        except (TypeError, ValueError):
            pid = 0

        if process_is_running(pid):
            return CheckResult(
                "Pipeline lock",
                "WARN",
                f"A live pipeline already owns the lock (PID {pid})",
            )

        if self.settings.repair_stale_lock:
            lock_path.unlink(missing_ok=True)
            return CheckResult(
                "Pipeline lock",
                "PASS",
                "Removed stale pipeline lock",
            )

        return CheckResult(
            "Pipeline lock",
            "FAIL",
            f"Stale lock detected at {lock_path}; rerun with --repair-stale-lock",
        )

    def check_dashboard(self) -> CheckResult:
        url = (
            self.environment.get("WAZUH_DASHBOARD_URL")
            or os.getenv("WAZUH_DASHBOARD_URL")
            or ""
        ).strip()
        if not url:
            return CheckResult(
                "Wazuh dashboard",
                "WARN",
                "WAZUH_DASHBOARD_URL is not configured; dashboard check skipped",
            )

        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return CheckResult(
                "Wazuh dashboard",
                "FAIL",
                f"Invalid WAZUH_DASHBOARD_URL: {url}",
            )
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not tcp_reachable(host, port, self.settings.timeout_seconds):
            return CheckResult(
                "Wazuh dashboard",
                "FAIL",
                f"Cannot connect to {host}:{port}",
            )
        return CheckResult(
            "Wazuh dashboard",
            "PASS",
            f"Dashboard TCP endpoint is reachable at {host}:{port}",
        )

    def check_opensearch(self) -> CheckResult:
        if self.settings.skip_opensearch:
            return CheckResult(
                "OpenSearch aliases",
                "WARN",
                "OpenSearch checks were skipped",
            )

        url = indexer_url()
        auth = indexer_auth()
        if auth is None:
            return CheckResult(
                "OpenSearch aliases",
                "FAIL",
                "Indexer username or password is missing from .env",
            )

        verify_tls = verify_tls_setting()
        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        read_alias = f"healthcare-risk-events-{self.environment_id}"
        write_alias = f"{read_alias}-write"

        try:
            response = requests.get(
                f"{url}/_alias/{read_alias},{write_alias}",
                auth=auth,
                verify=verify_tls,
                timeout=self.settings.timeout_seconds,
            )
        except requests.RequestException as exc:
            return CheckResult(
                "OpenSearch aliases",
                "FAIL",
                f"Indexer request failed: {exc}",
            )

        if response.status_code == 401:
            return CheckResult(
                "OpenSearch aliases",
                "FAIL",
                "Indexer authentication failed with HTTP 401",
            )
        if response.status_code != 200:
            return CheckResult(
                "OpenSearch aliases",
                "FAIL",
                f"Alias request returned HTTP {response.status_code}: {response.text[:200]}",
            )

        try:
            aliases = response.json()
        except ValueError:
            aliases = {}

        read_found = False
        write_found = False
        for index_metadata in aliases.values() if isinstance(aliases, dict) else []:
            alias_metadata = index_metadata.get("aliases", {})
            if read_alias in alias_metadata:
                read_found = True
            if write_alias in alias_metadata:
                write_found = True

        if not read_found or not write_found:
            return CheckResult(
                "OpenSearch aliases",
                "FAIL",
                f"Alias validation failed: read={read_found}, write={write_found}",
            )

        try:
            source_response = requests.get(
                f"{url}/{os.getenv('WAZUH_INDEX', 'wazuh-alerts-*')}/_count",
                auth=auth,
                verify=verify_tls,
                timeout=self.settings.timeout_seconds,
            )
        except requests.RequestException as exc:
            return CheckResult(
                "OpenSearch aliases",
                "FAIL",
                f"Wazuh source-index request failed: {exc}",
            )

        if source_response.status_code != 200:
            return CheckResult(
                "OpenSearch aliases",
                "FAIL",
                f"Wazuh source index returned HTTP {source_response.status_code}",
            )

        return CheckResult(
            "OpenSearch aliases",
            "PASS",
            f"Read/write aliases and Wazuh source index are reachable through {url}",
        )

    def check_zeek(self) -> CheckResult:
        if self.settings.skip_zeek:
            return CheckResult(
                "Zeek SSH and conn.log",
                "WARN",
                "Zeek checks were skipped",
            )

        host = self.environment.get("ZEEK_SSH_HOST", "").strip()
        user = self.environment.get("ZEEK_SSH_USER", "").strip()
        if not host or not user:
            return CheckResult(
                "Zeek SSH and conn.log",
                "FAIL",
                "ZEEK_SSH_HOST and ZEEK_SSH_USER must be configured",
            )

        port = self.environment.get("ZEEK_SSH_PORT", "22").strip()
        key = self.environment.get("ZEEK_SSH_KEY", "").strip()
        remote_path = self.environment.get(
            "ZEEK_REMOTE_CONN_LOG", "/home/vagrant/conn.log"
        ).strip()
        strict = self.environment.get(
            "ZEEK_STRICT_HOST_KEY_CHECKING", "accept-new"
        ).strip()

        command = [
            self.environment.get("ZEEK_SSH_EXECUTABLE", "ssh"),
            "-o",
            "BatchMode=yes",
            "-o",
            f"StrictHostKeyChecking={strict}",
            "-o",
            f"ConnectTimeout={self.settings.timeout_seconds}",
            "-p",
            port,
        ]
        if key:
            key_path = Path(key).expanduser().resolve()
            if not key_path.is_file():
                return CheckResult(
                    "Zeek SSH and conn.log",
                    "FAIL",
                    f"Zeek SSH key does not exist: {key_path}",
                )
            command.extend(["-i", str(key_path)])

        command.extend(
            [
                f"{user}@{host}",
                f"stat -c '%Y %s' -- {remote_path}",
            ]
        )

        try:
            completed = subprocess.run(
                command,
                cwd=str(self.project_root),
                env=self.environment,
                text=True,
                encoding="utf-8",
                errors="replace",
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.settings.timeout_seconds + 5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return CheckResult(
                "Zeek SSH and conn.log",
                "FAIL",
                f"Zeek SSH validation failed: {exc}",
            )

        if completed.returncode != 0:
            return CheckResult(
                "Zeek SSH and conn.log",
                "FAIL",
                completed.stderr.strip() or "Zeek SSH command failed",
            )

        fields = completed.stdout.strip().split()
        if len(fields) < 2:
            return CheckResult(
                "Zeek SSH and conn.log",
                "FAIL",
                f"Unexpected Zeek stat response: {completed.stdout.strip()}",
            )

        try:
            modified_epoch = int(fields[0])
            size_bytes = int(fields[1])
        except ValueError:
            return CheckResult(
                "Zeek SSH and conn.log",
                "FAIL",
                f"Unable to parse Zeek stat response: {completed.stdout.strip()}",
            )

        age_seconds = max(0, int(time.time() - modified_epoch))
        if size_bytes <= 0:
            return CheckResult(
                "Zeek SSH and conn.log",
                "FAIL",
                f"Remote conn.log is empty: {remote_path}",
            )
        if age_seconds > self.settings.max_zeek_age_seconds:
            return CheckResult(
                "Zeek SSH and conn.log",
                "FAIL",
                f"Remote conn.log is stale ({age_seconds}s old): {remote_path}",
            )

        return CheckResult(
            "Zeek SSH and conn.log",
            "PASS",
            f"Remote conn.log is readable, {size_bytes} bytes, {age_seconds}s old",
        )

    def run(self) -> list[CheckResult]:
        return [
            self.check_profile(),
            self.check_directories(),
            self.check_lock(),
            self.check_dashboard(),
            self.check_opensearch(),
            self.check_zeek(),
        ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate dependencies before starting the healthcare risk pipeline"
    )
    parser.add_argument("--environment", default=os.getenv("ENVIRONMENT_ID", "healthcare-lab"))
    parser.add_argument("--timeout-seconds", type=int, default=15)
    parser.add_argument("--max-zeek-age-seconds", type=int, default=300)
    parser.add_argument("--repair-stale-lock", action="store_true")
    parser.add_argument("--skip-opensearch", action="store_true")
    parser.add_argument("--skip-zeek", action="store_true")
    parser.add_argument("--json", action="store_true", dest="json_output")
    return parser


def main() -> int:
    load_dotenv(PROJECT_ROOT / ".env")
    args = build_parser().parse_args()

    settings = PreflightSettings(
        environment_id=args.environment,
        timeout_seconds=max(1, args.timeout_seconds),
        max_zeek_age_seconds=max(1, args.max_zeek_age_seconds),
        repair_stale_lock=args.repair_stale_lock,
        skip_opensearch=args.skip_opensearch,
        skip_zeek=args.skip_zeek,
    )
    checker = ResearchPreflight(
        project_root=PROJECT_ROOT,
        settings=settings,
    )
    results = checker.run()

    if args.json_output:
        print(json.dumps([asdict(result) for result in results], indent=2))
    else:
        print(f"Research preflight: {checker.environment_id}")
        for result in results:
            print(f"[{result.status}] {result.name}: {result.message}")

    return 0 if all(result.passed for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
