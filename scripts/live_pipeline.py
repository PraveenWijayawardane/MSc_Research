#!/usr/bin/env python3
"""
Environment-aware live pipeline orchestrator.

Pipeline sequence:

1. Collect recent Wazuh alerts.
2. Obtain the Zeek conn.log using a local source or non-interactive SCP.
3. Parse Zeek conn.log.
4. Run contextual risk scoring and correlation.
5. Publish through the environment-specific OpenSearch write alias.
6. Persist environment-specific logs and execution state.

The pipeline can run once or continuously. A per-environment lock prevents two
instances from processing the same hospital at the same time.
"""

from __future__ import annotations

import argparse
import json
import logging
from logging.handlers import TimedRotatingFileHandler
import os
import shutil
import socket
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from dotenv import load_dotenv


PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]

SRC_ROOT = PROJECT_ROOT / "src"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(SRC_ROOT),
    )


from environment_paths import EnvironmentPaths  # noqa: E402
from event_environment import resolve_environment_id  # noqa: E402


LOGGER_NAME = "live_pipeline"
LOGGER = logging.getLogger(LOGGER_NAME)


class PipelineError(RuntimeError):
    """Base error for pipeline operations."""


class PipelineLockError(PipelineError):
    """Raised when another pipeline instance owns the environment lock."""


class PipelineStepError(PipelineError):
    """Raised when one pipeline step fails."""


class CommandRunner(Protocol):
    """Protocol used to execute external commands."""

    def run(
        self,
        command: list[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int | None,
    ) -> "CommandResult":
        ...


@dataclass(frozen=True)
class CommandResult:
    """Result of one external command."""

    command: list[str]
    return_code: int
    stdout: str
    stderr: str
    duration_seconds: float


class SubprocessCommandRunner:
    """Execute commands with captured output and no interactive input."""

    def run(
        self,
        command: list[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int | None,
    ) -> CommandResult:
        started = time.monotonic()

        try:
            completed = subprocess.run(
                command,
                cwd=str(cwd),
                env=dict(environment),
                text=True,
                encoding="utf-8",
                errors="replace",
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            duration = (
                time.monotonic()
                - started
            )

            raise PipelineStepError(
                "Command timed out after "
                f"{timeout_seconds} second(s): "
                + format_command(command)
            ) from exc
        except OSError as exc:
            raise PipelineStepError(
                "Unable to start command: "
                + format_command(command)
                + f": {exc}"
            ) from exc

        duration = (
            time.monotonic()
            - started
        )

        return CommandResult(
            command=list(command),
            return_code=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            duration_seconds=round(
                duration,
                3,
            ),
        )


@dataclass(frozen=True)
class PipelineOptions:
    """Runtime options for one pipeline cycle."""

    wazuh_size: int = 100
    command_timeout_seconds: int = 120
    scp_timeout_seconds: int = 30
    skip_wazuh: bool = False
    skip_zeek: bool = False
    skip_zeek_copy: bool = False
    skip_publish: bool = False
    dry_run: bool = False
    refresh: bool = True
    zeek_local_source: Path | None = None


@dataclass
class StepRecord:
    """Execution information for one pipeline step."""

    name: str
    status: str
    started_at: str
    completed_at: str | None = None
    duration_seconds: float | None = None
    command: list[str] = field(
        default_factory=list
    )
    message: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "command": list(self.command),
            "message": self.message,
        }


def utc_now() -> datetime:
    """Return a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def utc_iso() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return (
        utc_now()
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def format_command(
    command: list[str],
) -> str:
    """Format a command for logs without invoking a shell."""
    return " ".join(
        subprocess.list2cmdline(
            [part]
        )
        for part in command
    )


def atomic_write_json(
    path: Path,
    value: Any,
) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = path.with_suffix(
        path.suffix + ".tmp"
    )

    with temporary.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        json.dump(
            value,
            file,
            indent=4,
            ensure_ascii=False,
            default=str,
        )
        file.write("\n")

    temporary.replace(path)


def load_json_file(
    path: Path,
    default: Any = None,
) -> Any:
    """Load JSON, returning a default only when the file is absent."""
    if not path.is_file():
        return default

    try:
        with path.open(
            "r",
            encoding="utf-8-sig",
        ) as file:
            return json.load(file)
    except json.JSONDecodeError as exc:
        raise PipelineError(
            f"Invalid JSON in {path}: {exc}"
        ) from exc


def count_json_list(
    path: Path,
) -> int:
    value = load_json_file(
        path,
        default=[],
    )

    if isinstance(value, list):
        return len(value)

    if isinstance(value, dict):
        hits = (
            value.get("hits", {})
            if isinstance(
                value.get("hits"),
                dict,
            )
            else {}
        )

        nested_hits = hits.get(
            "hits",
            [],
        )

        if isinstance(
            nested_hits,
            list,
        ):
            return len(nested_hits)

    return 0


def scored_output_counts(
    path: Path,
) -> dict[str, int]:
    """Calculate risk-engine output counters."""
    value = load_json_file(
        path,
        default={},
    )

    if not isinstance(value, dict):
        return {
            "wazuh_results": 0,
            "zeek_results": 0,
            "correlated_results": 0,
            "published_documents": 0,
        }

    wazuh = value.get(
        "wazuh_results",
        [],
    )
    zeek = value.get(
        "zeek_results",
        [],
    )
    correlated = value.get(
        "correlated_results",
        [],
    )

    wazuh = (
        wazuh
        if isinstance(wazuh, list)
        else []
    )
    zeek = (
        zeek
        if isinstance(zeek, list)
        else []
    )
    correlated = (
        correlated
        if isinstance(correlated, list)
        else []
    )

    wazuh_ids = {
        str(event.get("event_id"))
        for event in wazuh
        if (
            isinstance(event, dict)
            and event.get("event_id")
        )
    }

    network_by_id: dict[
        str,
        dict[str, Any],
    ] = {}

    for event in zeek:
        if (
            isinstance(event, dict)
            and event.get("event_id")
        ):
            network_by_id[
                str(event["event_id"])
            ] = event

    for event in correlated:
        if (
            isinstance(event, dict)
            and event.get("event_id")
        ):
            network_by_id[
                str(event["event_id"])
            ] = event

    published_documents = (
        len(wazuh_ids)
        + len(network_by_id)
    )

    return {
        "wazuh_results": len(wazuh),
        "zeek_results": len(zeek),
        "correlated_results": len(
            correlated
        ),
        "published_documents": (
            published_documents
        ),
    }


def process_is_running(
    process_id: int,
) -> bool:
    """
    Return whether a process appears to be running.

    On POSIX, signal 0 is a non-destructive existence check. On Windows,
    signal value 0 is CTRL_C_EVENT, so os.kill(pid, 0) must not be used.
    Windows process state is checked through OpenProcess and
    GetExitCodeProcess instead.
    """
    if process_id <= 0:
        return False

    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        process_query_limited_information = (
            0x1000
        )
        still_active = 259
        error_access_denied = 5

        kernel32 = ctypes.WinDLL(
            "kernel32",
            use_last_error=True,
        )

        open_process = (
            kernel32.OpenProcess
        )
        open_process.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        open_process.restype = (
            wintypes.HANDLE
        )

        get_exit_code_process = (
            kernel32.GetExitCodeProcess
        )
        get_exit_code_process.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(
                wintypes.DWORD
            ),
        ]
        get_exit_code_process.restype = (
            wintypes.BOOL
        )

        close_handle = (
            kernel32.CloseHandle
        )
        close_handle.argtypes = [
            wintypes.HANDLE,
        ]
        close_handle.restype = (
            wintypes.BOOL
        )

        handle = open_process(
            process_query_limited_information,
            False,
            process_id,
        )

        if not handle:
            return (
                ctypes.get_last_error()
                == error_access_denied
            )

        try:
            exit_code = wintypes.DWORD()

            if not get_exit_code_process(
                handle,
                ctypes.byref(
                    exit_code
                ),
            ):
                return False

            return (
                exit_code.value
                == still_active
            )
        finally:
            close_handle(handle)

    try:
        os.kill(
            process_id,
            0,
        )
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False

    return True


class PipelineLock:
    """Exclusive file lock implemented with atomic file creation."""

    def __init__(
        self,
        path: Path,
        environment_id: str,
    ) -> None:
        self.path = path
        self.environment_id = (
            environment_id
        )
        self.acquired = False

    def _existing_metadata(
        self,
    ) -> dict[str, Any]:
        value = load_json_file(
            self.path,
            default={},
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    def acquire(self) -> None:
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        while True:
            try:
                descriptor = os.open(
                    self.path,
                    (
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                    ),
                )
            except FileExistsError:
                metadata = (
                    self._existing_metadata()
                )

                try:
                    owner_pid = int(
                        metadata.get(
                            "pid",
                            0,
                        )
                    )
                except (
                    TypeError,
                    ValueError,
                ):
                    owner_pid = 0

                if process_is_running(
                    owner_pid
                ):
                    raise PipelineLockError(
                        "A live pipeline is already "
                        "running for environment "
                        f"{self.environment_id}. "
                        f"PID: {owner_pid}"
                    )

                LOGGER.warning(
                    "Removing stale pipeline lock: %s",
                    self.path,
                )

                try:
                    self.path.unlink()
                except FileNotFoundError:
                    pass

                continue

            try:
                metadata = {
                    "environment_id": (
                        self.environment_id
                    ),
                    "pid": os.getpid(),
                    "hostname": (
                        socket.gethostname()
                    ),
                    "acquired_at": (
                        utc_iso()
                    ),
                }

                os.write(
                    descriptor,
                    (
                        json.dumps(
                            metadata,
                            indent=4,
                        )
                        + "\n"
                    ).encode("utf-8"),
                )
            finally:
                os.close(descriptor)

            self.acquired = True
            return

    def release(self) -> None:
        if not self.acquired:
            return

        try:
            metadata = (
                self._existing_metadata()
            )

            lock_pid = int(
                metadata.get(
                    "pid",
                    0,
                )
            )

            if lock_pid in {
                0,
                os.getpid(),
            }:
                self.path.unlink(
                    missing_ok=True
                )
        finally:
            self.acquired = False

    def __enter__(
        self,
    ) -> "PipelineLock":
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: Any,
        exc_value: Any,
        exc_traceback: Any,
    ) -> None:
        self.release()


class LivePipeline:
    """Run the complete healthcare risk pipeline for one environment."""

    def __init__(
        self,
        *,
        project_root: Path,
        environment_id: str,
        python_executable: str | Path = sys.executable,
        runner: CommandRunner | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self.project_root = Path(
            project_root
        ).resolve()

        self.environment_id = (
            resolve_environment_id(
                environment_id
            )
        )

        self.python_executable = str(
            python_executable
        )

        self.runner = (
            runner
            if runner is not None
            else SubprocessCommandRunner()
        )

        self.environment = dict(
            os.environ
            if environment is None
            else environment
        )

        self.environment[
            "ENVIRONMENT_ID"
        ] = self.environment_id

        self.paths = EnvironmentPaths(
            project_root=self.project_root,
            environment_id=(
                self.environment_id
            ),
        )

        self.paths.ensure_directories()

    def python_command(
        self,
        relative_script: str,
        *arguments: str,
    ) -> list[str]:
        return [
            self.python_executable,
            str(
                self.project_root
                / relative_script
            ),
            *arguments,
        ]

    def _log_command_result(
        self,
        step_name: str,
        result: CommandResult,
    ) -> None:
        if result.stdout.strip():
            for line in (
                result.stdout.strip()
                .splitlines()
            ):
                LOGGER.info(
                    "[%s] %s",
                    step_name,
                    line,
                )

        if result.stderr.strip():
            log_method = (
                LOGGER.error
                if result.return_code
                else LOGGER.info
            )

            for line in (
                result.stderr.strip()
                .splitlines()
            ):
                log_method(
                    "[%s] %s",
                    step_name,
                    line,
                )

    def run_command_step(
        self,
        *,
        step_name: str,
        command: list[str],
        timeout_seconds: int,
        steps: list[StepRecord],
    ) -> CommandResult:
        started_at = utc_iso()
        started_monotonic = (
            time.monotonic()
        )

        record = StepRecord(
            name=step_name,
            status="running",
            started_at=started_at,
            command=list(command),
        )

        steps.append(record)

        LOGGER.info(
            "Starting step %s: %s",
            step_name,
            format_command(command),
        )

        result = self.runner.run(
            command,
            cwd=self.project_root,
            environment=self.environment,
            timeout_seconds=(
                timeout_seconds
            ),
        )

        record.completed_at = utc_iso()
        record.duration_seconds = round(
            time.monotonic()
            - started_monotonic,
            3,
        )

        self._log_command_result(
            step_name,
            result,
        )

        if result.return_code != 0:
            record.status = "failed"
            record.message = (
                result.stderr.strip()
                or result.stdout.strip()
                or (
                    "Command returned "
                    f"{result.return_code}"
                )
            )

            raise PipelineStepError(
                f"Pipeline step {step_name!r} "
                "failed with return code "
                f"{result.return_code}: "
                f"{record.message}"
            )

        record.status = "success"
        record.message = (
            f"Completed in "
            f"{record.duration_seconds} second(s)"
        )

        LOGGER.info(
            "Completed step %s in %.3f second(s)",
            step_name,
            record.duration_seconds,
        )

        return result

    def _copy_local_zeek_log(
        self,
        source: Path,
        steps: list[StepRecord],
    ) -> None:
        source = source.resolve()

        if not source.is_file():
            raise PipelineStepError(
                "Zeek local source file "
                f"was not found: {source}"
            )

        started_at = utc_iso()
        started = time.monotonic()

        destination = (
            self.paths
            .zeek_conn_log_file
        )

        temporary = destination.with_suffix(
            destination.suffix + ".tmp"
        )

        shutil.copy2(
            source,
            temporary,
        )

        temporary.replace(
            destination
        )

        duration = round(
            time.monotonic() - started,
            3,
        )

        steps.append(
            StepRecord(
                name="collect_zeek_log",
                status="success",
                started_at=started_at,
                completed_at=utc_iso(),
                duration_seconds=duration,
                command=[
                    "copy",
                    str(source),
                    str(destination),
                ],
                message=(
                    "Copied local Zeek log"
                ),
            )
        )

        LOGGER.info(
            "Copied Zeek log from %s to %s",
            source,
            destination,
        )

    def _build_scp_command(
        self,
        options: PipelineOptions,
    ) -> list[str] | None:
        host = str(
            self.environment.get(
                "ZEEK_SSH_HOST",
                "",
            )
        ).strip()

        user = str(
            self.environment.get(
                "ZEEK_SSH_USER",
                "",
            )
        ).strip()

        if not host or not user:
            return None

        remote_path = str(
            self.environment.get(
                "ZEEK_REMOTE_CONN_LOG",
                "/home/vagrant/conn.log",
            )
        ).strip()

        key_path = str(
            self.environment.get(
                "ZEEK_SSH_KEY",
                "",
            )
        ).strip()

        port = str(
            self.environment.get(
                "ZEEK_SSH_PORT",
                "22",
            )
        ).strip()

        scp_executable = str(
            self.environment.get(
                "ZEEK_SCP_EXECUTABLE",
                "scp",
            )
        ).strip()

        command = [
            scp_executable,
            "-o",
            "BatchMode=yes",
            "-o",
            (
                "StrictHostKeyChecking="
                + str(
                    self.environment.get(
                        "ZEEK_STRICT_HOST_KEY_CHECKING",
                        "accept-new",
                    )
                ).strip()
            ),
            "-o",
            (
                "ConnectTimeout="
                f"{options.scp_timeout_seconds}"
            ),
            "-P",
            port,
        ]

        if key_path:
            key = Path(
                key_path
            ).expanduser().resolve()

            if not key.is_file():
                raise PipelineStepError(
                    "ZEEK_SSH_KEY was not found: "
                    f"{key}"
                )

            command.extend(
                [
                    "-i",
                    str(key),
                ]
            )

        temporary_destination = (
            self.paths
            .zeek_conn_log_file
            .with_suffix(
                self.paths
                .zeek_conn_log_file
                .suffix
                + ".download"
            )
        )

        command.extend(
            [
                f"{user}@{host}:{remote_path}",
                str(temporary_destination),
            ]
        )

        return command

    def collect_zeek_log(
        self,
        options: PipelineOptions,
        steps: list[StepRecord],
    ) -> None:
        if options.zeek_local_source:
            self._copy_local_zeek_log(
                options.zeek_local_source,
                steps,
            )
            return

        scp_command = (
            self._build_scp_command(
                options
            )
        )

        if scp_command is not None:
            temporary_destination = (
                self.paths
                .zeek_conn_log_file
                .with_suffix(
                    self.paths
                    .zeek_conn_log_file
                    .suffix
                    + ".download"
                )
            )

            temporary_destination.unlink(
                missing_ok=True
            )

            self.run_command_step(
                step_name=(
                    "collect_zeek_log"
                ),
                command=scp_command,
                timeout_seconds=(
                    options
                    .command_timeout_seconds
                ),
                steps=steps,
            )

            if not temporary_destination.is_file():
                raise PipelineStepError(
                    "SCP reported success but the "
                    "downloaded Zeek log was not found: "
                    f"{temporary_destination}"
                )

            temporary_destination.replace(
                self.paths
                .zeek_conn_log_file
            )
            return

        if (
            self.paths
            .zeek_conn_log_file
            .is_file()
        ):
            steps.append(
                StepRecord(
                    name="collect_zeek_log",
                    status="skipped",
                    started_at=utc_iso(),
                    completed_at=utc_iso(),
                    duration_seconds=0.0,
                    command=[],
                    message=(
                        "No Zeek SSH settings "
                        "provided; using existing "
                        "environment-specific "
                        "conn.log"
                    ),
                )
            )

            LOGGER.warning(
                "No Zeek SSH settings provided; "
                "using existing file: %s",
                self.paths
                .zeek_conn_log_file,
            )
            return

        raise PipelineStepError(
            "No Zeek source is available. "
            "Provide --zeek-local-source, set "
            "ZEEK_SSH_HOST and ZEEK_SSH_USER, "
            "or place conn.log at "
            f"{self.paths.zeek_conn_log_file}"
        )

    def validate_required_inputs(
        self,
        options: PipelineOptions,
    ) -> None:
        required: list[
            tuple[str, Path]
        ] = []

        required.append(
            (
                "Wazuh events",
                self.paths
                .wazuh_events_file,
            )
        )

        required.append(
            (
                "Zeek parsed events",
                self.paths
                .zeek_conn_json_file,
            )
        )

        missing = [
            f"{label}: {path}"
            for label, path in required
            if not path.is_file()
        ]

        if missing:
            raise PipelineStepError(
                "Required risk-engine input "
                "file(s) are missing:\n- "
                + "\n- ".join(missing)
            )

    def state_snapshot(
        self,
        *,
        status: str,
        cycle_started_at: str,
        cycle_completed_at: str | None,
        duration_seconds: float | None,
        steps: list[StepRecord],
        error: str | None = None,
    ) -> dict[str, Any]:
        score_counts = (
            scored_output_counts(
                self.paths
                .scored_events_file
            )
        )

        return {
            "schema_version": "1.0",
            "environment_id": (
                self.environment_id
            ),
            "pid": os.getpid(),
            "hostname": (
                socket.gethostname()
            ),
            "status": status,
            "last_started_at": (
                cycle_started_at
            ),
            "last_completed_at": (
                cycle_completed_at
            ),
            "duration_seconds": (
                duration_seconds
            ),
            "wazuh_events": (
                count_json_list(
                    self.paths
                    .wazuh_events_file
                )
            ),
            "zeek_events": (
                count_json_list(
                    self.paths
                    .zeek_conn_json_file
                )
            ),
            "wazuh_results": (
                score_counts[
                    "wazuh_results"
                ]
            ),
            "zeek_results": (
                score_counts[
                    "zeek_results"
                ]
            ),
            "correlated_events": (
                score_counts[
                    "correlated_results"
                ]
            ),
            "published_documents": (
                score_counts[
                    "published_documents"
                ]
            ),
            "error": error,
            "steps": [
                step.as_dict()
                for step in steps
            ],
        }

    def write_state(
        self,
        state: dict[str, Any],
    ) -> None:
        atomic_write_json(
            self.paths
            .pipeline_state_file,
            state,
        )

    def run_cycle(
        self,
        options: PipelineOptions,
    ) -> dict[str, Any]:
        """Run one complete pipeline cycle."""
        cycle_started_at = utc_iso()
        cycle_started = time.monotonic()
        steps: list[StepRecord] = []

        running_state = (
            self.state_snapshot(
                status="running",
                cycle_started_at=(
                    cycle_started_at
                ),
                cycle_completed_at=None,
                duration_seconds=None,
                steps=steps,
            )
        )

        self.write_state(
            running_state
        )

        try:
            if options.skip_wazuh:
                steps.append(
                    StepRecord(
                        name=(
                            "collect_wazuh"
                        ),
                        status="skipped",
                        started_at=utc_iso(),
                        completed_at=utc_iso(),
                        duration_seconds=0.0,
                        message=(
                            "Using existing Wazuh "
                            "events file"
                        ),
                    )
                )
            else:
                self.run_command_step(
                    step_name=(
                        "collect_wazuh"
                    ),
                    command=(
                        self.python_command(
                            "src/"
                            "wazuh_live_collector.py",
                            "--environment",
                            self.environment_id,
                            "--size",
                            str(
                                options
                                .wazuh_size
                            ),
                        )
                    ),
                    timeout_seconds=(
                        options
                        .command_timeout_seconds
                    ),
                    steps=steps,
                )

            if options.skip_zeek:
                steps.append(
                    StepRecord(
                        name="zeek_pipeline",
                        status="skipped",
                        started_at=utc_iso(),
                        completed_at=utc_iso(),
                        duration_seconds=0.0,
                        message=(
                            "Using existing parsed "
                            "Zeek events file"
                        ),
                    )
                )
            else:
                if options.skip_zeek_copy:
                    if not (
                        self.paths
                        .zeek_conn_log_file
                        .is_file()
                    ):
                        raise PipelineStepError(
                            "--skip-zeek-copy was "
                            "provided, but the "
                            "environment-specific "
                            "conn.log does not exist: "
                            f"{self.paths.zeek_conn_log_file}"
                        )

                    steps.append(
                        StepRecord(
                            name=(
                                "collect_zeek_log"
                            ),
                            status="skipped",
                            started_at=utc_iso(),
                            completed_at=utc_iso(),
                            duration_seconds=0.0,
                            message=(
                                "Using existing Zeek "
                                "conn.log"
                            ),
                        )
                    )
                else:
                    self.collect_zeek_log(
                        options,
                        steps,
                    )

                self.run_command_step(
                    step_name="parse_zeek",
                    command=(
                        self.python_command(
                            "src/"
                            "zeek_log_parser.py",
                            "--environment",
                            self.environment_id,
                        )
                    ),
                    timeout_seconds=(
                        options
                        .command_timeout_seconds
                    ),
                    steps=steps,
                )

            self.validate_required_inputs(
                options
            )

            self.run_command_step(
                step_name="risk_engine",
                command=(
                    self.python_command(
                        "src/risk_engine.py",
                        "--environment",
                        self.environment_id,
                    )
                ),
                timeout_seconds=(
                    options
                    .command_timeout_seconds
                ),
                steps=steps,
            )

            if options.skip_publish:
                steps.append(
                    StepRecord(
                        name="publish",
                        status="skipped",
                        started_at=utc_iso(),
                        completed_at=utc_iso(),
                        duration_seconds=0.0,
                        message=(
                            "OpenSearch publishing "
                            "was skipped"
                        ),
                    )
                )
            else:
                publish_command = (
                    self.python_command(
                        "src/"
                        "push_scored_events.py",
                        "--environment",
                        self.environment_id,
                    )
                )

                if options.refresh:
                    publish_command.append(
                        "--refresh"
                    )

                if options.dry_run:
                    publish_command.append(
                        "--dry-run"
                    )

                self.run_command_step(
                    step_name="publish",
                    command=(
                        publish_command
                    ),
                    timeout_seconds=(
                        options
                        .command_timeout_seconds
                    ),
                    steps=steps,
                )

            cycle_completed_at = utc_iso()
            duration = round(
                time.monotonic()
                - cycle_started,
                3,
            )

            state = self.state_snapshot(
                status="success",
                cycle_started_at=(
                    cycle_started_at
                ),
                cycle_completed_at=(
                    cycle_completed_at
                ),
                duration_seconds=duration,
                steps=steps,
            )

            self.write_state(state)

            LOGGER.info(
                (
                    "Pipeline cycle completed: "
                    "Wazuh=%s, Zeek=%s, "
                    "correlated=%s, "
                    "documents=%s, "
                    "duration=%.3fs"
                ),
                state["wazuh_events"],
                state["zeek_events"],
                state[
                    "correlated_events"
                ],
                state[
                    "published_documents"
                ],
                duration,
            )

            return state

        except Exception as exc:
            cycle_completed_at = utc_iso()
            duration = round(
                time.monotonic()
                - cycle_started,
                3,
            )

            error_message = str(exc)

            state = self.state_snapshot(
                status="failed",
                cycle_started_at=(
                    cycle_started_at
                ),
                cycle_completed_at=(
                    cycle_completed_at
                ),
                duration_seconds=duration,
                steps=steps,
                error=error_message,
            )

            self.write_state(state)

            LOGGER.error(
                "Pipeline cycle failed: %s",
                error_message,
            )

            LOGGER.debug(
                "Pipeline exception details:\n%s",
                traceback.format_exc(),
            )

            raise


def configure_logging(
    log_file: Path,
    verbose: bool = False,
    retention_days: int = 30,
) -> None:
    """Configure console and daily rotating environment-specific logging."""
    log_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    level = (
        logging.DEBUG
        if verbose
        else logging.INFO
    )

    formatter = logging.Formatter(
        (
            "%(asctime)s %(levelname)s "
            "%(name)s: %(message)s"
        )
    )

    logger = logging.getLogger()
    logger.setLevel(level)

    for existing in list(
        logger.handlers
    ):
        logger.removeHandler(
            existing
        )

    console_handler = (
        logging.StreamHandler(
            sys.stdout
        )
    )
    console_handler.setLevel(level)
    console_handler.setFormatter(
        formatter
    )

    file_handler = TimedRotatingFileHandler(
        log_file,
        when="midnight",
        interval=1,
        backupCount=max(1, retention_days),
        encoding="utf-8",
        delay=True,
        utc=False,
    )
    file_handler.suffix = "%Y-%m-%d"
    file_handler.setLevel(level)
    file_handler.setFormatter(
        formatter
    )

    logger.addHandler(
        console_handler
    )
    logger.addHandler(
        file_handler
    )


def positive_integer(
    value: str,
) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "must be an integer"
        ) from exc

    if parsed <= 0:
        raise argparse.ArgumentTypeError(
            "must be greater than zero"
        )

    return parsed


def build_argument_parser(
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the environment-aware "
            "healthcare risk live pipeline"
        )
    )

    parser.add_argument(
        "--environment",
        default=os.getenv(
            "ENVIRONMENT_ID",
            "healthcare-lab",
        ),
        help=(
            "Hospital environment ID. "
            "ENVIRONMENT_ID may also be used."
        ),
    )

    parser.add_argument(
        "--continuous",
        action="store_true",
        help=(
            "Run repeatedly until Ctrl+C"
        ),
    )

    parser.add_argument(
        "--interval-seconds",
        type=positive_integer,
        default=30,
        help=(
            "Delay between continuous cycles"
        ),
    )

    parser.add_argument(
        "--wazuh-size",
        type=positive_integer,
        default=100,
        help=(
            "Maximum recent Wazuh alerts "
            "to collect per cycle"
        ),
    )

    parser.add_argument(
        "--command-timeout-seconds",
        type=positive_integer,
        default=120,
        help=(
            "Timeout for each pipeline command"
        ),
    )

    parser.add_argument(
        "--scp-timeout-seconds",
        type=positive_integer,
        default=30,
        help="Zeek SSH connection timeout",
    )

    parser.add_argument(
        "--zeek-local-source",
        type=Path,
        default=None,
        help=(
            "Copy Zeek conn.log from this "
            "local file instead of SCP"
        ),
    )

    parser.add_argument(
        "--skip-wazuh",
        action="store_true",
        help=(
            "Use the existing environment-specific "
            "Wazuh JSON file"
        ),
    )

    parser.add_argument(
        "--skip-zeek",
        action="store_true",
        help=(
            "Use the existing environment-specific "
            "parsed Zeek JSON file"
        ),
    )

    parser.add_argument(
        "--skip-zeek-copy",
        action="store_true",
        help=(
            "Parse the existing environment-specific "
            "Zeek conn.log without copying it"
        ),
    )

    parser.add_argument(
        "--skip-publish",
        action="store_true",
        help=(
            "Run scoring but do not publish "
            "to OpenSearch"
        ),
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Run collection, parsing, and scoring, "
            "then validate publishing without "
            "contacting OpenSearch"
        ),
    )

    parser.add_argument(
        "--no-refresh",
        action="store_true",
        help=(
            "Do not refresh the OpenSearch "
            "read alias after publishing"
        ),
    )

    parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help=(
            "In continuous mode, stop after "
            "the first failed cycle"
        ),
    )

    parser.add_argument(
        "--log-retention-days",
        type=positive_integer,
        default=positive_integer(
            os.getenv("PIPELINE_LOG_RETENTION_DAYS", "30")
        ),
        help="Number of rotated daily pipeline logs to retain",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
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

    environment_id = (
        resolve_environment_id(
            args.environment
        )
    )

    paths = EnvironmentPaths(
        project_root=PROJECT_ROOT,
        environment_id=(
            environment_id
        ),
    )

    paths.ensure_directories()

    configure_logging(
        paths.pipeline_log_file,
        verbose=args.verbose,
        retention_days=args.log_retention_days,
    )

    options = PipelineOptions(
        wazuh_size=args.wazuh_size,
        command_timeout_seconds=(
            args.command_timeout_seconds
        ),
        scp_timeout_seconds=(
            args.scp_timeout_seconds
        ),
        skip_wazuh=args.skip_wazuh,
        skip_zeek=args.skip_zeek,
        skip_zeek_copy=(
            args.skip_zeek_copy
        ),
        skip_publish=(
            args.skip_publish
        ),
        dry_run=args.dry_run,
        refresh=not args.no_refresh,
        zeek_local_source=(
            args.zeek_local_source
        ),
    )

    pipeline = LivePipeline(
        project_root=PROJECT_ROOT,
        environment_id=(
            environment_id
        ),
    )

    lock = PipelineLock(
        paths.pipeline_lock_file,
        environment_id,
    )

    LOGGER.info(
        "Starting live pipeline for %s",
        environment_id,
    )

    try:
        with lock:
            if not args.continuous:
                pipeline.run_cycle(
                    options
                )
                return 0

            LOGGER.info(
                (
                    "Continuous mode enabled. "
                    "Interval: %s second(s). "
                    "Press Ctrl+C to stop."
                ),
                args.interval_seconds,
            )

            while True:
                cycle_started = (
                    time.monotonic()
                )

                try:
                    pipeline.run_cycle(
                        options
                    )
                except Exception:
                    if args.stop_on_error:
                        return 1

                    LOGGER.warning(
                        (
                            "The failed cycle will "
                            "be retried after the "
                            "configured interval."
                        )
                    )

                elapsed = (
                    time.monotonic()
                    - cycle_started
                )

                remaining = max(
                    0.0,
                    (
                        args.interval_seconds
                        - elapsed
                    ),
                )

                if remaining > 0:
                    time.sleep(remaining)

    except KeyboardInterrupt:
        LOGGER.info(
            "Pipeline stopped by user."
        )
        return 0
    except (
        PipelineError,
        ValueError,
    ) as exc:
        LOGGER.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
