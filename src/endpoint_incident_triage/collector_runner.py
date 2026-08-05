"""Allowlisted collector execution with safety controls."""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from endpoint_incident_triage.collector_registry import (
    CollectorDefinition,
    resolve_collector_script,
)
from endpoint_incident_triage.normalization import (
    NormalizationError,
    build_collector_result,
    parse_collector_stdout,
    redact_error_text,
)
from endpoint_incident_triage.models import CollectorResult
from endpoint_incident_triage.statuses import CollectorStatus, SourceMode
from endpoint_incident_triage.timestamps import utc_now_iso

ALLOWED_ENV_PREFIXES = ("EIT_",)
ALLOWED_ENV_EXACT = frozenset(
    {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "HOME",
        "USERPROFILE",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
        "SHELL",
    }
)

FIXTURE_ENV = "EIT_FIXTURE_FILE"
SYNTHETIC_ENV = "EIT_SYNTHETIC_MODE"


class CollectorRunnerError(RuntimeError):
    """Collector execution error."""


@dataclass(slots=True)
class CollectorRunResult:
    result: CollectorResult
    execution_log: dict[str, Any]


def build_allowlisted_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build a minimal allowlisted environment for collector subprocesses."""
    env: dict[str, str] = {}
    for key, value in os.environ.items():
        if key in ALLOWED_ENV_EXACT or key.startswith(ALLOWED_ENV_PREFIXES):
            env[key] = value
    if extra:
        for key, value in extra.items():
            if not key.startswith(ALLOWED_ENV_PREFIXES) and key not in ALLOWED_ENV_EXACT:
                raise CollectorRunnerError(f"Refusing non-allowlisted env var: {key}")
            env[key] = value
    return env


def _resolve_fixture_path(collector: CollectorDefinition, collectors_root: Path) -> Path | None:
    fixture_env = os.environ.get(FIXTURE_ENV)
    if fixture_env:
        path = Path(fixture_env)
        if path.is_file():
            return path.resolve()
    synthetic_root = collectors_root.parent / "examples" / "synthetic-input"
    candidate = synthetic_root / collector.platform / f"{collector.id}.json"
    if candidate.is_file():
        return candidate.resolve()
    fixtures_root = collectors_root.parent / "tests" / "fixtures"
    candidate = fixtures_root / collector.platform / f"{collector.id}.json"
    if candidate.is_file():
        return candidate.resolve()
    return None


def _load_fixture_records(fixture_path: Path) -> list[dict[str, Any]]:
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        return [item for item in payload["records"] if isinstance(item, dict)]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [payload]
    raise CollectorRunnerError(f"Invalid fixture format: {fixture_path}")


def _build_command(
    collector: CollectorDefinition,
    script_path: Path,
    *,
    include_command_lines: bool = False,
    include_event_messages: bool = False,
    since_hours: int = 24,
) -> list[str]:
    if collector.interpreter == "powershell":
        command = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
        ]
    elif collector.interpreter == "bash":
        command = ["bash", str(script_path)]
    else:
        raise CollectorRunnerError(f"Unsupported interpreter: {collector.interpreter}")

    if include_command_lines:
        command.append("-IncludeCommandLines")
    if include_event_messages:
        command.append("-IncludeEventMessages")
    command.extend(["-SinceHours", str(since_hours)])
    return command


def _map_exit_status(exit_code: int, records: list[dict[str, Any]], stderr: str) -> CollectorStatus:
    if exit_code == 0 and records:
        return CollectorStatus.COLLECTED
    if exit_code == 0:
        return CollectorStatus.PARTIAL
    if exit_code == 127 or "not found" in stderr.lower():
        return CollectorStatus.UNAVAILABLE
    return CollectorStatus.ERROR


def run_collector(
    collector: CollectorDefinition,
    collectors_root: Path,
    *,
    source_mode: SourceMode = SourceMode.SYNTHETIC,
    platform: str,
    include_command_lines: bool = False,
    include_event_messages: bool = False,
    since_hours: int = 24,
    fixture_path: Path | None = None,
    prefer_fixture: bool = True,
) -> CollectorRunResult:
    """Run a single allowlisted collector or load fixture data."""
    started = utc_now_iso()
    start_ms = time.monotonic_ns() // 1_000_000
    script_path = resolve_collector_script(collector, collectors_root)
    provenance = [f"interpreter={collector.interpreter}", f"script={collector.script_path}"]

    records: list[dict[str, Any]] = []
    warnings: list[str] = []
    errors: list[str] = []
    exit_code: int | None = 0
    stderr_text = ""

    use_fixture = source_mode in {SourceMode.SYNTHETIC, SourceMode.FIXTURE} or prefer_fixture
    resolved_fixture = fixture_path or _resolve_fixture_path(collector, collectors_root)

    if use_fixture and resolved_fixture is not None:
        try:
            records = _load_fixture_records(resolved_fixture)
            status = CollectorStatus.COLLECTED if records else CollectorStatus.PARTIAL
            if not records:
                warnings.append("Fixture contained no records")
            provenance.append(f"fixture={resolved_fixture.name}")
            completed = utc_now_iso()
            duration = int(time.monotonic_ns() // 1_000_000 - start_ms)
            result = build_collector_result(
                collector_id=collector.id,
                platform=platform,
                category=collector.category,
                status=status,
                started_at_utc=started,
                completed_at_utc=completed,
                duration_ms=duration,
                privilege_state=collector.privilege,
                source_mode=SourceMode.FIXTURE if resolved_fixture else source_mode,
                records=records,
                warnings=warnings,
                errors=errors,
                command_provenance=provenance,
                exit_code=0,
            )
            log = {
                "collector_id": collector.id,
                "started_at_utc": started,
                "completed_at_utc": completed,
                "exit_code": 0,
                "source_mode": "fixture",
                "fixture_path": str(resolved_fixture),
            }
            return CollectorRunResult(result=result, execution_log=log)
        except (OSError, json.JSONDecodeError, CollectorRunnerError) as exc:
            errors.append(redact_error_text(str(exc)))

    env = build_allowlisted_env(
        {
            FIXTURE_ENV: str(resolved_fixture) if resolved_fixture else "",
            SYNTHETIC_ENV: "1" if source_mode == SourceMode.SYNTHETIC else "0",
        }
    )
    command = _build_command(
        collector,
        script_path,
        include_command_lines=include_command_lines,
        include_event_messages=include_event_messages,
        since_hours=since_hours,
    )
    provenance.append(" ".join(command[:4]) + " ...")

    try:
        completed_proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=collector.timeout_seconds,
            env=env,
            shell=False,
            cwd=str(collectors_root),
        )
        exit_code = completed_proc.returncode
        stdout = completed_proc.stdout or ""
        stderr_text = redact_error_text(completed_proc.stderr or "")
        if len(stdout.encode("utf-8")) > collector.maximum_output_bytes:
            stdout = stdout.encode("utf-8")[: collector.maximum_output_bytes].decode(
                "utf-8", errors="replace"
            )
            warnings.append("Collector stdout truncated to maximum_output_bytes")
        if stderr_text:
            warnings.append(f"stderr: {stderr_text}")
        try:
            records = parse_collector_stdout(stdout)
        except NormalizationError as exc:
            errors.append(redact_error_text(str(exc)))
            records = []
    except subprocess.TimeoutExpired:
        exit_code = 124
        errors.append(f"Collector timed out after {collector.timeout_seconds}s")
        records = []
    except OSError as exc:
        exit_code = 1
        errors.append(redact_error_text(str(exc)))
        records = []

    duration = int(time.monotonic_ns() // 1_000_000 - start_ms)
    completed = utc_now_iso()
    status = _map_exit_status(exit_code or 0, records, stderr_text)
    if source_mode == SourceMode.SYNTHETIC and not records:
        status = CollectorStatus.UNAVAILABLE

    result = build_collector_result(
        collector_id=collector.id,
        platform=platform,
        category=collector.category,
        status=status,
        started_at_utc=started,
        completed_at_utc=completed,
        duration_ms=duration,
        privilege_state=collector.privilege,
        source_mode=source_mode,
        records=records,
        warnings=warnings,
        errors=errors,
        command_provenance=provenance,
        exit_code=exit_code,
    )
    log = {
        "collector_id": collector.id,
        "started_at_utc": started,
        "completed_at_utc": completed,
        "exit_code": exit_code,
        "source_mode": source_mode.value,
        "status": status.value,
    }
    return CollectorRunResult(result=result, execution_log=log)


def run_collectors(
    collectors: list[CollectorDefinition],
    collectors_root: Path,
    *,
    platform: str,
    source_mode: SourceMode = SourceMode.SYNTHETIC,
    include_command_lines: bool = False,
    include_event_messages: bool = False,
    since_hours: int = 24,
    prefer_fixture: bool = True,
) -> tuple[list[CollectorResult], list[dict[str, Any]]]:
    """Run multiple allowlisted collectors in order."""
    results: list[CollectorResult] = []
    logs: list[dict[str, Any]] = []
    for collector in collectors:
        if collector.platform != platform:
            continue
        if source_mode == SourceMode.SYNTHETIC and prefer_fixture:
            run = run_collector(
                collector,
                collectors_root,
                source_mode=source_mode,
                platform=platform,
                include_command_lines=include_command_lines,
                include_event_messages=include_event_messages,
                since_hours=since_hours,
                prefer_fixture=True,
            )
        else:
            run = run_collector(
                collector,
                collectors_root,
                source_mode=source_mode,
                platform=platform,
                include_command_lines=include_command_lines,
                include_event_messages=include_event_messages,
                since_hours=since_hours,
                prefer_fixture=prefer_fixture,
            )
        results.append(run.result)
        logs.append(run.execution_log)
    return results, logs
