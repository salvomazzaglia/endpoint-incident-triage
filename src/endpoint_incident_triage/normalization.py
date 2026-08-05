"""Safe structured output normalization for collectors."""

from __future__ import annotations

import base64
import json
import re
from typing import Any

from endpoint_incident_triage import COLLECTOR_VERSION, SCHEMA_VERSION
from endpoint_incident_triage.models import CollectorResult, TruncationInfo
from endpoint_incident_triage.statuses import CollectorStatus, SourceMode
from endpoint_incident_triage.timestamps import utc_now_iso

PROTOCOL_PREFIX = "EIT1|"
ENCODED_FIELD_RE = re.compile(r"^b64:([A-Za-z0-9+/=]+)$")


class NormalizationError(ValueError):
    """Invalid collector output."""


def decode_protocol_line(line: str) -> dict[str, str]:
    """Decode a NUL-safe encoded-field protocol line.

    Format: EIT1|key=value|key=b64:<base64>|...
    Values that need escaping use b64: encoding.
    """
    text = line.strip()
    if not text.startswith(PROTOCOL_PREFIX):
        raise NormalizationError("Line missing EIT1 protocol prefix")
    payload = text[len(PROTOCOL_PREFIX) :]
    result: dict[str, str] = {}
    for part in payload.split("|"):
        if not part:
            continue
        if "=" not in part:
            raise NormalizationError(f"Invalid protocol field: {part}")
        key, value = part.split("=", 1)
        if not key or not re.fullmatch(r"[A-Za-z0-9_.-]+", key):
            raise NormalizationError(f"Invalid protocol key: {key}")
        match = ENCODED_FIELD_RE.fullmatch(value)
        if match:
            try:
                value = base64.b64decode(match.group(1), validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError) as exc:
                raise NormalizationError(f"Invalid b64 value for {key}") from exc
        result[key] = value
    return result


def parse_collector_stdout(stdout: str, *, prefer_json: bool = True) -> list[dict[str, Any]]:
    """Parse collector stdout as JSON array/object, JSONL, or EIT1 protocol lines."""
    text = stdout.strip()
    if not text:
        return []

    if prefer_json:
        try:
            payload = json.loads(text)
            if isinstance(payload, dict):
                if "records" in payload and isinstance(payload["records"], list):
                    return [item for item in payload["records"] if isinstance(item, dict)]
                return [payload]
            if isinstance(payload, list):
                return [item for item in payload if isinstance(item, dict)]
        except json.JSONDecodeError:
            pass

    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith(PROTOCOL_PREFIX):
            records.append(dict(decode_protocol_line(line)))
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise NormalizationError(f"Invalid structured output line: {line[:120]}") from exc
        if isinstance(item, dict):
            records.append(item)
        else:
            raise NormalizationError("JSONL records must be objects")
    return records


def build_collector_result(
    *,
    collector_id: str,
    platform: str,
    category: str,
    status: CollectorStatus,
    started_at_utc: str,
    completed_at_utc: str | None = None,
    duration_ms: int = 0,
    privilege_state: str = "standard",
    source_mode: SourceMode = SourceMode.SYNTHETIC,
    records: list[dict[str, Any]] | None = None,
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
    truncation: TruncationInfo | None = None,
    sensitive_fields_omitted: list[str] | None = None,
    command_provenance: list[str] | None = None,
    exit_code: int | None = None,
) -> CollectorResult:
    """Build a normalized collector result document."""
    completed = completed_at_utc or utc_now_iso()
    record_list = records or []
    return CollectorResult(
        schema_version=SCHEMA_VERSION,
        collector_id=collector_id,
        platform=platform,
        category=category,
        status=status,
        started_at_utc=started_at_utc,
        completed_at_utc=completed,
        duration_ms=duration_ms,
        privilege_state=privilege_state,
        source_mode=source_mode,
        record_count=len(record_list),
        records=record_list,
        warnings=warnings or [],
        errors=errors or [],
        truncation=truncation or TruncationInfo(),
        sensitive_fields_omitted=sensitive_fields_omitted or [],
        command_provenance=command_provenance or [],
        collector_version=COLLECTOR_VERSION,
        exit_code=exit_code,
    )


def redact_error_text(text: str, *, max_length: int = 400) -> str:
    """Redact likely secrets from error text and bound length."""
    redacted = text
    patterns = [
        (
            re.compile(r"(?i)(password|passwd|pwd|token|secret|api[_-]?key)\s*[:=]\s*\S+"),
            r"\1=[REDACTED]",
        ),
        (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"), "bearer [REDACTED]"),
        (re.compile(r"(?i)authorization:\s*\S+"), "Authorization: [REDACTED]"),
    ]
    for pattern, replacement in patterns:
        redacted = pattern.sub(replacement, redacted)
    if len(redacted) > max_length:
        return redacted[: max_length - 3] + "..."
    return redacted
