"""Tamper-evident hash-chained custody ledger (JSONL)."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from endpoint_incident_triage import SCHEMA_VERSION
from endpoint_incident_triage.hashing import sha256_canonical_json
from endpoint_incident_triage.models import CustodyRecord
from endpoint_incident_triage.timestamps import utc_now_iso

GENESIS_HASH = "0" * 64
CUSTODY_LEDGER_RELATIVE = "custody/custody.jsonl"

ALLOWED_EVENT_TYPES = frozenset(
    {
        "case_created",
        "collection_started",
        "collector_started",
        "collector_completed",
        "collector_partial",
        "collector_unavailable",
        "collector_error",
        "collection_completed",
        "manifest_created",
        "package_verified",
        "report_generated",
        "zip_created",
    }
)

SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd|token|secret|api[_-]?key)\s*[:=]\s*\S+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"),
]


class CustodyError(ValueError):
    """Custody ledger error."""


@dataclass(slots=True)
class LedgerVerification:
    ok: bool
    errors: list[str]
    record_count: int


def _sanitize_details(details: dict[str, Any]) -> dict[str, Any]:
    """Remove likely secrets from custody details."""
    sanitized: dict[str, Any] = {}
    for key, value in details.items():
        if isinstance(value, str):
            text = value
            for pattern in SECRET_PATTERNS:
                text = pattern.sub("[REDACTED]", text)
            sanitized[str(key)] = text
        elif isinstance(value, dict):
            sanitized[str(key)] = _sanitize_details(value)
        elif isinstance(value, list):
            sanitized[str(key)] = [
                _sanitize_details(item) if isinstance(item, dict) else item for item in value
            ]
        else:
            sanitized[str(key)] = value
    return sanitized


def compute_record_hash(record: dict[str, Any]) -> str:
    """Compute record_hash over canonical JSON excluding record_hash."""
    payload = {key: value for key, value in record.items() if key != "record_hash"}
    return sha256_canonical_json(payload)


def _record_to_dict(record: CustodyRecord) -> dict[str, Any]:
    data = record.to_dict()
    data["record_hash"] = compute_record_hash(data)
    return data


def make_record(
    *,
    sequence: int,
    event_type: str,
    package_id: str,
    actor_label: str,
    action: str,
    details: dict[str, Any] | None = None,
    previous_record_hash: str = GENESIS_HASH,
    occurred_at_utc: str | None = None,
    event_id: str | None = None,
) -> CustodyRecord:
    """Create a custody record with computed hash."""
    if event_type not in ALLOWED_EVENT_TYPES:
        raise CustodyError(f"Unsupported custody event type: {event_type}")
    clean_details = _sanitize_details(details or {})
    record = CustodyRecord(
        schema_version=SCHEMA_VERSION,
        sequence=sequence,
        event_id=event_id or str(uuid.uuid4()),
        event_type=event_type,
        occurred_at_utc=occurred_at_utc or utc_now_iso(),
        actor_label=actor_label,
        action=action,
        package_id=package_id,
        details=clean_details,
        previous_record_hash=previous_record_hash,
        record_hash="",
    )
    data = record.to_dict()
    record.record_hash = compute_record_hash(data)
    return record


def append_record(
    ledger: list[CustodyRecord],
    *,
    event_type: str,
    package_id: str,
    actor_label: str,
    action: str,
    details: dict[str, Any] | None = None,
    occurred_at_utc: str | None = None,
) -> CustodyRecord:
    """Append a hash-chained record to an in-memory ledger."""
    sequence = len(ledger) + 1
    previous = ledger[-1].record_hash if ledger else GENESIS_HASH
    record = make_record(
        sequence=sequence,
        event_type=event_type,
        package_id=package_id,
        actor_label=actor_label,
        action=action,
        details=details,
        previous_record_hash=previous,
        occurred_at_utc=occurred_at_utc,
    )
    ledger.append(record)
    return record


def read_ledger(path: Path) -> list[CustodyRecord]:
    """Read custody records from a JSONL file."""
    if not path.is_file():
        raise CustodyError(f"Custody ledger not found: {path}")
    records: list[CustodyRecord] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        text = line.strip()
        if not text:
            continue
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CustodyError(f"Invalid JSON at line {line_no}: {exc}") from exc
        if not isinstance(payload, dict):
            raise CustodyError(f"Line {line_no} must be a JSON object")
        records.append(_dict_to_record(payload))
    return records


def write_ledger(path: Path, ledger: list[CustodyRecord]) -> None:
    """Write custody records to JSONL (one canonical record per line)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for record in ledger:
        data = _record_to_dict(record)
        lines.append(json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _dict_to_record(payload: dict[str, Any]) -> CustodyRecord:
    return CustodyRecord(
        schema_version=str(payload.get("schema_version", "")),
        sequence=int(payload["sequence"]),
        event_id=str(payload["event_id"]),
        event_type=str(payload["event_type"]),
        occurred_at_utc=str(payload["occurred_at_utc"]),
        actor_label=str(payload["actor_label"]),
        action=str(payload["action"]),
        package_id=str(payload["package_id"]),
        details=dict(payload.get("details") or {}),
        previous_record_hash=str(payload["previous_record_hash"]),
        record_hash=str(payload.get("record_hash", "")),
    )


def verify_ledger(ledger: list[CustodyRecord]) -> LedgerVerification:
    """Verify hash chain, sequence contiguity, and record integrity."""
    errors: list[str] = []
    if not ledger:
        return LedgerVerification(ok=True, errors=[], record_count=0)

    expected_previous = GENESIS_HASH
    for index, record in enumerate(ledger):
        position = index + 1
        if record.sequence != position:
            errors.append(
                f"Sequence mismatch at position {position}: expected {position}, "
                f"found {record.sequence}"
            )
        if record.previous_record_hash != expected_previous:
            errors.append(
                f"Previous hash mismatch at sequence {record.sequence}: "
                f"expected {expected_previous}, found {record.previous_record_hash}"
            )
        if record.event_type not in ALLOWED_EVENT_TYPES:
            errors.append(f"Unknown event type at sequence {record.sequence}: {record.event_type}")

        data = record.to_dict()
        stored_hash = data.pop("record_hash", "")
        computed = compute_record_hash(data)
        if stored_hash != computed:
            errors.append(
                f"Record hash mismatch at sequence {record.sequence}: content may have been mutated"
            )
        expected_previous = stored_hash or computed

    return LedgerVerification(ok=not errors, errors=errors, record_count=len(ledger))


def custody_status_label(verification: LedgerVerification) -> str:
    """Human-readable custody status for reports."""
    if verification.record_count == 0:
        return "Missing"
    if verification.ok:
        return "Verified"
    return "Failed"
