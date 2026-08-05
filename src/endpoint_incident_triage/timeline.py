"""UTC timeline normalization from collector results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from endpoint_incident_triage.models import CollectorResult, TimelineEvent
from endpoint_incident_triage.timestamps import format_utc, parse_utc, utc_now_iso

TIMESTAMP_FIELDS = (
    "timestamp",
    "timestamp_utc",
    "time_utc",
    "started_at",
    "started_at_utc",
    "created_at",
    "created_at_utc",
    "modified_at",
    "modified_at_utc",
    "last_run",
    "next_run",
    "boot_time",
    "event_time",
)

ENTITY_ID_FIELDS = ("id", "entity_id", "pid", "process_id", "name", "task_name", "service_name")


def _extract_timestamp(record: dict[str, Any]) -> tuple[str | None, str]:
    """Return (timestamp_text, source_field) from a record."""
    for field in TIMESTAMP_FIELDS:
        value = record.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip(), field
    return None, ""


def _normalize_timestamp(raw: str) -> tuple[str, str, str, list[str]]:
    """Normalize timestamp to UTC ISO; return (utc, precision, assumption, warnings)."""
    warnings: list[str] = []
    text = raw.strip()
    assumption = "UTC"
    precision = "seconds"
    if text.endswith("Z"):
        assumption = "explicit_utc"
    elif "+" in text or text.count("-") > 2:
        assumption = "offset_provided"
    else:
        assumption = "assumed_local_or_utc"
        warnings.append(f"Timestamp '{raw}' lacks explicit timezone; normalized assuming UTC")
    try:
        parsed = parse_utc(text if text.endswith("Z") or "+" in text else text + "Z")
        if "." in text:
            precision = "subsecond"
        return format_utc(parsed), precision, assumption, warnings
    except ValueError:
        warnings.append(f"Unable to parse timestamp: {raw}")
        fallback = utc_now_iso()
        return fallback, "unknown", "unparsed", warnings


def _entity_id(record: dict[str, Any]) -> str:
    for field in ENTITY_ID_FIELDS:
        value = record.get(field)
        if value is not None and str(value):
            return str(value)
    return "unknown"


def _event_type(record: dict[str, Any], collector: CollectorResult) -> str:
    if record.get("event_type"):
        return str(record["event_type"])
    if record.get("record_type"):
        return str(record["record_type"])
    return collector.category


def _entity_type(record: dict[str, Any], collector: CollectorResult) -> str:
    if record.get("entity_type"):
        return str(record["entity_type"])
    return collector.category


def _summary(record: dict[str, Any], collector: CollectorResult) -> str:
    for field in ("summary", "description", "message", "name", "title"):
        value = record.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()[:240]
    return f"{collector.collector_id} record"


def events_from_collector(collector: CollectorResult) -> list[TimelineEvent]:
    """Build timeline events from a single collector result."""
    events: list[TimelineEvent] = []
    artifact = f"artifacts/{collector.platform}/{collector.collector_id}.json"
    for record in collector.records:
        raw_ts, source_field = _extract_timestamp(record)
        if not raw_ts:
            continue
        timestamp_utc, precision, assumption, warnings = _normalize_timestamp(raw_ts)
        details = dict(record)
        if warnings:
            details["clock_skew_warnings"] = warnings
        events.append(
            TimelineEvent(
                timestamp_utc=timestamp_utc,
                timestamp_source=source_field or "record",
                timestamp_precision=precision,
                platform=collector.platform,
                collector_id=collector.collector_id,
                event_type=_event_type(record, collector),
                entity_type=_entity_type(record, collector),
                entity_id=_entity_id(record),
                summary=_summary(record, collector),
                details=details,
                confidence="collector_reported",
                source_artifact=artifact,
                original_timestamp=raw_ts,
                timezone_assumption=assumption,
            )
        )
    return events


def build_timeline(collector_results: list[CollectorResult]) -> list[TimelineEvent]:
    """Build a deterministic UTC timeline from collector results."""
    events: list[TimelineEvent] = []
    for collector in collector_results:
        events.extend(events_from_collector(collector))
    events.sort(
        key=lambda item: (
            item.timestamp_utc,
            item.platform,
            item.collector_id,
            item.entity_type,
            item.entity_id,
            item.event_type,
        )
    )
    return events


def timeline_summary(events: list[TimelineEvent]) -> dict[str, Any]:
    """Summarize timeline for reports."""
    if not events:
        return {"event_count": 0, "first_timestamp_utc": None, "last_timestamp_utc": None}
    return {
        "event_count": len(events),
        "first_timestamp_utc": events[0].timestamp_utc,
        "last_timestamp_utc": events[-1].timestamp_utc,
        "collectors_represented": sorted({event.collector_id for event in events}),
    }


def write_timeline_jsonl(path: Path, events: list[TimelineEvent]) -> None:
    """Write timeline events as JSONL."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        for event in events
    ]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def read_timeline_jsonl(path: Path) -> list[TimelineEvent]:
    """Read timeline events from JSONL."""
    events: list[TimelineEvent] = []
    if not path.is_file():
        return events
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        payload = json.loads(text)
        events.append(
            TimelineEvent(
                timestamp_utc=str(payload["timestamp_utc"]),
                timestamp_source=str(payload["timestamp_source"]),
                timestamp_precision=str(payload["timestamp_precision"]),
                platform=str(payload["platform"]),
                collector_id=str(payload["collector_id"]),
                event_type=str(payload["event_type"]),
                entity_type=str(payload["entity_type"]),
                entity_id=str(payload["entity_id"]),
                summary=str(payload["summary"]),
                details=dict(payload.get("details") or {}),
                confidence=str(payload["confidence"]),
                source_artifact=str(payload["source_artifact"]),
                original_timestamp=payload.get("original_timestamp"),
                timezone_assumption=str(payload["timezone_assumption"]),
            )
        )
    return events
