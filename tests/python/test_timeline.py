"""Tests for UTC timeline normalization."""

from __future__ import annotations

from pathlib import Path

from endpoint_incident_triage.timeline import (
    build_timeline,
    events_from_collector,
    read_timeline_jsonl,
    timeline_summary,
    write_timeline_jsonl,
)
from tests.helpers.factories import make_collector_result

TIMESTAMPED_RECORDS = [
    {
        "artifact_type": "process",
        "pid": 1,
        "name": "a",
        "timestamp_utc": "2026-08-05T06:00:00Z",
    },
    {
        "artifact_type": "process",
        "pid": 2,
        "name": "b",
        "timestamp_utc": "2026-08-05T17:55:00Z",
    },
]


def test_events_from_collector_extracts_timestamps():
    result = make_collector_result(records=TIMESTAMPED_RECORDS)
    events = events_from_collector(result)
    assert events
    assert all(event.timestamp_utc.endswith("Z") for event in events)


def test_build_timeline_sorted():
    result = make_collector_result(records=TIMESTAMPED_RECORDS)
    timeline = build_timeline([result])
    stamps = [event.timestamp_utc for event in timeline]
    assert stamps == sorted(stamps)


def test_timeline_summary():
    result = make_collector_result(records=TIMESTAMPED_RECORDS)
    timeline = build_timeline([result])
    summary = timeline_summary(timeline)
    assert summary["event_count"] == len(timeline)
    assert summary["first_timestamp_utc"] <= summary["last_timestamp_utc"]


def test_timeline_summary_empty():
    summary = timeline_summary([])
    assert summary["event_count"] == 0


def test_write_and_read_timeline_jsonl(tmp_path: Path):
    result = make_collector_result(records=TIMESTAMPED_RECORDS)
    timeline = build_timeline([result])
    path = tmp_path / "timeline.jsonl"
    write_timeline_jsonl(path, timeline)
    loaded = read_timeline_jsonl(path)
    assert len(loaded) == len(timeline)


def test_timeline_includes_source_artifact():
    result = make_collector_result(records=TIMESTAMPED_RECORDS)
    event = events_from_collector(result)[0]
    assert event.source_artifact == "artifacts/windows/windows.processes.json"
