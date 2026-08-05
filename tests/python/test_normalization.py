"""Tests for collector output normalization."""

from __future__ import annotations

import base64

import pytest

from endpoint_incident_triage.normalization import (
    NormalizationError,
    build_collector_result,
    decode_protocol_line,
    parse_collector_stdout,
    redact_error_text,
)
from endpoint_incident_triage.statuses import CollectorStatus, SourceMode


def test_decode_protocol_line_basic():
    line = "EIT1|pid=1234|name=test"
    decoded = decode_protocol_line(line)
    assert decoded["pid"] == "1234"
    assert decoded["name"] == "test"


def test_decode_protocol_line_base64_value():
    encoded = base64.b64encode(b"weird|value").decode("ascii")
    line = f"EIT1|msg=b64:{encoded}"
    decoded = decode_protocol_line(line)
    assert decoded["msg"] == "weird|value"


def test_decode_protocol_line_rejects_missing_prefix():
    with pytest.raises(NormalizationError, match="EIT1"):
        decode_protocol_line("BAD|pid=1")


def test_parse_collector_stdout_json_object_with_records():
    stdout = '{"records":[{"artifact_type":"process","pid":1}]}'
    records = parse_collector_stdout(stdout)
    assert len(records) == 1


def test_parse_collector_stdout_jsonl():
    stdout = '{"a":1}\n{"b":2}\n'
    records = parse_collector_stdout(stdout)
    assert len(records) == 2


def test_parse_collector_stdout_protocol_lines():
    stdout = "EIT1|pid=1|name=a\nEIT1|pid=2|name=b\n"
    records = parse_collector_stdout(stdout, prefer_json=False)
    assert len(records) == 2


def test_build_collector_result_counts_records():
    result = build_collector_result(
        collector_id="test.collector",
        platform="linux",
        category="process",
        status=CollectorStatus.COLLECTED,
        started_at_utc="2026-08-05T18:00:00Z",
        records=[{"pid": 1}],
        source_mode=SourceMode.FIXTURE,
    )
    assert result.record_count == 1
    assert result.source_mode == SourceMode.FIXTURE


def test_redact_error_text_masks_secrets():
    text = "login failed password=Secret123 for user"
    redacted = redact_error_text(text)
    assert "Secret123" not in redacted
    assert "[REDACTED]" in redacted
