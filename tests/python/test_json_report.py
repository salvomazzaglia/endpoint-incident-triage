"""Tests for JSON triage report generation."""

from __future__ import annotations

import json
from pathlib import Path

from endpoint_incident_triage.json_report import build_triage_report, write_json_report
from endpoint_incident_triage.statuses import PrivacyMode, SourceMode
from tests.helpers.factories import make_case_metadata, make_collector_result, make_finding


def _sample_report():
    return build_triage_report(
        package_id="case-TEST-20260805T180000Z",
        case_metadata=make_case_metadata(source_mode=SourceMode.SYNTHETIC),
        collector_results=[make_collector_result()],
        findings=[make_finding()],
        timeline_events=[],
        synthetic=True,
        privacy_mode=PrivacyMode.MASKED,
        integrity_status="Verified",
        custody_status="Verified",
        verification_ok=True,
    )


def test_build_triage_report_fields():
    report = _sample_report()
    assert report.synthetic is True
    assert report.security_notice
    assert report.case_summary["case_id"] == "SYNTHETIC-001"


def test_write_json_report_utf8(tmp_path: Path):
    path = tmp_path / "triage-report.json"
    warnings = write_json_report(path, _sample_report())
    assert isinstance(warnings, list)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0.0"
    assert payload["privacy_mode"] == "masked"


def test_json_report_includes_advisory_notice():
    report = _sample_report()
    assert "advisory" in report.security_notice.lower()


def test_json_report_finding_counts():
    report = _sample_report()
    assert sum(report.finding_counts.values()) >= 1
