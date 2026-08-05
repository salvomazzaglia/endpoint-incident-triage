"""Tests for HTML report generation."""

from __future__ import annotations

import html as html_module
from pathlib import Path

from endpoint_incident_triage.html_report import render_html_report, write_html_report
from endpoint_incident_triage.json_report import build_triage_report
from endpoint_incident_triage.statuses import PrivacyMode
from tests.helpers.factories import make_case_metadata, make_collector_result, make_finding


def _sample_report(*, synthetic: bool = True):
    metadata = make_case_metadata(
        source_mode=__import__(
            "endpoint_incident_triage.statuses", fromlist=["SourceMode"]
        ).SourceMode.SYNTHETIC
    )
    findings = [make_finding(title="<script>alert(1)</script>")]
    return build_triage_report(
        package_id="case-TEST-20260805T180000Z",
        case_metadata=metadata,
        collector_results=[make_collector_result()],
        findings=findings,
        timeline_events=[],
        synthetic=synthetic,
        privacy_mode=PrivacyMode.MASKED,
        integrity_status="Verified",
        custody_status="Verified",
        verification_ok=True,
    )


def test_render_html_report_standalone():
    rendered = render_html_report(_sample_report())
    assert rendered.startswith("<!DOCTYPE html>")
    assert "<style>" in rendered
    assert 'src="' not in rendered
    assert 'href="http' not in rendered


def test_render_html_escapes_user_content():
    rendered = render_html_report(_sample_report())
    assert "<script>alert(1)</script>" not in rendered
    assert html_module.escape("<script>alert(1)</script>") in rendered


def test_render_html_includes_synthetic_banner():
    rendered = render_html_report(_sample_report(synthetic=True))
    assert "SYNTHETIC DEMONSTRATION DATA" in rendered


def test_render_html_includes_advisory_wording():
    rendered = render_html_report(_sample_report())
    assert "Requires review" in rendered
    assert "heuristic" in rendered.lower()


def test_write_html_report(tmp_path: Path):
    path = tmp_path / "report.html"
    write_html_report(path, _sample_report())
    text = path.read_text(encoding="utf-8")
    assert path.is_file()
    assert "endpoint-incident-triage" in text
