"""UTF-8 JSON triage report generation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from endpoint_incident_triage import SCHEMA_VERSION, TOOL_NAME, __version__
from endpoint_incident_triage.aggregation import (
    aggregate_report_fields,
    build_collection_summary,
    build_platform_summary,
)
from endpoint_incident_triage.models import CaseMetadata, CollectorResult, Finding, TriageReport
from endpoint_incident_triage.privacy import apply_privacy
from endpoint_incident_triage.statuses import PrivacyMode, ReportStatus
from endpoint_incident_triage.timestamps import utc_now_iso

SECURITY_NOTICE = (
    "Heuristic findings are advisory only and require analyst review. "
    "This report does not confirm malware, compromise, or a clean endpoint. "
    "Integrity verification confirms consistency with recorded manifests and "
    "custody records, not legal provenance or completeness."
)


def build_triage_report(
    *,
    package_id: str,
    case_metadata: CaseMetadata,
    collector_results: list[CollectorResult],
    findings: list[Finding],
    timeline_events: list[Any],
    synthetic: bool,
    privacy_mode: PrivacyMode = PrivacyMode.MASKED,
    integrity_status: str,
    custody_status: str,
    verification_ok: bool,
    limitations: list[str] | None = None,
    recommendations: list[str] | None = None,
    exit_code: int = 0,
    hash_salt: str | None = None,
    hash_salt_env: str = "EIT_HASH_SALT",
) -> TriageReport:
    """Build a TriageReport from package components."""
    timeline_first = timeline_events[0].timestamp_utc if timeline_events else None
    timeline_last = timeline_events[-1].timestamp_utc if timeline_events else None
    aggregated = aggregate_report_fields(
        collector_results=collector_results,
        findings=findings,
        timeline_events_count=len(timeline_events),
        timeline_first=timeline_first,
        timeline_last=timeline_last,
        verification_ok=verification_ok,
        integrity_status=integrity_status,
        custody_status=custody_status,
    )
    status = ReportStatus(aggregated["report_status"])
    report = TriageReport(
        tool_name=TOOL_NAME,
        tool_version=__version__,
        schema_version=SCHEMA_VERSION,
        generated_at_utc=utc_now_iso(),
        synthetic=synthetic,
        package_id=package_id,
        status=status,
        case_summary=case_metadata.to_dict(),
        collection_summary=build_collection_summary(collector_results),
        platform_summary=build_platform_summary(collector_results),
        collector_status_counts=aggregated["collector_status_counts"],
        artifact_counts=aggregated["artifact_counts"],
        timeline_summary=aggregated["timeline_summary"],
        finding_counts=aggregated["finding_counts"],
        highest_finding_severity=aggregated["highest_finding_severity"],
        integrity_status=integrity_status,
        custody_status=custody_status,
        limitations=limitations or list(case_metadata.limitations),
        findings=findings,
        collector_results=[item.to_dict() for item in collector_results],
        recommendations=recommendations or [],
        privacy_mode=privacy_mode,
        security_notice=SECURITY_NOTICE,
        exit_code=exit_code,
    )
    return report


def write_json_report(path: Path, report: TriageReport, *, indent: int = 2) -> list[str]:
    """Write triage report as indented UTF-8 JSON; return privacy warnings."""
    payload, warnings = apply_privacy(report.to_dict(), report.privacy_mode)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=indent, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return warnings
