"""Aggregate collector and finding statistics for reports."""

from __future__ import annotations

from typing import Any

from endpoint_incident_triage.findings import count_by_severity, highest_severity
from endpoint_incident_triage.models import CollectorResult, Finding, TriageReport
from endpoint_incident_triage.statuses import CollectorStatus, ReportStatus


def count_collector_statuses(results: list[CollectorResult]) -> dict[str, int]:
    """Count collector results by status label."""
    counts = {status.value: 0 for status in CollectorStatus}
    for result in results:
        counts[result.status.value] = counts.get(result.status.value, 0) + 1
    return counts


def count_artifacts(results: list[CollectorResult]) -> dict[str, int]:
    """Count artifacts by platform."""
    counts: dict[str, int] = {"collector_results": len(results), "records": 0}
    for result in results:
        counts["records"] += result.record_count
        key = f"{result.platform}_collectors"
        counts[key] = counts.get(key, 0) + 1
    return counts


def derive_report_status(
    collector_results: list[CollectorResult],
    *,
    verification_ok: bool,
    mandatory_failed: bool = False,
) -> ReportStatus:
    """Derive overall report status from collectors and verification."""
    if not verification_ok or mandatory_failed:
        return ReportStatus.FAILED
    statuses = {result.status for result in collector_results}
    if statuses - {CollectorStatus.COLLECTED, CollectorStatus.SKIPPED}:
        if CollectorStatus.ERROR in statuses:
            return ReportStatus.FAILED
        return ReportStatus.PARTIAL
    return ReportStatus.COMPLETE


def build_collection_summary(results: list[CollectorResult]) -> dict[str, Any]:
    """Build collection summary section."""
    if not results:
        return {"collector_count": 0, "record_count": 0}
    return {
        "collector_count": len(results),
        "record_count": sum(item.record_count for item in results),
        "started_at_utc": min(item.started_at_utc for item in results),
        "completed_at_utc": max(item.completed_at_utc for item in results),
        "platforms": sorted({item.platform for item in results}),
    }


def build_platform_summary(results: list[CollectorResult]) -> dict[str, Any]:
    """Summarize per-platform collector outcomes."""
    summary: dict[str, Any] = {}
    for result in results:
        bucket = summary.setdefault(
            result.platform, {"collectors": 0, "records": 0, "statuses": {}}
        )
        bucket["collectors"] += 1
        bucket["records"] += result.record_count
        statuses: dict[str, int] = bucket["statuses"]
        statuses[result.status.value] = statuses.get(result.status.value, 0) + 1
    return summary


def aggregate_report_fields(
    *,
    collector_results: list[CollectorResult],
    findings: list[Finding],
    timeline_events_count: int,
    timeline_first: str | None,
    timeline_last: str | None,
    verification_ok: bool,
    integrity_status: str,
    custody_status: str,
) -> dict[str, Any]:
    """Aggregate common report count fields."""
    highest = highest_severity(findings)
    return {
        "collector_status_counts": count_collector_statuses(collector_results),
        "artifact_counts": count_artifacts(collector_results),
        "timeline_summary": {
            "event_count": timeline_events_count,
            "first_timestamp_utc": timeline_first,
            "last_timestamp_utc": timeline_last,
        },
        "finding_counts": count_by_severity(findings),
        "highest_finding_severity": highest.value if highest else None,
        "integrity_status": integrity_status,
        "custody_status": custody_status,
        "report_status": derive_report_status(
            collector_results, verification_ok=verification_ok
        ).value,
    }


def summarize_for_console(report: TriageReport) -> dict[str, str]:
    """Build concise console summary strings."""
    return {
        "status": report.status.value,
        "integrity": report.integrity_status,
        "custody": report.custody_status,
        "findings": str(sum(report.finding_counts.values())),
        "highest_severity": report.highest_finding_severity or "None",
        "collectors": str(sum(report.collector_status_counts.values())),
    }
