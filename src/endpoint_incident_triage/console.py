"""Console summary output for triage operations."""

from __future__ import annotations

import sys
from typing import Any, TextIO

from endpoint_incident_triage.aggregation import summarize_for_console
from endpoint_incident_triage.models import TriageReport
from endpoint_incident_triage.verification import VerificationResult


def _write(line: str, stream: TextIO) -> None:
    stream.write(line + "\n")


def print_verification_summary(result: VerificationResult, *, stream: TextIO | None = None) -> None:
    """Print package verification summary."""
    out = stream or sys.stdout
    status = "PASS" if result.ok else "FAIL"
    _write(f"Verification: {status}", out)
    _write(f"  Integrity: {result.integrity_status}", out)
    _write(f"  Custody:   {result.custody_status}", out)
    if result.package_id:
        _write(f"  Package:   {result.package_id}", out)
    if result.manifest_hash:
        _write(f"  Manifest:  {result.manifest_hash[:16]}...", out)
    for warning in result.warnings:
        _write(f"  Warning: {warning}", out)
    for error in result.errors:
        _write(f"  Error: {error}", out)


def print_report_summary(
    report: TriageReport,
    report_paths: list[str] | None = None,
    *,
    stream: TextIO | None = None,
) -> None:
    """Print triage report summary."""
    out = stream or sys.stdout
    summary = summarize_for_console(report)
    _write(f"Triage report: {summary['status']}", out)
    _write(f"  Package:     {report.package_id}", out)
    _write(f"  Synthetic:   {report.synthetic}", out)
    _write(f"  Integrity:   {summary['integrity']}", out)
    _write(f"  Custody:     {summary['custody']}", out)
    _write(f"  Collectors:  {summary['collectors']}", out)
    _write(f"  Findings:    {summary['findings']} (highest: {summary['highest_severity']})", out)
    _write(f"  Privacy:     {report.privacy_mode.value}", out)
    if report_paths:
        _write("  Reports:", out)
        for path in report_paths:
            _write(f"    - {path}", out)
    if report.limitations:
        _write("  Limitations:", out)
        for item in report.limitations[:5]:
            _write(f"    - {item}", out)


def print_collector_status_counts(counts: dict[str, int], *, stream: TextIO | None = None) -> None:
    """Print collector status counts."""
    out = stream or sys.stdout
    _write("Collector statuses:", out)
    for status, count in sorted(counts.items()):
        _write(f"  {status}: {count}", out)


def print_finding_counts(counts: dict[str, int], *, stream: TextIO | None = None) -> None:
    """Print finding severity counts."""
    out = stream or sys.stdout
    _write("Finding severities:", out)
    for severity, count in sorted(counts.items()):
        _write(f"  {severity}: {count}", out)


def print_collection_plan(
    collectors: list[Any],
    *,
    platform: str,
    profile: str,
    since_hours: int | None = None,
    stream: TextIO | None = None,
) -> None:
    """Print planned collectors without executing them."""
    out = stream or sys.stdout
    hours = f", since_hours={since_hours}" if since_hours is not None else ""
    _write(f"Collection plan ({platform}, profile={profile}{hours})", out)
    for collector in collectors:
        mandatory = "mandatory" if collector.mandatory else "optional"
        _write(
            f"  [{collector.volatility_order:02d}] {collector.id} "
            f"({collector.category}, {mandatory})",
            out,
        )
