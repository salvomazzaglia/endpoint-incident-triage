"""Core data models for cases, collectors, manifests, findings, and reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from endpoint_incident_triage.statuses import (
    CollectorStatus,
    FindingSeverity,
    PrivacyMode,
    ReportStatus,
    SourceMode,
)


def to_jsonable(obj: Any) -> Any:
    """Convert dataclasses and enums into JSON-serializable structures."""
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, list):
        return [to_jsonable(item) for item in obj]
    if isinstance(obj, dict):
        return {str(key): to_jsonable(value) for key, value in obj.items()}
    if hasattr(obj, "value") and hasattr(obj, "name"):
        return obj.value
    if hasattr(obj, "__dataclass_fields__"):
        return {key: to_jsonable(value) for key, value in asdict(obj).items()}
    return obj


@dataclass(slots=True)
class TruncationInfo:
    truncated: bool = False
    reason: str | None = None
    original_bytes: int | None = None
    retained_bytes: int | None = None
    original_records: int | None = None
    retained_records: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CollectorResult:
    schema_version: str
    collector_id: str
    platform: str
    category: str
    status: CollectorStatus
    started_at_utc: str
    completed_at_utc: str
    duration_ms: int
    privilege_state: str
    source_mode: SourceMode
    record_count: int
    records: list[dict[str, Any]]
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    truncation: TruncationInfo = field(default_factory=TruncationInfo)
    sensitive_fields_omitted: list[str] = field(default_factory=list)
    command_provenance: list[str] = field(default_factory=list)
    collector_version: str = "1.0.0"
    exit_code: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "collector_id": self.collector_id,
            "platform": self.platform,
            "category": self.category,
            "status": self.status.value,
            "started_at_utc": self.started_at_utc,
            "completed_at_utc": self.completed_at_utc,
            "duration_ms": self.duration_ms,
            "privilege_state": self.privilege_state,
            "source_mode": self.source_mode.value,
            "record_count": self.record_count,
            "records": self.records,
            "warnings": self.warnings,
            "errors": self.errors,
            "truncation": self.truncation.to_dict(),
            "sensitive_fields_omitted": self.sensitive_fields_omitted,
            "command_provenance": self.command_provenance,
            "collector_version": self.collector_version,
            "exit_code": self.exit_code,
        }


@dataclass(slots=True)
class CaseMetadata:
    case_id: str
    collection_id: str
    authorization_reference: str
    operator_label: str
    collection_reason: str
    target_label: str
    started_at_utc: str
    completed_at_utc: str | None
    source_mode: SourceMode
    platform: str
    tool_version: str
    profile: str
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "collection_id": self.collection_id,
            "authorization_reference": self.authorization_reference,
            "operator_label": self.operator_label,
            "collection_reason": self.collection_reason,
            "target_label": self.target_label,
            "started_at_utc": self.started_at_utc,
            "completed_at_utc": self.completed_at_utc,
            "source_mode": self.source_mode.value,
            "platform": self.platform,
            "tool_version": self.tool_version,
            "profile": self.profile,
            "limitations": self.limitations,
        }


@dataclass(slots=True)
class ManifestEntry:
    relative_path: str
    size_bytes: int
    sha256: str
    artifact_type: str
    collector_id: str | None
    created_at_utc: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ManifestDocument:
    schema_version: str
    generated_at_utc: str
    package_id: str
    algorithm: str
    entries: list[ManifestEntry]
    manifest_scope: str
    excluded_paths: list[str]
    generator_version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at_utc": self.generated_at_utc,
            "package_id": self.package_id,
            "algorithm": self.algorithm,
            "entries": [entry.to_dict() for entry in self.entries],
            "manifest_scope": self.manifest_scope,
            "excluded_paths": self.excluded_paths,
            "generator_version": self.generator_version,
        }


@dataclass(slots=True)
class CustodyRecord:
    schema_version: str
    sequence: int
    event_id: str
    event_type: str
    occurred_at_utc: str
    actor_label: str
    action: str
    package_id: str
    details: dict[str, Any]
    previous_record_hash: str
    record_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "occurred_at_utc": self.occurred_at_utc,
            "actor_label": self.actor_label,
            "action": self.action,
            "package_id": self.package_id,
            "details": self.details,
            "previous_record_hash": self.previous_record_hash,
            "record_hash": self.record_hash,
        }


@dataclass(slots=True)
class TimelineEvent:
    timestamp_utc: str
    timestamp_source: str
    timestamp_precision: str
    platform: str
    collector_id: str
    event_type: str
    entity_type: str
    entity_id: str
    summary: str
    details: dict[str, Any]
    confidence: str
    source_artifact: str
    original_timestamp: str | None
    timezone_assumption: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    id: str
    rule_id: str
    title: str
    description: str
    severity: FindingSeverity
    platform: str
    artifact_type: str
    entity_id: str
    rationale: str
    recommendation: str
    references: list[str]
    tags: list[str]
    advisory_wording: str
    source_artifact: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(slots=True)
class TriageReport:
    tool_name: str
    tool_version: str
    schema_version: str
    generated_at_utc: str
    synthetic: bool
    package_id: str
    status: ReportStatus
    case_summary: dict[str, Any]
    collection_summary: dict[str, Any]
    platform_summary: dict[str, Any]
    collector_status_counts: dict[str, int]
    artifact_counts: dict[str, int]
    timeline_summary: dict[str, Any]
    finding_counts: dict[str, int]
    highest_finding_severity: str | None
    integrity_status: str
    custody_status: str
    limitations: list[str]
    findings: list[Finding]
    collector_results: list[dict[str, Any]]
    recommendations: list[str]
    privacy_mode: PrivacyMode
    security_notice: str
    exit_code: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "schema_version": self.schema_version,
            "generated_at_utc": self.generated_at_utc,
            "synthetic": self.synthetic,
            "package_id": self.package_id,
            "status": self.status.value,
            "case_summary": self.case_summary,
            "collection_summary": self.collection_summary,
            "platform_summary": self.platform_summary,
            "collector_status_counts": self.collector_status_counts,
            "artifact_counts": self.artifact_counts,
            "timeline_summary": self.timeline_summary,
            "finding_counts": self.finding_counts,
            "highest_finding_severity": self.highest_finding_severity,
            "integrity_status": self.integrity_status,
            "custody_status": self.custody_status,
            "limitations": self.limitations,
            "findings": [finding.to_dict() for finding in self.findings],
            "collector_results": self.collector_results,
            "recommendations": self.recommendations,
            "privacy_mode": self.privacy_mode.value,
            "security_notice": self.security_notice,
            "exit_code": self.exit_code,
        }
