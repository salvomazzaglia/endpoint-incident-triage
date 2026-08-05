"""Small factories and path helpers for pytest."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from endpoint_incident_triage import SCHEMA_VERSION
from endpoint_incident_triage.custody import GENESIS_HASH, append_record, make_record
from endpoint_incident_triage.models import CaseMetadata, CollectorResult, Finding
from endpoint_incident_triage.rules import RuleCondition, TriageRule
from endpoint_incident_triage.statuses import (
    CollectorStatus,
    FindingSeverity,
    SourceMode,
)


def repo_root() -> Path:
    """Return repository root (parent of tests/)."""
    return Path(__file__).resolve().parents[2]


def synthetic_input_dir() -> Path:
    return repo_root() / "examples" / "synthetic-input"


def synthetic_package_dir() -> Path:
    return repo_root() / "examples" / "synthetic-evidence-package"


def demo_config_path() -> Path:
    return repo_root() / "config" / "demo.config.json"


def default_config_path() -> Path:
    return repo_root() / "config" / "default.config.json"


def load_fixture_records(platform: str, collector_id: str) -> list[dict[str, Any]]:
    """Load records from tests/fixtures or examples/synthetic-input."""
    for root in (repo_root() / "tests" / "fixtures", synthetic_input_dir()):
        path = root / platform / f"{collector_id}.json"
        if path.is_file():
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("records"), list):
                return payload["records"]
            if isinstance(payload, list):
                return payload
    return []


def make_collector_result(
    *,
    collector_id: str = "windows.processes",
    platform: str = "windows",
    category: str = "process",
    status: CollectorStatus = CollectorStatus.COLLECTED,
    records: list[dict[str, Any]] | None = None,
    source_mode: SourceMode = SourceMode.SYNTHETIC,
) -> CollectorResult:
    record_list = records if records is not None else load_fixture_records(platform, collector_id)
    return CollectorResult(
        schema_version=SCHEMA_VERSION,
        collector_id=collector_id,
        platform=platform,
        category=category,
        status=status,
        started_at_utc="2026-08-05T18:00:00Z",
        completed_at_utc="2026-08-05T18:00:05Z",
        duration_ms=5000,
        privilege_state="standard",
        source_mode=source_mode,
        record_count=len(record_list),
        records=record_list,
    )


def make_case_metadata(**overrides: Any) -> CaseMetadata:
    defaults = {
        "case_id": "SYNTHETIC-001",
        "collection_id": str(uuid.uuid4()),
        "authorization_reference": "SYNTHETIC-AUTH",
        "operator_label": "TEST-OPERATOR",
        "collection_reason": "Unit test",
        "target_label": "SYNTHETIC-ENDPOINT",
        "started_at_utc": "2026-08-05T18:00:00Z",
        "completed_at_utc": "2026-08-05T18:05:00Z",
        "source_mode": SourceMode.SYNTHETIC,
        "platform": "windows",
        "tool_version": "1.0.0",
        "profile": "standard",
        "limitations": ["Synthetic test data only."],
    }
    defaults.update(overrides)
    return CaseMetadata(**defaults)


def make_rule(**overrides: Any) -> TriageRule:
    defaults: dict[str, Any] = {
        "id": "test_rule",
        "title": "Test rule",
        "description": "Test description",
        "platform": "any",
        "artifact_type": "process",
        "enabled": True,
        "priority": 50,
        "conditions": [
            RuleCondition(type="contains", field_name="path", value="Temp"),
        ],
        "severity": FindingSeverity.MEDIUM,
        "rationale": "Test rationale",
        "recommendation": "Test recommendation",
        "references": [],
        "tags": ["test"],
        "advisory_wording": "Requires review",
    }
    defaults.update(overrides)
    return TriageRule(**defaults)


def make_finding(**overrides: Any) -> Finding:
    defaults: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "rule_id": "process_from_temp_path",
        "title": "Process from temp",
        "description": "Advisory finding",
        "severity": FindingSeverity.MEDIUM,
        "platform": "windows",
        "artifact_type": "process",
        "entity_id": "4512",
        "rationale": "Heuristic match",
        "recommendation": "Review manually",
        "references": [],
        "tags": ["test"],
        "advisory_wording": "Requires review",
        "source_artifact": "artifacts/windows/windows.processes.json",
    }
    defaults.update(overrides)
    return Finding(**defaults)


def make_custody_ledger(package_id: str = "case-TEST-20260805T180000Z") -> list:
    ledger = []
    append_record(
        ledger,
        event_type="case_created",
        package_id=package_id,
        actor_label="TEST",
        action="create_case_package",
        details={"case_id": "TEST"},
    )
    append_record(
        ledger,
        event_type="collection_started",
        package_id=package_id,
        actor_label="TEST",
        action="start_collection",
        details={"profile": "standard"},
    )
    return ledger


def minimal_config_dict(**overrides: Any) -> dict[str, Any]:
    base = {
        "schema_version": "1.0.0",
        "tool": {"name": "endpoint-incident-triage"},
        "defaults": {"profile": "minimal", "platform": "auto", "since_hours": 24},
        "privacy": {"report_mode": "masked"},
        "safety": {},
        "paths": {
            "collector_registry": "config/collector-registry.json",
            "collection_profiles": "config/collection-profiles.json",
            "triage_rules": "config/triage-rules.json",
            "collectors_root": "collectors",
        },
    }
    base.update(overrides)
    return base
