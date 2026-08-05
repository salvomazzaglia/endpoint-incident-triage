"""Tests for case package creation helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from endpoint_incident_triage.case import (
    build_package_id,
    create_case_metadata,
    initialize_case_package,
    write_collector_artifact,
    write_findings_json,
    write_readme,
)
from endpoint_incident_triage.evidence_paths import PathValidationError, package_layout
from endpoint_incident_triage.statuses import SourceMode
from tests.helpers.factories import make_collector_result, repo_root


def test_build_package_id_format():
    package_id = build_package_id("SYNTHETIC-001", "20260805T180000Z")
    assert package_id == "case-SYNTHETIC-001-20260805T180000Z"


def test_build_package_id_rejects_invalid_case_id():
    with pytest.raises(PathValidationError):
        build_package_id("../bad", "20260805T180000Z")


def test_create_case_metadata_defaults():
    meta = create_case_metadata(
        case_id="TEST-001",
        authorization_reference="AUTH-1",
        operator_label="OP",
        collection_reason="Test",
        target_label="HOST",
        platform="windows",
        profile="minimal",
        source_mode=SourceMode.SYNTHETIC,
    )
    assert meta.case_id == "TEST-001"
    assert meta.source_mode == SourceMode.SYNTHETIC
    assert meta.started_at_utc.endswith("Z")


def test_initialize_case_package_creates_layout(tmp_path: Path):
    meta = create_case_metadata(
        case_id="TEST-002",
        authorization_reference="AUTH",
        operator_label="OP",
        collection_reason="Test",
        target_label="HOST",
        platform="linux",
        profile="standard",
        source_mode=SourceMode.SYNTHETIC,
    )
    ctx = initialize_case_package(
        tmp_path,
        case_id="TEST-002",
        stamp="20260805T180000Z",
        metadata=meta,
        actor_label="OP",
    )
    layout = ctx.layout
    assert (layout["metadata"] / "case.json").is_file()
    assert (layout["custody"]).is_dir()
    assert len(ctx.custody_ledger) == 1
    assert ctx.custody_ledger[0].event_type == "case_created"


def test_write_readme_includes_synthetic_notice(tmp_path: Path):
    meta = create_case_metadata(
        case_id="TEST-003",
        authorization_reference="AUTH",
        operator_label="OP",
        collection_reason="Test",
        target_label="HOST",
        platform="windows",
        profile="minimal",
        source_mode=SourceMode.SYNTHETIC,
    )
    layout = package_layout(tmp_path / "pkg")
    layout["root"].mkdir()
    write_readme(layout, package_id="case-TEST-003-20260805T180000Z", metadata=meta)
    text = (layout["root"] / "README.txt").read_text(encoding="utf-8")
    assert "SYNTHETIC DEMONSTRATION DATA" in text
    assert "SENSITIVITY WARNING" in text


def test_write_collector_artifact(tmp_path: Path):
    layout = package_layout(tmp_path / "pkg")
    for key, path in layout.items():
        if key != "root":
            path.mkdir(parents=True)
    result = make_collector_result()
    path = write_collector_artifact(layout, result)
    assert path.is_file()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["collector_id"] == result.collector_id


def test_write_findings_json(tmp_path: Path):
    layout = package_layout(tmp_path / "pkg")
    layout["findings"].mkdir(parents=True)
    path = write_findings_json(layout, [{"rule_id": "test", "title": "Finding"}])
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["findings"][0]["rule_id"] == "test"


def test_synthetic_input_fixtures_exist():
    root = repo_root() / "examples" / "synthetic-input"
    assert (root / "windows" / "windows.processes.json").is_file()
    assert (root / "linux" / "linux.processes.json").is_file()
