"""Tests for evidence path validation and package layout."""

from __future__ import annotations

from pathlib import Path

import pytest

from endpoint_incident_triage.evidence_paths import (
    PathValidationError,
    create_case_directory,
    ensure_package_layout,
    ensure_within,
    is_system_sensitive_path,
    normalize_relative_path,
    package_layout,
    refuse_output_inside_source,
    validate_case_id,
)


def test_validate_case_id_accepts_safe_values():
    assert validate_case_id("SYNTHETIC-001") == "SYNTHETIC-001"


def test_validate_case_id_rejects_traversal():
    with pytest.raises(PathValidationError):
        validate_case_id("../escape")


def test_validate_case_id_rejects_windows_reserved():
    with pytest.raises(PathValidationError):
        validate_case_id("CON")


def test_normalize_relative_path_posix():
    assert normalize_relative_path("metadata/case.json") == "metadata/case.json"


def test_normalize_relative_path_rejects_traversal():
    with pytest.raises(PathValidationError):
        normalize_relative_path("../etc/passwd")


def test_normalize_relative_path_rejects_absolute():
    with pytest.raises(PathValidationError):
        normalize_relative_path("/etc/passwd")


def test_ensure_within_rejects_escape(tmp_path: Path):
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(PathValidationError):
        ensure_within(base, outside)


def test_is_system_sensitive_path_detects_windows():
    assert is_system_sensitive_path(Path("C:/Windows/Temp"))


def test_refuse_output_inside_source(tmp_path: Path):
    source = tmp_path / "collectors"
    source.mkdir()
    output = source / "out"
    output.mkdir()
    with pytest.raises(PathValidationError):
        refuse_output_inside_source(output, [source])


def test_create_case_directory_refuses_overwrite(tmp_path: Path):
    create_case_directory(tmp_path, "CASE-001", "20260805T180000Z")
    with pytest.raises(PathValidationError, match="Refuse overwrite"):
        create_case_directory(tmp_path, "CASE-001", "20260805T180000Z")


def test_ensure_package_layout_creates_subdirs(tmp_path: Path):
    root = tmp_path / "pkg"
    root.mkdir()
    layout = ensure_package_layout(root)
    assert layout["metadata"].is_dir()
    assert layout["artifacts"].is_dir()
    assert layout["custody"].is_dir()


def test_package_layout_keys():
    layout = package_layout(Path("/tmp/pkg"))
    assert set(layout) >= {"metadata", "artifacts", "manifests", "custody", "timeline"}
