"""Tests for manifest generation and validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from endpoint_incident_triage.manifest import (
    EXCLUDED_PATHS,
    ManifestError,
    build_manifest,
    compute_manifest_document_hash,
    load_manifest,
    parse_sha256sums,
    verify_entry_hash,
    write_manifest,
    write_sha256sums,
)
from tests.helpers.factories import synthetic_package_dir


def test_build_manifest_from_synthetic_package():
    root = synthetic_package_dir()
    manifest = build_manifest(root, package_id=root.name)
    assert manifest.entries
    assert manifest.algorithm == "sha256"
    paths = [entry.relative_path for entry in manifest.entries]
    assert paths == sorted(paths)
    for excluded in EXCLUDED_PATHS:
        assert excluded not in paths


def test_write_manifest_and_hash(tmp_path: Path):
    (tmp_path / "README.txt").write_text("test package", encoding="utf-8")
    (tmp_path / "metadata").mkdir()
    (tmp_path / "metadata" / "case.json").write_text('{"case_id":"T"}', encoding="utf-8")
    doc = build_manifest(tmp_path, package_id="case-T-stamp")
    manifest_path = tmp_path / "manifests" / "manifest.json"
    write_manifest(manifest_path, doc)
    digest = compute_manifest_document_hash(manifest_path)
    assert len(digest) == 64


def test_write_sha256sums(tmp_path: Path):
    (tmp_path / "README.txt").write_text("x", encoding="utf-8")
    doc = build_manifest(tmp_path, package_id="pkg")
    sums_path = tmp_path / "manifests" / "SHA256SUMS"
    write_sha256sums(sums_path, doc)
    entries, invalid = parse_sha256sums(sums_path.read_text(encoding="utf-8"))
    assert not invalid
    assert entries


def test_parse_sha256sums_invalid_line():
    entries, invalid = parse_sha256sums("not-a-valid-line\n")
    assert invalid
    assert not entries


def test_load_manifest_roundtrip(tmp_path: Path):
    (tmp_path / "README.txt").write_text("x", encoding="utf-8")
    doc = build_manifest(tmp_path, package_id="pkg")
    path = tmp_path / "manifests" / "manifest.json"
    write_manifest(path, doc)
    loaded = load_manifest(path)
    assert loaded.package_id == doc.package_id
    assert len(loaded.entries) == len(doc.entries)


def test_verify_entry_hash_ok(tmp_path: Path):
    target = tmp_path / "README.txt"
    target.write_text("content", encoding="utf-8")
    doc = build_manifest(tmp_path, package_id="pkg")
    error = verify_entry_hash(tmp_path, doc.entries[0])
    assert error is None


def test_verify_entry_hash_mismatch(tmp_path: Path):
    target = tmp_path / "README.txt"
    target.write_text("content", encoding="utf-8")
    doc = build_manifest(tmp_path, package_id="pkg")
    entry = doc.entries[0]
    entry.sha256 = "0" * 64
    error = verify_entry_hash(tmp_path, entry)
    assert error and "mismatch" in error.lower()


def test_build_manifest_rejects_symlink(tmp_path: Path):
    real = tmp_path / "real.txt"
    real.write_text("x", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("Symlinks not supported")
    with pytest.raises(ManifestError, match="Symlink"):
        build_manifest(tmp_path, package_id="pkg")
