"""Tests for evidence package verification."""

from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

import pytest

from endpoint_incident_triage.custody import read_ledger, verify_ledger, write_ledger
from endpoint_incident_triage.manifest import build_manifest, write_manifest, write_sha256sums
from endpoint_incident_triage.package import create_zip_package
from endpoint_incident_triage.verification import (
    VerificationError,
    verify_directory,
    verify_package,
)
from tests.helpers.factories import synthetic_package_dir


@pytest.fixture
def verified_copy(tmp_path: Path) -> Path:
    src = synthetic_package_dir()
    dest = tmp_path / "package"
    shutil.copytree(src, dest)
    from tests.helpers.package_rehash import rehash_package_directory

    rehash_package_directory(dest)
    return dest


def test_verify_synthetic_directory_ok(verified_copy: Path):
    result = verify_directory(verified_copy)
    assert result.ok
    assert result.integrity_status == "Verified"
    assert result.custody_status == "Verified"


def test_verify_detects_tampered_file(verified_copy: Path):
    artifact = next((verified_copy / "artifacts").rglob("*.json"))
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    payload["tampered"] = True
    artifact.write_text(json.dumps(payload), encoding="utf-8")
    result = verify_directory(verified_copy)
    assert not result.ok
    assert any("mismatch" in err.lower() for err in result.errors)


def test_verify_detects_missing_manifest(verified_copy: Path):
    (verified_copy / "manifests" / "manifest.json").unlink()
    result = verify_directory(verified_copy)
    assert not result.ok
    assert any("Missing manifests" in err for err in result.errors)


def test_verify_detects_custody_tamper(verified_copy: Path):
    ledger_path = verified_copy / "custody" / "custody.jsonl"
    ledger = read_ledger(ledger_path)
    ledger[0].details = {"tampered": True}
    write_ledger(ledger_path, ledger)
    result = verify_directory(verified_copy)
    assert result.custody_status == "Failed"


def test_verify_zip_package(tmp_path: Path, verified_copy: Path):
    zip_path = tmp_path / "pkg.zip"
    create_zip_package(verified_copy, zip_path)
    result = verify_package(zip_path)
    assert result.ok


def test_verify_zip_rejects_traversal_names(tmp_path: Path):
    bad_zip = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad_zip, "w") as archive:
        archive.writestr("../escape.txt", "evil")
    result = verify_package(bad_zip)
    assert not result.ok
    assert any("Unsafe ZIP" in err for err in result.errors)


def test_verify_unsupported_path(tmp_path: Path):
    file_path = tmp_path / "not-a-package.txt"
    file_path.write_text("nope", encoding="utf-8")
    with pytest.raises(VerificationError):
        verify_package(file_path)


def test_verify_unexpected_file_on_disk(verified_copy: Path):
    (verified_copy / "unexpected.txt").write_text("extra", encoding="utf-8")
    result = verify_directory(verified_copy)
    assert not result.ok
    assert any("Unexpected artifact" in err for err in result.errors)
