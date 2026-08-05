"""Tests for ZIP evidence packaging."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from endpoint_incident_triage.package import PackageError, create_zip_package, write_zip_sidecar
from tests.helpers.factories import synthetic_package_dir


def test_create_zip_from_verified_package(tmp_path: Path):
    package = synthetic_package_dir()
    zip_path = tmp_path / "package.zip"
    result = create_zip_package(package, zip_path)
    assert result.zip_path.is_file()
    assert result.sha256_path.is_file()
    assert len(result.sha256) == 64
    assert result.member_count > 0


def test_zip_members_use_normalized_paths(tmp_path: Path):
    package = synthetic_package_dir()
    zip_path = tmp_path / "package.zip"
    create_zip_package(package, zip_path)
    with zipfile.ZipFile(zip_path, "r") as archive:
        names = archive.namelist()
    assert all("\\" not in name for name in names)
    assert all(not name.startswith("/") for name in names)
    assert "README.txt" in names


def test_create_zip_refuses_overwrite(tmp_path: Path):
    package = synthetic_package_dir()
    zip_path = tmp_path / "package.zip"
    create_zip_package(package, zip_path)
    with pytest.raises(PackageError, match="Refuse overwrite"):
        create_zip_package(package, zip_path)


def test_create_zip_rejects_unverified_package(tmp_path: Path):
    bad_root = tmp_path / "bad-pkg"
    bad_root.mkdir()
    (bad_root / "README.txt").write_text("incomplete", encoding="utf-8")
    zip_path = tmp_path / "bad.zip"
    with pytest.raises(PackageError, match="verification failed"):
        create_zip_package(bad_root, zip_path)


def test_write_zip_sidecar(tmp_path: Path):
    package = synthetic_package_dir()
    zip_path = tmp_path / "package.zip"
    result = create_zip_package(package, zip_path)
    sidecar = write_zip_sidecar(result.zip_path, result.sha256)
    text = sidecar.read_text(encoding="utf-8")
    assert result.sha256 in text


def test_zip_traversal_member_names_rejected_on_extract(tmp_path: Path):
    """Packaging normalizes paths; malicious names must not appear in archive."""
    package = synthetic_package_dir()
    zip_path = tmp_path / "safe.zip"
    create_zip_package(package, zip_path)
    with zipfile.ZipFile(zip_path, "r") as archive:
        for name in archive.namelist():
            assert ".." not in name.split("/")
