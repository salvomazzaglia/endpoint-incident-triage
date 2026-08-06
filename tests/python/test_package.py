"""Tests for ZIP evidence packaging."""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

import pytest

from endpoint_incident_triage.package import PackageError, create_zip_package, write_zip_sidecar
from tests.helpers.factories import synthetic_package_dir
from tests.helpers.package_rehash import rehash_package_directory


@pytest.fixture
def rehashed_package(tmp_path: Path) -> Path:
    dest = tmp_path / "package"
    shutil.copytree(synthetic_package_dir(), dest)
    rehash_package_directory(dest)
    return dest


def test_create_zip_from_verified_package(rehashed_package: Path, tmp_path: Path):
    zip_path = tmp_path / "out" / "package.zip"
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    result = create_zip_package(rehashed_package, zip_path)
    assert result.zip_path.is_file()
    assert result.sha256_path.is_file()
    assert len(result.sha256) == 64
    assert result.member_count > 0


def test_zip_members_use_normalized_paths(rehashed_package: Path, tmp_path: Path):
    zip_path = tmp_path / "out" / "package.zip"
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    create_zip_package(rehashed_package, zip_path)
    with zipfile.ZipFile(zip_path, "r") as archive:
        names = archive.namelist()
    assert all("\\" not in name for name in names)
    assert all(not name.startswith("/") for name in names)
    assert "README.txt" in names


def test_create_zip_refuses_overwrite(rehashed_package: Path, tmp_path: Path):
    zip_path = tmp_path / "out" / "package.zip"
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    create_zip_package(rehashed_package, zip_path)
    with pytest.raises(PackageError, match="Refuse overwrite"):
        create_zip_package(rehashed_package, zip_path)


def test_create_zip_rejects_unverified_package(tmp_path: Path):
    bad_root = tmp_path / "bad-pkg"
    bad_root.mkdir()
    (bad_root / "README.txt").write_text("incomplete", encoding="utf-8")
    zip_path = tmp_path / "bad.zip"
    with pytest.raises(PackageError, match="verification failed"):
        create_zip_package(bad_root, zip_path)


def test_write_zip_sidecar(rehashed_package: Path, tmp_path: Path):
    zip_path = tmp_path / "out" / "package.zip"
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    result = create_zip_package(rehashed_package, zip_path)
    sidecar = write_zip_sidecar(result.zip_path, result.sha256)
    text = sidecar.read_text(encoding="utf-8")
    assert result.sha256 in text


def test_zip_traversal_member_names_rejected_on_extract(rehashed_package: Path, tmp_path: Path):
    """Packaging normalizes paths; malicious names must not appear in archive."""
    zip_path = tmp_path / "out" / "safe.zip"
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    create_zip_package(rehashed_package, zip_path)
    with zipfile.ZipFile(zip_path, "r") as archive:
        for name in archive.namelist():
            assert ".." not in name.split("/")
