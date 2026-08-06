"""Shared pytest fixtures."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tests.helpers.factories import (
    demo_config_path,
    repo_root,
    synthetic_package_dir,
)
from tests.helpers.package_rehash import rehash_package_directory


@pytest.fixture(scope="session")
def project_root() -> Path:
    return repo_root()


@pytest.fixture(scope="session")
def demo_config() -> Path:
    return demo_config_path()


@pytest.fixture(scope="session")
def verified_synthetic_package(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Copy and rehash the public sample so Windows EOL checkout still verifies."""
    src = synthetic_package_dir()
    dest = tmp_path_factory.mktemp("synthetic-package") / "package"
    shutil.copytree(src, dest)
    rehash_package_directory(dest)
    return dest
