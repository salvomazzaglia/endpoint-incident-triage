"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.factories import (
    demo_config_path,
    repo_root,
    synthetic_package_dir,
)


@pytest.fixture(scope="session")
def project_root() -> Path:
    return repo_root()


@pytest.fixture(scope="session")
def demo_config() -> Path:
    return demo_config_path()


@pytest.fixture(scope="session")
def verified_synthetic_package() -> Path:
    return synthetic_package_dir()
