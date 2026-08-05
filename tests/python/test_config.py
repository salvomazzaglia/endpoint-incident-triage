"""Tests for configuration loading and validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from endpoint_incident_triage.config import (
    ConfigError,
    load_config,
    validate_all_configs,
    validate_config_dict,
)
from tests.helpers.factories import (
    default_config_path,
    demo_config_path,
    minimal_config_dict,
    repo_root,
)


def test_load_demo_config():
    config = load_config(demo_config_path())
    assert config.schema_version == "1.0.0"
    assert config.registry_path.is_file()
    assert config.rules_path.is_file()


def test_load_default_config():
    config = load_config(default_config_path())
    assert config.defaults.profile == "minimal"


def test_validate_all_configs():
    root = repo_root()
    messages = validate_all_configs(root)
    assert len(messages) == 2
    assert all(msg.startswith("OK") for msg in messages)


def test_config_rejects_unknown_keys(tmp_path: Path):
    data = minimal_config_dict(unknown_key=True)
    with pytest.raises(ConfigError, match="Unknown config keys"):
        validate_config_dict(data, base_dir=repo_root())


def test_config_rejects_bad_schema_version(tmp_path: Path):
    data = minimal_config_dict(schema_version="2.0.0")
    with pytest.raises(ConfigError, match="schema_version"):
        validate_config_dict(data, base_dir=repo_root())


def test_config_rejects_invalid_profile(tmp_path: Path):
    data = minimal_config_dict(defaults={"profile": "turbo", "platform": "auto", "since_hours": 24})
    with pytest.raises(ConfigError, match="Invalid profile"):
        validate_config_dict(data, base_dir=repo_root())


def test_config_rejects_timeout_over_max(tmp_path: Path):
    data = minimal_config_dict(
        defaults={
            "profile": "minimal",
            "platform": "auto",
            "since_hours": 24,
            "collector_timeout_seconds": 9999,
        }
    )
    with pytest.raises(ConfigError, match="exceeds maximum"):
        validate_config_dict(data, base_dir=repo_root())


def test_config_rejects_absolute_paths(tmp_path: Path):
    data = minimal_config_dict(
        paths={
            "collector_registry": "C:/Windows/System32/evil.json",
            "collection_profiles": "config/collection-profiles.json",
            "triage_rules": "config/triage-rules.json",
            "collectors_root": "collectors",
        }
    )
    with pytest.raises(ConfigError, match="must be relative"):
        validate_config_dict(data, base_dir=repo_root())


def test_config_rejects_path_traversal(tmp_path: Path):
    data = minimal_config_dict(
        paths={
            "collector_registry": "../evil/registry.json",
            "collection_profiles": "config/collection-profiles.json",
            "triage_rules": "config/triage-rules.json",
            "collectors_root": "collectors",
        }
    )
    with pytest.raises(ConfigError, match="traversal"):
        validate_config_dict(data, base_dir=repo_root())


def test_config_rejects_invalid_privacy_mode(tmp_path: Path):
    data = minimal_config_dict(privacy={"report_mode": "public"})
    with pytest.raises(ConfigError, match="privacy.report_mode"):
        validate_config_dict(data, base_dir=repo_root())


def test_load_config_missing_file(tmp_path: Path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.json")
