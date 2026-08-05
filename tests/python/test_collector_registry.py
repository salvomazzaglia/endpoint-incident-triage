"""Tests for allowlisted collector registry."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from endpoint_incident_triage.collector_registry import (
    RegistryError,
    load_registry,
    resolve_collector_script,
    select_collectors,
)
from endpoint_incident_triage.config import load_config
from tests.helpers.factories import demo_config_path, repo_root


@pytest.fixture
def registry_bundle():
    config = load_config(demo_config_path())
    registry = load_registry(config.registry_path, config.collectors_root)
    return config, registry


def test_load_registry_from_demo_config(registry_bundle):
    config, registry = registry_bundle
    assert len(registry) > 0
    assert all(item.script_path for item in registry.values())


def test_registry_rejects_duplicate_ids(tmp_path: Path, registry_bundle):
    config, _ = registry_bundle
    data = json.loads(config.registry_path.read_text(encoding="utf-8"))
    data["collectors"].append(data["collectors"][0])
    bad_path = tmp_path / "registry.json"
    bad_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(RegistryError, match="Duplicate"):
        load_registry(bad_path, config.collectors_root)


def test_registry_rejects_arbitrary_command(tmp_path: Path, registry_bundle):
    config, _ = registry_bundle
    data = json.loads(config.registry_path.read_text(encoding="utf-8"))
    data["collectors"][0]["command"] = "cmd.exe /c whoami"
    bad_path = tmp_path / "registry.json"
    bad_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(RegistryError, match="Arbitrary command"):
        load_registry(bad_path, config.collectors_root)


def test_select_collectors_minimal_windows(registry_bundle):
    _, registry = registry_bundle
    selected = select_collectors(registry, platform="windows", profile="minimal")
    assert selected
    assert all(item.platform == "windows" for item in selected)
    assert selected == sorted(selected, key=lambda item: (item.volatility_order, item.id))


def test_select_collectors_unknown_id(registry_bundle):
    _, registry = registry_bundle
    with pytest.raises(RegistryError, match="Unknown collector"):
        select_collectors(
            registry,
            platform="windows",
            profile="minimal",
            collector_ids=["does-not-exist"],
        )


def test_select_collectors_platform_mismatch(registry_bundle):
    _, registry = registry_bundle
    linux_id = next(item.id for item in registry.values() if item.platform == "linux")
    with pytest.raises(RegistryError, match="platform mismatch"):
        select_collectors(
            registry,
            platform="windows",
            profile="minimal",
            collector_ids=[linux_id],
        )


def test_resolve_collector_script(registry_bundle):
    config, registry = registry_bundle
    collector = next(iter(registry.values()))
    script = resolve_collector_script(collector, config.collectors_root)
    assert script.is_file()
    assert script.resolve().is_relative_to(config.collectors_root.resolve())


def test_registry_interpreter_allowlist(registry_bundle):
    _, registry = registry_bundle
    for collector in registry.values():
        assert collector.interpreter in {"powershell", "bash"}
