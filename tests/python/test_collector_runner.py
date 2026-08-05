"""Tests for collector runner (monkeypatched, no live execution)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from endpoint_incident_triage.collector_registry import select_collectors
from endpoint_incident_triage.collector_runner import (
    CollectorRunnerError,
    build_allowlisted_env,
    run_collector,
    run_collectors,
)
from endpoint_incident_triage.config import load_config
from endpoint_incident_triage.statuses import CollectorStatus, SourceMode
from tests.helpers.factories import demo_config_path, repo_root


@pytest.fixture
def windows_collector():
    config = load_config(demo_config_path())
    registry = __import__(
        "endpoint_incident_triage.collector_registry", fromlist=["load_registry"]
    ).load_registry(config.registry_path, config.collectors_root)
    selected = select_collectors(registry, platform="windows", profile="minimal")
    return config, selected[0]


def test_run_collector_loads_synthetic_fixture(windows_collector):
    config, collector = windows_collector
    run = run_collector(
        collector,
        config.collectors_root,
        platform="windows",
        source_mode=SourceMode.SYNTHETIC,
        prefer_fixture=True,
    )
    assert run.result.status == CollectorStatus.COLLECTED
    assert run.result.record_count > 0
    assert any("fixture" in item for item in run.result.command_provenance)


def test_run_collector_uses_shell_false(windows_collector, monkeypatch):
    config, collector = windows_collector
    captured: dict = {}

    def fake_run(*args, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            args=args[0], returncode=0, stdout='{"records":[]}', stderr=""
        )

    monkeypatch.setenv("EIT_FIXTURE_FILE", "/nonexistent/fixture.json")
    monkeypatch.setattr(subprocess, "run", fake_run)
    run_collector(
        collector,
        config.collectors_root,
        platform="windows",
        source_mode=SourceMode.LIVE,
        prefer_fixture=False,
    )
    assert captured.get("shell") is False


def test_run_collector_timeout(windows_collector, monkeypatch):
    config, collector = windows_collector

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout", 1))

    monkeypatch.setenv("EIT_FIXTURE_FILE", "/nonexistent/fixture.json")
    monkeypatch.setattr(subprocess, "run", fake_run)
    run = run_collector(
        collector,
        config.collectors_root,
        platform="windows",
        source_mode=SourceMode.LIVE,
        prefer_fixture=False,
    )
    assert run.result.status == CollectorStatus.ERROR
    assert any("timed out" in err for err in run.result.errors)


def test_run_collector_truncates_large_stdout(windows_collector, monkeypatch):
    config, collector = windows_collector
    huge = "x" * (collector.maximum_output_bytes + 1000)

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout=huge, stderr="")

    monkeypatch.setenv("EIT_FIXTURE_FILE", "/nonexistent/fixture.json")
    monkeypatch.setattr(subprocess, "run", fake_run)
    run = run_collector(
        collector,
        config.collectors_root,
        platform="windows",
        source_mode=SourceMode.LIVE,
        prefer_fixture=False,
    )
    assert any("truncated" in warn.lower() for warn in run.result.warnings)


def test_run_collector_custom_fixture_path(windows_collector, tmp_path: Path):
    config, collector = windows_collector
    fixture = tmp_path / "custom.json"
    fixture.write_text(
        json.dumps({"records": [{"artifact_type": "process", "pid": 1, "name": "test"}]}),
        encoding="utf-8",
    )
    run = run_collector(
        collector,
        config.collectors_root,
        platform="windows",
        fixture_path=fixture,
        prefer_fixture=True,
    )
    assert run.result.record_count == 1


def test_run_collectors_batch(windows_collector):
    config, collector = windows_collector
    results, logs = run_collectors(
        [collector],
        config.collectors_root,
        platform="windows",
        source_mode=SourceMode.SYNTHETIC,
        prefer_fixture=True,
    )
    assert len(results) == 1
    assert len(logs) == 1
    assert logs[0]["source_mode"] == "fixture"


def test_build_allowlisted_env_rejects_unknown():
    with pytest.raises(CollectorRunnerError, match="non-allowlisted"):
        build_allowlisted_env({"SECRET_TOKEN": "value"})


def test_build_allowlisted_env_allows_eit_prefix():
    env = build_allowlisted_env({"EIT_TEST": "1"})
    assert env["EIT_TEST"] == "1"
