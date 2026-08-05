"""Tests for CLI entry points (no live collection)."""

from __future__ import annotations

from pathlib import Path

import pytest

from endpoint_incident_triage.cli import main
from endpoint_incident_triage.exit_codes import EXIT_ERROR, EXIT_FAILURE, EXIT_OK, EXIT_PARTIAL
from tests.helpers.factories import demo_config_path, repo_root, synthetic_package_dir


def test_cli_version():
    assert main(["version"]) == EXIT_OK


def test_cli_validate_config_all(project_root: Path):
    assert main(["validate-config", "--repo-root", str(project_root)]) == EXIT_OK


def test_cli_validate_config_single(demo_config: Path):
    assert main(["validate-config", "--config", str(demo_config)]) == EXIT_OK


def test_cli_list_collectors(demo_config: Path):
    assert (
        main(["list-collectors", "--config", str(demo_config), "--platform", "windows"]) == EXIT_OK
    )


def test_cli_plan_no_execution(demo_config: Path, capsys):
    code = main(
        [
            "plan",
            "--config",
            str(demo_config),
            "--profile",
            "minimal",
            "--platform",
            "windows",
        ]
    )
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert "No live collectors were executed" in captured.out


def test_cli_collect_without_acknowledge_fails(tmp_path: Path, demo_config: Path, capsys):
    code = main(
        [
            "collect",
            "--case-id",
            "TEST-NO-ACK",
            "--output-directory",
            str(tmp_path),
            "--profile",
            "minimal",
            "--config",
            str(demo_config),
            "--platform",
            "windows",
        ]
    )
    captured = capsys.readouterr()
    assert code == EXIT_ERROR
    assert "--acknowledge-live-collection" in captured.err


def test_cli_collect_synthetic_windows(tmp_path: Path, demo_config: Path, capsys):
    code = main(
        [
            "collect-synthetic",
            "--case-id",
            "SYNTHETIC-CLI",
            "--platform",
            "windows",
            "--output-directory",
            str(tmp_path),
            "--config",
            str(demo_config),
            "--profile",
            "minimal",
        ]
    )
    captured = capsys.readouterr()
    assert code in {EXIT_OK, EXIT_PARTIAL}
    assert "SYNTHETIC DEMONSTRATION DATA" in captured.out
    packages = list(tmp_path.glob("case-SYNTHETIC-CLI-*"))
    assert len(packages) == 1
    assert (packages[0] / "manifests" / "manifest.json").is_file()


def test_cli_collect_synthetic_linux(tmp_path: Path, demo_config: Path):
    code = main(
        [
            "collect-synthetic",
            "--case-id",
            "SYNTHETIC-LINUX",
            "--platform",
            "linux",
            "--output-directory",
            str(tmp_path),
            "--config",
            str(demo_config),
            "--profile",
            "minimal",
        ]
    )
    assert code in {EXIT_OK, EXIT_PARTIAL}
    assert list(tmp_path.glob("case-SYNTHETIC-LINUX-*"))


def test_cli_verify_synthetic_package(verified_synthetic_package: Path):
    code = main(["verify", "--package", str(verified_synthetic_package)])
    assert code == EXIT_OK


def test_cli_verify_missing_package(tmp_path: Path):
    missing = tmp_path / "missing"
    missing.mkdir()
    code = main(["verify", "--package", str(missing)])
    assert code == EXIT_FAILURE


def test_cli_plan_invalid_config(tmp_path: Path):
    bad = tmp_path / "bad.config.json"
    bad.write_text('{"schema_version":"9.9.9"}', encoding="utf-8")
    assert main(["plan", "--config", str(bad), "--profile", "minimal"]) == EXIT_ERROR


def test_cli_unknown_command():
    with pytest.raises(SystemExit):
        main(["not-a-command"])
