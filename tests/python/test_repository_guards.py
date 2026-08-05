"""Repository security and content guards for public release."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# RFC 5737 / RFC 3849 documentation ranges and locally administered MAC pattern.
PRIVATE_IPV4 = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3})\b"
)
REAL_MAC_OUI = re.compile(
    r"\b(?:00|04|08|0[Cc]|10|14|18|1[Cc])[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}"
)
EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@(?!users\.noreply\.github\.com)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
FORBIDDEN_CI = re.compile(r"pull_request_target|runs-on:\s*self-hosted", re.IGNORECASE)
SHELL_TRUE = re.compile(r"shell\s*=\s*True")
INVOKE_EXPRESSION = re.compile(r"Invoke-Expression|\biex\b")
EVAL_CALL = re.compile(r"\beval\s*\(")
LSASS_DUMP = re.compile(r"MiniDumpWriteDump|comsvcs\.dll|\blsass\b", re.IGNORECASE)

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "temp",
    "htmlcov",
    "dist",
    "build",
}


def _iter_tracked_text_files() -> list[Path]:
    files: list[Path] = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in {".png", ".zip", ".pyc", ".pyo", ".whl", ".egg"}:
            continue
        if path.suffix.lower() in {
            ".py",
            ".ps1",
            ".sh",
            ".json",
            ".jsonl",
            ".md",
            ".yml",
            ".yaml",
            ".toml",
            ".txt",
            ".html",
        }:
            files.append(path)
    return files


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


@pytest.fixture(scope="module")
def text_files() -> list[Path]:
    return _iter_tracked_text_files()


def test_ci_workflow_is_github_hosted_only() -> None:
    workflow = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    assert workflow.is_file()
    content = _read(workflow)
    assert "permissions:" in content
    assert "contents: read" in content
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert not FORBIDDEN_CI.search(line), f"Forbidden CI pattern in workflow line: {line!r}"


def test_ci_workflow_has_no_secrets() -> None:
    content = _read(REPO_ROOT / ".github" / "workflows" / "ci.yml")
    assert "secrets." not in content


def test_no_shell_true_in_python_src(text_files: list[Path]) -> None:
    offenders = [
        path.relative_to(REPO_ROOT)
        for path in text_files
        if path.suffix == ".py" and "src" in path.parts and SHELL_TRUE.search(_read(path))
    ]
    assert offenders == []


def test_no_invoke_expression_in_collectors(text_files: list[Path]) -> None:
    offenders = [
        path.relative_to(REPO_ROOT)
        for path in text_files
        if path.suffix == ".ps1"
        and "collectors" in path.parts
        and "tests" not in path.parts
        and INVOKE_EXPRESSION.search(_read(path))
    ]
    assert offenders == []


def test_no_eval_in_bash_collectors(text_files: list[Path]) -> None:
    offenders = [
        path.relative_to(REPO_ROOT)
        for path in text_files
        if path.suffix == ".sh" and "collectors" in path.parts and EVAL_CALL.search(_read(path))
    ]
    assert offenders == []


def test_public_examples_use_documentation_ips_only() -> None:
    roots = [
        REPO_ROOT / "examples",
        REPO_ROOT / "tests" / "fixtures",
    ]
    for root in roots:
        for path in root.rglob("*.json"):
            if PRIVATE_IPV4.search(_read(path)):
                pytest.fail(f"Private IPv4 found in public example: {path.relative_to(REPO_ROOT)}")


def test_sample_reports_are_synthetic() -> None:
    for name in ("sample-triage-report.json", "sample-triage-report.html"):
        path = REPO_ROOT / "examples" / name
        assert path.is_file(), f"Missing {name}"
        content = _read(path)
        assert "SYNTHETIC" in content.upper()


def test_synthetic_evidence_package_marker() -> None:
    readme = REPO_ROOT / "examples" / "synthetic-evidence-package" / "README.txt"
    assert readme.is_file()
    assert "SYNTHETIC" in _read(readme).upper()


def test_no_real_email_in_public_tree(text_files: list[Path]) -> None:
    public_roots = ("examples", "docs", "tests/fixtures", "config")
    for path in text_files:
        rel = path.relative_to(REPO_ROOT).as_posix()
        if not any(rel.startswith(root) for root in public_roots):
            continue
        if EMAIL.search(_read(path)):
            pytest.fail(f"Email-like string in public content: {rel}")


def test_no_lsass_dump_commands_in_collectors(text_files: list[Path]) -> None:
    offenders = [
        path.relative_to(REPO_ROOT)
        for path in text_files
        if path.suffix in {".ps1", ".py"}
        and "collectors" in path.parts
        and LSASS_DUMP.search(_read(path))
    ]
    assert offenders == []


def test_no_upload_or_cloud_enrichment_calls() -> None:
    src = REPO_ROOT / "src" / "endpoint_incident_triage"
    pattern = re.compile(r"virustotal|requests\.(get|post)|urllib\.request\.urlopen|httpx\.", re.I)
    for path in src.rglob("*.py"):
        if pattern.search(_read(path)):
            pytest.fail(f"Unexpected network enrichment in {path.relative_to(REPO_ROOT)}")


def test_gitignore_excludes_live_evidence_artifacts() -> None:
    gitignore = _read(REPO_ROOT / ".gitignore")
    for token in ("*.evtx", "*.dmp", "*.pcap", "evidence/", ".env"):
        assert token in gitignore


def test_schemas_directory_exists() -> None:
    schemas = REPO_ROOT / "schemas"
    expected = {
        "artifact.schema.json",
        "case.schema.json",
        "collection.schema.json",
        "custody-record.schema.json",
        "finding.schema.json",
        "manifest.schema.json",
        "report.schema.json",
    }
    assert expected.issubset({path.name for path in schemas.glob("*.schema.json")})


def test_collector_runner_enforces_shell_false() -> None:
    runner = REPO_ROOT / "src" / "endpoint_incident_triage" / "collector_runner.py"
    assert "shell=False" in _read(runner)


def test_synthetic_input_readme_marked() -> None:
    readme = REPO_ROOT / "examples" / "synthetic-input" / "README.md"
    assert readme.is_file()
    assert "synthetic" in _read(readme).lower()
