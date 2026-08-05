#!/usr/bin/env python3
"""Verify the synthetic evidence package and generate masked sample reports."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE = REPO_ROOT / "examples" / "synthetic-evidence-package"
OUTPUT = REPO_ROOT / "examples"
CONFIG = REPO_ROOT / "config" / "demo.config.json"


def _run_cli(*args: str) -> None:
    cmd = [sys.executable, "-m", "endpoint_incident_triage.cli", *args]
    env = {"PYTHONPATH": str(REPO_ROOT / "src"), **__import__("os").environ}
    result = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout.rstrip())
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr.rstrip(), file=sys.stderr)
        raise SystemExit(result.returncode)


def main() -> int:
    if not PACKAGE.is_dir():
        print(
            f"Missing package: {PACKAGE.relative_to(REPO_ROOT)} — "
            "run scripts/generate-sample-package.py first",
            file=sys.stderr,
        )
        return 2

    print("Verifying synthetic evidence package...")
    _run_cli("verify", "--package", str(PACKAGE), "--verbose")

    print("Generating masked reports...")
    _run_cli(
        "report",
        "--package",
        str(PACKAGE),
        "--output-directory",
        str(OUTPUT),
        "--format",
        "all",
        "--privacy-mode",
        "masked",
        "--config",
        str(CONFIG),
    )

    json_report = OUTPUT / "triage-report.json"
    html_report = OUTPUT / "triage-report.html"
    sample_json = OUTPUT / "sample-triage-report.json"
    sample_html = OUTPUT / "sample-triage-report.html"
    if json_report.is_file():
        json_report.replace(sample_json)
    if html_report.is_file():
        html_report.replace(sample_html)
    print(f"JSON report: {sample_json.relative_to(REPO_ROOT)}")
    print(f"HTML report: {sample_html.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
