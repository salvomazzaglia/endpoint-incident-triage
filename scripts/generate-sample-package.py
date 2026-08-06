#!/usr/bin/env python3
"""Build synthetic evidence packages for Windows and Linux demo workflows."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMP_ROOT = REPO_ROOT / "temp" / "package-build"
PUBLIC_PACKAGE = REPO_ROOT / "examples" / "synthetic-evidence-package"
CASE_ID = "SYNTHETIC-CASE-001"
CONFIG = "config/demo.config.json"


def _run_collect(platform: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "endpoint_incident_triage.cli",
        "collect-synthetic",
        "--case-id",
        CASE_ID,
        "--platform",
        platform,
        "--output-directory",
        str(output_dir),
        "--config",
        str(REPO_ROOT / CONFIG),
        "--profile",
        "standard",
        "--include-optional",
    ]
    env = {"PYTHONPATH": str(REPO_ROOT / "src"), **__import__("os").environ}
    result = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True)
    if result.returncode not in (0, 2):
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"collect-synthetic failed for {platform} (exit {result.returncode})")
    if result.stdout:
        print(result.stdout.rstrip())
    case_dirs = sorted(output_dir.glob(f"case-{CASE_ID}-*"))
    if not case_dirs:
        raise SystemExit(f"No case directory created under {output_dir}")
    return case_dirs[-1]


def _copy_public_sample(windows_case: Path) -> None:
    if PUBLIC_PACKAGE.exists():
        shutil.rmtree(PUBLIC_PACKAGE)
    shutil.copytree(windows_case, PUBLIC_PACKAGE)
    print(f"Public sample package: {PUBLIC_PACKAGE.relative_to(REPO_ROOT)}")


def main() -> int:
    print("SYNTHETIC DEMONSTRATION DATA — building sample packages")
    if TEMP_ROOT.exists():
        shutil.rmtree(TEMP_ROOT)
    TEMP_ROOT.mkdir(parents=True)

    windows_case = _run_collect("windows", TEMP_ROOT / "windows")
    linux_case = _run_collect("linux", TEMP_ROOT / "linux")
    print(f"Windows package: {windows_case.relative_to(REPO_ROOT)}")
    print(f"Linux package:   {linux_case.relative_to(REPO_ROOT)}")

    _copy_public_sample(windows_case)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
