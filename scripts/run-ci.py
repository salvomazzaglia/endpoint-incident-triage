#!/usr/bin/env python3
"""Run available local CI checks for endpoint-incident-triage."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
SCRIPTS = REPO_ROOT / "scripts"
TESTS = REPO_ROOT / "tests" / "python"


def _run_step(
    name: str,
    cmd: list[str],
    *,
    optional: bool = False,
    env: dict[str, str] | None = None,
) -> bool:
    print(f"\n==> {name}")
    result = subprocess.run(cmd, cwd=REPO_ROOT, env=env)
    if result.returncode != 0:
        if optional:
            print(f"SKIP (optional failed): {name}", file=sys.stderr)
            return True
        print(f"FAILED: {name}", file=sys.stderr)
        return False
    return True


def main() -> int:
    import os

    env = {"PYTHONPATH": str(SRC), **os.environ}
    ok = True

    ok &= _run_step(
        "validate-config",
        [sys.executable, "-m", "endpoint_incident_triage.cli", "validate-config"],
        env=env,
    )

    if shutil.which("ruff"):
        ok &= _run_step(
            "ruff check",
            ["ruff", "check", str(SRC), str(SCRIPTS), str(TESTS)],
        )
        ok &= _run_step(
            "ruff format --check",
            ["ruff", "format", "--check", str(SRC), str(SCRIPTS), str(TESTS)],
        )
    else:
        print("\n==> ruff (not installed, skipped)")

    if shutil.which("mypy"):
        ok &= _run_step(
            "mypy",
            ["mypy", str(SRC)],
            optional=True,
        )
    else:
        print("\n==> mypy (not installed, skipped)")

    if TESTS.is_dir() and shutil.which("pytest"):
        ok &= _run_step(
            "pytest",
            [sys.executable, "-m", "pytest", str(TESTS)],
            optional=True,
            env=env,
        )
    else:
        print("\n==> pytest (no tests dir or pytest missing, skipped)")

    ok &= _run_step(
        "generate-demo-data",
        [sys.executable, str(SCRIPTS / "generate-demo-data.py")],
    )

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
