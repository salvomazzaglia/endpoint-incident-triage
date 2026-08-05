#!/usr/bin/env python3
"""Safely remove generated artifacts under temp/ only."""

from __future__ import annotations

import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMP_ROOT = REPO_ROOT / "temp"

ALLOWED_PREFIX = TEMP_ROOT.resolve()


def _safe_under_temp(path: Path) -> bool:
    try:
        path.resolve().relative_to(ALLOWED_PREFIX)
        return True
    except ValueError:
        return False


def clean_temp() -> list[Path]:
    removed: list[Path] = []
    if not TEMP_ROOT.exists():
        return removed
    if not _safe_under_temp(TEMP_ROOT):
        raise SystemExit(f"Refusing to clean outside temp root: {TEMP_ROOT}")
    for child in TEMP_ROOT.iterdir():
        if not _safe_under_temp(child):
            continue
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
        removed.append(child)
    return removed


def main() -> int:
    removed = clean_temp()
    if removed:
        print(f"Cleaned {len(removed)} item(s) under temp/:")
        for path in removed:
            print(path.relative_to(REPO_ROOT))
    else:
        print("Nothing to clean under temp/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
