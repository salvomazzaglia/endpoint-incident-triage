"""Path validation and evidence-package directory helpers."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
UNSAFE_CHARS = re.compile(r'[<>:"|?*\x00-\x1f\\/]')


class PathValidationError(ValueError):
    """Raised when a path or case identifier is unsafe."""


def validate_case_id(case_id: str) -> str:
    """Validate a case identifier for filesystem and package safety."""
    if not case_id or not CASE_ID_PATTERN.fullmatch(case_id):
        raise PathValidationError(
            "case_id must be 1-64 chars, start alphanumeric, and contain only A-Z a-z 0-9 . _ -"
        )
    stem = case_id.split(".")[0].upper()
    if stem in WINDOWS_RESERVED:
        raise PathValidationError(f"case_id uses a Windows reserved name: {case_id}")
    return case_id


def normalize_relative_path(path: str) -> str:
    """Normalize a relative path to POSIX separators without traversal."""
    text = path.replace("\\", "/").strip()
    if not text or text.startswith("/") or text.startswith("~"):
        raise PathValidationError(f"Absolute or empty relative path rejected: {path}")
    if ":" in text.split("/")[0]:
        raise PathValidationError(f"Drive-absolute path rejected: {path}")
    parts = [part for part in text.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise PathValidationError(f"Path traversal rejected: {path}")
    if any(UNSAFE_CHARS.search(part) for part in parts):
        raise PathValidationError(f"Unsafe characters in path: {path}")
    for part in parts:
        stem = part.split(".")[0].upper()
        if stem in WINDOWS_RESERVED:
            raise PathValidationError(f"Windows reserved name in path: {path}")
    return "/".join(parts)


def ensure_within(base: Path, candidate: Path) -> Path:
    """Resolve candidate and ensure it remains under base."""
    base_resolved = base.resolve()
    candidate_resolved = candidate.resolve()
    try:
        candidate_resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise PathValidationError(
            f"Path escapes base directory: {candidate} not under {base}"
        ) from exc
    return candidate_resolved


def reject_symlink(path: Path) -> None:
    """Reject symlink paths for evidence handling."""
    if path.is_symlink():
        raise PathValidationError(f"Symlinks are not permitted: {path}")


def is_system_sensitive_path(path: Path) -> bool:
    """Return True for obviously unsafe output roots."""
    resolved = str(path.resolve()).lower().replace("\\", "/")
    sensitive = (
        "/windows/",
        "/windows\\",
        "c:/windows",
        "c:\\windows",
        "/system32",
        "/etc/",
        "/usr/",
        "/bin/",
        "/sbin/",
        "/boot/",
        "/proc/",
        "/sys/",
        "/dev/",
        "/root/",
    )
    return any(token in resolved for token in sensitive) or resolved in {
        "/",
        "c:\\",
        "c:/",
    }


def refuse_output_inside_source(output: Path, source_roots: list[Path]) -> None:
    """Refuse writing evidence inside collector/source trees."""
    out = output.resolve()
    for root in source_roots:
        root_resolved = root.resolve()
        try:
            out.relative_to(root_resolved)
        except ValueError:
            continue
        raise PathValidationError(
            f"Output directory inside source tree is refused: {out} under {root_resolved}"
        )


def set_restrictive_permissions(path: Path) -> None:
    """Best-effort restrictive permissions (owner read/write only)."""
    try:
        if path.is_dir():
            os.chmod(path, stat.S_IRWXU)
        else:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        # Windows and some filesystems may not support POSIX modes.
        pass


def create_case_directory(parent: Path, case_id: str, stamp: str) -> Path:
    """Create a unique case package directory; refuse overwrite."""
    validate_case_id(case_id)
    if UNSAFE_CHARS.search(stamp) or ".." in stamp:
        raise PathValidationError(f"Unsafe timestamp stamp: {stamp}")
    name = f"case-{case_id}-{stamp}"
    target = parent / name
    if target.exists():
        raise PathValidationError(f"Refuse overwrite of existing package: {target}")
    parent.mkdir(parents=True, exist_ok=True)
    target.mkdir(parents=False, exist_ok=False)
    set_restrictive_permissions(target)
    return target


def package_layout(root: Path) -> dict[str, Path]:
    """Return standard evidence-package subdirectory paths."""
    layout = {
        "root": root,
        "metadata": root / "metadata",
        "artifacts": root / "artifacts",
        "artifacts_windows": root / "artifacts" / "windows",
        "artifacts_linux": root / "artifacts" / "linux",
        "timeline": root / "timeline",
        "findings": root / "findings",
        "manifests": root / "manifests",
        "custody": root / "custody",
        "logs": root / "logs",
        "reports": root / "reports",
    }
    return layout


def ensure_package_layout(root: Path) -> dict[str, Path]:
    """Create the standard evidence-package directory layout."""
    layout = package_layout(root)
    for key, path in layout.items():
        if key == "root":
            continue
        path.mkdir(parents=True, exist_ok=True)
        set_restrictive_permissions(path)
    return layout
