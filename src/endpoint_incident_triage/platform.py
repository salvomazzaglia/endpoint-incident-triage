"""Platform detection helpers."""

from __future__ import annotations

import sys

from endpoint_incident_triage.statuses import PlatformName


def detect_platform() -> PlatformName:
    """Detect the current operating system family."""
    if sys.platform.startswith("win"):
        return PlatformName.WINDOWS
    if sys.platform.startswith("linux"):
        return PlatformName.LINUX
    raise RuntimeError(f"Unsupported platform for live collection: {sys.platform}")


def resolve_platform(requested: str | PlatformName) -> PlatformName:
    """Resolve auto/windows/linux to a concrete platform."""
    value = requested.value if isinstance(requested, PlatformName) else requested.lower()
    if value == PlatformName.AUTO.value:
        return detect_platform()
    if value == PlatformName.WINDOWS.value:
        return PlatformName.WINDOWS
    if value == PlatformName.LINUX.value:
        return PlatformName.LINUX
    raise ValueError(f"Invalid platform: {requested}")


def is_windows() -> bool:
    return sys.platform.startswith("win")


def is_linux() -> bool:
    return sys.platform.startswith("linux")
