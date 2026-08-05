"""Collector and report status enumerations."""

from __future__ import annotations

from enum import Enum


class CollectorStatus(str, Enum):
    """Exact collector statuses used throughout the toolkit."""

    COLLECTED = "Collected"
    PARTIAL = "Partial"
    UNAVAILABLE = "Unavailable"
    ERROR = "Error"
    SKIPPED = "Skipped"


class ReportStatus(str, Enum):
    """Overall report status (separate from finding severities)."""

    COMPLETE = "Complete"
    PARTIAL = "Partial"
    FAILED = "Failed"


class FindingSeverity(str, Enum):
    """Heuristic finding severities (advisory only)."""

    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class PrivacyMode(str, Enum):
    """Report privacy transformation modes."""

    MASKED = "masked"
    HASHED = "hashed"
    FULL = "full"


class SourceMode(str, Enum):
    """How artifacts were produced."""

    LIVE = "live"
    SYNTHETIC = "synthetic"
    FIXTURE = "fixture"


class PlatformName(str, Enum):
    """Supported collection platforms."""

    WINDOWS = "windows"
    LINUX = "linux"
    AUTO = "auto"
