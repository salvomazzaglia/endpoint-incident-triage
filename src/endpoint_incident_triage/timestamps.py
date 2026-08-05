"""UTC timestamp helpers."""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return current UTC datetime with timezone info."""
    return datetime.now(UTC)


def utc_now_iso() -> str:
    """Return current UTC time as ISO 8601 with Z suffix."""
    return format_utc(utc_now())


def format_utc(value: datetime) -> str:
    """Format a datetime as ISO 8601 UTC with Z suffix."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    else:
        value = value.astimezone(UTC)
    text = value.isoformat(timespec="seconds")
    if text.endswith("+00:00"):
        return text[:-6] + "Z"
    return text


def parse_utc(value: str) -> datetime:
    """Parse an ISO 8601 timestamp into a timezone-aware UTC datetime."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
