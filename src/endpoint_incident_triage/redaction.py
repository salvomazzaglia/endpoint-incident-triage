"""Privacy-aware redaction helpers."""

from __future__ import annotations

import re
from typing import Any

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
USER_PATH_WIN = re.compile(r"(?i)\b([A-Z]:\\Users\\)([^\\\/\s]+)")
USER_PATH_UNIX = re.compile(r"(/home/)([^/\s]+)")


def mask_ipv4(value: str) -> str:
    return IPV4_RE.sub("x.x.x.x", value)


def mask_ipv6(value: str) -> str:
    return IPV6_RE.sub("xxxx:xxxx:xxxx:xxxx::", value)


def mask_mac(value: str) -> str:
    return MAC_RE.sub("xx:xx:xx:xx:xx:xx", value)


def mask_email(value: str) -> str:
    return EMAIL_RE.sub("[redacted-email]", value)


def generalize_path(value: str) -> str:
    text = USER_PATH_WIN.sub(r"\1[user]", value)
    text = USER_PATH_UNIX.sub(r"\1[user]", text)
    return text


def mask_hostname(value: str) -> str:
    if not value:
        return value
    if value.upper().startswith("SYNTHETIC"):
        return "SYNTHETIC-[host]"
    return "[hostname]"


def mask_username(value: str) -> str:
    if not value:
        return value
    if value.lower().startswith("synthetic"):
        return "synthetic-[user]"
    return "[user]"


def mask_scalar(key: str, value: Any) -> Any:
    """Mask a scalar value based on field name heuristics."""
    if value is None:
        return None
    if not isinstance(value, str):
        return value
    key_l = key.lower()
    if key_l in {"username", "user", "owner", "account", "service_account", "user_name"}:
        return mask_username(value)
    if key_l in {"hostname", "computer_name", "host", "target_label"}:
        return mask_hostname(value)
    if "mac" in key_l:
        return mask_mac(value)
    if any(token in key_l for token in ("ip", "address", "endpoint", "remote", "local")):
        text = mask_ipv4(value)
        text = mask_ipv6(text)
        return text
    if "path" in key_l or "file" in key_l or "exec" in key_l:
        return generalize_path(value)
    if "email" in key_l:
        return mask_email(value)
    text = mask_ipv4(value)
    text = mask_ipv6(text)
    text = mask_mac(text)
    text = mask_email(text)
    return generalize_path(text)


def mask_structure(payload: Any) -> Any:
    """Recursively mask privacy-sensitive fields."""
    if isinstance(payload, dict):
        return {
            str(key): mask_structure(mask_scalar(str(key), value)) for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [mask_structure(item) for item in payload]
    if isinstance(payload, str):
        text = mask_ipv4(payload)
        text = mask_ipv6(text)
        text = mask_mac(text)
        text = mask_email(text)
        return generalize_path(text)
    return payload
