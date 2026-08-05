"""Privacy mode transformations for shareable reports."""

from __future__ import annotations

import os
from typing import Any

from endpoint_incident_triage.hashing import HashError, salted_pseudonym
from endpoint_incident_triage.redaction import (
    generalize_path,
    mask_hostname,
    mask_ipv4,
    mask_ipv6,
    mask_mac,
    mask_structure,
    mask_username,
)
from endpoint_incident_triage.statuses import PrivacyMode

PSEUDONYM_KEYS = frozenset(
    {
        "username",
        "user",
        "owner",
        "account",
        "service_account",
        "hostname",
        "computer_name",
        "host",
        "target_label",
    }
)


class PrivacyError(ValueError):
    """Privacy transformation error."""


def resolve_salt(env_name: str, *, explicit: str | None = None) -> str | None:
    """Resolve hash salt from explicit value or environment; never persist it."""
    if explicit is not None:
        return explicit
    return os.environ.get(env_name) or None


def apply_privacy(
    payload: Any,
    mode: PrivacyMode | str,
    *,
    salt: str | None = None,
    salt_env: str = "EIT_HASH_SALT",
) -> tuple[Any, list[str]]:
    """Apply privacy transformation. Returns (payload, warnings)."""
    warnings: list[str] = []
    mode_value = mode.value if isinstance(mode, PrivacyMode) else mode
    if mode_value == PrivacyMode.MASKED.value:
        return mask_structure(payload), warnings
    if mode_value == PrivacyMode.FULL.value:
        warnings.append(
            "Privacy mode FULL selected: reports may contain sensitive identifiers. "
            "Do not use for public samples."
        )
        return payload, warnings
    if mode_value == PrivacyMode.HASHED.value:
        effective = salt if salt is not None else resolve_salt(salt_env)
        if not effective:
            warnings.append(
                "Hashed privacy mode requested without salt; falling back to masked mode. "
                f"Set {salt_env} for stable salted pseudonyms. Unsalted hashing is not anonymization."
            )
            return mask_structure(payload), warnings
        return _hash_structure(payload, effective), warnings
    raise PrivacyError(f"Unknown privacy mode: {mode_value}")


def _hash_structure(payload: Any, salt: str) -> Any:
    if isinstance(payload, dict):
        result: dict[str, Any] = {}
        for key, value in payload.items():
            key_s = str(key)
            if isinstance(value, str) and key_s.lower() in PSEUDONYM_KEYS:
                try:
                    result[key_s] = "hash:" + salted_pseudonym(value, salt)[:16]
                except HashError:
                    result[key_s] = (
                        mask_username(value) if "user" in key_s.lower() else mask_hostname(value)
                    )
            elif isinstance(value, str) and any(
                token in key_s.lower() for token in ("ip", "address", "endpoint")
            ):
                text = mask_ipv4(value)
                text = mask_ipv6(text)
                result[key_s] = text
            elif isinstance(value, str) and "mac" in key_s.lower():
                result[key_s] = mask_mac(value)
            elif isinstance(value, str) and any(
                token in key_s.lower() for token in ("path", "file", "exec")
            ):
                result[key_s] = generalize_path(value)
            else:
                result[key_s] = _hash_structure(value, salt)
        return result
    if isinstance(payload, list):
        return [_hash_structure(item, salt) for item in payload]
    return payload


def ensure_no_salt_leak(payload: Any, salt: str | None) -> None:
    """Raise if salt appears in serialized report content."""
    if not salt:
        return
    blob = repr(payload)
    if salt in blob:
        raise PrivacyError("Salt leakage detected in report payload")
