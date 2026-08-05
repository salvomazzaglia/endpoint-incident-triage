"""Tests for privacy mode transformations."""

from __future__ import annotations

import os

import pytest

from endpoint_incident_triage.privacy import (
    PrivacyError,
    apply_privacy,
    ensure_no_salt_leak,
    resolve_salt,
)
from endpoint_incident_triage.statuses import PrivacyMode


def test_apply_privacy_masked():
    payload = {"username": "alice", "remote_ip": "10.1.2.3"}
    result, warnings = apply_privacy(payload, PrivacyMode.MASKED)
    assert result["username"] == "[user]"
    assert "x.x.x.x" in result["remote_ip"]
    assert not warnings


def test_apply_privacy_full_emits_warning():
    payload = {"username": "alice"}
    result, warnings = apply_privacy(payload, PrivacyMode.FULL)
    assert result["username"] == "alice"
    assert any("FULL" in warn for warn in warnings)


def test_apply_privacy_hashed_with_salt():
    payload = {"username": "alice"}
    result, warnings = apply_privacy(payload, PrivacyMode.HASHED, salt="test-salt")
    assert str(result["username"]).startswith("hash:")
    assert not warnings


def test_apply_privacy_hashed_without_salt_falls_back():
    payload = {"username": "alice"}
    result, warnings = apply_privacy(payload, PrivacyMode.HASHED, salt=None)
    assert result["username"] == "[user]"
    assert warnings


def test_resolve_salt_from_env(monkeypatch):
    monkeypatch.setenv("EIT_HASH_SALT", "env-salt")
    assert resolve_salt("EIT_HASH_SALT") == "env-salt"


def test_resolve_salt_explicit_over_env(monkeypatch):
    monkeypatch.setenv("EIT_HASH_SALT", "env-salt")
    assert resolve_salt("EIT_HASH_SALT", explicit="explicit") == "explicit"


def test_ensure_no_salt_leak_raises():
    with pytest.raises(PrivacyError, match="Salt leakage"):
        ensure_no_salt_leak({"note": "uses secret-salt-value"}, "secret-salt-value")


def test_apply_privacy_unknown_mode():
    with pytest.raises(PrivacyError):
        apply_privacy({}, "unknown-mode")
