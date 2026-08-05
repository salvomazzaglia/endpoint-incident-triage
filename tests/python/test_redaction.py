"""Tests for redaction and masking helpers."""

from __future__ import annotations

from endpoint_incident_triage.redaction import (
    generalize_path,
    mask_email,
    mask_hostname,
    mask_ipv4,
    mask_ipv6,
    mask_mac,
    mask_scalar,
    mask_structure,
    mask_username,
)


def test_mask_ipv4():
    assert mask_ipv4("Contact 192.168.1.50 now") == "Contact x.x.x.x now"


def test_mask_ipv6():
    assert "xxxx:xxxx" in mask_ipv6("addr fe80::1 dead")


def test_mask_mac():
    assert mask_mac("aa:bb:cc:dd:ee:ff") == "xx:xx:xx:xx:xx:xx"


def test_mask_email():
    assert mask_email("user@example.com") == "[redacted-email]"


def test_generalize_path_windows():
    path = r"C:\Users\alice\Documents\file.txt"
    assert "[user]" in generalize_path(path)


def test_generalize_path_unix():
    assert generalize_path("/home/bob/file") == "/home/[user]/file"


def test_mask_hostname_synthetic():
    assert mask_hostname("SYNTHETIC-HOST-01") == "SYNTHETIC-[host]"


def test_mask_username_synthetic():
    assert mask_username("synthetic-user") == "synthetic-[user]"


def test_mask_scalar_by_key():
    assert mask_scalar("username", "alice") == "[user]"


def test_mask_structure_nested():
    payload = {"user": {"username": "alice", "remote_ip": "10.0.0.1"}}
    masked = mask_structure(payload)
    assert masked["user"]["username"] == "[user]"
