"""Tests for SHA-256 hashing helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from endpoint_incident_triage.hashing import (
    HashError,
    canonical_json_bytes,
    salted_pseudonym,
    sha256_bytes,
    sha256_canonical_json,
    sha256_text,
    stream_sha256,
)


def test_sha256_text_deterministic():
    assert sha256_text("hello") == sha256_text("hello")
    assert len(sha256_text("hello")) == 64


def test_sha256_bytes():
    assert sha256_bytes(b"data") == sha256_text("data")


def test_canonical_json_sorted_keys():
    payload = {"b": 2, "a": 1}
    encoded = canonical_json_bytes(payload)
    assert encoded == b'{"a":1,"b":2}'


def test_sha256_canonical_json():
    digest = sha256_canonical_json({"z": 1, "a": 2})
    assert len(digest) == 64


def test_stream_sha256_file(tmp_path: Path):
    target = tmp_path / "file.bin"
    target.write_bytes(b"evidence bytes")
    assert stream_sha256(target) == sha256_bytes(b"evidence bytes")


def test_stream_sha256_rejects_symlink(tmp_path: Path):
    real = tmp_path / "real.txt"
    real.write_text("x", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("Symlinks not supported on this platform")
    with pytest.raises(HashError, match="symlink"):
        stream_sha256(link)


def test_salted_pseudonym_requires_salt():
    with pytest.raises(HashError):
        salted_pseudonym("user", "")


def test_salted_pseudonym_stable():
    a = salted_pseudonym("alice", "salt")
    b = salted_pseudonym("alice", "salt")
    c = salted_pseudonym("bob", "salt")
    assert a == b
    assert a != c
