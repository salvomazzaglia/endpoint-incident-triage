"""Streaming SHA-256 hashing helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class HashError(Exception):
    """Hashing error."""


def stream_sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Compute SHA-256 of a file by streaming; does not follow symlinks."""
    if path.is_symlink():
        raise HashError(f"Refusing to hash symlink: {path}")
    if not path.is_file():
        raise HashError(f"Not a regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """SHA-256 hex digest of UTF-8 text."""
    return sha256_bytes(text.encode("utf-8"))


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    """Canonical JSON encoding for hashing (sorted keys, no whitespace)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_canonical_json(payload: dict[str, Any]) -> str:
    """SHA-256 of canonical JSON."""
    return sha256_bytes(canonical_json_bytes(payload))


def salted_pseudonym(value: str, salt: str) -> str:
    """Stable salted SHA-256 pseudonym; salt must never be persisted."""
    if not salt:
        raise HashError("Salt is required for hashed privacy mode")
    return sha256_text(f"{salt}:{value}")
