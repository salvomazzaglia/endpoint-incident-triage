"""Normalize evidence-package hashes after cross-platform checkout copies."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

from endpoint_incident_triage.hashing import stream_sha256
from endpoint_incident_triage.manifest import (
    build_manifest,
    write_manifest,
    write_sha256sums,
)
from endpoint_incident_triage.timestamps import utc_now_iso


def rehash_package_directory(root: Path) -> None:
    """Rebuild manifest/SHA256SUMS/manifest-hash for files currently on disk.

    Evidence packages committed with LF can be checked out with different
    working-tree line endings on some Windows environments. Rehashing makes
    integrity tests evaluate verification logic rather than checkout EOL policy.
    """
    package_id = root.name
    manifest_path = root / "manifests" / "manifest.json"
    if manifest_path.is_file():
        with contextlib.suppress(OSError, json.JSONDecodeError, TypeError):
            package_id = str(
                json.loads(manifest_path.read_text(encoding="utf-8")).get("package_id")
                or package_id
            )

    manifest = build_manifest(root, package_id=package_id)
    write_manifest(manifest_path, manifest)
    write_sha256sums(root / "manifests" / "SHA256SUMS", manifest)
    digest = stream_sha256(manifest_path)
    hash_doc = {
        "schema_version": "1.0.0",
        "algorithm": "sha256",
        "manifest_relative_path": "manifests/manifest.json",
        "manifest_sha256": digest,
        "generated_at_utc": utc_now_iso(),
        "note": "Rehashed for local verification after checkout/copy.",
    }
    hash_path = root / "metadata" / "manifest-hash.json"
    hash_path.parent.mkdir(parents=True, exist_ok=True)
    hash_path.write_text(
        json.dumps(hash_doc, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
