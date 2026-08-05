"""SHA-256 manifest.json and SHA256SUMS generation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from endpoint_incident_triage import COLLECTOR_VERSION, SCHEMA_VERSION
from endpoint_incident_triage.evidence_paths import (
    normalize_relative_path,
    reject_symlink,
)
from endpoint_incident_triage.hashing import HashError, stream_sha256
from endpoint_incident_triage.models import ManifestDocument, ManifestEntry
from endpoint_incident_triage.timestamps import utc_now_iso

MANIFEST_RELATIVE = "manifests/manifest.json"
SHA256SUMS_RELATIVE = "manifests/SHA256SUMS"
MANIFEST_HASH_RELATIVE = "metadata/manifest-hash.json"
MANIFEST_SCOPE = "package"
EXCLUDED_PATHS = (MANIFEST_RELATIVE, SHA256SUMS_RELATIVE, MANIFEST_HASH_RELATIVE)
ALGORITHM = "sha256"


class ManifestError(ValueError):
    """Manifest generation or validation error."""


@dataclass(slots=True)
class ScannedFile:
    relative_path: str
    size_bytes: int
    sha256: str
    artifact_type: str
    collector_id: str | None
    created_at_utc: str


def _infer_artifact_type(relative_path: str) -> tuple[str, str | None]:
    """Infer artifact type and optional collector_id from relative path."""
    parts = relative_path.split("/")
    if relative_path == "README.txt":
        return "readme", None
    if parts[0] == "metadata":
        return "metadata", None
    if parts[0] == "custody":
        return "custody", None
    if parts[0] == "manifests":
        return "manifest", None
    if parts[0] == "timeline":
        return "timeline", None
    if parts[0] == "findings":
        return "findings", None
    if parts[0] == "logs":
        return "log", None
    if parts[0] == "reports":
        return "report", None
    if parts[0] == "artifacts" and len(parts) >= 3:
        filename = parts[-1]
        if filename.endswith(".json"):
            collector_id = filename.removesuffix(".json")
            return "collector_result", collector_id
        return "collector_artifact", parts[-1]
    return "artifact", None


def _scan_file(root: Path, file_path: Path) -> ScannedFile:
    reject_symlink(file_path)
    if not file_path.is_file():
        raise ManifestError(f"Not a regular file: {file_path}")
    relative = normalize_relative_path(file_path.relative_to(root).as_posix())
    digest = stream_sha256(file_path)
    artifact_type, collector_id = _infer_artifact_type(relative)
    stat = file_path.stat()
    created = utc_now_iso()
    return ScannedFile(
        relative_path=relative,
        size_bytes=stat.st_size,
        sha256=digest,
        artifact_type=artifact_type,
        collector_id=collector_id,
        created_at_utc=created,
    )


def build_manifest(
    package_root: Path,
    *,
    package_id: str,
    generated_at_utc: str | None = None,
) -> ManifestDocument:
    """Build a manifest by scanning all regular files under package_root."""
    root = package_root.resolve()
    if not root.is_dir():
        raise ManifestError(f"Package root is not a directory: {root}")

    scanned: list[ScannedFile] = []
    seen: set[str] = set()

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            if path.is_symlink():
                raise ManifestError(f"Symlink not permitted in package: {path}")
            continue
        reject_symlink(path)
        relative = normalize_relative_path(path.relative_to(root).as_posix())
        if relative in EXCLUDED_PATHS:
            continue
        if relative in seen:
            raise ManifestError(f"Duplicate normalized path: {relative}")
        seen.add(relative)
        scanned.append(_scan_file(root, path))

    scanned.sort(key=lambda item: item.relative_path)
    entries = [
        ManifestEntry(
            relative_path=item.relative_path,
            size_bytes=item.size_bytes,
            sha256=item.sha256,
            artifact_type=item.artifact_type,
            collector_id=item.collector_id,
            created_at_utc=item.created_at_utc,
        )
        for item in scanned
    ]

    return ManifestDocument(
        schema_version=SCHEMA_VERSION,
        generated_at_utc=generated_at_utc or utc_now_iso(),
        package_id=package_id,
        algorithm=ALGORITHM,
        entries=entries,
        manifest_scope=MANIFEST_SCOPE,
        excluded_paths=list(EXCLUDED_PATHS),
        generator_version=COLLECTOR_VERSION,
    )


def manifest_to_json_text(document: ManifestDocument) -> str:
    """Serialize manifest document as indented UTF-8 JSON."""
    return json.dumps(document.to_dict(), indent=2, ensure_ascii=False) + "\n"


def write_manifest(path: Path, document: ManifestDocument) -> None:
    """Write manifest.json to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(manifest_to_json_text(document), encoding="utf-8")


def write_sha256sums(path: Path, document: ManifestDocument) -> None:
    """Write SHA256SUMS from manifest entries (deterministic order)."""
    lines: list[str] = []
    for entry in sorted(document.entries, key=lambda item: item.relative_path):
        lines.append(f"{entry.sha256}  {entry.relative_path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def compute_manifest_document_hash(manifest_path: Path) -> str:
    """Compute SHA-256 of the written manifest.json file."""
    try:
        return stream_sha256(manifest_path)
    except HashError as exc:
        raise ManifestError(str(exc)) from exc


def parse_sha256sums(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Parse SHA256SUMS content; return (entries, invalid_lines)."""
    entries: list[tuple[str, str]] = []
    invalid: list[str] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            invalid.append(f"line {line_no}: invalid format")
            continue
        digest, rel_path = parts
        if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest.lower()):
            invalid.append(f"line {line_no}: invalid digest")
            continue
        try:
            normalized = normalize_relative_path(rel_path)
        except ValueError as exc:
            invalid.append(f"line {line_no}: {exc}")
            continue
        entries.append((digest.lower(), normalized))
    return entries, invalid


def load_manifest(path: Path) -> ManifestDocument:
    """Load manifest.json from disk."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"Unable to read manifest: {exc}") from exc
    if not isinstance(payload, dict):
        raise ManifestError("Manifest must be a JSON object")
    entries_raw = payload.get("entries")
    if not isinstance(entries_raw, list):
        raise ManifestError("Manifest entries must be an array")
    entries = [
        ManifestEntry(
            relative_path=str(item["relative_path"]),
            size_bytes=int(item["size_bytes"]),
            sha256=str(item["sha256"]).lower(),
            artifact_type=str(item["artifact_type"]),
            collector_id=item.get("collector_id"),
            created_at_utc=str(item["created_at_utc"]),
        )
        for item in entries_raw
        if isinstance(item, dict)
    ]
    return ManifestDocument(
        schema_version=str(payload.get("schema_version", "")),
        generated_at_utc=str(payload.get("generated_at_utc", "")),
        package_id=str(payload.get("package_id", "")),
        algorithm=str(payload.get("algorithm", ALGORITHM)),
        entries=entries,
        manifest_scope=str(payload.get("manifest_scope", MANIFEST_SCOPE)),
        excluded_paths=list(payload.get("excluded_paths") or list(EXCLUDED_PATHS)),
        generator_version=str(payload.get("generator_version", COLLECTOR_VERSION)),
    )


def verify_entry_hash(root: Path, entry: ManifestEntry) -> str | None:
    """Return error message if on-disk file does not match manifest entry."""
    target = root / Path(*entry.relative_path.split("/"))
    if not target.is_file():
        return f"Missing artifact: {entry.relative_path}"
    try:
        reject_symlink(target)
        digest = stream_sha256(target)
    except (HashError, ValueError) as exc:
        return f"Unable to hash {entry.relative_path}: {exc}"
    if digest.lower() != entry.sha256.lower():
        return f"Hash mismatch: {entry.relative_path}"
    stat = target.stat()
    if stat.st_size != entry.size_bytes:
        return f"Size mismatch: {entry.relative_path}"
    return None
