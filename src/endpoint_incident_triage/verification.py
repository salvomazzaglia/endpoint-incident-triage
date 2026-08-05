"""Evidence package verification (directory or ZIP)."""

from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from endpoint_incident_triage import SCHEMA_VERSION
from endpoint_incident_triage.custody import (
    CUSTODY_LEDGER_RELATIVE,
    read_ledger,
    verify_ledger,
)
from endpoint_incident_triage.evidence_paths import (
    normalize_relative_path,
    package_layout,
    reject_symlink,
)
from endpoint_incident_triage.hashing import stream_sha256
from endpoint_incident_triage.manifest import (
    EXCLUDED_PATHS,
    MANIFEST_RELATIVE,
    SHA256SUMS_RELATIVE,
    load_manifest,
    parse_sha256sums,
    verify_entry_hash,
)

INTEGRITY_VERIFIED = "Verified"
INTEGRITY_FAILED = "Failed"
INTEGRITY_PARTIAL = "Partial"
CUSTODY_VERIFIED = "Verified"
CUSTODY_FAILED = "Failed"
CUSTODY_MISSING = "Missing"


class VerificationError(ValueError):
    """Package verification error."""


@dataclass(slots=True)
class VerificationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    integrity_status: str = INTEGRITY_FAILED
    custody_status: str = CUSTODY_MISSING
    package_id: str | None = None
    manifest_hash: str | None = None


def _validate_zip_member(name: str) -> str:
    """Normalize and validate a ZIP member name."""
    normalized = normalize_relative_path(name.replace("\\", "/"))
    return normalized


def _safe_extract_zip(zip_path: Path, dest: Path) -> list[str]:
    """Extract ZIP to dest with path-traversal protection."""
    errors: list[str] = []
    dest_resolved = dest.resolve()
    with zipfile.ZipFile(zip_path, "r") as archive:
        seen: set[str] = set()
        for info in archive.infolist():
            if info.is_dir():
                continue
            try:
                member = _validate_zip_member(info.filename)
            except ValueError as exc:
                errors.append(f"Unsafe ZIP member: {info.filename} ({exc})")
                continue
            if member in seen:
                errors.append(f"Duplicate normalized ZIP member: {member}")
                continue
            seen.add(member)
            target = dest_resolved / Path(*member.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as handle:
                shutil.copyfileobj(source, handle)
    return errors


def _scan_unexpected_files(root: Path, manifest_paths: set[str]) -> list[str]:
    """Find on-disk files not listed in manifest (excluding excluded paths)."""
    unexpected: list[str] = []
    seen: set[str] = set()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            if path.is_symlink():
                unexpected.append(f"Symlink present: {path.relative_to(root).as_posix()}")
            continue
        try:
            reject_symlink(path)
            relative = normalize_relative_path(path.relative_to(root).as_posix())
        except ValueError as exc:
            unexpected.append(str(exc))
            continue
        if relative in EXCLUDED_PATHS:
            continue
        if relative in seen:
            unexpected.append(f"Duplicate normalized path on disk: {relative}")
            continue
        seen.add(relative)
        if relative not in manifest_paths:
            unexpected.append(f"Unexpected artifact: {relative}")
    return unexpected


def _verify_metadata(root: Path, result: VerificationResult) -> None:
    """Verify case metadata files and schema versions."""
    case_path = root / "metadata" / "case.json"
    if not case_path.is_file():
        result.warnings.append("Missing metadata/case.json")
        return
    try:
        case = json.loads(case_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result.errors.append(f"Invalid metadata/case.json: {exc}")
        return
    if not isinstance(case, dict):
        result.errors.append("metadata/case.json must be an object")
        return
    if case.get("case_id") and not result.package_id:
        result.package_id = str(case.get("case_id"))


def _verify_custody(root: Path, result: VerificationResult) -> None:
    """Verify custody ledger hash chain."""
    ledger_path = root / Path(*CUSTODY_LEDGER_RELATIVE.split("/"))
    if not ledger_path.is_file():
        result.custody_status = CUSTODY_MISSING
        result.warnings.append("Custody ledger missing")
        return
    try:
        ledger = read_ledger(ledger_path)
        verification = verify_ledger(ledger)
    except ValueError as exc:
        result.custody_status = CUSTODY_FAILED
        result.errors.append(f"Custody ledger error: {exc}")
        return
    if verification.ok:
        result.custody_status = CUSTODY_VERIFIED
    else:
        result.custody_status = CUSTODY_FAILED
        result.errors.extend(verification.errors)


def verify_directory(root: Path) -> VerificationResult:
    """Verify an evidence-package directory."""
    result = VerificationResult(ok=True)
    package_root = root.resolve()
    if not package_root.is_dir():
        result.ok = False
        result.errors.append(f"Not a directory: {package_root}")
        result.integrity_status = INTEGRITY_FAILED
        return result

    manifest_path = package_root / Path(*MANIFEST_RELATIVE.split("/"))
    sums_path = package_root / Path(*SHA256SUMS_RELATIVE.split("/"))

    if not manifest_path.is_file():
        result.errors.append("Missing manifests/manifest.json")
        result.ok = False
        result.integrity_status = INTEGRITY_FAILED
        _verify_custody(package_root, result)
        _verify_metadata(package_root, result)
        result.ok = not result.errors
        return result

    try:
        document = load_manifest(manifest_path)
    except ValueError as exc:
        result.errors.append(str(exc))
        result.ok = False
        result.integrity_status = INTEGRITY_FAILED
        return result

    if document.schema_version != SCHEMA_VERSION:
        result.warnings.append(
            f"Manifest schema_version {document.schema_version} differs from "
            f"tool schema {SCHEMA_VERSION}"
        )

    result.package_id = document.package_id
    try:
        result.manifest_hash = stream_sha256(manifest_path)
    except ValueError as exc:
        result.errors.append(f"Unable to hash manifest: {exc}")

    manifest_paths = {entry.relative_path for entry in document.entries}
    sorted_paths = [entry.relative_path for entry in document.entries]
    if sorted_paths != sorted(sorted_paths):
        result.errors.append("Manifest entries are not sorted deterministically")

    if len(manifest_paths) != len(document.entries):
        result.errors.append("Duplicate manifest entry paths detected")

    for entry in document.entries:
        try:
            normalize_relative_path(entry.relative_path)
        except ValueError as exc:
            result.errors.append(str(exc))
            continue
        error = verify_entry_hash(package_root, entry)
        if error:
            result.errors.append(error)

    if sums_path.is_file():
        entries, invalid = parse_sha256sums(sums_path.read_text(encoding="utf-8"))
        result.errors.extend(invalid)
        sums_map = {rel_path: digest for digest, rel_path in entries}
        for entry in document.entries:
            if entry.relative_path not in sums_map:
                result.errors.append(f"SHA256SUMS missing entry for {entry.relative_path}")
            elif sums_map[entry.relative_path].lower() != entry.sha256.lower():
                result.errors.append(f"SHA256SUMS hash mismatch for {entry.relative_path}")
        for rel_path in sums_map:
            if rel_path not in manifest_paths:
                result.errors.append(f"SHA256SUMS lists unexpected path: {rel_path}")
    else:
        result.warnings.append("Missing manifests/SHA256SUMS")

    result.errors.extend(_scan_unexpected_files(package_root, manifest_paths))
    _verify_custody(package_root, result)
    _verify_metadata(package_root, result)

    layout = package_layout(package_root)
    for key, path in layout.items():
        if key == "root":
            continue
        if key.startswith("artifacts_"):
            continue
        if not path.exists():
            result.warnings.append(f"Expected package directory missing: {path.name}/")

    if result.errors:
        result.ok = False
        result.integrity_status = INTEGRITY_FAILED
    elif result.warnings:
        result.integrity_status = INTEGRITY_PARTIAL
        result.ok = True
    else:
        result.integrity_status = INTEGRITY_VERIFIED
        result.ok = True

    return result


def verify_package(package_path: Path) -> VerificationResult:
    """Verify a directory or ZIP evidence package."""
    path = package_path.resolve()
    if path.is_dir():
        return verify_directory(path)
    if path.is_file() and path.suffix.lower() == ".zip":
        with tempfile.TemporaryDirectory(prefix="eit-verify-") as temp:
            temp_root = Path(temp)
            result = VerificationResult(ok=True)
            extract_errors = _safe_extract_zip(path, temp_root)
            if extract_errors:
                result.errors.extend(extract_errors)
            inner = verify_directory(temp_root)
            result.errors.extend(inner.errors)
            result.warnings.extend(inner.warnings)
            result.package_id = inner.package_id
            result.manifest_hash = inner.manifest_hash
            result.custody_status = inner.custody_status
            result.integrity_status = inner.integrity_status
            result.ok = not result.errors
            if not result.ok:
                result.integrity_status = INTEGRITY_FAILED
            return result
    raise VerificationError(f"Unsupported package path: {path}")
