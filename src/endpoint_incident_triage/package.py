"""ZIP packaging for verified evidence packages."""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path

from endpoint_incident_triage.evidence_paths import (
    normalize_relative_path,
    refuse_output_inside_source,
    reject_symlink,
)
from endpoint_incident_triage.hashing import stream_sha256
from endpoint_incident_triage.verification import verify_directory

ZIP_HASH_SUFFIX = ".sha256"


class PackageError(ValueError):
    """ZIP packaging error."""


@dataclass(slots=True)
class ZipPackageResult:
    zip_path: Path
    sha256_path: Path
    sha256: str
    member_count: int


def _collect_members(root: Path) -> list[tuple[str, Path]]:
    """Collect safe ZIP members from package root."""
    members: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            if path.is_symlink():
                raise PackageError(f"Symlink not permitted: {path}")
            continue
        reject_symlink(path)
        relative = normalize_relative_path(path.relative_to(root).as_posix())
        if relative in seen:
            raise PackageError(f"Duplicate normalized member name: {relative}")
        seen.add(relative)
        members.append((relative, path))
    return members


def create_zip_package(
    package_root: Path,
    output_zip: Path,
    *,
    verify_before_pack: bool = True,
    refuse_overwrite: bool = True,
) -> ZipPackageResult:
    """Create a ZIP archive from a verified evidence-package directory."""
    root = package_root.resolve()
    output = output_zip.resolve()

    if not root.is_dir():
        raise PackageError(f"Package root is not a directory: {root}")
    if refuse_overwrite and output.exists():
        raise PackageError(f"Refuse overwrite of existing ZIP: {output}")
    refuse_output_inside_source(output.parent, [root])

    if verify_before_pack:
        verification = verify_directory(root)
        if not verification.ok:
            raise PackageError(
                "Package verification failed before ZIP creation: "
                + "; ".join(verification.errors[:5])
            )

    members = _collect_members(root)
    if not members:
        raise PackageError("Package contains no files to archive")

    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative, file_path in members:
            archive.write(file_path, arcname=relative)

    digest = stream_sha256(output)
    sidecar = output.with_suffix(output.suffix + ZIP_HASH_SUFFIX)
    if refuse_overwrite and sidecar.exists():
        raise PackageError(f"Refuse overwrite of existing sidecar: {sidecar}")
    sidecar.write_text(f"{digest}  {output.name}\n", encoding="utf-8")

    return ZipPackageResult(
        zip_path=output,
        sha256_path=sidecar,
        sha256=digest,
        member_count=len(members),
    )


def write_zip_sidecar(zip_path: Path, sha256: str | None = None) -> Path:
    """Write adjacent .sha256 sidecar for an existing ZIP."""
    resolved = zip_path.resolve()
    digest = sha256 or stream_sha256(resolved)
    sidecar = resolved.with_suffix(resolved.suffix + ZIP_HASH_SUFFIX)
    sidecar.write_text(f"{digest}  {resolved.name}\n", encoding="utf-8")
    return sidecar
