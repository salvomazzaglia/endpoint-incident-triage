# Manifest and verification

## SHA-256 manifest

`manifests/manifest.json` includes:

- `schema_version`, `generated_at_utc`, `package_id`
- `algorithm`: `sha256`
- `entries[]`: `relative_path`, `size_bytes`, `sha256`, `artifact_type`, `collector_id`, `created_at_utc`
- `manifest_scope`, `excluded_paths`

Files are hashed by streaming. Entries are sorted deterministically.

## Self-reference limitation

The manifest cannot include its own hash inside the hashed scope. The final manifest SHA-256 is stored in:

- `metadata/manifest-hash.json`
- Custody ledger `manifest_created` event details

## SHA256SUMS

Text file generated from the same entries for tooling interoperability.

## Verification command

```bash
endpoint-incident-triage verify --package path/to/case-dir
endpoint-incident-triage verify --package path/to/case.zip
```

Checks include:

- Manifest structure and hash
- Every listed artifact present and matching hash
- Missing, added, or modified files
- Duplicate paths, traversal, absolute paths
- Symlink rejection
- Custody ledger hash chain
- Metadata schema versions

## ZIP verification

ZIP packages are inspected in a temporary directory without unsafe extraction paths. Symlinks and traversal members are rejected.

## What verification proves

- Package contents match the recorded manifest at verification time
- Custody ledger has not been tampered with since creation (within model limits)

## What verification does not prove

- Truth or completeness of original host state
- Legal provenance or chain of custody in organizational sense
- Absence of malware or compromise

See [custody-ledger.md](custody-ledger.md) and [chain-of-custody-limitations.md](chain-of-custody-limitations.md).
