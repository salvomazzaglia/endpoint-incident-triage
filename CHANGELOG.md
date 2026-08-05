# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-05

### Added

- Cross-platform Python CLI (`plan`, `collect`, `collect-synthetic`, `verify`, `report`, `package`, `list-collectors`, `validate-config`, `version`)
- Twelve Windows PowerShell collectors and eleven Linux Bash collectors with allowlisted registry
- Collection profiles: `minimal` and `standard`
- Evidence-package layout with metadata, artifacts, timeline, findings, manifests, custody, and logs
- SHA-256 manifest generation and verification (`manifest.json`, `SHA256SUMS`)
- Tamper-evident hash-chained custody ledger (JSONL)
- UTC timeline normalization with original timestamp preservation
- Defensive heuristic findings engine with advisory severities
- Privacy modes for reports: masked, hashed, full
- Standalone JSON and HTML triage reports
- ZIP packaging with checksum sidecar (no encryption)
- Deterministic synthetic fixtures, sample evidence package, and sample reports
- pytest, Pester, and Bats test suites with GitHub-hosted CI
- Comprehensive documentation under `docs/`

### Security

- Live collection requires `--acknowledge-live-collection`
- Repository guards block secrets, private IPs in public examples, and unsafe CI patterns
- Collectors forbid destructive operations, credential access, and arbitrary execution

### Known limitations

- Not a forensic image or memory acquisition tool
- Custody ledger is tamper-evident, not tamper-proof
- Live collection is minimally invasive, not perfectly read-only
- Heuristic findings require analyst review

[1.0.0]: https://github.com/salvomazzaglia/endpoint-incident-triage/releases/tag/v1.0.0
