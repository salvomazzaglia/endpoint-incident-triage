# Release notes — v1.0.0

**Release date:** 2026-08-05  
**Author:** Salvatore Mazzaglia

## Highlights

Initial public release of **endpoint-incident-triage** — a cross-platform, non-destructive endpoint incident-triage toolkit with evidence-integrity verification and privacy-aware reporting.

## Features

- Python CLI with planning, synthetic/live collection, verification, reporting, and ZIP packaging
- 12 Windows + 11 Linux allowlisted collectors
- `minimal` and `standard` collection profiles
- SHA-256 manifest, tamper-evident custody ledger, package verification
- UTC timeline and defensive heuristic findings
- Masked, hashed, and full report privacy modes
- Deterministic synthetic fixtures, sample package, and sample reports
- pytest, Pester, Bats, and GitHub Actions CI

## Documentation

Full documentation under `docs/` including architecture, methodology, threat model, and NIST reference alignment.

## Upgrade notes

First release — no migration path.

## Known limitations

See README **Known limitations** and [chain-of-custody-limitations.md](chain-of-custody-limitations.md).

## Checksums

Synthetic sample package verified in CI. Release ZIP checksums to be published when GitHub release is created manually.

## Links

- Repository: https://github.com/salvomazzaglia/endpoint-incident-triage
- Changelog: [CHANGELOG.md](../CHANGELOG.md)
