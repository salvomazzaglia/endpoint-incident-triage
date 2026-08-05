# Final release checklist — v1.0.0

## Package and CLI

- [x] Editable install works (`pip install -e ".[dev]"`)
- [x] `endpoint-incident-triage version` prints 1.0.0
- [x] All CLI subcommands implemented
- [x] Live collection requires `--acknowledge-live-collection`

## Collectors

- [x] 12 Windows PowerShell collectors with fixture mode
- [x] 11 Linux Bash collectors with fixture mode
- [x] Allowlisted registry; arbitrary paths rejected
- [x] No destructive or credential-extraction behavior

## Evidence integrity

- [x] Evidence package layout documented and generated
- [x] SHA-256 manifest and SHA256SUMS
- [x] Custody hash chain with verification
- [x] ZIP packaging with checksum sidecar
- [x] Verification for directory and ZIP packages

## Analysis and reporting

- [x] UTC timeline with original timestamps retained
- [x] Heuristic findings (advisory wording)
- [x] Privacy modes: masked, hashed, full
- [x] Standalone JSON/HTML reports
- [x] Synthetic sample package and reports

## Testing and CI

- [x] pytest suite under `tests/python/`
- [x] Pester suite under `tests/pester/`
- [x] Bats suite under `tests/bats/`
- [x] GitHub-hosted CI (Ubuntu + Windows matrix)
- [x] Repository guards
- [x] No live collection in CI

## Documentation

- [x] README (sections 1–38)
- [x] SECURITY.md, CONTRIBUTING.md, CHANGELOG.md
- [x] Complete `docs/` set
- [x] Screenshot at `docs/images/sample-triage-report.png`

## Security audit

- [x] `docs/security-audit-v1.0.0.md`
- [x] Only synthetic data in tracked examples
- [x] `.gitignore` excludes live evidence artifacts

## Release artifacts

- [x] `examples/sample-triage-report.json`
- [x] `examples/sample-triage-report.html`
- [x] `examples/synthetic-evidence-package/`

## Not in scope for v1.0.0

- [ ] Remote collection
- [ ] Memory/disk acquisition
- [ ] Digital signatures on packages
- [ ] Git push or GitHub release (manual follow-up)
