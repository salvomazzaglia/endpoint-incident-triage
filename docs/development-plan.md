# Development Plan — endpoint-incident-triage 1.0.0

## Objective

Build a cross-platform, non-destructive endpoint incident-triage toolkit that
collects, normalizes, hashes, verifies, packages, and reports selected
security-relevant artifacts from Windows and Linux systems using synthetic
fixtures for all development and CI demonstrations.

## Constraints

- No live collection against the developer host
- No administrator/root elevation
- No forensic imaging or memory acquisition
- No credential extraction or offensive features
- Synthetic data only in tracked examples
- GitHub-hosted CI only

## Phases

| Phase | Work |
|------:|------|
| 1 | Inspect directory; write this plan |
| 2 | Repository structure and metadata |
| 3 | Models, statuses, paths, configuration |
| 4 | Collector registry and allowlist |
| 5 | Synthetic fixture protocol |
| 6 | Windows PowerShell collectors |
| 7 | Linux Bash collectors |
| 8 | Collector runner and normalization |
| 9 | Case and evidence-package creation |
| 10 | Hashing and SHA-256 manifest |
| 11 | Tamper-evident custody ledger |
| 12 | Package verification |
| 13 | ZIP packaging |
| 14 | UTC timeline |
| 15 | Safe heuristic rules |
| 16 | Privacy and redaction |
| 17 | JSON, HTML, and console reports |
| 18 | CLI commands |
| 19 | Deterministic synthetic inputs |
| 20 | Synthetic evidence package |
| 21 | Sample reports |
| 22 | Sample screenshot |
| 23 | pytest, Pester, and Bats tests |
| 24 | Ruff, mypy, PSScriptAnalyzer, ShellCheck, shfmt |
| 25 | GitHub-hosted CI |
| 26 | Complete documentation |
| 27 | Isolated development environments |
| 28 | Local validation |
| 29 | Synthetic demo workflows only |
| 30 | Security and privacy audit |
| 31 | Defect fixes and revalidation |
| 32 | Local Git initialization with noreply identity |

**Status (2026-08-05):** Phases 1–26 complete for v1.0.0 — documentation, GitHub metadata, pytest/Pester/Bats suites, and CI workflow delivered. Phases 27–32 remain for local validation and Git initialization.

## Terminology

Use: non-destructive, minimally invasive, best-effort preservation,
live-response collection, evidence-integrity verification,
tamper-evident custody ledger.

Do not claim: read-only live collection, forensic image, legal admissibility,
tamper-proof ledger, clean-endpoint proof, malware verdicts.

## Success Criteria

See repository acceptance criteria in the project brief and
`docs/final-release-checklist.md`.
