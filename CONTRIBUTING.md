# Contributing to endpoint-incident-triage

Thank you for helping improve this incident-triage toolkit. This project handles sensitive forensic workflows; please follow these guidelines.

## Development setup

```bash
git clone https://github.com/salvomazzaglia/endpoint-incident-triage.git
cd endpoint-incident-triage
python -m pip install -e ".[dev]"
python scripts/generate-demo-data.py
```

Requirements: Python 3.11+, PowerShell 5.1+ (Windows tests), Bash 5+ and Bats (Linux tests).

## Branch naming

- `feature/<short-description>`
- `fix/<short-description>`
- `docs/<short-description>`

## Code style

| Language | Tools |
|----------|-------|
| Python | Ruff (lint + format), mypy, type hints throughout |
| PowerShell | `Set-StrictMode -Version Latest`, PSScriptAnalyzer, Pester |
| Bash | `set -Eeuo pipefail`, ShellCheck, shfmt (`-i 2 -ci`), Bats |

Match existing patterns in neighboring files. Minimize scope of changes.

## Testing requirements

- Add or update pytest, Pester, and/or Bats tests for behavior changes
- Use **synthetic fixtures only** — never commit live endpoint output
- CI must not execute live collectors
- Run locally before opening a PR:

```bash
python -m pytest tests/python
pwsh -Command "Invoke-Pester -Path tests/pester"   # Windows
bats tests/bats/                                  # Linux
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src/endpoint_incident_triage
```

## Fixture requirements

- Hostname: `SYNTHETIC-ENDPOINT-01`
- Users: `synthetic-admin`, `synthetic-user`, `synthetic-service`
- IPs: RFC 5737/3849 documentation ranges only
- MACs: locally administered (second nibble 2, 6, A, or E)
- No real emails, credentials, or private keys

## Security review

Changes touching collectors, verification, custody, packaging, or privacy require explicit consideration of:

- Destructive or offensive capability
- Path traversal and symlink handling
- Secret leakage
- Arbitrary script execution
- Documentation accuracy (no false forensic/legal claims)

## Pull request checklist

- [ ] Tests pass on relevant platform(s)
- [ ] Documentation updated
- [ ] No real endpoint data
- [ ] No credentials or tokens
- [ ] No live collector execution in CI
- [ ] Synthetic examples remain clearly marked

## Prohibited contributions

- Credential extraction or LSASS/memory dumping
- Disk imaging or raw-volume access
- EDR/AV bypass or disabling
- Log clearing or persistence removal
- Remote exploitation or lateral movement tooling
- Cloud upload / threat-intel enrichment by default

## Documentation

Update README and relevant `docs/*.md` files when CLI behavior, collectors, or evidence formats change.

## Questions

Open a [feature request](.github/ISSUE_TEMPLATE/feature_request.yml) or [bug report](.github/ISSUE_TEMPLATE/bug_report.yml) using synthetic data only.
