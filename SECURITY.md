# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Reporting a vulnerability

**Do not open public issues for security vulnerabilities.**

Report privately to the maintainer via GitHub Security Advisories on the repository, or contact [@salvomazzaglia](https://github.com/salvomazzaglia) through GitHub's private reporting channel when available.

Include:

- Description and impact
- Steps to reproduce (use synthetic fixtures only)
- Affected version
- Suggested mitigation if known

Expect an initial response within a reasonable timeframe. Coordinated disclosure is preferred.

## In-scope concerns

- Unsafe collector behavior (destructive commands, credential extraction, arbitrary execution)
- Secret leakage in artifacts, reports, or logs
- Path traversal, symlink, or ZIP slip vulnerabilities
- Evidence corruption or verification bypass
- HTML injection in reports
- Command injection in orchestration
- Unauthorized collection enablers
- Misleading legal or forensic claims in documentation

## Out of scope

- Issues requiring live compromise of a target endpoint before collection
- Findings in synthetic demonstration data by design
- Operational incidents caused by running live collection without authorization
- Third-party tools invoked read-only by collectors on the host OS

## Safe harbor

Good-faith security research on synthetic fixtures and local test environments is appreciated. Do not test against systems you do not own or lack written authorization to examine.

## Security design principles

- Allowlisted collectors only
- No `shell=True` in Python orchestration
- No `Invoke-Expression` / `eval` in collectors
- Explicit acknowledgement for live collection
- Repository guards in CI
- Privacy modes for shareable reports

See [docs/threat-model.md](docs/threat-model.md) and [docs/security-audit-v1.0.0.md](docs/security-audit-v1.0.0.md).
