# Threat model

## Assets

- Endpoint runtime state (processes, network, logs)
- Evidence package directory
- SHA-256 manifest and SHA256SUMS
- Custody ledger
- Operator and case metadata
- Collector scripts and configuration
- Generated reports

## Threats and mitigations

| Threat | Mitigation | Residual risk |
|--------|------------|---------------|
| Unauthorized collection | Authorization warnings, acknowledgement flag | Operator misuse |
| Malicious collector modification | Code review, static tests, allowlist | Supply-chain compromise |
| Evidence tampering post-collection | Manifest + custody verification | Privileged attacker rebuilds package |
| Path traversal / symlink attacks | Path validation, ZIP checks | Implementation bugs |
| Secret leakage in reports | Redaction, privacy modes, HTML escape | Misconfiguration |
| Command injection | No `shell=True`, no `eval`/`Invoke-Expression` | Future regression |
| Arbitrary collector execution | Registry allowlist, path checks | Config tampering on host |
| Unbounded collection | Timeouts, output byte limits | Operator selects `--include-*` flags |
| ZIP slip | Normalized member names, verify before extract | Archive edge cases |
| Misleading timestamps | Original values retained, confidence field | Clock skew |
| Host pre-compromise | Documented limitation | Undetectable by integrity tools |
| False confidence in findings | Advisory wording, no auto-verdict | Analyst error |
| HTML injection | Escape all dynamic HTML fields | Template bug |
| CI live collection | Synthetic/fixture tests only | Workflow misconfiguration |

## Out of scope threats

- Nation-state memory-resident malware invisible to APIs
- Hardware firmware implants
- Legal admissibility challenges in court

## CI security

- GitHub-hosted runners only
- `permissions: contents: read`
- No secrets, no `pull_request_target`, no self-hosted runners
- Repository guard tests

See [security-audit-v1.0.0.md](security-audit-v1.0.0.md).
