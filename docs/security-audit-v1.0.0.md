# Security audit — v1.0.0

**Audit date:** 2026-08-05  
**Scope:** endpoint-incident-triage v1.0.0 pre-release  
**Auditor role:** Maintainer self-review per release checklist

## Checks performed

| Area | Method | Result |
|------|--------|--------|
| Real endpoint data in repo | Grep + repository guard tests | Pass — synthetic only |
| Private IPs in public examples | RFC5737 range validation | Pass |
| Credentials / tokens / keys | Pattern scan | Pass |
| `shell=True` in Python | Static scan | Pass |
| `Invoke-Expression` / `eval` in collectors | Pester/Bats/guards | Pass |
| LSASS / memory dump commands | Pattern scan | Pass |
| Destructive commands in collectors | Static tests | Pass |
| HTML injection | Report generation tests | Pass |
| Path traversal / symlinks | pytest evidence_paths, verification | Pass |
| CI safety | Workflow review | Pass — hosted only, no secrets |
| Documentation claims | Manual review | Pass — no legal admissibility claims |
| Live collection in CI | Workflow review | Pass — synthetic only |

## Corrections applied

- Collectors use fixture mode for all automated tests
- Public examples labeled SYNTHETIC DEMONSTRATION DATA
- Default config disables live collection (`allow_live_collection: false`)
- Privacy-sensitive flags off by default

## False positives

- Documentation mentions prohibited techniques (LSASS, etc.) in **prohibition context** — acceptable
- Synthetic paths resemble real paths (`AppData`, `/tmp`) — fictional hosts only

## Remaining limitations

- No third-party penetration test
- No digital signature on releases in v1.0.0
- GitHub Actions use version tags; full SHA pinning documented as follow-up
- Self-review does not replace organizational security assessment before operational deployment

## Synthetic data confirmation

Tracked evidence artifacts:

- `examples/synthetic-evidence-package/` — synthetic
- `examples/sample-triage-report.json/html` — synthetic
- `tests/fixtures/**` — synthetic
- `examples/synthetic-input/**` — synthetic

No EVTX, memory dumps, registry hives, packet captures, or live host exports are tracked.

## Recommendations for operators

- Obtain written authorization before live collection
- Store packages on encrypted media with access controls
- Use masked reports for sharing; never publish `full` mode samples
- Re-verify packages after transfer
- Treat heuristic findings as review queues, not verdicts

See [threat-model.md](threat-model.md) and [SECURITY.md](../SECURITY.md).
