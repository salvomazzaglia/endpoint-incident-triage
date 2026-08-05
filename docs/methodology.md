# Methodology

## Phases

This toolkit supports a pragmatic live-response workflow aligned with common incident-response practice:

1. **Preparation** — Validate config, select profile, confirm authorization, choose output path
2. **Authorization** — Record case metadata and acknowledgement
3. **Collection planning** — Run `plan`; confirm collector list and order
4. **Live response** — Execute `collect` (or `collect-synthetic` for demos)
5. **Normalization** — Orchestrator structures collector JSON, timeline, findings
6. **Integrity verification** — Manifest and custody ledger creation; run `verify`
7. **Analysis** — Review timeline and heuristic findings (analyst judgment required)
8. **Reporting** — Generate masked/hashed/full reports for stakeholders
9. **Preservation** — Store package under organizational custody; optional ZIP
10. **Lessons learned** — Document limitations, gaps, and follow-up actions

## Alignment with guidance

| Source | Relevance |
|--------|-----------|
| [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/publications/detail/sp/800-61/rev-3/final) | Incident response lifecycle, coordination, communication |
| [NIST SP 800-86](https://csrc.nist.gov/publications/detail/sp/800-86/final) | Forensic techniques in incident handling (conceptual alignment) |

See [incident-response-references.md](incident-response-references.md) for distinctions between current IR guidance and forensic technique documents.

## What this toolkit is not

- A substitute for forensic imaging or volatile memory capture
- A malware analysis sandbox
- A legal evidence certification system
- An automated containment platform

## Terminology

Use: non-destructive, minimally invasive, live-response collection, evidence-integrity verification, tamper-evident custody ledger.

Avoid claiming: read-only collection, forensic image, legal admissibility, tamper-proof ledger, clean-endpoint proof.

## Side effects

Document that live commands may alter caches, access times, and security telemetry. Collection order prioritizes volatile data but cannot guarantee preservation.
