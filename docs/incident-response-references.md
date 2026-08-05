# Incident response references

## Primary sources

### NIST SP 800-61 Revision 3

**Computer Security Incident Handling Guide** (2025)

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/publications/detail/sp/800-61/rev-3/final)
- Focus: incident response lifecycle, preparation, detection, analysis, containment, eradication, recovery, post-incident activity
- **Use for:** methodology alignment, communication, coordination, risk-based response

This project's phases (plan → collect → verify → report) map loosely to **analysis and evidence gathering** within a broader IR program, not full lifecycle automation.

### NIST SP 800-86

**Guide to Integrating Forensic Techniques into Incident Response** (2006)

- [NIST SP 800-86](https://csrc.nist.gov/publications/detail/sp/800-86/final)
- Focus: forensic techniques, evidence handling concepts, tool categories
- **Use for:** understanding forensic terminology, evidence integrity concepts, limitations of live analysis

800-86 predates many modern cloud and EDR paradigms but remains relevant for **live-response tradeoffs** and integrity documentation.

## Distinctions

| Topic | NIST guidance | This project |
|-------|---------------|--------------|
| Live response | Recognized with caveats | Supported with explicit warnings |
| Disk imaging | Recommended for deep forensics | **Not implemented** in v1.0 |
| Memory capture | Volatile evidence priority | **Not implemented** |
| Integrity hashing | Best practice | SHA-256 manifest implemented |
| Legal admissibility | Organizational and legal context | **Not claimed** |

## Additional reading

- SANS Incident Handler's Handbook (conceptual IR workflows)
- Vendor playbooks for Windows/Linux live response (evaluate against your authorization model)

## Project-specific decisions

- Synthetic-only CI and public examples
- Heuristic rules without automated verdicts
- Tamper-evident (not tamper-proof) custody ledger
- Privacy modes for reporting only

This document is informational and not legal advice.
