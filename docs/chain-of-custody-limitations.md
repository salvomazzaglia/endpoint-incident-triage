# Chain of custody limitations

## Organizational procedures

Technical integrity features complement — but do not replace — organizational chain-of-custody procedures:

- Written authorization and scope
- Witnesses or supervisor approval where required
- Physical media handling logs
- Secure storage with access controls
- Jurisdiction-specific evidence rules

## What the project provides

| Feature | Provides | Does not provide |
|---------|----------|------------------|
| SHA-256 manifest | File consistency vs recorded hashes | Original data authenticity |
| Custody ledger | Tamper-evident event sequence | Legal certification |
| Case metadata | Collection context labels | Identity verification |
| Reports | Analyst-readable summary | Automated verdict |

## Trust anchors missing in v1.0

- Digital signatures on packages
- Trusted timestamp authority
- Hardware security module integration
- WORM storage guarantees
- Remote immutable audit log

## Host compromise

If the endpoint was compromised before collection, attackers may have altered artifacts the collectors read. Verification cannot detect pre-collection manipulation on the host.

## Operator error

Mislabeled case IDs, wrong output directories, or accidental package overwrite attempts (refused by tool) must be handled procedurally.

## Why "tamper-evident" only

A privileged user with filesystem access can replace files and rebuild manifests unless independent controls exist. The ledger raises the bar for undetected modification but is not a legal instrument on its own.

See [custody-ledger.md](custody-ledger.md) and [manifest-and-verification.md](manifest-and-verification.md).
