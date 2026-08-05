# Custody ledger

## Format

JSONL file at `custody/custody.jsonl`. Each line is one record:

| Field | Description |
|-------|-------------|
| `sequence` | Contiguous integer starting at 1 |
| `event_id` | Unique event identifier |
| `event_type` | Lifecycle event name |
| `occurred_at_utc` | ISO 8601 UTC timestamp |
| `actor_label` | Operator label (not identity proof) |
| `action` | Short action verb |
| `package_id` | Case directory name |
| `details` | Structured context |
| `previous_record_hash` | SHA-256 of prior record |
| `record_hash` | SHA-256 of canonical JSON excluding this field |

## Hash chain

`record_hash` covers canonical JSON of all fields except `record_hash`. Genesis previous hash is 64 zeros.

## Event types

Including: `case_created`, `collection_started`, `collector_started`, `collector_completed`, `collector_partial`, `collector_unavailable`, `collector_error`, `collection_completed`, `manifest_created`, `package_verified`, `report_generated`, `zip_created`.

## Verification

`verify_ledger` detects:

- Hash mismatch (mutation)
- Broken previous hash link
- Non-contiguous sequence
- Missing or inserted records
- Reordered records

## Limitations

- **Tamper-evident**, not tamper-proof
- Local administrators can delete evidence and recreate a new package
- Does not prove actor identity without external authentication
- No digital signature or timestamp authority in v1.0

See [chain-of-custody-limitations.md](chain-of-custody-limitations.md).

## Secrets

Ledger records must not contain credentials, tokens, or full command lines with secrets.
