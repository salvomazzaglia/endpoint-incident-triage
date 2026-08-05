# Privacy and redaction

## Raw evidence vs reports

**Raw evidence packages are potentially sensitive.** Privacy modes apply to generated **reports**, not to the underlying collected JSON in `artifacts/`.

Do not assume raw evidence is anonymized.

## Modes

### masked (default)

- Mask usernames, hostnames, IPv4/IPv6, MAC addresses
- Generalize user-specific paths while preserving investigative categories
- Suitable for internal sharing with reduced PII exposure

### hashed

- Replace identifiers with stable SHA-256 pseudonyms
- Salt read from environment variable (`EIT_HASH_SALT` by default)
- Salt is **never** written to evidence or reports
- Warn when salt is missing; unsalted hashing is not called anonymization

### full

- Include raw identifiers
- Requires explicit `--privacy-mode full`
- Prints strong privacy warning
- **Never** use for public samples or screenshots

## Synthetic demos

Public examples use masked mode with deterministic demo data. Synthetic banner displayed in HTML reports.

## Pseudonymization limits

Hashed mode prevents casual identification but may be reversible with salt access or small datasets. It is not formal anonymization under privacy regulations.

## Safe sharing checklist

- Use masked or hashed mode
- Remove internal case IDs if required
- Verify no command lines with secrets were collected
- Do not share raw `artifacts/` without authorization

See [data-sensitivity.md](data-sensitivity.md).
