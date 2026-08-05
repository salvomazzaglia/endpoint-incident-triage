# Data sensitivity

## High-sensitivity fields

| Category | Examples | Default handling |
|----------|----------|------------------|
| Identity | Usernames, SIDs, UIDs | Masked in reports |
| Network | IP addresses, MACs | Masked in reports |
| Host | Hostname, domain | Masked in reports |
| Execution | Command lines | Omitted unless `--include-command-lines` |
| Events | Full event message text | Metadata only unless `--include-event-messages` |
| Paths | User profile paths | Generalized in masked reports |
| SSH | authorized_keys content | Not collected; metadata only |

## Evidence package classification

Treat complete packages as **confidential** at minimum. Classification may increase when command lines or full event messages are enabled.

## Storage

- Restrict filesystem ACLs on output directories
- Avoid cloud sync folders without encryption
- Do not commit packages to git (see `.gitignore`)

## Transmission

Verify integrity before and after transfer. ZIP files are not encrypted in v1.0.

## Retention

Follow organizational schedules. Secure deletion includes extracted ZIP contents and report copies.

## Developer / CI data

Only synthetic fixtures and pre-built sample packages belong in the repository. CI generates temporary packages under `temp/` (gitignored).

See [privacy-and-redaction.md](privacy-and-redaction.md).
