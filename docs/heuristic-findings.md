# Heuristic findings

## Purpose

The rule engine (`config/triage-rules.json`) evaluates normalized collector records and emits **advisory** findings for analyst review.

## Rule structure

Each rule includes: `id`, `title`, `description`, `platform`, `artifact_type`, `enabled`, `priority`, `conditions`, `severity`, `rationale`, `recommendation`, `references`, `tags`.

## Safe condition types

- `equals`, `not_equals`, `contains`, `regex`
- `path_under`, `path_missing`, `field_missing`
- `numeric_greater_than`, `value_in`, `network_scope`

Rules do **not** execute arbitrary code or expressions from configuration.

## Severities

`Informational`, `Low`, `Medium`, `High`, `Critical` — describe review priority, not confirmed compromise.

## Wording

Use: *Requires review*, *Potentially suspicious*, *Context-dependent*, *Heuristic match*.

Do **not** use: *Malware confirmed*, *Compromise confirmed*, *Attacker confirmed*.

## Example synthetic matches

- Process from user-writable/temp directory
- Service binary in unexpected writable location
- Scheduled task referencing missing path
- Autorun pointing to absent file
- Listener on all interfaces
- SSH authorized_keys unsafe permissions
- WMI permanent subscription present
- Security tool unavailable

## False positives

Legitimate software may trigger rules. Analysts must validate with context, baselines, and additional evidence.

## Exit codes

Finding severity does **not** change collection exit codes by default. Optional `--fail-on-high-finding` on `report` returns exit code 2 for High/Critical findings.

See [exit-codes.md](exit-codes.md).
