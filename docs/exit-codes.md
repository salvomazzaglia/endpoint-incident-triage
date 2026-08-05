# Exit codes

## Standard codes

| Code | Name | Meaning |
|------|------|---------|
| `0` | OK | Operation succeeded; mandatory collectors collected or intentionally skipped; verification passed |
| `1` | Partial | Optional collectors unavailable, partial output, or non-fatal warnings; package may still verify |
| `2` | Failure | Mandatory collector failure, integrity failure, unsafe structure, or policy exit |
| `3` | Error | Invalid configuration, invalid metadata, output path failure, unexpected internal error |

## Collection

Exit code derives from collector statuses:

- Any mandatory collector `Error` → `2`
- Any `Partial` or `Unavailable` → `1` (or `2` with `--strict`)

## Verification

Failed verification returns `2`.

## Report

- Verification failure before report → `2`
- Generation error → `3`
- `--fail-on-high-finding` with High/Critical findings → `2` (policy exit, not application bug)

## Strict mode

`--strict` on `collect` and `collect-synthetic` promotes partial/unavailable optional collectors to exit `2`.

## Automation

Document exit codes in playbooks. Distinguish policy exit (`--fail-on-high-finding`) from integrity failures.

## Python API

Constants in `endpoint_incident_triage.exit_codes`:

- `EXIT_OK`, `EXIT_PARTIAL`, `EXIT_FAILURE`, `EXIT_ERROR`
