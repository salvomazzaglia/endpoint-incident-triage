# Configuration

## Files

| File | Purpose |
|------|---------|
| `config/default.config.json` | Production defaults; live collection disabled by default |
| `config/demo.config.json` | Synthetic demos and CI |
| `config/collector-registry.json` | Allowlisted collectors |
| `config/collection-profiles.json` | Profile descriptions |
| `config/triage-rules.json` | Heuristic finding rules |

Local overrides (`config/local.config.json`) are gitignored.

## Key sections

### defaults

- `profile`, `platform`, `since_hours`
- `include_command_lines`, `include_event_messages` (default false)
- Timeouts and output size limits

### safety

- `refuse_overwrite`, `refuse_system_sensitive_output`
- `refuse_output_inside_collectors`, `never_self_elevate`
- `allow_live_collection` (false in default config)

### paths

- Registry, rules, and collectors root (relative paths only)

### privacy

- Default report mode and hash salt environment variable name

## Validation

```bash
endpoint-incident-triage validate-config
endpoint-incident-triage validate-config --config config/demo.config.json
```

Rejects unknown keys, traversal paths, duplicate collector IDs, excessive limits, and invalid profiles.

## Environment

| Variable | Purpose |
|----------|---------|
| `EIT_FIXTURE_FILE` | Collector fixture path (tests/synthetic) |
| `EIT_HASH_SALT` | Salt for hashed privacy mode |

## Customization

Do not add arbitrary collector paths via config — extend the registry in source with review. Rules support safe condition types only.

See [collection-profiles.md](collection-profiles.md).
