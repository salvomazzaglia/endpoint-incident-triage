# Linux collectors

Bash scripts in `collectors/linux/` use native read-only commands and a Python-assisted JSON output protocol.

## Common requirements

- `#!/usr/bin/env bash`
- `set -Eeuo pipefail`; `umask 077`
- `--fixture` flag and `EIT_FIXTURE_FILE` support
- No `eval`, `sudo`, network probes, journal clearing, or `find /`
- Structured JSON via embedded Python (safe escaping)

## Collectors

| Script | ID | Profile | Notes |
|--------|-----|---------|-------|
| `system-context.sh` | `linux.system_context` | minimal | OS, kernel, boot, UID |
| `time-context.sh` | `linux.time_context` | minimal | UTC/local, time sync |
| `users-sessions.sh` | `linux.users_sessions` | minimal | passwd metadata, sessions |
| `processes.sh` | `linux.processes` | minimal | `ps` metadata; `--include-command-lines` opt-in |
| `network-connections.sh` | `linux.network_connections` | minimal | `ss` where available |
| `systemd-services.sh` | `linux.systemd_services` | minimal | Unit states, ExecStart |
| `systemd-timers.sh` | `linux.systemd_timers` | minimal | Timer schedules |
| `cron-persistence.sh` | `linux.cron_persistence` | standard | Cron file metadata |
| `auth-event-summary.sh` | `linux.auth_event_summary` | minimal | Bounded journal/log summary |
| `ssh-key-metadata.sh` | `linux.ssh_key_metadata` | standard | authorized_keys metadata only |
| `recent-file-metadata.sh` | `linux.recent_file_metadata` | standard | Allowlisted roots |

## Prohibited collection

- `/etc/shadow`, password hashes
- Private SSH keys (`id_rsa`, etc.)
- Shell history files
- Full home-directory scans

## Testing

Bats tests in `tests/bats/` with fixtures under `tests/fixtures/linux/`.

## Missing commands

When required tools (`ss`, `systemctl`) are absent, collectors return structured errors without attempting installation.
