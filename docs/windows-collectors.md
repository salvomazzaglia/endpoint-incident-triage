# Windows collectors

PowerShell scripts in `collectors/windows/` implement read-oriented live collection with deterministic fixture mode for tests.

## Common requirements

- `#Requires -Version 5.1`
- `Set-StrictMode -Version Latest`
- `$ErrorActionPreference = 'Stop'`
- `-FixturePath` parameter and `EIT_FIXTURE_FILE` support
- JSON via `ConvertTo-Json`; UTC timestamps
- No `Invoke-Expression`, downloads, registry writes, service changes, or process termination

## Collectors

| Script | ID | Profile | Notes |
|--------|-----|---------|-------|
| `system-context.ps1` | `windows.system_context` | minimal | OS, hostname, boot time, elevation |
| `time-context.ps1` | `windows.time_context` | minimal | UTC/local time, NTP status |
| `users-sessions.ps1` | `windows.users_sessions` | minimal | Sessions, local users, admin groups |
| `processes.ps1` | `windows.processes` | minimal | Processes; `-IncludeCommandLines` opt-in |
| `network-connections.ps1` | `windows.network_connections` | minimal | TCP/UDP metadata |
| `services.ps1` | `windows.services` | minimal | Service config, binary paths |
| `scheduled-tasks.ps1` | `windows.scheduled_tasks` | minimal | Task triggers and actions |
| `autoruns.ps1` | `windows.autoruns` | minimal | Run/RunOnce, startup folder |
| `wmi-persistence.ps1` | `windows.wmi_persistence` | standard | WMI permanent subscriptions |
| `defender-status.ps1` | `windows.defender_status` | minimal | Defender status; may be Unavailable |
| `event-log-summary.ps1` | `windows.event_log_summary` | minimal | Bounded events; messages opt-in |
| `recent-file-metadata.ps1` | `windows.recent_file_metadata` | standard | Allowlisted roots only |

## Sensitive options

| Flag | Risk |
|------|------|
| `-IncludeCommandLines` | Credentials in process arguments |
| `-IncludeEventMessages` | PII in event text |

## Testing

Pester tests in `tests/pester/` use fixtures under `tests/fixtures/windows/`. CI does not execute live collectors.

## Privilege

Collectors target standard user privilege where possible. Some WMI or event-log reads may require elevation on hardened hosts; status is recorded as `Partial` or `Unavailable`.
