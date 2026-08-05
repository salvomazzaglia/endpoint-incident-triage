#!/usr/bin/env python3
"""Generate deterministic synthetic fixture JSON for endpoint-incident-triage.

Writes fixtures under examples/synthetic-input/ and tests/fixtures/.
Never inspects or collects from the local endpoint.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]

HOSTNAME = "SYNTHETIC-ENDPOINT-01"
DOMAIN = "SYNTHETIC-WORKGROUP"
USERS = ("synthetic-admin", "synthetic-user", "synthetic-service")
STAMP = "2026-08-05T18:00:00.000Z"
MAC = "02:00:5e:00:53:01"

# RFC 5737 / RFC 3849 documentation ranges only.
IPV4_A = "192.0.2.10"
IPV4_B = "198.51.100.20"
IPV4_C = "203.0.113.30"
IPV6 = "2001:db8::1"

# Collectors intentionally omitted from tests/fixtures (unavailable-collector tests).
TESTS_OMIT_WINDOWS = frozenset({"windows.defender_status"})
TESTS_OMIT_LINUX: frozenset[str] = frozenset()


def _records(*items: dict[str, Any]) -> dict[str, Any]:
    return {"records": list(items)}


def windows_fixtures() -> dict[str, Any]:
    return {
        "windows.system_context": _records(
            {
                "record_type": "system_context",
                "hostname": HOSTNAME,
                "os_caption": "Microsoft Windows 11 Synthetic Edition",
                "os_version": "10.0.26200",
                "os_architecture": "64-bit",
                "domain": DOMAIN,
                "manufacturer": "Synthetic Hardware Corp",
                "model": "SYNTHETIC-MODEL-01",
                "total_physical_memory_gb": 16.0,
                "logical_processors": 8,
                "boot_time_utc": "2026-08-05T06:00:00.000Z",
                "collected_at_utc": STAMP,
            }
        ),
        "windows.time_context": _records(
            {
                "record_type": "time_context",
                "utc_now": STAMP,
                "local_now": "2026-08-05T20:00:00.000+02:00",
                "timezone_id": "Central Europe Standard Time",
                "timezone_offset_minutes": 120,
                "uptime_seconds": 43200,
                "ntp_sync_status": "synchronized",
                "collected_at_utc": STAMP,
            }
        ),
        "windows.users_sessions": _records(
            {
                "record_type": "interactive_session",
                "username": USERS[1],
                "session_id": 1,
                "state": "Active",
                "logon_type": "Interactive",
                "source_address": IPV4_A,
                "collected_at_utc": STAMP,
            },
            {
                "record_type": "logon_session",
                "username": USERS[0],
                "logon_id": "0x3e7",
                "authentication_package": "Negotiate",
                "collected_at_utc": STAMP,
            },
            {
                "record_type": "service_account_session",
                "username": USERS[2],
                "session_id": 0,
                "state": "Service",
                "collected_at_utc": STAMP,
            },
        ),
        "windows.processes": _records(
            {
                "artifact_type": "process",
                "record_type": "process",
                "pid": 4,
                "name": "System",
                "session_id": 0,
                "path": "C:\\Windows\\System32\\ntoskrnl.exe",
                "parent_pid": 0,
                "start_time_utc": "2026-08-05T06:00:00.000Z",
            },
            {
                "artifact_type": "process",
                "record_type": "process",
                "pid": 892,
                "name": "svchost",
                "session_id": 0,
                "path": "C:\\Windows\\System32\\svchost.exe",
                "parent_pid": 684,
                "start_time_utc": "2026-08-05T06:00:05.000Z",
            },
            {
                "artifact_type": "process",
                "record_type": "process",
                "pid": 4512,
                "name": "payload",
                "session_id": 1,
                "path": (
                    "C:\\Users\\synthetic-user\\AppData\\Local\\Temp\\"
                    "synthetic-example\\payload.exe"
                ),
                "parent_pid": 1200,
                "start_time_utc": "2026-08-05T17:55:00.000Z",
            },
        ),
        "windows.network_connections": _records(
            {
                "artifact_type": "network_connection",
                "record_type": "tcp_connection",
                "local_address": "192.0.2.1",
                "local_port": 49821,
                "remote_address": IPV4_A,
                "remote_port": 443,
                "state": "Established",
                "owning_process": 4512,
                "creation_time_utc": "2026-08-05T17:56:00.000Z",
            },
            {
                "artifact_type": "network_connection",
                "record_type": "tcp_connection",
                "local_address": "0.0.0.0",
                "local_port": 8080,
                "remote_address": "0.0.0.0",
                "remote_port": 0,
                "state": "Listen",
                "owning_process": 3300,
                "listen_all_interfaces": True,
                "creation_time_utc": "2026-08-05T12:00:00.000Z",
            },
            {
                "artifact_type": "network_connection",
                "record_type": "udp_endpoint",
                "local_address": "::",
                "local_port": 5353,
                "owning_process": 2100,
            },
        ),
        "windows.services": _records(
            {
                "artifact_type": "service",
                "record_type": "service",
                "name": "WinDefend",
                "display_name": "Synthetic Windows Defender Service",
                "state": "Running",
                "start_mode": "Auto",
                "path_name": '"C:\\Program Files\\Windows Defender\\MsMpEng.exe"',
                "service_account": "LocalSystem",
                "binary_dir_writable": False,
            },
            {
                "artifact_type": "service",
                "record_type": "service",
                "name": "SynEvilSvc",
                "display_name": "Synthetic Writable Service Example",
                "state": "Stopped",
                "start_mode": "Manual",
                "path_name": (
                    '"C:\\Users\\synthetic-user\\AppData\\Local\\'
                    'synthetic-writable\\evil-svc.exe" --synthetic'
                ),
                "service_account": USERS[2],
                "binary_dir_writable": True,
                "recently_created": True,
            },
        ),
        "windows.scheduled_tasks": _records(
            {
                "artifact_type": "scheduled_task",
                "record_type": "scheduled_task",
                "task_name": "SyntheticMaintenance",
                "task_path": "\\Synthetic\\",
                "state": "Ready",
                "author": "SYNTHETIC\\synthetic-admin",
                "description": "Synthetic maintenance task for demonstration",
                "execute": "C:\\Windows\\System32\\synthetic-maint.exe",
                "arguments": "/quiet",
                "execute_exists": True,
                "last_run_time_utc": "2026-08-05T03:00:00.000Z",
                "next_run_time_utc": "2026-08-06T03:00:00.000Z",
            },
            {
                "artifact_type": "scheduled_task",
                "record_type": "scheduled_task",
                "task_name": "SyntheticMissingTarget",
                "task_path": "\\Synthetic\\",
                "state": "Ready",
                "author": "SYNTHETIC\\synthetic-user",
                "description": "Synthetic task with missing executable target",
                "execute": "C:\\Temp\\synthetic-missing\\not-present.exe",
                "arguments": None,
                "execute_exists": False,
                "last_run_time_utc": None,
                "next_run_time_utc": "2026-08-06T06:00:00.000Z",
            },
        ),
        "windows.autoruns": _records(
            {
                "artifact_type": "autorun",
                "record_type": "autorun",
                "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "name": "SyntheticUpdater",
                "command": "C:\\Program Files\\Synthetic\\updater.exe /check",
                "source": "registry_run",
                "target_exists": True,
            },
            {
                "artifact_type": "autorun",
                "record_type": "autorun",
                "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "name": "SyntheticGhost",
                "command": "C:\\Users\\synthetic-user\\AppData\\Local\\removed\\ghost.exe",
                "source": "registry_run",
                "target_exists": False,
                "recently_created": True,
            },
        ),
        "windows.wmi_persistence": _records(
            {
                "record_type": "wmi_event_filter",
                "name": "SyntheticFilter",
                "query": "SELECT * FROM __InstanceModificationEvent WITHIN 60",
                "query_language": "WQL",
                "namespace": "root/subscription",
            },
            {
                "record_type": "wmi_event_consumer",
                "name": "SyntheticConsumer",
                "class_name": "CommandLineEventConsumer",
                "namespace": "root/subscription",
            },
            {
                "artifact_type": "wmi_persistence",
                "record_type": "wmi_filter_consumer_binding",
                "filter": "SyntheticFilter",
                "consumer": "SyntheticConsumer",
                "namespace": "root/subscription",
                "permanent": True,
                "recently_created": True,
            },
        ),
        "windows.defender_status": _records(
            {
                "artifact_type": "security_tool",
                "record_type": "defender_status",
                "available": True,
                "antivirus_enabled": True,
                "antispyware_enabled": True,
                "real_time_protection_enabled": True,
                "on_access_protection_enabled": True,
                "product_version": "4.18.25070.5-synthetic",
                "engine_version": "1.1.25070.5-synthetic",
                "antivirus_signature_age": 1,
                "collected_at_utc": STAMP,
            },
            {
                "record_type": "defender_preference",
                "cloud_protection": 2,
                "submit_samples_consent": 1,
                "disable_realtime_monitoring": False,
                "collected_at_utc": STAMP,
            },
        ),
        "windows.event_log_summary": _records(
            {
                "record_type": "event_log_entry",
                "log_name": "Security",
                "event_id": 4624,
                "level": "Information",
                "provider": "Microsoft-Windows-Security-Auditing",
                "time_created_utc": "2026-08-05T17:30:00.000Z",
                "machine": HOSTNAME,
            },
            {
                "record_type": "event_log_entry",
                "log_name": "Security",
                "event_id": 4625,
                "level": "Information",
                "provider": "Microsoft-Windows-Security-Auditing",
                "time_created_utc": "2026-08-05T17:31:00.000Z",
                "machine": HOSTNAME,
            },
            {
                "record_type": "event_log_summary",
                "log_name": "Security",
                "since_utc": "2026-08-04T18:00:00.000Z",
                "max_events": 200,
                "collected": 2,
            },
            {
                "record_type": "event_log_summary",
                "log_name": "System",
                "since_utc": "2026-08-04T18:00:00.000Z",
                "max_events": 200,
                "collected": 0,
            },
        ),
        "windows.recent_file_metadata": _records(
            {
                "record_type": "recent_file",
                "path": (
                    "C:\\Users\\synthetic-user\\AppData\\Local\\Temp\\"
                    "synthetic-example\\payload.exe"
                ),
                "name": "payload.exe",
                "size_bytes": 4096,
                "created_time_utc": "2026-08-05T17:50:00.000Z",
                "modified_time_utc": "2026-08-05T17:55:00.000Z",
                "extension": ".exe",
                "search_root": "C:\\Users\\synthetic-user\\AppData\\Local\\Temp",
            },
            {
                "record_type": "collection_summary",
                "since_utc": "2026-08-04T18:00:00.000Z",
                "max_files": 50,
                "max_depth": 2,
                "collected": 1,
            },
        ),
    }


def linux_fixtures() -> dict[str, Any]:
    return {
        "linux.system_context": _records(
            {
                "record_type": "system_context",
                "hostname": HOSTNAME,
                "fqdn": f"{HOSTNAME.lower()}.synthetic.invalid",
                "platform": "Linux-6.8.0-synthetic-x86_64",
                "system": "Linux",
                "release": "6.8.0-synthetic",
                "version": "#1 SMP Synthetic",
                "machine": "x86_64",
                "processor": "Synthetic CPU",
                "os_pretty_name": "Synthetic Linux 24.04",
                "os_id": "synthetic-linux",
                "os_version_id": "24.04",
                "mac_address": MAC,
                "collected_at_utc": STAMP,
            }
        ),
        "linux.time_context": _records(
            {
                "record_type": "time_context",
                "utc_now": STAMP,
                "local_now": "2026-08-05T20:00:00.000+0200",
                "timezone": "Europe/Synthetic",
                "uptime_seconds": 43200,
                "boot_time_utc": "2026-08-05T06:00:00.000Z",
                "ntp_synchronized": True,
                "collected_at_utc": STAMP,
            }
        ),
        "linux.users_sessions": _records(
            {
                "record_type": "interactive_session",
                "user": USERS[1],
                "tty": "pts/0",
                "source_address": IPV4_B,
                "login_time_utc": "2026-08-05T08:00:00.000Z",
                "collected_at_utc": STAMP,
            },
            {
                "record_type": "login_history",
                "user": USERS[0],
                "source_address": IPV4_C,
                "login_time_utc": "2026-08-05T07:00:00.000Z",
                "collected_at_utc": STAMP,
            },
        ),
        "linux.processes": _records(
            {
                "artifact_type": "process",
                "record_type": "process",
                "pid": 1,
                "name": "systemd",
                "user": "root",
                "path": "/usr/lib/systemd/systemd",
                "start_time_utc": "2026-08-05T06:00:00.000Z",
            },
            {
                "artifact_type": "process",
                "record_type": "process",
                "pid": 8842,
                "name": "agent",
                "user": USERS[1],
                "path": "/tmp/synthetic-example/agent",
                "start_time_utc": "2026-08-05T17:55:00.000Z",
            },
            {
                "artifact_type": "process",
                "record_type": "process",
                "pid": 2200,
                "name": "sshd",
                "user": "root",
                "path": "/usr/sbin/sshd",
                "start_time_utc": "2026-08-05T06:00:10.000Z",
            },
        ),
        "linux.network_connections": _records(
            {
                "artifact_type": "network_connection",
                "record_type": "socket",
                "state": "ESTAB",
                "local_address": f"{IPV4_B}:22",
                "peer_address": f"{IPV4_A}:54321",
                "listen_all_interfaces": False,
            },
            {
                "artifact_type": "network_connection",
                "record_type": "socket",
                "state": "LISTEN",
                "local_address": "0.0.0.0:8080",
                "peer_address": "*:*",
                "listen_all_interfaces": True,
            },
            {
                "artifact_type": "network_connection",
                "record_type": "socket",
                "state": "LISTEN",
                "local_address": f"[{IPV6}]:8443",
                "peer_address": "*:*",
                "listen_all_interfaces": True,
            },
        ),
        "linux.systemd_services": _records(
            {
                "artifact_type": "service",
                "record_type": "systemd_service",
                "unit": "ssh.service",
                "load_state": "loaded",
                "active_state": "active",
                "sub_state": "running",
                "description": "Synthetic OpenSSH server",
                "exec_start": "/usr/sbin/sshd -D",
                "binary_dir_writable": False,
            },
            {
                "artifact_type": "service",
                "record_type": "systemd_service",
                "unit": "synthetic-writable.service",
                "load_state": "loaded",
                "active_state": "inactive",
                "sub_state": "dead",
                "description": "Synthetic service with writable binary directory",
                "exec_start": "/home/synthetic-user/synthetic-writable/evil-svc",
                "binary_dir_writable": True,
                "recently_created": True,
            },
        ),
        "linux.systemd_timers": _records(
            {
                "artifact_type": "scheduled_task",
                "record_type": "systemd_timer",
                "unit": "synthetic-maint.timer",
                "load_state": "loaded",
                "active_state": "active",
                "next_elapse_utc": "2026-08-06T03:00:00.000Z",
                "last_trigger_utc": "2026-08-05T03:00:00.000Z",
            },
        ),
        "linux.cron_persistence": _records(
            {
                "artifact_type": "autorun",
                "record_type": "cron_file",
                "path": "/etc/cron.d/synthetic-demo",
                "entry": "0 3 * * * synthetic-service /opt/synthetic/maint.sh",
                "recently_created": False,
            },
            {
                "artifact_type": "autorun",
                "record_type": "user_crontab",
                "user": USERS[1],
                "entry": "*/15 * * * * /home/synthetic-user/bin/synthetic-check.sh",
            },
        ),
        "linux.auth_event_summary": _records(
            {
                "record_type": "auth_event",
                "event_type": "accepted_publickey",
                "user": USERS[1],
                "source_address": IPV4_B,
                "time_utc": "2026-08-05T08:00:00.000Z",
            },
            {
                "record_type": "auth_event",
                "event_type": "failed_password",
                "user": "synthetic-unknown",
                "source_address": IPV4_C,
                "time_utc": "2026-08-05T09:15:00.000Z",
            },
            {
                "record_type": "auth_event_summary",
                "since_utc": "2026-08-04T18:00:00.000Z",
                "accepted_count": 1,
                "failed_count": 1,
            },
        ),
        "linux.ssh_key_metadata": _records(
            {
                "artifact_type": "ssh_key_metadata",
                "record_type": "authorized_keys_file",
                "username": USERS[1],
                "path": "/home/synthetic-user/.ssh/authorized_keys",
                "source": "user_home",
                "size_bytes": 128,
                "mode": "0o666",
                "mode_octal": 666,
                "modified_time_utc": "2026-08-05T10:00:00.000Z",
            },
            {
                "artifact_type": "ssh_key_metadata",
                "record_type": "authorized_key_entry",
                "username": USERS[1],
                "path": "/home/synthetic-user/.ssh/authorized_keys",
                "line_number": 1,
                "key_type": "ssh-ed25519",
                "comment": "synthetic-demo-key-no-material",
                "fingerprint_present": True,
                "key_material_length": 68,
            },
        ),
        "linux.recent_file_metadata": _records(
            {
                "record_type": "recent_file",
                "path": "/tmp/synthetic-example/agent",
                "name": "agent",
                "size_bytes": 8192,
                "modified_time_utc": "2026-08-05T17:55:00.000Z",
                "owner": USERS[1],
            },
            {
                "record_type": "collection_summary",
                "since_utc": "2026-08-04T18:00:00.000Z",
                "collected": 1,
            },
        ),
    }


def write_fixture(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_readme(path: Path) -> None:
    text = """\
# Synthetic Input Fixtures

All JSON files in this directory are **SYNTHETIC DEMONSTRATION DATA**.

They are generated by `scripts/generate-demo-data.py` and must never be mistaken
for real endpoint telemetry.

## Conventions

| Field | Value |
|-------|-------|
| Hostname | `SYNTHETIC-ENDPOINT-01` |
| Users | `synthetic-admin`, `synthetic-user`, `synthetic-service` |
| IPv4 | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737) |
| IPv6 | `2001:db8::/32` (RFC 3849) |
| MAC | Locally administered (e.g. `02:00:5e:00:53:01`) |

## File naming

`{collector_id}.json` — e.g. `windows.processes.json`

Each file is either a JSON array of records or an object with a `records` array.

Records include `artifact_type` where relevant for triage rule evaluation.

## Regeneration

```bash
python scripts/generate-demo-data.py
```

## Test fixtures

Copies are written to `tests/fixtures/` with one intentional difference:

- **`tests/fixtures/windows/`** omits `windows.defender_status.json` so tests can
  simulate an unavailable security-tool collector (missing fixture → UNAVAILABLE).

Linux partial-collector scenarios can be simulated in tests by omitting or
truncating individual fixture files under `tests/fixtures/linux/`.
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def generate_all() -> list[Path]:
    written: list[Path] = []
    targets = [
        (REPO_ROOT / "examples" / "synthetic-input", frozenset(), frozenset()),
        (
            REPO_ROOT / "tests" / "fixtures",
            TESTS_OMIT_WINDOWS,
            TESTS_OMIT_LINUX,
        ),
    ]

    for platform_name, fixture_map in (
        ("windows", windows_fixtures()),
        ("linux", linux_fixtures()),
    ):
        for base_dir, omit_windows, omit_linux in targets:
            omit = omit_windows if platform_name == "windows" else omit_linux
            for collector_id, payload in sorted(fixture_map.items()):
                if collector_id in omit:
                    continue
                out = base_dir / platform_name / f"{collector_id}.json"
                write_fixture(out, payload)
                written.append(out)

    readme = REPO_ROOT / "examples" / "synthetic-input" / "README.md"
    write_readme(readme)
    written.append(readme)
    return written


def main() -> int:
    paths = generate_all()
    print("SYNTHETIC DEMONSTRATION DATA")
    print(f"Generated {len(paths)} file(s):")
    for path in paths:
        print(path.relative_to(REPO_ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
