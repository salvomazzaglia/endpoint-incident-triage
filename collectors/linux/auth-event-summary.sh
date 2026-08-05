#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

FIXTURE_PATH="${EIT_FIXTURE_FILE:-}"
INCLUDE_COMMAND_LINES=0
INCLUDE_EVENT_MESSAGES=0
SINCE_HOURS=24
MAX_EVENTS=200
MAX_FILES=50
MAX_DEPTH=2

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fixture)
      FIXTURE_PATH="${2:-}"
      shift 2
      ;;
    --include-command-lines)
      INCLUDE_COMMAND_LINES=1
      shift
      ;;
    --include-event-messages)
      INCLUDE_EVENT_MESSAGES=1
      shift
      ;;
    --since-hours)
      SINCE_HOURS="${2:-24}"
      shift 2
      ;;
    --max-events)
      MAX_EVENTS="${2:-200}"
      shift 2
      ;;
    --max-files)
      MAX_FILES="${2:-50}"
      shift 2
      ;;
    --max-depth)
      MAX_DEPTH="${2:-2}"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -n "${FIXTURE_PATH}" && -f "${FIXTURE_PATH}" ]]; then
  cat "${FIXTURE_PATH}"
  exit 0
fi

export EIT_SINCE_HOURS="${SINCE_HOURS}"
export EIT_MAX_EVENTS="${MAX_EVENTS}"
export EIT_INCLUDE_EVENT_MESSAGES="${INCLUDE_EVENT_MESSAGES}"

python3 - <<'PY'
import json
import os
import subprocess
from datetime import datetime, timedelta, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


since_hours = int(os.environ.get("EIT_SINCE_HOURS", "24"))
max_events = int(os.environ.get("EIT_MAX_EVENTS", "200"))
include_messages = os.environ.get("EIT_INCLUDE_EVENT_MESSAGES", "0") == "1"
since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
records = []
collected = 0


def append_event(source, line):
    global collected
    if collected >= max_events:
        return
    entry = {
        "record_type": "auth_event",
        "source": source,
        "raw_line": line.strip(),
    }
    lower = line.lower()
    if "failed password" in lower or "authentication failure" in lower:
        entry["event_kind"] = "auth_failure"
    elif "accepted publickey" in lower or "accepted password" in lower:
        entry["event_kind"] = "auth_success"
    elif "invalid user" in lower:
        entry["event_kind"] = "invalid_user"
    records.append(entry)
    collected += 1


try:
    result = subprocess.run(
        [
            "journalctl",
            "_SYSTEMD_UNIT=ssh.service",
            "--since",
            since.isoformat(),
            "--no-pager",
            "-n",
            str(max_events),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.splitlines():
            append_event("journalctl_ssh", line)
    else:
        auth_paths = [
            "/var/log/auth.log",
            "/var/log/secure",
        ]
        for path in auth_paths:
            if not os.path.isfile(path):
                continue
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        if collected >= max_events:
                            break
                        append_event(path, line)
            except OSError as exc:
                records.append(
                    {
                        "record_type": "collection_error",
                        "source": path,
                        "error": str(exc),
                    }
                )
            break
except (OSError, subprocess.SubprocessError) as exc:
    records.append(
        {
            "record_type": "collection_error",
            "source": "auth_events",
            "error": str(exc),
        }
    )

records.append(
    {
        "record_type": "auth_event_summary",
        "since_utc": since.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "max_events": max_events,
        "collected": collected,
        "include_messages": include_messages,
    }
)

output = {
    "collector_id": "linux.auth_event_summary",
    "collected_at_utc": utc_now(),
    "record_count": len(records),
    "records": records,
}
print(json.dumps(output, indent=2))
PY
