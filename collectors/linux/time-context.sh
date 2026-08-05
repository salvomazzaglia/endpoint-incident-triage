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

python3 - <<'PY'
import json
import subprocess
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


record = {
    "record_type": "time_context",
    "current_time_utc": utc_now(),
    "collected_at_utc": utc_now(),
}

try:
    result = subprocess.run(
        ["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode == 0:
        record["date_utc"] = result.stdout.strip()
except (OSError, subprocess.SubprocessError) as exc:
    record["date_error"] = str(exc)

try:
    result = subprocess.run(
        ["uptime", "-s"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode == 0:
        record["boot_time_local"] = result.stdout.strip()
except (OSError, subprocess.SubprocessError) as exc:
    record["uptime_error"] = str(exc)

try:
    result = subprocess.run(
        ["timedatectl", "show", "-p", "Timezone", "-p", "NTPSynchronized", "--value"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode == 0:
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if lines:
            record["timezone"] = lines[0]
        if len(lines) > 1:
            record["ntp_synchronized"] = lines[1]
except (OSError, subprocess.SubprocessError) as exc:
    record["timedatectl_error"] = str(exc)

output = {
    "collector_id": "linux.time_context",
    "collected_at_utc": utc_now(),
    "record_count": 1,
    "records": [record],
}
print(json.dumps(output, indent=2))
PY
