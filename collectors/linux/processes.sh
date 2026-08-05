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

export EIT_INCLUDE_COMMAND_LINES="${INCLUDE_COMMAND_LINES}"

python3 - <<'PY'
import json
import os
import subprocess
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


include_cmd = os.environ.get("EIT_INCLUDE_COMMAND_LINES", "0") == "1"
records = []

try:
    args = ["ps", "-eo", "pid,ppid,user,stat,lstart,comm,args"] if include_cmd else [
        "ps",
        "-eo",
        "pid,ppid,user,stat,lstart,comm",
    ]
    result = subprocess.run(
        args,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        records.append(
            {
                "record_type": "collection_error",
                "source": "ps",
                "error": result.stderr.strip() or "ps failed",
            }
        )
    else:
        lines = result.stdout.splitlines()
        header = lines[0] if lines else ""
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 6 if include_cmd else 5)
            entry = {
                "record_type": "process",
                "raw_line": line,
            }
            if len(parts) >= 1:
                entry["pid"] = parts[0]
            if len(parts) >= 2:
                entry["ppid"] = parts[1]
            if len(parts) >= 3:
                entry["user"] = parts[2]
            if len(parts) >= 4:
                entry["stat"] = parts[3]
            if include_cmd and len(parts) >= 7:
                entry["command_line"] = parts[6]
            records.append(entry)
except (OSError, subprocess.SubprocessError) as exc:
    records.append(
        {
            "record_type": "collection_error",
            "source": "ps",
            "error": str(exc),
        }
    )

output = {
    "collector_id": "linux.processes",
    "collected_at_utc": utc_now(),
    "record_count": len(records),
    "records": records,
}
print(json.dumps(output, indent=2))
PY
