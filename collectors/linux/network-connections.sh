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

# Uniform CLI surface retained for orchestrator compatibility.
: "${FIXTURE_PATH}" "${INCLUDE_COMMAND_LINES}" "${INCLUDE_EVENT_MESSAGES}" "${SINCE_HOURS}" "${MAX_EVENTS}" "${MAX_FILES}" "${MAX_DEPTH}"

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


records = []


def collect_with(command, record_type):
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            records.append(
                {
                    "record_type": "collection_error",
                    "source": " ".join(command),
                    "error": result.stderr.strip() or "command failed",
                }
            )
            return
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            entry = {
                "record_type": record_type,
                "raw_line": line,
            }
            parts = line.split()
            if record_type == "socket" and len(parts) >= 5:
                entry["state"] = parts[0]
                entry["local_address"] = parts[3]
                entry["peer_address"] = parts[4]
                if entry["local_address"].endswith(":0") or entry["local_address"] == "*:*":
                    entry["listen_all"] = True
                if entry["local_address"].startswith("0.0.0.0:") or entry["local_address"].startswith("[::]:"):
                    entry["listen_all_interfaces"] = True
            records.append(entry)
    except (OSError, subprocess.SubprocessError) as exc:
        records.append(
            {
                "record_type": "collection_error",
                "source": " ".join(command),
                "error": str(exc),
            }
        )


collect_with(["ss", "-tunap"], "socket")
if not any(r.get("record_type") == "socket" for r in records):
    collect_with(["netstat", "-tunap"], "socket")

output = {
    "collector_id": "linux.network_connections",
    "collected_at_utc": utc_now(),
    "record_count": len(records),
    "records": records,
}
print(json.dumps(output, indent=2))
PY
