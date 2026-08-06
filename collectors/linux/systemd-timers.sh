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

try:
    result = subprocess.run(
        ["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        records.append(
            {
                "record_type": "collection_error",
                "source": "systemctl list-timers",
                "error": result.stderr.strip() or "systemctl failed",
            }
        )
    else:
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 5)
            records.append(
                {
                    "record_type": "systemd_timer",
                    "next_run": parts[0] if parts else None,
                    "left": parts[1] if len(parts) > 1 else None,
                    "last_run": parts[2] if len(parts) > 2 else None,
                    "passed": parts[3] if len(parts) > 3 else None,
                    "unit": parts[4] if len(parts) > 4 else None,
                    "activates": parts[5] if len(parts) > 5 else None,
                    "raw_line": line,
                }
            )
except (OSError, subprocess.SubprocessError) as exc:
    records.append(
        {
            "record_type": "collection_error",
            "source": "systemctl list-timers",
            "error": str(exc),
        }
    )

output = {
    "collector_id": "linux.systemd_timers",
    "collected_at_utc": utc_now(),
    "record_count": len(records),
    "records": records,
}
print(json.dumps(output, indent=2))
PY
