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
import os
import subprocess
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


records = []

try:
    result = subprocess.run(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--all",
            "--no-pager",
            "--no-legend",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        records.append(
            {
                "record_type": "collection_error",
                "source": "systemctl list-units",
                "error": result.stderr.strip() or "systemctl failed",
            }
        )
    else:
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 4)
            unit = parts[0] if parts else line
            load_state = parts[1] if len(parts) > 1 else None
            active_state = parts[2] if len(parts) > 2 else None
            sub_state = parts[3] if len(parts) > 3 else None
            description = parts[4] if len(parts) > 4 else None

            exec_path = None
            exec_writable = None
            try:
                show = subprocess.run(
                    ["systemctl", "show", unit, "-p", "ExecStart", "--value"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if show.returncode == 0:
                    exec_path = show.stdout.strip()
                    if exec_path.startswith("{") and "path=" in exec_path:
                        for token in exec_path.replace("{", " ").replace("}", " ").split():
                            if token.startswith("path="):
                                exec_path = token.split("=", 1)[1]
                                break
                    if exec_path and os.path.isabs(exec_path):
                        exec_dir = os.path.dirname(exec_path)
                        exec_writable = os.access(exec_dir, os.W_OK)
            except (OSError, subprocess.SubprocessError):
                pass

            records.append(
                {
                    "record_type": "systemd_service",
                    "unit": unit,
                    "load_state": load_state,
                    "active_state": active_state,
                    "sub_state": sub_state,
                    "description": description,
                    "exec_start": exec_path,
                    "exec_dir_writable": exec_writable,
                }
            )
except (OSError, subprocess.SubprocessError) as exc:
    records.append(
        {
            "record_type": "collection_error",
            "source": "systemctl",
            "error": str(exc),
        }
    )

output = {
    "collector_id": "linux.systemd_services",
    "collected_at_utc": utc_now(),
    "record_count": len(records),
    "records": records,
}
print(json.dumps(output, indent=2))
PY
