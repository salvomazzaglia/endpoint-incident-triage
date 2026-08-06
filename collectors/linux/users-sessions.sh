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


def run_command(args):
    try:
        result = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result.returncode, result.stdout, result.stderr
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", str(exc)


code, stdout, stderr = run_command(["who"])
if code == 0 and stdout.strip():
    for line in stdout.splitlines():
        records.append(
            {
                "record_type": "who_session",
                "raw_line": line.strip(),
            }
        )
else:
    records.append(
        {
            "record_type": "collection_error",
            "source": "who",
            "error": stderr.strip() or "who unavailable",
        }
    )

code, stdout, stderr = run_command(["w", "-h"])
if code == 0 and stdout.strip():
    for line in stdout.splitlines():
        parts = line.split()
        records.append(
            {
                "record_type": "w_session",
                "user": parts[0] if parts else None,
                "raw_line": line.strip(),
            }
        )
elif code != 0:
    records.append(
        {
            "record_type": "collection_error",
            "source": "w",
            "error": stderr.strip() or "w unavailable",
        }
    )

code, stdout, stderr = run_command(["last", "-n", "20"])
if code == 0 and stdout.strip():
    for line in stdout.splitlines():
        if line.startswith("wtmp") or line.startswith("reboot"):
            continue
        records.append(
            {
                "record_type": "last_login",
                "raw_line": line.strip(),
            }
        )
elif code != 0:
    records.append(
        {
            "record_type": "collection_error",
            "source": "last",
            "error": stderr.strip() or "last unavailable",
        }
    )

output = {
    "collector_id": "linux.users_sessions",
    "collected_at_utc": utc_now(),
    "record_count": len(records),
    "records": records,
}
print(json.dumps(output, indent=2))
PY
