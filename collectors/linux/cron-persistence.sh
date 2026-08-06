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


def add_file_record(path, source):
    try:
        stat = os.stat(path)
        records.append(
            {
                "record_type": "cron_file",
                "source": source,
                "path": path,
                "size_bytes": stat.st_size,
                "modified_time_utc": datetime.fromtimestamp(
                    stat.st_mtime, tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
                + "Z",
            }
        )
    except OSError as exc:
        records.append(
            {
                "record_type": "collection_error",
                "source": source,
                "path": path,
                "error": str(exc),
            }
        )


for cron_dir in ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"):
    if not os.path.isdir(cron_dir):
        continue
    for name in sorted(os.listdir(cron_dir)):
        add_file_record(os.path.join(cron_dir, name), "cron_directory")

if os.path.isfile("/etc/crontab"):
    add_file_record("/etc/crontab", "system_crontab")

try:
    result = subprocess.run(
        ["crontab", "-l"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode == 0:
        for idx, line in enumerate(result.stdout.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            records.append(
                {
                    "record_type": "user_crontab_entry",
                    "line_number": idx,
                    "entry": line,
                }
            )
    elif result.returncode != 1:
        records.append(
            {
                "record_type": "collection_error",
                "source": "crontab -l",
                "error": result.stderr.strip() or "crontab failed",
            }
        )
except (OSError, subprocess.SubprocessError) as exc:
    records.append(
        {
            "record_type": "collection_error",
            "source": "crontab -l",
            "error": str(exc),
        }
    )

output = {
    "collector_id": "linux.cron_persistence",
    "collected_at_utc": utc_now(),
    "record_count": len(records),
    "records": records,
}
print(json.dumps(output, indent=2))
PY
