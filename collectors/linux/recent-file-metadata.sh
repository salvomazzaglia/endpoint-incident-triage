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

export EIT_SINCE_HOURS="${SINCE_HOURS}"
export EIT_MAX_FILES="${MAX_FILES}"
export EIT_MAX_DEPTH="${MAX_DEPTH}"

python3 - <<'PY'
import json
import os
from datetime import datetime, timedelta, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


since_hours = int(os.environ.get("EIT_SINCE_HOURS", "24"))
max_files = int(os.environ.get("EIT_MAX_FILES", "50"))
max_depth = int(os.environ.get("EIT_MAX_DEPTH", "2"))
since = datetime.now(timezone.utc) - timedelta(hours=since_hours)

search_roots = []
for candidate in (
    os.environ.get("TMPDIR"),
    "/tmp",
    "/var/tmp",
    os.path.expanduser("~"),
):
    if candidate and os.path.isdir(candidate):
        search_roots.append(candidate)
search_roots = list(dict.fromkeys(search_roots))

records = []
collected = 0

for root in search_roots:
    if collected >= max_files:
        break
    for dirpath, dirnames, filenames in os.walk(root):
        depth = dirpath[len(root) :].count(os.sep)
        if depth > max_depth:
            dirnames[:] = []
            continue
        for name in filenames:
            if collected >= max_files:
                break
            path = os.path.join(dirpath, name)
            try:
                stat = os.stat(path)
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                if mtime < since:
                    continue
                records.append(
                    {
                        "record_type": "recent_file",
                        "path": path,
                        "name": name,
                        "size_bytes": stat.st_size,
                        "modified_time_utc": mtime.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
                        + "Z",
                        "search_root": root,
                    }
                )
                collected += 1
            except OSError as exc:
                records.append(
                    {
                        "record_type": "parse_error",
                        "path": path,
                        "error": str(exc),
                    }
                )

records.sort(key=lambda item: item.get("modified_time_utc", ""), reverse=True)
records = records[:max_files]

records.append(
    {
        "record_type": "collection_summary",
        "since_utc": since.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "max_files": max_files,
        "max_depth": max_depth,
        "collected": min(collected, max_files),
    }
)

output = {
    "collector_id": "linux.recent_file_metadata",
    "collected_at_utc": utc_now(),
    "record_count": len(records),
    "records": records,
}
print(json.dumps(output, indent=2))
PY
