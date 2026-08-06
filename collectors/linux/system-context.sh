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
import platform
import socket
import subprocess
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


record = {
    "record_type": "system_context",
    "hostname": socket.gethostname(),
    "fqdn": socket.getfqdn(),
    "platform": platform.platform(),
    "system": platform.system(),
    "release": platform.release(),
    "version": platform.version(),
    "machine": platform.machine(),
    "processor": platform.processor(),
    "python_version": platform.python_version(),
    "collected_at_utc": utc_now(),
}

try:
    with open("/etc/os-release", encoding="utf-8") as handle:
        os_release = {}
        for line in handle:
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os_release[key] = value.strip('"')
        record["os_pretty_name"] = os_release.get("PRETTY_NAME")
        record["os_id"] = os_release.get("ID")
        record["os_version_id"] = os_release.get("VERSION_ID")
except OSError as exc:
    record["os_release_error"] = str(exc)

try:
    result = subprocess.run(
        ["uname", "-a"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode == 0:
        record["uname"] = result.stdout.strip()
except (OSError, subprocess.SubprocessError) as exc:
    record["uname_error"] = str(exc)

output = {
    "collector_id": "linux.system_context",
    "collected_at_utc": utc_now(),
    "record_count": 1,
    "records": [record],
}
print(json.dumps(output, indent=2))
PY
