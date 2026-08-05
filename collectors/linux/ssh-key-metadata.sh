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
import os
import pwd
import stat
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


records = []


def mode_to_octal(mode):
    return oct(stat.S_IMODE(mode))


def inspect_authorized_keys(path, username, source):
    try:
        file_stat = os.stat(path)
        records.append(
            {
                "record_type": "authorized_keys_file",
                "username": username,
                "path": path,
                "source": source,
                "size_bytes": file_stat.st_size,
                "mode": mode_to_octal(file_stat.st_mode),
                "modified_time_utc": datetime.fromtimestamp(
                    file_stat.st_mtime, tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
                + "Z",
            }
        )
        with open(path, encoding="utf-8", errors="replace") as handle:
            for idx, line in enumerate(handle, start=1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                entry = {
                    "record_type": "authorized_key_entry",
                    "username": username,
                    "path": path,
                    "line_number": idx,
                    "key_type": parts[0] if parts else None,
                    "comment": parts[2] if len(parts) > 2 else None,
                    "fingerprint_present": len(parts) >= 2,
                }
                if len(parts) >= 2:
                    entry["key_material_length"] = len(parts[1])
                records.append(entry)
    except OSError as exc:
        records.append(
            {
                "record_type": "collection_error",
                "source": source,
                "path": path,
                "error": str(exc),
            }
        )


for user in pwd.getpwall():
    home = user.pw_dir
    if not home or not os.path.isdir(home):
        continue
    auth_keys = os.path.join(home, ".ssh", "authorized_keys")
    if os.path.isfile(auth_keys):
        inspect_authorized_keys(auth_keys, user.pw_name, "user_home")

global_auth = "/etc/ssh/sshd_config"
if os.path.isfile(global_auth):
    records.append(
        {
            "record_type": "sshd_config_present",
            "path": global_auth,
            "size_bytes": os.path.getsize(global_auth),
        }
    )

output = {
    "collector_id": "linux.ssh_key_metadata",
    "collected_at_utc": utc_now(),
    "record_count": len(records),
    "records": records,
}
print(json.dumps(output, indent=2))
PY
