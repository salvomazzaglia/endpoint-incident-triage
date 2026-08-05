#!/usr/bin/env bats

# Linux collector structured output protocol tests (fixture mode only).

setup() {
  REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  COLLECTORS="${REPO_ROOT}/collectors/linux"
  FIXTURES="${REPO_ROOT}/tests/fixtures/linux"
}

@test "processes fixture records include pid and comm fields" {
  run bash "${COLLECTORS}/processes.sh" --fixture "${FIXTURES}/linux.processes.json"
  echo "${output}" | python3 -c "
import json, sys
rec = json.load(sys.stdin)['records'][0]
assert 'pid' in rec and 'comm' in rec
"
}

@test "network fixture uses documentation IP ranges only" {
  run bash "${COLLECTORS}/network-connections.sh" --fixture "${FIXTURES}/linux.network_connections.json"
  [[ "${output}" == *"192.0.2."* || "${output}" == *"198.51.100."* || "${output}" == *"203.0.113."* ]]
}

@test "users-sessions fixture includes synthetic usernames" {
  run bash "${COLLECTORS}/users-sessions.sh" --fixture "${FIXTURES}/linux.users_sessions.json"
  [[ "${output}" == *"synthetic-admin"* ]]
}

@test "systemd-timers fixture JSON parses cleanly" {
  run bash "${COLLECTORS}/systemd-timers.sh" --fixture "${FIXTURES}/linux.systemd_timers.json"
  echo "${output}" | python3 -m json.tool >/dev/null
}

@test "time-context fixture retains UTC timestamp fields" {
  run bash "${COLLECTORS}/time-context.sh" --fixture "${FIXTURES}/linux.time_context.json"
  [[ "${output}" == *"utc"* ]]
}

@test "processes.sh uses python helper for structured JSON emission" {
  grep -q "python3 - <<'PY'" "${COLLECTORS}/processes.sh"
}

@test "processes.sh uses subprocess with argument list not shell=True equivalent" {
  ! grep -q 'shell=True' "${COLLECTORS}/processes.sh"
  grep -q 'subprocess.run' "${COLLECTORS}/processes.sh"
}

@test "system-context.sh emits JSON via python block" {
  grep -q "python3 - <<'PY'" "${COLLECTORS}/system-context.sh"
}

@test "fixture mode exits zero before live commands" {
  run bash "${COLLECTORS}/processes.sh" --fixture "${FIXTURES}/linux.processes.json"
  [ "${status}" -eq 0 ]
  [ -n "${output}" ]
}

@test "linux.processes.json fixture includes temp path review example" {
  grep -q '/tmp/synthetic-example' "${FIXTURES}/linux.processes.json"
}

@test "linux.ssh_key_metadata.json reports metadata without key content" {
  ! grep -q 'ssh-rsa AAAA' "${FIXTURES}/linux.ssh_key_metadata.json"
  grep -q 'authorized_keys' "${FIXTURES}/linux.ssh_key_metadata.json"
}

@test "all linux fixtures are valid JSON objects" {
  for fixture in "${FIXTURES}"/*.json; do
    python3 -m json.tool "${fixture}" >/dev/null
  done
}

@test "all linux fixtures include a records array" {
  for fixture in "${FIXTURES}"/*.json; do
    python3 -c "import json; d=json.load(open('${fixture}')); assert isinstance(d.get('records'), list), '${fixture}'"
  done
}
