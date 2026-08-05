#!/usr/bin/env bats

# Linux collector fixture-mode and inventory tests (no live host inspection).

setup() {
  REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  COLLECTORS="${REPO_ROOT}/collectors/linux"
  FIXTURES="${REPO_ROOT}/tests/fixtures/linux"
  export EIT_FIXTURE_FILE=""
}

teardown() {
  unset EIT_FIXTURE_FILE
}

@test "linux collectors directory contains eleven scripts" {
  count="$(find "${COLLECTORS}" -maxdepth 1 -name '*.sh' | wc -l | tr -d ' ')"
  [ "${count}" -eq 11 ]
}

@test "every linux collector has a matching synthetic fixture" {
  for script in "${COLLECTORS}"/*.sh; do
    base="$(basename "${script}" .sh)"
    fixture_id="linux.${base//-/_}"
    fixture="${FIXTURES}/${fixture_id}.json"
    [ -f "${fixture}" ]
  done
}

@test "processes.sh returns fixture JSON with --fixture" {
  run bash "${COLLECTORS}/processes.sh" --fixture "${FIXTURES}/linux.processes.json"
  [ "${status}" -eq 0 ]
  echo "${output}" | python3 -c "import json,sys; d=json.load(sys.stdin); assert 'records' in d"
}

@test "system-context.sh honors EIT_FIXTURE_FILE environment variable" {
  export EIT_FIXTURE_FILE="${FIXTURES}/linux.system_context.json"
  run bash "${COLLECTORS}/system-context.sh"
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"SYNTHETIC-ENDPOINT-01"* ]]
}

@test "network-connections.sh fixture output is valid JSON" {
  run bash "${COLLECTORS}/network-connections.sh" --fixture "${FIXTURES}/linux.network_connections.json"
  [ "${status}" -eq 0 ]
  echo "${output}" | python3 -m json.tool >/dev/null
}

@test "systemd-services.sh fixture passthrough preserves bytes" {
  expected="$(cat "${FIXTURES}/linux.systemd_services.json")"
  run bash "${COLLECTORS}/systemd-services.sh" --fixture "${FIXTURES}/linux.systemd_services.json"
  [ "${output}" = "${expected}" ]
}

@test "cron-persistence.sh fixture includes records" {
  run bash "${COLLECTORS}/cron-persistence.sh" --fixture "${FIXTURES}/linux.cron_persistence.json"
  echo "${output}" | python3 -c "import json,sys; assert len(json.load(sys.stdin)['records'])>0"
}

@test "ssh-key-metadata.sh fixture never includes private key markers" {
  run bash "${COLLECTORS}/ssh-key-metadata.sh" --fixture "${FIXTURES}/linux.ssh_key_metadata.json"
  [[ "${output}" != *"BEGIN OPENSSH PRIVATE KEY"* ]]
  [[ "${output}" != *"BEGIN RSA PRIVATE KEY"* ]]
}

@test "auth-event-summary.sh fixture respects bounded records" {
  run bash "${COLLECTORS}/auth-event-summary.sh" --fixture "${FIXTURES}/linux.auth_event_summary.json"
  count="$(echo "${output}" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['records']))")"
  [ "${count}" -le 200 ]
}

@test "recent-file-metadata.sh accepts bounded CLI limits" {
  run bash "${COLLECTORS}/recent-file-metadata.sh" \
    --fixture "${FIXTURES}/linux.recent_file_metadata.json" \
    --max-files 10 --max-depth 1
  [ "${status}" -eq 0 ]
}

@test "unknown argument returns exit code 2" {
  run bash "${COLLECTORS}/processes.sh" --not-a-real-flag
  [ "${status}" -eq 2 ]
}
