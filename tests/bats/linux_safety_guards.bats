#!/usr/bin/env bats

# Static safety analysis for Linux bash collectors (no live execution).

setup() {
  REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  COLLECTORS="${REPO_ROOT}/collectors/linux"
}

_collectors() {
  find "${COLLECTORS}" -maxdepth 1 -name '*.sh' | sort
}

@test "all collectors use bash shebang" {
  for script in $(_collectors); do
    head -n1 "${script}" | grep -q '#!/usr/bin/env bash'
  done
}

@test "all collectors enable errexit nounset and pipefail" {
  for script in $(_collectors); do
    grep -q 'set -Eeuo pipefail' "${script}"
  done
}

@test "all collectors set restrictive umask 077" {
  for script in $(_collectors); do
    grep -q 'umask 077' "${script}"
  done
}

@test "no collector uses eval" {
  for script in $(_collectors); do
    ! grep -E '\beval\b' "${script}" >/dev/null
  done
}

@test "no collector invokes sudo" {
  for script in $(_collectors); do
    ! grep -E '\bsudo\b' "${script}" >/dev/null
  done
}

@test "no collector performs network probes" {
  for script in $(_collectors); do
    ! grep -E '\b(curl|wget|ping|nc |ncat|telnet)\b' "${script}" >/dev/null
  done
}

@test "no collector clears journals or logs" {
  for script in $(_collectors); do
    ! grep -E 'journalctl\s+--vacuum|> /var/log/' "${script}" >/dev/null
  done
}

@test "no collector kills processes" {
  for script in $(_collectors); do
    ! grep -E '\b(kill|killall|pkill)\b' "${script}" >/dev/null
  done
}

@test "no collector reads /etc/shadow" {
  for script in $(_collectors); do
    ! grep -F '/etc/shadow' "${script}" >/dev/null
  done
}

@test "no collector dumps shell history" {
  for script in $(_collectors); do
    ! grep -E '\.bash_history|\.zsh_history' "${script}" >/dev/null
  done
}

@test "no collector uses find / recursion" {
  for script in $(_collectors); do
    ! grep -E "find\s+/" "${script}" >/dev/null
  done
}

@test "no collector sources arbitrary config as shell code" {
  for script in $(_collectors); do
    ! grep -E '^\s*source\s+' "${script}" >/dev/null
  done
}

@test "ssh-key-metadata never reads private key paths" {
  script="${COLLECTORS}/ssh-key-metadata.sh"
  ! grep -E 'id_rsa|id_ed25519|id_ecdsa|\.pem' "${script}" | grep -v authorized_keys >/dev/null || true
  ! grep -F 'id_rsa' "${script}" >/dev/null
}

@test "each collector supports fixture early exit" {
  for script in $(_collectors); do
    grep -q 'FIXTURE_PATH\|EIT_FIXTURE_FILE' "${script}"
    grep -q 'cat "${FIXTURE_PATH}"\|cat .*FIXTURE' "${script}"
  done
}

@test "processes.sh documents include-command-lines opt-in" {
  grep -q 'include-command-lines' "${COLLECTORS}/processes.sh"
}

@test "auth-event-summary supports include-event-messages flag" {
  grep -q 'include-event-messages' "${COLLECTORS}/auth-event-summary.sh"
}
