#!/usr/bin/env bash
# Development-only fixture. No existing Vault instance is modified.
set -euo pipefail

cd "$(dirname "$0")/.."

vault_image="${VAULT_TEST_IMAGE:-hashicorp/vault:2.2.0}"
fixture_dir="$(mktemp -d)"
container_id=""
vault_pid=""

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM
  if [[ -n "$container_id" ]]; then
    docker rm -f "$container_id" >/dev/null 2>&1 || true
  fi
  if [[ -n "$vault_pid" ]]; then
    kill "$vault_pid" >/dev/null 2>&1 || true
    wait "$vault_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$fixture_dir"
  exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

command -v curl >/dev/null || { echo 'curl is required to check fixture readiness.' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'python3 is required to prepare the integration fixture.' >&2; exit 1; }

# Use a fresh, unauthenticated health endpoint; ignore operator credentials and
# TLS settings so this fixture never contacts a configured production server.
for variable in "${!VAULT_@}"; do
  unset "$variable"
done

# The root credential belongs only to this disposable fixture. It is never
# placed on a process command line, printed, or written outside its private
# temporary directory. Tests receive only the file location.
export VAULT_TEST_ROOT_TOKEN_FILE="$fixture_dir/root-token"
python3 - "$VAULT_TEST_ROOT_TOKEN_FILE" <<'PY'
from pathlib import Path
import os
import secrets
import sys

descriptor = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, 'w') as token_file:
    token_file.write(secrets.token_hex(32))
PY
fixture_root_token="$(cat "$VAULT_TEST_ROOT_TOKEN_FILE")"

if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  container_id="$(VAULT_DEV_ROOT_TOKEN_ID="$fixture_root_token" docker run --detach --rm \
    --env VAULT_DEV_ROOT_TOKEN_ID \
    --publish 127.0.0.1::8200 \
    "$vault_image" server -dev -dev-no-store-token \
    -dev-listen-address=0.0.0.0:8200)"
  vault_port="$(docker port "$container_id" 8200/tcp)"
  export VAULT_ADDR="http://${vault_port}"
  echo "Started ephemeral Vault container ($vault_image)."
elif command -v vault >/dev/null; then
  # Reserve a free loopback port. The listener is opened by Vault immediately
  # afterwards; a competing bind is reported as a fixture startup failure.
  vault_port="$(python3 - <<'PY'
import socket
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    print(listener.getsockname()[1])
PY
)"
  export VAULT_ADDR="http://127.0.0.1:${vault_port}"
  VAULT_DEV_ROOT_TOKEN_ID="$fixture_root_token" vault server -dev -dev-no-store-token \
    -dev-listen-address="127.0.0.1:${vault_port}" \
    >"$fixture_dir/vault.log" 2>&1 &
  vault_pid=$!
  echo 'Started ephemeral local Vault process.'
else
  echo 'Integration requires an accessible Docker daemon or an installed Vault binary.' >&2
  exit 1
fi

ready=false
for attempt in {1..60}; do
  if [[ -n "$vault_pid" ]] && ! kill -0 "$vault_pid" 2>/dev/null; then
    echo 'The Vault fixture exited during startup. Logs are withheld because dev mode logs credentials.' >&2
    exit 1
  fi
  if curl --noproxy '*' --fail --silent --output /dev/null \
    --connect-timeout 1 --max-time 1 "${VAULT_ADDR}/v1/sys/health"; then
    ready=true
    break
  fi
  sleep 0.5
done
if [[ "$ready" != true ]]; then
  echo 'The Vault fixture did not become ready within 60 attempts.' >&2
  exit 1
fi

# Route this loopback fixture directly without changing outbound proxy settings.
export NO_PROXY="${NO_PROXY:+${NO_PROXY},}127.0.0.1,localhost"
export no_proxy="${no_proxy:+${no_proxy},}127.0.0.1,localhost"
make integration
make build
./bin/secretwright status

# Exercise the compiled binary, including file-over-environment precedence.
# Capture authentication output so a regression cannot publish a credential in
# CI logs; inspect it locally and report only fixed diagnostic messages.
VAULT_TOKEN=f01-deliberately-invalid-inherited-token \
  ./bin/secretwright auth check --token-file "$VAULT_TEST_ROOT_TOKEN_FILE" \
  >"$fixture_dir/auth-valid.json" 2>"$fixture_dir/auth-valid.err"

expect_authentication_failure() {
  local fixture_name="$1"
  shift
  local result=0
  "$@" >"$fixture_dir/$fixture_name.json" 2>"$fixture_dir/$fixture_name.err" || result=$?
  if [[ "$result" -ne 2 ]]; then
    echo 'Authentication failure smoke returned an unexpected exit code.' >&2
    exit 1
  fi
}

expect_authentication_failure auth-missing ./bin/secretwright auth check
expect_authentication_failure auth-invalid env VAULT_TOKEN=f01-deliberately-invalid-token \
  ./bin/secretwright auth check

python3 - "$fixture_dir" <<'PY'
from pathlib import Path
import json
import sys

fixture = Path(sys.argv[1])
root_token = (fixture / 'root-token').read_text()
for case in ['auth-valid', 'auth-missing', 'auth-invalid']:
    output = (fixture / (case + '.json')).read_text()
    error = (fixture / (case + '.err')).read_text()
    if root_token in output + error or 'f01-deliberately-invalid' in output + error:
        raise SystemExit('Authentication smoke exposed a credential.')
    if case == 'auth-valid':
        try:
            report = json.loads(output)
        except (ValueError, TypeError):
            raise SystemExit('Authentication smoke did not produce valid JSON.') from None
        if report.get('authenticated') is not True or error:
            raise SystemExit('Authentication smoke did not confirm the fixture token.')
    elif output or not error:
        raise SystemExit('Authentication failure smoke produced unexpected output.')
print('CLI authentication smoke passed: valid file, missing token, invalid token.')
PY
