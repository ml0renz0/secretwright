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

# Use a fresh, unauthenticated health endpoint; ignore operator credentials and
# TLS settings so this fixture never contacts a configured production server.
for variable in "${!VAULT_@}"; do
  unset "$variable"
done

if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  container_id="$(docker run --detach --rm \
    --publish 127.0.0.1::8200 \
    "$vault_image" server -dev -dev-no-store-token \
    -dev-listen-address=0.0.0.0:8200)"
  vault_port="$(docker port "$container_id" 8200/tcp)"
  export VAULT_ADDR="http://${vault_port}"
  echo "Started ephemeral Vault container ($vault_image)."
elif command -v vault >/dev/null; then
  # Reserve a free loopback port. The listener is opened by Vault immediately
  # afterwards; a competing bind is reported as a fixture startup failure.
  command -v python3 >/dev/null || { echo 'python3 is required for the local Vault binary fixture.' >&2; exit 1; }
  vault_port="$(python3 - <<'PY'
import socket
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    print(listener.getsockname()[1])
PY
)"
  export VAULT_ADDR="http://127.0.0.1:${vault_port}"
  vault server -dev -dev-no-store-token \
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
