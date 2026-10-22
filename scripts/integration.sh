#!/usr/bin/env bash
# Development-only fixture. No existing Vault instance is modified.
set -euo pipefail
umask 077

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

# Provision a second, independent KV fixture for the compiled binary. Its token
# can read/list only its own allowed subtree and cannot perform lookup-self.
# Expected secret values and captured cat output remain in the private fixture.
python3 - "$fixture_dir" <<'PY'
from pathlib import Path
import json
import os
import secrets
import sys
import urllib.error
import urllib.request

fixture = Path(sys.argv[1])
address = os.environ['VAULT_ADDR']
root_token = (fixture / 'root-token').read_text().strip()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def request(path, payload=None, method='POST'):
    body = None if payload is None else json.dumps(payload).encode()
    message = urllib.request.Request(address + '/v1/' + path, data=body, method=method)
    message.add_header('X-Vault-Token', root_token)
    message.add_header('Content-Type', 'application/json')
    with opener.open(message, timeout=5) as response:
        content = response.read()
        return json.loads(content) if content else None

def private_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as target:
        json.dump(value, target)

mounts = [('f02-smoke-v1', 1), ('f02-smoke-v2', 2), ('f02-smoke-parent/kv', 2)]
expected = {}
policy = []
try:
    for mount, version in mounts:
        request('sys/mounts/' + mount, {'type': 'kv', 'options': {'version': str(version)}})
        for key in ['allowed/item', 'allowed/data/item', 'denied/item']:
            values = {'value': 'private-kv-smoke-' + secrets.token_hex(16), 'data': {'nested': 'private-nested-' + secrets.token_hex(16)}}
            expected[mount + '/' + key] = values
            path = mount + '/' + ('data/' if version == 2 else '') + key
            request(path, {'data': values} if version == 2 else values)
        read_path = mount + '/' + ('data/' if version == 2 else '') + 'allowed/*'
        list_path = mount + '/' + ('metadata/' if version == 2 else '') + 'allowed'
        policy.extend([
            'path ' + json.dumps(read_path) + ' { capabilities = ["read"] }',
            'path ' + json.dumps(list_path) + ' { capabilities = ["list"] }',
            'path ' + json.dumps(list_path + '/*') + ' { capabilities = ["list"] }',
        ])
    request('f02-smoke-v2/data/allowed/deleted', {'data': {'value': 'private-deleted-' + secrets.token_hex(16)}})
    request('f02-smoke-v2/data/allowed/deleted', method='DELETE')
    request('sys/policies/acl/f02-smoke-read-list', {'policy': '\n'.join(policy)})
    response = request('auth/token/create', {'policies': ['f02-smoke-read-list'], 'no_default_policy': True, 'ttl': '2m', 'display_name': 'secretwright-f02-smoke'})
    token = response['auth']['client_token']
    descriptor = os.open(fixture / 'kv-token', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as target:
        target.write(token)
    private_json(fixture / 'kv-expected.json', expected)
except (OSError, ValueError, TypeError, KeyError, urllib.error.URLError):
    raise SystemExit('Could not prepare the disposable KV smoke fixture.') from None
PY

VAULT_TOKEN=f02-deliberately-invalid-inherited-token \
  ./bin/secretwright cat --token-file "$fixture_dir/kv-token" \
  --mount f02-smoke-v1 --kv-version 1 /f02-smoke-v1/allowed/item \
  >"$fixture_dir/kv-v1.json" 2>"$fixture_dir/kv-v1.err"
VAULT_TOKEN=f02-deliberately-invalid-inherited-token \
  ./bin/secretwright cat --token-file "$fixture_dir/kv-token" \
  --cwd /f02-smoke-v2/allowed item \
  >"$fixture_dir/kv-v2.json" 2>"$fixture_dir/kv-v2.err"
VAULT_TOKEN=f02-deliberately-invalid-inherited-token \
  ./bin/secretwright cat --token-file "$fixture_dir/kv-token" \
  --cwd /f02-smoke-v2/allowed data/item \
  >"$fixture_dir/kv-v2-data.json" 2>"$fixture_dir/kv-v2-data.err"
./bin/secretwright ls --token-file "$fixture_dir/kv-token" /f02-smoke-v1/allowed \
  >"$fixture_dir/kv-ls.json" 2>"$fixture_dir/kv-ls.err"
./bin/secretwright cd --token-file "$VAULT_TEST_ROOT_TOKEN_FILE" /f02-smoke-parent \
  >"$fixture_dir/kv-cd.json" 2>"$fixture_dir/kv-cd.err"
./bin/secretwright mounts --token-file "$VAULT_TEST_ROOT_TOKEN_FILE" \
  >"$fixture_dir/kv-mounts.json" 2>"$fixture_dir/kv-mounts.err"

expect_kv_failure() {
  local expected_status="$1"
  local fixture_name="$2"
  shift 2
  local result=0
  "$@" >"$fixture_dir/$fixture_name.json" 2>"$fixture_dir/$fixture_name.err" || result=$?
  if [[ "$result" -ne "$expected_status" ]]; then
    echo 'KV failure smoke returned an unexpected exit code.' >&2
    exit 1
  fi
}

expect_kv_failure 2 kv-denied ./bin/secretwright cat \
  --token-file "$fixture_dir/kv-token" /f02-smoke-v2/denied/item
expect_kv_failure 3 kv-missing ./bin/secretwright cat \
  --token-file "$fixture_dir/kv-token" /f02-smoke-v1/allowed/missing
expect_kv_failure 3 kv-deleted ./bin/secretwright cat \
  --token-file "$fixture_dir/kv-token" /f02-smoke-v2/allowed/deleted

python3 - "$fixture_dir" <<'PY'
from pathlib import Path
import json
import sys

fixture = Path(sys.argv[1])
expected = json.loads((fixture / 'kv-expected.json').read_text())
credentials = [(fixture / 'root-token').read_text().strip(), (fixture / 'kv-token').read_text().strip()]
outputs = {}
for case in ['kv-v1', 'kv-v2', 'kv-v2-data', 'kv-ls', 'kv-cd', 'kv-mounts', 'kv-denied', 'kv-missing', 'kv-deleted']:
    output = (fixture / (case + '.json')).read_text()
    error = (fixture / (case + '.err')).read_text()
    if any(token in output + error for token in credentials) or 'f02-deliberately-invalid' in output + error:
        raise SystemExit('KV smoke exposed a credential.')
    if case in ['kv-denied', 'kv-missing', 'kv-deleted']:
        if output or not error or 'private-kv-smoke-' in error or 'private-nested-' in error:
            raise SystemExit('KV failure smoke exposed secret values or unexpected output.')
    else:
        try:
            outputs[case] = json.loads(output)
        except (ValueError, TypeError):
            raise SystemExit('KV smoke did not produce valid JSON.') from None
        if error:
            raise SystemExit('KV success smoke emitted unexpected diagnostics.')

for case, path in [('kv-v1', 'f02-smoke-v1/allowed/item'), ('kv-v2', 'f02-smoke-v2/allowed/item'), ('kv-v2-data', 'f02-smoke-v2/allowed/data/item')]:
    if outputs[case] != expected[path]:
        raise SystemExit('KV smoke returned the wrong record or a wire-level wrapper.')
if outputs['kv-ls'] != ['data/', 'item']:
    raise SystemExit('KV smoke returned an incorrect directory listing.')
if outputs['kv-cd'] != {'path': '/f02-smoke-parent'}:
    raise SystemExit('KV smoke did not select the virtual directory.')
for path, version in [('f02-smoke-v1/', 1), ('f02-smoke-v2/', 2), ('f02-smoke-parent/kv/', 2)]:
    if not any(item.get('path') == path and item.get('version') == version for item in outputs['kv-mounts']):
        raise SystemExit('KV smoke omitted a mount or engine version.')
print('CLI KV smoke passed: v1/v2, nested mounts, navigation and access denial.')
PY

# Keep mutation inputs, expected values and every captured result private. The
# writer has access only to this new fixture; partial moves use an extra exact
# deny on source-version deletion, without granting administration or self-read.
python3 - "$fixture_dir" <<'PY'
from pathlib import Path
import json
import os
import secrets
import sys
import urllib.error
import urllib.request

fixture = Path(sys.argv[1])
address = os.environ['VAULT_ADDR']
root_token = (fixture / 'root-token').read_text().strip()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def request(path, payload):
    message = urllib.request.Request(address + '/v1/' + path, data=json.dumps(payload).encode(), method='POST')
    message.add_header('X-Vault-Token', root_token)
    message.add_header('Content-Type', 'application/json')
    with opener.open(message, timeout=5) as response:
        content = response.read()
        return json.loads(content) if content else None

def private_json(name, value):
    descriptor = os.open(fixture / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as target:
        json.dump(value, target)

def private_token(name, value):
    descriptor = os.open(fixture / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as target:
        target.write(value)

try:
    policy = []
    for mount, version in [('f03-smoke-v1', 1), ('f03-smoke-v2', 2)]:
        request('sys/mounts/' + mount, {'type': 'kv', 'options': {'version': str(version)}})
        if version == 1:
            policy.append('path ' + json.dumps(mount + '/allowed/*') + ' { capabilities = ["create","read","update","delete","list"] }')
        else:
            policy.append('path ' + json.dumps(mount + '/data/allowed/*') + ' { capabilities = ["create","read","update","delete"] }')
            policy.append('path ' + json.dumps(mount + '/metadata/allowed/*') + ' { capabilities = ["read","list"] }')
            for operation in ['delete', 'undelete', 'destroy']:
                policy.append('path ' + json.dumps(mount + '/' + operation + '/allowed/*') + ' { capabilities = ["update"] }')
    for policy_name, token_file, extra in [
        ('f03-smoke-write', 'kv-write-token', ''),
        ('f03-smoke-partial', 'kv-partial-token', 'path "f03-smoke-v2/delete/allowed/partial-source" { capabilities = ["deny"] }'),
    ]:
        request('sys/policies/acl/' + policy_name, {'policy': '\n'.join(policy + [extra])})
        response = request('auth/token/create', {'policies': [policy_name], 'no_default_policy': True, 'ttl': '2m', 'display_name': 'secretwright-f03-smoke'})
        private_token(token_file, response['auth']['client_token'])
    for name in ['first', 'second']:
        private_json('f03-input-' + name + '.json', {
            'value': 'private-f03-smoke-' + secrets.token_hex(16),
            'large': 9007199254740994,
            'large_id': '9007199254740993',
            'data': {'nested': 'private-f03-nested-' + secrets.token_hex(16)},
        })
    private_json('f03-input-unsafe.json', {
        'value': 'private-f03-smoke-' + secrets.token_hex(16),
        'large': 9007199254740993,
    })
except (OSError, ValueError, TypeError, KeyError, urllib.error.URLError):
    raise SystemExit('Could not prepare the disposable KV mutation smoke fixture.') from None
PY

expect_kv_failure 1 f03-unsafe-put ./bin/secretwright put \
  --token-file "$fixture_dir/kv-write-token" --file "$fixture_dir/f03-input-unsafe.json" \
  /f03-smoke-v2/allowed/unsafe
expect_kv_failure 3 f03-unsafe-missing ./bin/secretwright cat \
  --token-file "$fixture_dir/kv-write-token" /f03-smoke-v2/allowed/unsafe
./bin/secretwright put --token-file "$fixture_dir/kv-write-token" \
  --file "$fixture_dir/f03-input-unsafe.json" /f03-smoke-v1/allowed/unsafe-source \
  >"$fixture_dir/f03-unsafe-v1-put.json" 2>"$fixture_dir/f03-unsafe-v1-put.err"
expect_kv_failure 1 f03-unsafe-move ./bin/secretwright mv \
  --token-file "$fixture_dir/kv-write-token" --force \
  /f03-smoke-v1/allowed/unsafe-source /f03-smoke-v2/allowed/unsafe-moved
./bin/secretwright cat --token-file "$fixture_dir/kv-write-token" /f03-smoke-v1/allowed/unsafe-source \
  >"$fixture_dir/f03-cat-unsafe-v1.json" 2>"$fixture_dir/f03-cat-unsafe-v1.err"
expect_kv_failure 3 f03-unsafe-move-missing ./bin/secretwright cat \
  --token-file "$fixture_dir/kv-write-token" /f03-smoke-v2/allowed/unsafe-moved

./bin/secretwright put --token-file "$fixture_dir/kv-write-token" \
  /f03-smoke-v2/allowed/history <"$fixture_dir/f03-input-first.json" \
  >"$fixture_dir/f03-put-stdin.json" 2>"$fixture_dir/f03-put-stdin.err"
./bin/secretwright put --token-file "$fixture_dir/kv-write-token" \
  --file "$fixture_dir/f03-input-second.json" --cas 1 /f03-smoke-v2/allowed/history \
  >"$fixture_dir/f03-put-file.json" 2>"$fixture_dir/f03-put-file.err"
expect_kv_failure 4 f03-stale-cas ./bin/secretwright put \
  --token-file "$fixture_dir/kv-write-token" --file "$fixture_dir/f03-input-first.json" \
  --cas 1 /f03-smoke-v2/allowed/history
./bin/secretwright cat --token-file "$fixture_dir/kv-write-token" /f03-smoke-v2/allowed/history \
  >"$fixture_dir/f03-cat-current.json" 2>"$fixture_dir/f03-cat-current.err"
./bin/secretwright cat --token-file "$fixture_dir/kv-write-token" --version 1 /f03-smoke-v2/allowed/history \
  >"$fixture_dir/f03-cat-historical.json" 2>"$fixture_dir/f03-cat-historical.err"
./bin/secretwright versions --token-file "$fixture_dir/kv-write-token" /f03-smoke-v2/allowed/history \
  >"$fixture_dir/f03-versions-before.json" 2>"$fixture_dir/f03-versions-before.err"
./bin/secretwright rm --token-file "$fixture_dir/kv-write-token" /f03-smoke-v2/allowed/history \
  >"$fixture_dir/f03-rm-latest.json" 2>"$fixture_dir/f03-rm-latest.err"
expect_kv_failure 3 f03-soft-deleted ./bin/secretwright cat \
  --token-file "$fixture_dir/kv-write-token" /f03-smoke-v2/allowed/history
./bin/secretwright undelete --token-file "$fixture_dir/kv-write-token" --versions 2,2 /f03-smoke-v2/allowed/history \
  >"$fixture_dir/f03-undelete.json" 2>"$fixture_dir/f03-undelete.err"
./bin/secretwright cat --token-file "$fixture_dir/kv-write-token" /f03-smoke-v2/allowed/history \
  >"$fixture_dir/f03-cat-restored.json" 2>"$fixture_dir/f03-cat-restored.err"
./bin/secretwright rollback --token-file "$fixture_dir/kv-write-token" /f03-smoke-v2/allowed/history 1 \
  >"$fixture_dir/f03-rollback.json" 2>"$fixture_dir/f03-rollback.err"
./bin/secretwright cat --token-file "$fixture_dir/kv-write-token" /f03-smoke-v2/allowed/history \
  >"$fixture_dir/f03-cat-rollback.json" 2>"$fixture_dir/f03-cat-rollback.err"
./bin/secretwright destroy --token-file "$fixture_dir/kv-write-token" --versions 1 --force /f03-smoke-v2/allowed/history \
  >"$fixture_dir/f03-destroy.json" 2>"$fixture_dir/f03-destroy.err"
expect_kv_failure 3 f03-destroyed ./bin/secretwright cat \
  --token-file "$fixture_dir/kv-write-token" --version 1 /f03-smoke-v2/allowed/history
./bin/secretwright versions --token-file "$fixture_dir/kv-write-token" /f03-smoke-v2/allowed/history \
  >"$fixture_dir/f03-versions-after.json" 2>"$fixture_dir/f03-versions-after.err"

./bin/secretwright put --token-file "$fixture_dir/kv-write-token" --file - \
  /f03-smoke-v1/allowed/source <"$fixture_dir/f03-input-first.json" \
  >"$fixture_dir/f03-v1-put.json" 2>"$fixture_dir/f03-v1-put.err"
./bin/secretwright cp --token-file "$fixture_dir/kv-write-token" \
  /f03-smoke-v1/allowed/source /f03-smoke-v2/allowed/copied \
  >"$fixture_dir/f03-copy.json" 2>"$fixture_dir/f03-copy.err"
expect_kv_failure 1 f03-v1-copy-unforced ./bin/secretwright cp \
  --token-file "$fixture_dir/kv-write-token" /f03-smoke-v2/allowed/copied /f03-smoke-v1/allowed/copied
./bin/secretwright cp --token-file "$fixture_dir/kv-write-token" --force \
  /f03-smoke-v2/allowed/copied /f03-smoke-v1/allowed/copied \
  >"$fixture_dir/f03-v1-copy.json" 2>"$fixture_dir/f03-v1-copy.err"
./bin/secretwright cat --token-file "$fixture_dir/kv-write-token" /f03-smoke-v1/allowed/copied \
  >"$fixture_dir/f03-cat-v1-copy.json" 2>"$fixture_dir/f03-cat-v1-copy.err"
expect_kv_failure 1 f03-v1-move-unforced ./bin/secretwright mv \
  --token-file "$fixture_dir/kv-write-token" /f03-smoke-v1/allowed/source /f03-smoke-v2/allowed/moved
./bin/secretwright mv --token-file "$fixture_dir/kv-write-token" --force \
  /f03-smoke-v1/allowed/source /f03-smoke-v2/allowed/moved \
  >"$fixture_dir/f03-move.json" 2>"$fixture_dir/f03-move.err"
./bin/secretwright cat --token-file "$fixture_dir/kv-write-token" /f03-smoke-v2/allowed/moved \
  >"$fixture_dir/f03-cat-moved.json" 2>"$fixture_dir/f03-cat-moved.err"
expect_kv_failure 3 f03-moved-source ./bin/secretwright cat \
  --token-file "$fixture_dir/kv-write-token" /f03-smoke-v1/allowed/source
expect_kv_failure 1 f03-v1-rm-unforced ./bin/secretwright rm \
  --token-file "$fixture_dir/kv-write-token" /f03-smoke-v1/allowed/copied
./bin/secretwright rm --token-file "$fixture_dir/kv-write-token" --force /f03-smoke-v1/allowed/copied \
  >"$fixture_dir/f03-v1-rm.json" 2>"$fixture_dir/f03-v1-rm.err"
expect_kv_failure 3 f03-v1-removed ./bin/secretwright cat \
  --token-file "$fixture_dir/kv-write-token" /f03-smoke-v1/allowed/copied

./bin/secretwright put --token-file "$fixture_dir/kv-write-token" --file "$fixture_dir/f03-input-second.json" \
  /f03-smoke-v2/allowed/partial-source \
  >"$fixture_dir/f03-partial-put.json" 2>"$fixture_dir/f03-partial-put.err"
expect_kv_failure 5 f03-partial ./bin/secretwright mv --token-file "$fixture_dir/kv-partial-token" \
  /f03-smoke-v2/allowed/partial-source /f03-smoke-v2/allowed/partial-destination
./bin/secretwright cat --token-file "$fixture_dir/kv-write-token" /f03-smoke-v2/allowed/partial-source \
  >"$fixture_dir/f03-cat-partial-source.json" 2>"$fixture_dir/f03-cat-partial-source.err"
./bin/secretwright cat --token-file "$fixture_dir/kv-write-token" /f03-smoke-v2/allowed/partial-destination \
  >"$fixture_dir/f03-cat-partial-destination.json" 2>"$fixture_dir/f03-cat-partial-destination.err"

python3 - "$fixture_dir" <<'PY'
from pathlib import Path
import json
import stat
import sys

fixture = Path(sys.argv[1])
credentials = [(fixture / name).read_text().strip() for name in ['root-token', 'kv-token', 'kv-write-token', 'kv-partial-token']]
first = json.loads((fixture / 'f03-input-first.json').read_text())
second = json.loads((fixture / 'f03-input-second.json').read_text())
unsafe = json.loads((fixture / 'f03-input-unsafe.json').read_text())
cat_values = {
    'f03-cat-current': second, 'f03-cat-historical': first,
    'f03-cat-restored': second, 'f03-cat-rollback': first,
    'f03-cat-v1-copy': first, 'f03-cat-moved': first,
    'f03-cat-partial-source': second, 'f03-cat-partial-destination': second,
    'f03-cat-unsafe-v1': unsafe,
}
failures = {
    'f03-stale-cas', 'f03-soft-deleted', 'f03-destroyed',
    'f03-v1-copy-unforced', 'f03-v1-move-unforced', 'f03-moved-source',
    'f03-v1-rm-unforced', 'f03-v1-removed', 'f03-partial',
    'f03-unsafe-put', 'f03-unsafe-missing', 'f03-unsafe-move', 'f03-unsafe-move-missing',
}
reports = {}
for output_file in sorted(fixture.glob('f03-*.json')):
    if stat.S_IMODE(output_file.stat().st_mode) != 0o600:
        raise SystemExit('KV mutation smoke created a non-private capture.')
    case = output_file.stem
    if case.startswith('f03-input-'):
        continue
    output = output_file.read_text()
    error = output_file.with_suffix('.err').read_text()
    if any(token in output + error for token in credentials):
        raise SystemExit('KV mutation smoke exposed a credential.')
    if 'private-f03-' in error or '9007199254740993' in error or '9007199254740994' in error:
        raise SystemExit('KV mutation diagnostics exposed a secret value.')
    if case in failures:
        if output or not error:
            raise SystemExit('KV mutation failure produced unexpected output.')
        continue
    try:
        report = json.loads(output)
    except (ValueError, TypeError):
        raise SystemExit('KV mutation smoke did not produce valid JSON.') from None
    if error:
        raise SystemExit('KV mutation success emitted unexpected diagnostics.')
    if case in cat_values:
        if report != cat_values[case]:
            raise SystemExit('KV mutation readback changed values or numeric precision.')
    else:
        if 'private-f03-' in output or '9007199254740993' in output or '9007199254740994' in output:
            raise SystemExit('KV mutation report exposed a secret value.')
        reports[case] = report

if reports['f03-put-stdin'] != {'path': '/f03-smoke-v2/allowed/history', 'kv_version': 2, 'version': 1}:
    raise SystemExit('KV mutation stdin put report was incorrect.')
if reports['f03-put-file'].get('version') != 2 or reports['f03-rollback'].get('version') != 3:
    raise SystemExit('KV mutation CAS or rollback revision was incorrect.')
if reports['f03-undelete'].get('versions') != [2] or reports['f03-destroy'].get('versions') != [1]:
    raise SystemExit('KV mutation version selection was not canonical.')
for case, current, destroyed in [('f03-versions-before', 2, False), ('f03-versions-after', 3, True)]:
    history = reports[case]
    if set(history) != {'path', 'current_version', 'oldest_version', 'versions'} or history['current_version'] != current:
        raise SystemExit('KV mutation history projection was incorrect.')
    versions = history['versions']
    if [item.get('version') for item in versions] != list(range(1, current + 1)) or versions[0].get('destroyed') is not destroyed:
        raise SystemExit('KV mutation version history was not preserved.')
    if any(set(item) != {'version', 'created_time', 'deletion_time', 'destroyed'} for item in versions):
        raise SystemExit('KV mutation history included unexpected metadata.')
if reports['f03-copy'].get('source_deleted') is not False or reports['f03-move'].get('source_deleted') is not True:
    raise SystemExit('KV mutation copy/move report was incorrect.')
print('CLI KV mutation smoke passed: stdin/file, CAS, version lifecycle and partial move.')
PY

CGO_ENABLED=1 "${GO:-go}" build -race -trimpath -o "$fixture_dir/secretwright-shell-race" ./cmd/secretwright
python3 ./scripts/shell_smoke.py "$fixture_dir/secretwright-shell-race" "$fixture_dir"

python3 ./scripts/advanced_smoke.py ./bin/secretwright "$fixture_dir"
