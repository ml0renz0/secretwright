#!/usr/bin/env python3
"""Private CLI acceptance checks for native keytabs and Vault KV v2."""

from pathlib import Path
import base64
import hashlib
import json
import os
import stat
import struct
import subprocess
import sys
import urllib.request


class SmokeFailure(Exception):
    pass


STAGE = 'startup'


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


def main():
    global STAGE
    binary, fixture = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    address = os.environ['VAULT_ADDR']
    root_file = fixture / 'root-token'
    root_token = root_file.read_text().strip()
    environment = dict(os.environ, VAULT_TOKEN='private-f12-unselected-token', VAULT_NAMESPACE='private-f12-unselected-namespace')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    captures, artifacts = [], []
    forbidden = [root_token, 'private-f12-unselected-token', 'private-f12-key-marker-']

    def write_file(path, source):
        data = source.encode() if isinstance(source, str) else source
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
        artifacts.append(path)

    def request(path, payload=None, method='POST'):
        body = None if payload is None else json.dumps(payload).encode()
        message = urllib.request.Request(address + '/v1/' + path, data=body, method=method)
        message.add_header('Content-Type', 'application/json')
        message.add_header('X-Vault-Token', root_token)
        with opener.open(message, timeout=10) as response:
            result = response.read()
            return json.loads(result) if result else None

    def run(name, args, expected=0, offline=False, raw=False, token_file=None):
        depth = 1 if args[0] == 'shell' else 2
        injected = [] if offline else ['--address', address, '--namespace', '', '--timeout', '1m', '--token-file', str(token_file or operator_file)]
        command = [str(binary), *args[:depth], *injected, *args[depth:]]
        output, error = [fixture / ('f12-capture-' + name + suffix) for suffix in ['.json', '.err']]
        descriptors = [os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600) for path in [output, error]]
        captures.extend([output, error])
        selected = environment
        if offline:
            selected = dict(environment, VAULT_ADDR='private-f12-invalid-address', VAULT_CLIENT_TIMEOUT='private-f12-invalid-timeout')
        with os.fdopen(descriptors[0], 'w') as stdout, os.fdopen(descriptors[1], 'w') as stderr:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=selected, cwd=fixture, timeout=60)
        body, diagnostics = output.read_text(), error.read_text()
        require(result.returncode == expected, 'Keytab CLI returned an unexpected exit code [check=' + name + '].')
        require(not diagnostics if expected == 0 else bool(diagnostics), 'Keytab CLI emitted unexpected diagnostics [check=' + name + '].')
        require(all(marker not in body + diagnostics for marker in forbidden if marker), 'Keytab CLI exposed a key, encoding, digest or Vault credential.')
        if raw:
            return body
        return json.loads(body) if body.strip() else None

    def dictionaries(value):
        if isinstance(value, dict):
            yield value
            for child in value.values():
                yield from dictionaries(child)
        elif isinstance(value, list):
            for child in value:
                yield from dictionaries(child)

    def metadata(value):
        return next((item for item in dictionaries(value) if isinstance(item.get('entries'), list) and item.get('version') == 2), {})

    def check_unchecked_authentication(value):
        reports = [item for item in dictionaries(value) if 'authentication_checked' in item]
        require(reports and all(item['authentication_checked'] is False for item in reports), 'Keytab report falsely claimed Kerberos authentication or omitted its scope.')

    def make_keytab(policy, kvno, fill):
        principal = policy['principal']
        counted = lambda value: struct.pack('>H', len(value.encode())) + value.encode()
        key = (b'private-f12-key-marker-' + bytes([fill]) * 32)[:32]
        entry = struct.pack('>H', len(principal['components'])) + counted(principal['realm'])
        entry += b''.join(counted(value) for value in principal['components'])
        entry += struct.pack('>IIBHH', 2, 0x90000000, 3, 18, len(key)) + key
        entry += struct.pack('>I', kvno) + bytes([0xc1, 0x72, 0x93])
        body = b'\x05\x02' + struct.pack('>i', -5) + bytes([0xde, 0xad, 0x65, 0x99, 0x71])
        body += struct.pack('>i', len(entry)) + entry + struct.pack('>i', 0) + b'\0\0\0'
        forbidden.extend([base64.b64encode(body).decode(), base64.b64encode(key).decode(), key.hex(), hashlib.sha256(key).hexdigest(), hashlib.sha256(body).hexdigest()])
        return body

    STAGE = 'offline-schema-and-policy-formats'
    schema = run('schema', ['keytab', 'schema'], offline=True)
    require(schema.get('$id') == 'urn:secretwright:keytab:v1', 'Keytab policy schema lost its offline version.')
    example = run('example-yaml', ['keytab', 'example'], offline=True, raw=True)
    require(example.lstrip().startswith('api_version:') and not example.lstrip().startswith('{'), 'Keytab policy example did not default to YAML.')
    policy_file = fixture / 'f12-policy.yaml'
    write_file(policy_file, example)
    policy = run('example-json', ['keytab', 'example', '--format', 'json'], offline=True)
    require(policy.get('api_version') == 'secretwright/keytab/v1' and isinstance(policy.get('principal'), dict), 'Explicit JSON keytab policy lost its structured principal.')
    raw_first = make_keytab(policy, 259, 65)
    raw_second = make_keytab(policy, 260, 66)
    source, changed = fixture / 'f12-original.keytab', fixture / 'f12-updated.keytab'
    write_file(source, raw_first)
    write_file(changed, raw_second)
    inspected = run('inspect', ['keytab', 'inspect', '--file', str(source)], offline=True)
    check_unchecked_authentication(inspected)
    require(metadata(inspected).get('holes') == 1 and metadata(inspected)['entries'][0].get('kvno') == 259, 'Keytab inspection lost holes or effective KVNO32.')
    validated = run('validate-structural', ['keytab', 'validate', '--file', str(source)], offline=True)
    require(validated.get('valid') is True and validated.get('policy_checked') is False, 'Structural keytab validation silently claimed to apply an absent policy.')
    check_unchecked_authentication(validated)
    validated = run('validate-policy', ['keytab', 'validate', '--file', str(source), '--policy', str(policy_file)], offline=True)
    require(validated.get('valid') is True and validated.get('policy_checked') is True, 'Matching explicit keytab policy was not applied.')
    check_unchecked_authentication(validated)
    rejected_policy = dict(policy, minimum_kvno=261)
    rejected_file = fixture / 'f12-rejected-policy.json'
    write_file(rejected_file, json.dumps(rejected_policy))
    rejected = run('reject-old-kvno', ['keytab', 'validate', '--file', str(source), '--policy', str(rejected_file)], expected=4, offline=True)
    require(rejected.get('valid') is False, 'A keytab below the required KVNO passed explicit validation.')
    os.chmod(source, 0o644)
    run('reject-public-source', ['keytab', 'inspect', '--file', str(source)], expected=1, offline=True)
    os.chmod(source, 0o600)

    STAGE = 'disposable-kv-v2-and-restricted-token'
    mount, policy_name = 'f12-smoke-kv', 'f12-smoke-keytabs'
    request('sys/mounts/' + mount, {'type': 'kv', 'options': {'version': '2'}})
    acl = 'path ' + json.dumps(mount + '/data/allowed/*') + ' { capabilities = ["create", "update", "read"] }'
    request('sys/policies/acl/' + policy_name, {'policy': acl})
    selected_token = request('auth/token/create', {'policies': [policy_name], 'no_default_policy': True, 'ttl': '5m', 'explicit_max_ttl': '10m', 'renewable': False})['auth']['client_token']
    forbidden.append(selected_token)
    operator_file = fixture / 'f12-operator-token'
    write_file(operator_file, selected_token + '\n')
    denied_policy = 'f12-smoke-denied'
    request('sys/policies/acl/' + denied_policy, {'policy': 'path "f12-unrelated/*" { capabilities = ["read"] }'})
    denied_token = request('auth/token/create', {'policies': [denied_policy], 'no_default_policy': True, 'ttl': '5m', 'renewable': False})['auth']['client_token']
    forbidden.append(denied_token)
    denied_file = fixture / 'f12-denied-token'
    write_file(denied_file, denied_token + '\n')
    target = '/' + mount + '/allowed/service'
    common = ['--mount', mount, '--path', target]

    STAGE = 'create-only-import-exact-export-and-cas'
    imported = run('import', ['keytab', 'import', '--file', str(source), '--policy', str(policy_file), *common])
    require(imported.get('version') == 1, 'Keytab import did not return its actual first revision.')
    check_unchecked_authentication(imported)
    exported_file = fixture / 'f12-exported.keytab'
    exported = run('export', ['keytab', 'export', *common, '--out', str(exported_file), '--policy', str(policy_file)])
    artifacts.append(exported_file)
    require(exported.get('version') == 1 and exported_file.read_bytes() == raw_first, 'Keytab export did not preserve every binary byte and same-read revision.')
    check_unchecked_authentication(exported)
    run('existing-import-conflict', ['keytab', 'import', '--file', str(changed), *common], expected=4)
    updated = run('cas-update', ['keytab', 'import', '--file', str(changed), *common, '--cas', '1'])
    require(updated.get('version') == 2, 'Matching keytab CAS failed to create the next revision.')
    run('stale-cas-conflict', ['keytab', 'import', '--file', str(source), *common, '--cas', '1'], expected=4)
    current = fixture / 'f12-current.keytab'
    report = run('current-export', ['keytab', 'export', *common, '--out', str(current)])
    artifacts.append(current)
    require(report.get('version') == 2 and current.read_bytes() == raw_second, 'A stale keytab write changed the current revision.')
    history = fixture / 'f12-history.keytab'
    report = run('historical-export', ['keytab', 'export', *common, '--version', '1', '--out', str(history)])
    artifacts.append(history)
    require(report.get('version') == 1 and history.read_bytes() == raw_first, 'Explicit keytab history returned a different revision.')
    original = exported_file.read_bytes()
    run('existing-output', ['keytab', 'export', *common, '--out', str(exported_file)], expected=4, token_file=fixture / 'f12-missing-token')
    require(exported_file.read_bytes() == original, 'Keytab export overwrote an existing private file.')
    denied_output = fixture / 'f12-denied.keytab'
    run('denied-export', ['keytab', 'export', *common, '--out', str(denied_output)], expected=2, token_file=denied_file)
    require(not denied_output.exists(), 'Denied keytab export retained a private output placeholder.')
    run('denied-import', ['keytab', 'import', '--file', str(source), '--mount', mount, '--path', '/' + mount + '/denied/service'], expected=2)

    STAGE = 'fixed-shell-connection-and-private-history'
    session, shell_output = fixture / 'f12-session.sw', fixture / 'f12-shell.keytab'
    write_file(session, 'keytab inspect --file ' + json.dumps(str(source)) + '\n'
               + 'keytab export --mount ' + mount + ' --path ' + target + ' --version 1 --out ' + json.dumps(str(shell_output)) + '\n'
               + 'history\n')
    stream = run('shell', ['shell', '--no-prompt', '--script', str(session)], raw=True)
    artifacts.append(shell_output)
    decoder, reports = json.JSONDecoder(), []
    while stream.strip():
        stream = stream.lstrip()
        report, end = decoder.raw_decode(stream)
        reports.append(report)
        stream = stream[end:]
    require(len(reports) == 3 and metadata(reports[0]) and reports[1].get('version') == 1 and reports[2] == [] and shell_output.read_bytes() == raw_first, 'Keytab shell changed its fixed connection, binary bytes or private history.')

    STAGE = 'deleted-history-never-falls-back'
    request(mount + '/delete/allowed/service', {'versions': [2]})
    for suffix, flags in [('latest', []), ('exact', ['--version', '2'])]:
        missing = fixture / ('f12-deleted-' + suffix + '.keytab')
        run('deleted-' + suffix, ['keytab', 'export', *common, *flags, '--out', str(missing)], expected=3)
        require(not missing.exists(), 'Deleted keytab export retained a placeholder or fell back to an older credential.')
    available = fixture / 'f12-available-history.keytab'
    run('available-history', ['keytab', 'export', *common, '--version', '1', '--out', str(available)])
    artifacts.append(available)
    require(available.read_bytes() == raw_first, 'Deleting the current keytab lost explicitly available history.')
    request(mount + '/destroy/allowed/service', {'versions': [1]})
    missing = fixture / 'f12-destroyed.keytab'
    run('destroyed-history', ['keytab', 'export', *common, '--version', '1', '--out', str(missing)], expected=3)
    require(not missing.exists(), 'Destroyed keytab revision was published or left a placeholder.')

    STAGE = 'private-file-and-capture-audit'
    for path in artifacts + captures:
        require(not path.is_symlink() and stat.S_IMODE(path.stat().st_mode) == 0o600, 'Keytab smoke created a public file or symbolic link.')
    for path in captures:
        text = path.read_text()
        require(all(marker not in text for marker in forbidden if marker), 'Keytab metadata exposed sensitive binary content, encoding, digest or token.')
    print('CLI keytab smoke passed: native v2 inspection, YAML/JSON policy, private exact-byte KV2 import/export, CAS, historical/deleted versions and shell privacy; Kerberos authentication was not checked.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Keytab smoke failed [stage=' + STAGE + ']; private captures are withheld.') from None
