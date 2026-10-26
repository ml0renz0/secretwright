#!/usr/bin/env python3
"""Private executable acceptance checks for one-shot credential lifecycle."""

from pathlib import Path
import hashlib
import json
import os
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
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
    environment = dict(os.environ, VAULT_TOKEN='private-f10-inherited-token', VAULT_NAMESPACE='private-f10-inherited-namespace')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    captures, artifacts, receipts = [], [], []
    forbidden = [root_token, 'private-f10-inherited-token', 'private-f10-probe-value']

    def write_file(path, source):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            output.write(source)
        artifacts.append(path)

    def request(path, payload=None, method='POST', token=root_token, expected=None):
        body = None if payload is None else json.dumps(payload).encode()
        message = urllib.request.Request(address + '/v1/' + urllib.parse.quote(path, safe='/'), data=body, method=method)
        message.add_header('Content-Type', 'application/json')
        message.add_header('X-Vault-Token', token)
        try:
            with opener.open(message, timeout=10) as response:
                body = response.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            if error.code == expected:
                return None
            raise

    def run(name, args, expected=0, offline=False, raw=False):
        depth = 1 if args[0] == 'shell' else 2
        if args[:2] in [['lifecycle', 'token'], ['lifecycle', 'lease']]:
            depth = 3
        injected = [] if offline else ['--address', address, '--namespace', '', '--timeout', '1m']
        if not offline and args[:2] != ['approle', 'login']:
            injected += ['--token-file', str(root_file)]
        command = [str(binary), *args[:depth], *injected, *args[depth:]]
        output = fixture / ('f10-capture-' + name + '.json')
        error = fixture / ('f10-capture-' + name + '.err')
        descriptors = [os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600) for path in [output, error]]
        captures.extend([output, error])
        with os.fdopen(descriptors[0], 'w') as stdout, os.fdopen(descriptors[1], 'w') as stderr:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=environment, cwd=fixture, timeout=60)
        body, diagnostics = output.read_text(), error.read_text()
        require(result.returncode == expected, 'Lifecycle CLI returned an unexpected exit code [check=' + name + '].')
        require((not diagnostics) if expected == 0 else bool(diagnostics), 'Lifecycle CLI emitted unexpected diagnostics [check=' + name + '].')
        require(all(value not in body + diagnostics for value in forbidden if isinstance(value, str) and value), 'Lifecycle CLI exposed credentials, lease IDs or probe data.')
        if raw:
            return body
        return json.loads(body) if body.strip() else None

    STAGE = 'offline-schema-and-yaml-default'
    schema = run('schema', ['lifecycle', 'schema'], offline=True)
    require(schema.get('$schema') and schema.get('type') == 'object', 'Lifecycle schema was not a JSON object schema.')
    yaml_example = run('example-yaml', ['lifecycle', 'example'], offline=True, raw=True)
    require(yaml_example.lstrip().startswith('api_version:') and not yaml_example.lstrip().startswith('{'), 'Lifecycle example did not default to YAML.')
    example_file = fixture / 'f10-example.yaml'
    write_file(example_file, yaml_example)
    run('validate-yaml', ['lifecycle', 'validate', '--file', str(example_file)], offline=True)
    example = run('example-json', ['lifecycle', 'example', '--format', 'json'], offline=True)
    require(example.get('api_version') == 'secretwright/lifecycle/v1', 'Explicit JSON lifecycle example lost its version.')

    STAGE = 'disposable-approle-bootstrap'
    auth, mount, role, policy = 'f10-smoke-auth', 'f10-smoke-kv', 'application', 'f10-smoke-read'
    request('sys/auth/' + auth, {'type': 'approle'})
    request('sys/mounts/' + mount, {'type': 'kv', 'options': {'version': '2'}})
    request('sys/policies/acl/' + policy, {'policy': 'path "' + mount + '/data/health" { capabilities = ["read"] }'})
    request(mount + '/data/health', {'data': {'value': 'private-f10-probe-value'}})
    role_body = {'token_policies': [policy], 'token_ttl': '1m', 'token_max_ttl': '5m', 'secret_id_ttl': '2m', 'secret_id_num_uses': 5, 'token_num_uses': 0, 'token_no_default_policy': True, 'token_type': 'service', 'bind_secret_id': True}
    request('auth/' + auth + '/role/' + role, role_body)
    bundle, consumer = fixture / 'f10-bootstrap-bundle.json', fixture / 'f10-consumer-token'
    run('bootstrap-credentials', ['approle', 'credentials', '--auth-mount', auth, '--out', str(bundle), role])
    artifacts.append(bundle)
    forbidden.extend(value for value in json.loads(bundle.read_text()).values() if isinstance(value, str))
    run('bootstrap-login', ['approle', 'login', '--auth-mount', auth, '--file', str(bundle), '--out', str(consumer)])
    artifacts.append(consumer)
    old = consumer.read_text().strip()
    forbidden.append(old)
    require(request(mount + '/data/health', method='GET', token=old)['data']['data']['value'] == 'private-f10-probe-value', 'Bootstrap consumer could not read its probe.')
    role_body['token_ttl'] = '2m'
    request('auth/' + auth + '/role/' + role, role_body)
    source = {'api_version': 'secretwright/lifecycle/v1', 'name': 'application', 'provider': {'kind': 'approle', 'auth_mount': auth, 'role': role}, 'consumer': {'kind': 'token-file', 'path': str(consumer)}, 'verify': {'kind': 'kv-read', 'mount': mount, 'kv_version': 2, 'path': '/' + mount + '/health'}, 'policy': {'rotate_below': '90s', 'minimum_new_ttl': '90s'}}
    policy_file, receipt = fixture / 'f10-policy.json', fixture / 'f10-rotation.yaml'
    write_file(policy_file, json.dumps(source))
    run('validate-json', ['lifecycle', 'validate', '--file', str(policy_file)], offline=True)

    STAGE = 'read-only-dry-run'
    before = hashlib.sha256(consumer.read_bytes()).digest()
    due = run('rotate-dry', ['lifecycle', 'rotate', '--file', str(policy_file), '--receipt', str(receipt), '--dry-run'])
    require(due.get('status') == 'would_rotate' and due.get('due') is True, 'Real short-lived consumer was not due for rotation.')
    run('inspect-initial', ['lifecycle', 'inspect', '--file', str(policy_file), '--receipt', str(receipt)])
    require(not any(Path(str(receipt) + suffix).exists() for suffix in ['', '.lock', '.d']) and hashlib.sha256(consumer.read_bytes()).digest() == before, 'Read-only lifecycle commands created artifacts or changed the consumer.')

    STAGE = 'failed-new-probe'
    denied_source = json.loads(json.dumps(source))
    denied_source['verify']['path'] = '/' + mount + '/denied'
    denied_file, denied_receipt = fixture / 'f10-denied-policy.json', fixture / 'f10-denied-rotation.json'
    write_file(denied_file, json.dumps(denied_source))
    run('denied-probe', ['lifecycle', 'rotate', '--file', str(denied_file), '--receipt', str(denied_receipt), '--format', 'json'], expected=5)
    receipts.append(denied_receipt)
    denied = json.loads(denied_receipt.read_text())
    require(denied.get('phase') == 'candidate_ready' and hashlib.sha256(consumer.read_bytes()).digest() == before, 'Failed candidate probe changed the old consumer or lost its checkpoint.')
    require(request(mount + '/data/health', method='GET', token=old) is not None, 'Failed new-token verification revoked the old consumer.')

    STAGE = 'publish-and-explicit-retirement'
    published = run('rotate', ['lifecycle', 'rotate', '--file', str(policy_file), '--receipt', str(receipt)])
    receipts.append(receipt)
    require(published.get('phase') == 'published' and published.get('status') == 'awaiting_consumer_ack', 'Rotation did not stop after verified consumer publication.')
    new = consumer.read_text().strip()
    forbidden.append(new)
    require(new != old and receipt.read_text().lstrip().startswith('api_version:'), 'Rotation did not publish a new credential with a YAML receipt.')
    for token in [old, new]:
        require(request(mount + '/data/health', method='GET', token=token) is not None, 'Both credentials were not usable while consumer acknowledgement was pending.')
    receipt_digest = hashlib.sha256(receipt.read_bytes()).digest()
    repeated = run('rotate-repeat', ['lifecycle', 'rotate', '--file', str(policy_file), '--receipt', str(receipt)])
    require(repeated.get('status') == 'awaiting_consumer_ack' and hashlib.sha256(receipt.read_bytes()).digest() == receipt_digest, 'Repeated published rotation changed the checkpoint or issued again.')
    run('retire-no-ack', ['lifecycle', 'retire', '--file', str(policy_file), '--receipt', str(receipt)], expected=1)
    require(hashlib.sha256(receipt.read_bytes()).digest() == receipt_digest and request(mount + '/data/health', method='GET', token=old) is not None, 'Retirement without acknowledgement changed the receipt or old token.')
    retired = run('retire', ['lifecycle', 'retire', '--file', str(policy_file), '--receipt', str(receipt), '--ack-consumer'])
    require(retired.get('phase') == 'retired', 'Acknowledged retirement did not reach its terminal checkpoint.')
    require(request(mount + '/data/health', method='GET', token=old, expected=403) is None, 'Retired old token still had effective access.')
    require(request(mount + '/data/health', method='GET', token=new) is not None and consumer.read_text().strip() == new, 'Retirement disturbed the live new consumer.')
    recovered = run('recover-retired', ['lifecycle', 'recover', '--file', str(policy_file), '--receipt', str(receipt)])
    require(recovered.get('phase') == 'retired', 'Read-only recovery changed a retired generation.')

    STAGE = 'bounded-token-ttl-management'
    inspected = run('token-inspect', ['lifecycle', 'token', 'inspect', '--file', str(consumer)])
    require(inspected.get('exists') is True and inspected.get('ttl_seconds', 0) > 0, 'Token inspection did not report a live finite TTL.')
    run('token-dry-renew', ['lifecycle', 'token', 'renew', '--file', str(consumer), '--increment', '4m', '--dry-run'])
    renewed = run('token-renew', ['lifecycle', 'token', 'renew', '--file', str(consumer), '--increment', '4m'])
    require(0 < renewed.get('ttl_seconds', 0) <= 240, 'Token renewal did not report an actual bounded TTL.')
    run('token-threshold-noop', ['lifecycle', 'token', 'renew', '--file', str(consumer), '--increment', '1m', '--if-ttl-below', '1s'])

    if os.environ.get('VAULT_TEST_DATABASE_CONTAINER'):
        STAGE = 'database-lease-cli'
        password = Path(os.environ['VAULT_TEST_DATABASE_PASSWORD_FILE']).read_text().strip()
        forbidden.append(password)
        database_mount = 'f10-smoke-database'
        request('sys/mounts/' + database_mount, {'type': 'database'})
        request(database_mount + '/config/fixture', {'plugin_name': 'postgresql-database-plugin', 'allowed_roles': ['application'], 'connection_url': 'postgresql://{{username}}:{{password}}@' + os.environ['VAULT_TEST_DATABASE_ADDRESS'] + '/secretwright?sslmode=disable', 'username': 'secretwright_fixture', 'password': password})
        statement = 'CREATE ROLE "{{name}}" WITH LOGIN PASSWORD \'{{password}}\' VALID UNTIL \'{{expiration}}\';'
        request(database_mount + '/roles/application', {'db_name': 'fixture', 'creation_statements': [statement], 'default_ttl': '2m', 'max_ttl': '10m'})
        grant = request(database_mount + '/creds/application', method='GET')
        forbidden.extend([grant['lease_id'], grant['data']['username'], grant['data']['password']])
        lease_file = fixture / 'f10-lease.yaml'
        write_file(lease_file, 'lease_id: ' + json.dumps(grant['lease_id']) + '\n')
        lease = run('lease-inspect', ['lifecycle', 'lease', 'inspect', '--file', str(lease_file)])
        require(lease.get('exists') is True and lease.get('renewable') is True and lease.get('ttl_seconds', 0) > 0, 'Lease CLI did not inspect a real renewable database lease.')
        run('lease-dry-renew', ['lifecycle', 'lease', 'renew', '--file', str(lease_file), '--increment', '4m', '--dry-run'])
        lease = run('lease-renew', ['lifecycle', 'lease', 'renew', '--file', str(lease_file), '--increment', '4m'])
        require(0 < lease.get('ttl_seconds', 0) <= 240, 'Lease CLI renewal did not report an actual bounded TTL.')
        run('lease-threshold-noop', ['lifecycle', 'lease', 'renew', '--file', str(lease_file), '--increment', '1m', '--if-ttl-below', '1s'])
        run('lease-no-force', ['lifecycle', 'lease', 'revoke', '--file', str(lease_file)], expected=1)
        run('lease-dry-revoke', ['lifecycle', 'lease', 'revoke', '--file', str(lease_file), '--dry-run'])
        run('lease-revoke', ['lifecycle', 'lease', 'revoke', '--file', str(lease_file), '--force'])
        missing = run('lease-missing', ['lifecycle', 'lease', 'inspect', '--file', str(lease_file)])
        require(missing.get('exists') is False, 'Exact synchronous lease revocation left a live lease.')
        run('lease-revoke-repeat', ['lifecycle', 'lease', 'revoke', '--file', str(lease_file), '--force'])
    else:
        require(os.environ.get('VAULT_TEST_REQUIRE_DATABASE') != '1', 'Required PostgreSQL CLI fixture was unavailable.')

    STAGE = 'fixed-connection-shell-and-history'
    session_file = fixture / 'f10-session.sw'
    write_file(session_file, 'lifecycle token inspect --file ' + json.dumps(str(consumer)) + '\n'
               + 'lifecycle inspect --file ' + json.dumps(str(policy_file)) + ' --receipt ' + json.dumps(str(receipt)) + '\n'
               + 'history\n')
    session = run('shell', ['shell', '--no-prompt', '--script', str(session_file)], raw=True)
    decoder, reports = json.JSONDecoder(), []
    while session.strip():
        session = session.lstrip()
        report, end = decoder.raw_decode(session)
        reports.append(report)
        session = session[end:]
    require(len(reports) == 3 and reports[0].get('exists') is True and reports[1].get('phase') == 'retired' and reports[2] == [], 'Lifecycle shell lost its fixed connection or saved lifecycle commands in history.')

    STAGE = 'private-artifact-audit'
    # Private generation files intentionally contain credentials. Metadata,
    # terminal captures and receipts must contain none of those credentials.
    for current in receipts:
        require(current.is_file() and not Path(str(current) + '.lock').exists(), 'Lifecycle command lost its receipt or retained a lock.')
        directory = Path(str(current) + '.d')
        require(directory.is_dir(), 'Lifecycle command lost its private generation directory.')
        for path in directory.rglob('*'):
            require(not path.is_symlink(), 'Lifecycle generation contained a symbolic link.')
            require(stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600), 'Lifecycle generation weakened credential permissions.')
            if path.name in ['old.token', 'new.token']:
                forbidden.append(path.read_text().strip())
            elif path.name == 'bundle.json':
                forbidden.extend(value for value in json.loads(path.read_text()).values() if isinstance(value, str))
            elif path.is_file():
                raise SmokeFailure('Lifecycle generation contained an unexpected credential file.')
    for path in artifacts + captures + receipts:
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, 'Lifecycle smoke created a non-private file.')
    for path in captures + receipts:
        require(all(value not in path.read_text() for value in forbidden if isinstance(value, str) and value), 'Lifecycle metadata or diagnostics exposed private credentials, lease IDs or probe data.')
    print('CLI lifecycle smoke passed: YAML/JSON, due dry run, failed-probe protection, verified publication, explicit retirement, token TTL and exact database leases.')


if __name__ == '__main__':
    try:
        main()
    except SmokeFailure as error:
        raise SystemExit(str(error) + ' [stage=' + STAGE + ']') from None
    except Exception as error:
        frames, frame = [], error.__traceback__
        while frame is not None:
            if frame.tb_frame.f_code.co_filename == __file__:
                frames.append(str(frame.tb_lineno))
            frame = frame.tb_next
        raise SystemExit('Private lifecycle fixture failed [stage=' + STAGE + '; class=' + type(error).__name__ + '; script_lines=' + ','.join(frames) + ']') from None
