#!/usr/bin/env python3
"""Private executable checks for ACLs, AppRoles, tokens and identities."""

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


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as target:
        target.write(data)


def decode_documents(source):
    decoder = json.JSONDecoder()
    values = []
    while source.strip():
        source = source.lstrip()
        value, end = decoder.raw_decode(source)
        values.append(value)
        source = source[end:]
    return values


def safe_exception_details(error):
    lines = []
    frame = error.__traceback__
    while frame is not None:
        if frame.tb_frame.f_code.co_filename == __file__:
            lines.append(str(frame.tb_lineno))
        frame = frame.tb_next
    return 'stage=' + STAGE + '; class=' + type(error).__name__ + '; script_lines=' + ','.join(lines)


def main():
    global STAGE
    binary, fixture = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    address = os.environ['VAULT_ADDR']
    root_file = fixture / 'root-token'
    root_token = root_file.read_text().strip()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    mount, auth_mount, role = 'f06-smoke-kv', 'f06-smoke-approle', 'application'
    policy, extra_policy = 'f06-smoke-read', 'f06-smoke-group'
    forbidden = [root_token, 'private-f06-value', 'f06-deliberately-invalid-inherited-token']
    captures, artifacts = [], []
    environment = dict(os.environ)
    environment['VAULT_TOKEN'] = 'f06-deliberately-invalid-inherited-token'

    def request(path, payload=None, method='POST', token=root_token, expected=None):
        body = None if payload is None else json.dumps(payload).encode()
        message = urllib.request.Request(address + '/v1/' + urllib.parse.quote(path, safe='/'), data=body, method=method)
        if token:
            message.add_header('X-Vault-Token', token)
        message.add_header('Content-Type', 'application/json')
        try:
            with opener.open(message, timeout=5) as response:
                content = response.read()
                return json.loads(content) if content else None
        except urllib.error.HTTPError as error:
            if expected is not None and error.code == expected:
                return None
            raise

    def write_json(path, value):
        private_write(path, json.dumps(value).encode())
        artifacts.append(path)

    def run(name, args, expected=0, token_path=root_file):
        output_path, error_path = fixture / ('f06-' + name + '-stdout.json'), fixture / ('f06-' + name + '-stderr.txt')
        depth = 1 if args[0] == 'shell' else 3 if args[0] == 'identity' else 2
        login = args[:2] == ['approle', 'login']
        injected = ['--address', address, '--namespace', '']
        if not login:
            injected += ['--token-file', str(token_path)]
        command = [str(binary), *args[:depth], *injected, *args[depth:]]
        with open(output_path, 'xb') as output, open(error_path, 'xb') as error:
            os.chmod(output_path, 0o600)
            os.chmod(error_path, 0o600)
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output, stderr=error, env=environment, timeout=20)
        captures.extend([output_path, error_path])
        stdout, stderr = output_path.read_text(), error_path.read_text()
        require(result.returncode == expected, 'Access CLI command returned an unexpected exit code.')
        require((not stderr) if expected == 0 else bool(stderr), 'Access CLI command produced unexpected diagnostics.')
        require(all(value not in stdout + stderr for value in forbidden), 'Access CLI exposed a credential or private value.')
        documents = decode_documents(stdout)
        return documents[0] if len(documents) == 1 else documents

    def role_args(action, *args):
        return ['approle', action, '--auth-mount', auth_mount, *args]

    def raw_token(path):
        value = path.read_text().strip()
        require(bool(value) and not any(character.isspace() for character in value), 'Access CLI did not write a reusable raw credential.')
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, 'Access CLI created a non-private credential file.')
        forbidden.append(value)
        artifacts.append(path)
        return value

    def secret_id_count():
        response = request('auth/' + auth_mount + '/role/' + role + '/secret-id', method='LIST', expected=404)
        return len(response['data']['keys']) if response else 0

    def read_value(token, key, allowed):
        value = request(mount + '/data/' + key, method='GET', token=token, expected=None if allowed else 403)
        if allowed:
            require(value['data']['data'] == {'value': 'private-f06-value'}, 'Issued credential could not read its permitted value.')
        else:
            require(value is None, 'Issued credential gained an unrelated permission.')

    STAGE = 'fixture-provision'
    request('sys/mounts/' + mount, {'type': 'kv', 'options': {'version': '2'}})
    request('sys/auth/' + auth_mount, {'type': 'approle'})
    for key in ['allowed/item', 'extra/item', 'denied/item']:
        request(mount + '/data/' + key, {'data': {'value': 'private-f06-value'}})
    policy_file = fixture / 'f06-policy.hcl'
    policy_body = '\n'.join([
        'path "' + mount + '/data/allowed/item" { capabilities = ["read"] }',
        'path "auth/token/lookup-self" { capabilities = ["read"] }',
        'path "auth/token/revoke-self" { capabilities = ["update"] }',
        'path "sys/capabilities-self" { capabilities = ["update"] }',
    ])
    private_write(policy_file, policy_body.encode())
    artifacts.append(policy_file)
    role_file, token_spec = fixture / 'f06-role.json', fixture / 'f06-token-spec.json'
    write_json(role_file, {'token_policies': [policy], 'token_ttl': '2m', 'token_max_ttl': '5m', 'secret_id_ttl': '2m', 'secret_id_num_uses': 5, 'token_num_uses': 0})
    write_json(token_spec, {'policies': [policy], 'ttl': '1m', 'explicit_max_ttl': '2m', 'renewable': False, 'num_uses': 0})

    STAGE = 'policy-role-configuration'
    run('policy-write', ['policy', 'write', '--file', str(policy_file), policy])
    require(policy in run('policy-list', ['policy', 'list']), 'ACL listing omitted the configured policy.')
    policy_report = run('policy-read', ['policy', 'read', policy])
    require(policy_report.get('name') == policy and policy_body in policy_report.get('policy', ''), 'ACL read did not preserve the explicitly requested configuration.')
    run('role-write', role_args('write', '--file', str(role_file), role))
    require(role in run('role-list', role_args('list')), 'AppRole listing omitted the configured role.')
    role_report = run('role-read', role_args('read', role))
    require(role_report.get('bind_secret_id') is True and role_report.get('token_no_default_policy') is True and role_report.get('token_policies') == [policy], 'AppRole configuration lost explicit credential restrictions.')

    STAGE = 'private-credential-export'
    role_id_path, bundle_path = fixture / 'f06-role-id', fixture / 'f06-credentials.json'
    run('role-id', role_args('role-id', '--out', str(role_id_path), role))
    role_id = raw_token(role_id_path)
    credentials_report = run('credentials', role_args('credentials', '--out', str(bundle_path), role))
    credentials = json.loads(bundle_path.read_text())
    artifacts.append(bundle_path)
    require(set(credentials) == {'role_id', 'secret_id', 'secret_id_accessor'} and credentials['role_id'] == role_id and all(credentials.values()), 'AppRole credential bundle omitted required private fields.')
    forbidden.extend(credentials.values())
    require(stat.S_IMODE(bundle_path.stat().st_mode) == 0o600 and credentials_report.get('ttl_seconds', 0) > 0, 'AppRole credential output was not private or bounded.')
    occupied = fixture / 'f06-occupied-output'
    private_write(occupied, b'private-f06-existing-artifact')
    artifacts.append(occupied)
    digest = hashlib.sha256(occupied.read_bytes()).digest()
    before = secret_id_count()
    run('credentials-existing', role_args('credentials', '--out', str(occupied), role), expected=1)
    require(secret_id_count() == before and hashlib.sha256(occupied.read_bytes()).digest() == digest, 'An occupied credential output minted a SecretID or changed the file.')
    link = fixture / 'f06-output-symlink'
    link.symlink_to(occupied)
    run('credentials-symlink', role_args('credentials', '--out', str(link), role), expected=1)
    require(link.is_symlink() and secret_id_count() == before and hashlib.sha256(occupied.read_bytes()).digest() == digest, 'Credential export followed a symlink or minted before output validation.')

    STAGE = 'login-and-permissions'
    login_path = fixture / 'f06-login-token'
    login_report = run('login', role_args('login', '--file', str(bundle_path), '--out', str(login_path)))
    login_token = raw_token(login_path)
    entity_id = login_report.get('entity_id')
    require(login_report.get('policies') == [policy] and login_report.get('ttl_seconds', 0) > 0 and entity_id, 'AppRole login inherited issuer policies or lost identity metadata.')
    read_value(login_token, 'allowed/item', True)
    read_value(login_token, 'extra/item', False)
    read_value(login_token, 'denied/item', False)
    capabilities = run('capabilities', ['token', 'capabilities', mount + '/data/allowed/item', mount + '/data/denied/item'], token_path=login_path)
    permissions = {entry['path']: entry['capabilities'] for entry in capabilities}
    require('read' in permissions.get(mount + '/data/allowed/item', []) and permissions.get(mount + '/data/denied/item') == ['deny'], 'Self capabilities confused physical paths or permissions.')
    run('application-admin-denied', ['policy', 'list'], expected=2, token_path=login_path)

    STAGE = 'identity-and-groups'
    entity_spec, entity_update = fixture / 'f06-entity.json', fixture / 'f06-entity-update.json'
    write_json(entity_spec, {'name': 'f06-independent-entity', 'policies': [policy], 'disabled': False})
    write_json(entity_update, {'name': 'f06-independent-entity', 'policies': [policy], 'disabled': True})
    entity = run('entity-write', ['identity', 'entity', 'write', '--file', str(entity_spec)])
    independent_id = entity.get('id')
    require(independent_id and independent_id in run('entity-list', ['identity', 'entity', 'list']), 'Identity creation or listing omitted the selected entity.')
    run('entity-update', ['identity', 'entity', 'write', '--file', str(entity_update), independent_id])
    require(run('entity-read', ['identity', 'entity', 'read', independent_id]).get('disabled') is True, 'Explicit entity update did not retain its disabled state.')
    run('entity-delete', ['identity', 'entity', 'delete', '--force', independent_id])
    run('entity-absent', ['identity', 'entity', 'read', independent_id], expected=3)
    extra_file, group_file = fixture / 'f06-extra-policy.hcl', fixture / 'f06-group.json'
    private_write(extra_file, ('path "' + mount + '/data/extra/item" { capabilities = ["read"] }').encode())
    artifacts.append(extra_file)
    run('extra-policy-write', ['policy', 'write', '--file', str(extra_file), extra_policy])
    write_json(group_file, {'name': 'f06-internal-group', 'policies': [extra_policy], 'member_entity_ids': [entity_id], 'member_group_ids': []})
    group = run('group-write', ['identity', 'group', 'write', '--file', str(group_file)])
    group_id = group.get('id')
    require(group_id and group_id in run('group-list', ['identity', 'group', 'list']), 'Identity group listing omitted the explicitly created group.')
    group_read = run('group-read', ['identity', 'group', 'read', group_id])
    require(group_read.get('type') == 'internal' and group_read.get('member_entity_ids') == [entity_id] and group_read.get('policies') == [extra_policy], 'Identity group projection lost its explicit membership or policy.')
    read_value(login_token, 'extra/item', True)
    run('group-delete', ['identity', 'group', 'delete', '--force', group_id])
    read_value(login_token, 'extra/item', False)

    STAGE = 'token-create-self-revoke'
    created_path = fixture / 'f06-created-token'
    created_report = run('token-create', ['token', 'create', '--file', str(token_spec), '--out', str(created_path)])
    created_token = raw_token(created_path)
    require(created_report.get('policies') == [policy] and 0 < created_report.get('ttl_seconds', 0) <= 60, 'Created token inherited root policy or lost its finite lifetime.')
    read_value(created_token, 'allowed/item', True)
    read_value(created_token, 'denied/item', False)
    run('token-revoke-self', ['token', 'revoke-self', '--force'], token_path=created_path)
    read_value(created_token, 'allowed/item', False)

    STAGE = 'shell-fixed-context'
    shell_token_path, script_path = fixture / 'f06-shell-token', fixture / 'f06-session.sw'
    private_write(script_path, ('approle login --auth-mount ' + auth_mount + ' --file "' + str(bundle_path) + '" --out "' + str(shell_token_path) + '"\ntoken capabilities sys/auth\nhistory\n').encode())
    artifacts.append(script_path)
    session = run('session', ['shell', '--script', str(script_path)])
    shell_token = raw_token(shell_token_path)
    require(len(session) == 3 and session[0].get('entity_id') == entity_id and session[1] == [{'path': 'sys/auth', 'capabilities': ['root']}] and session[2] == [], 'Access shell commands changed the operator session or retained sensitive history.')
    read_value(shell_token, 'allowed/item', True)

    STAGE = 'separate-secret-and-token-revocation'
    run('secret-id-revoke', role_args('revoke-secret-id', '--file', str(bundle_path), role))
    failed_path = fixture / 'f06-rejected-login-token'
    run('rejected-login', role_args('login', '--file', str(bundle_path), '--out', str(failed_path)), expected=1)
    require(not failed_path.exists(), 'Rejected login retained an incomplete credential output.')
    read_value(login_token, 'allowed/item', True)
    run('token-revoke', ['token', 'revoke', '--force', '--file', str(login_path)])
    read_value(login_token, 'allowed/item', False)
    run('shell-token-revoke', ['token', 'revoke', '--force', '--file', str(shell_token_path)])
    read_value(shell_token, 'allowed/item', False)
    run('role-delete', role_args('delete', '--force', role))
    run('role-absent', role_args('read', role), expected=3)
    run('policy-delete', ['policy', 'delete', '--force', policy])
    run('policy-absent', ['policy', 'read', policy], expected=3)
    run('extra-policy-delete', ['policy', 'delete', '--force', extra_policy])

    STAGE = 'capture-audit'
    for path in artifacts + captures:
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, 'Access smoke created a non-private artifact or capture.')
    for path in captures:
        data = path.read_text()
        require(all(value not in data for value in forbidden), 'Access smoke exposed a credential in captured output.')
    print('CLI access smoke passed: policies, bounded AppRole/token issuance, private files, permissions, identities and separate revocation.')


if __name__ == '__main__':
    try:
        main()
    except SmokeFailure as error:
        raise SystemExit(str(error) + ' [stage=' + STAGE + ']') from None
    except Exception as error:
        raise SystemExit('Private access smoke fixture failed: ' + safe_exception_details(error)) from None
