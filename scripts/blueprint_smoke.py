#!/usr/bin/env python3
"""Private executable acceptance checks for the declarative blueprint engine."""

from pathlib import Path
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


def private_write(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as target:
        target.write(value)


def decode_documents(source):
    decoder = json.JSONDecoder()
    documents = []
    while source.strip():
        source = source.lstrip()
        value, end = decoder.raw_decode(source)
        documents.append(value)
        source = source[end:]
    return documents


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
    before_files = set(fixture.iterdir())
    address = os.environ['VAULT_ADDR']
    root_file = fixture / 'root-token'
    root_token = root_file.read_text().strip()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    mount, auth_mount, prefix = 'f07-smoke-kv', 'f07-smoke-approle', 'f07-smoke-app'
    policy, role = prefix + '-read', prefix + '-role'
    forbidden = [root_token, 'private-f07-secret-value', 'private-f07-policy-body', 'private-f07-variable-note', 'f07-deliberately-invalid-inherited-token']
    artifacts, captures = [], []
    environment = dict(os.environ)
    environment['VAULT_TOKEN'] = 'f07-deliberately-invalid-inherited-token'
    environment['VAULT_NAMESPACE'] = 'private-f07-invalid-inherited-namespace'

    def request(path, payload=None, method='POST', token=root_token, expected=None):
        body = None if payload is None else json.dumps(payload).encode()
        message = urllib.request.Request(address + '/v1/' + urllib.parse.quote(path, safe='/'), data=body, method=method)
        if token:
            message.add_header('X-Vault-Token', token)
        message.add_header('Content-Type', 'application/json')
        try:
            with opener.open(message, timeout=5) as response:
                data = response.read()
                return json.loads(data) if data else None
        except urllib.error.HTTPError as error:
            if expected is not None and error.code == expected:
                return None
            raise

    def write_file(path, source):
        private_write(path, source.encode())
        artifacts.append(path)

    def run(name, args, expected=0, online=True, token_path=root_file, selected_environment=None):
        output_path = fixture / ('f07-' + name + '-stdout.json')
        error_path = fixture / ('f07-' + name + '-stderr.txt')
        depth = 2 if args[0] in ['blueprint', 'approle'] else 1
        injected = []
        if online:
            injected = ['--address', address, '--namespace', '', '--timeout', '1m']
            if args[:2] != ['approle', 'login']:
                injected += ['--token-file', str(token_path)]
        command = [str(binary), *args[:depth], *injected, *args[depth:]]
        with open(output_path, 'xb') as output, open(error_path, 'xb') as error:
            os.chmod(output_path, 0o600)
            os.chmod(error_path, 0o600)
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output, stderr=error, env=selected_environment or environment, cwd=fixture, timeout=20)
        captures.extend([output_path, error_path])
        stdout, stderr = output_path.read_text(), error_path.read_text()
        require(result.returncode == expected, 'Blueprint CLI command returned an unexpected exit code.')
        require((not stderr) if expected == 0 else bool(stderr), 'Blueprint CLI command produced unexpected diagnostics.')
        require(all(value not in stdout + stderr for value in forbidden), 'Blueprint CLI exposed configuration contents or credentials.')
        documents = decode_documents(stdout)
        return documents[0] if len(documents) == 1 else documents

    STAGE = 'fixture-prerequisite'
    request('sys/auth/' + auth_mount, {'type': 'approle'})
    source = '''api_version: secretwright/v1
name: ${var.prefix}
variables:
  storage: {type: string}
  prefix: {type: string}
  uses: {type: integer}
  disabled: {type: boolean}
  note: {type: string, default: private-f07-variable-note}
resources:
  - id: storage
    kind: kv_mount
    name: ${var.storage}
    spec: {version: 2}
  - id: read
    kind: policy
    name: ${var.prefix}-read
    depends_on: [storage]
    spec:
      policy: |
        # private-f07-policy-body ${var.note}
        path "${var.storage}/data/allowed/item" { capabilities = ["read"] }
  - id: role
    kind: approle
    name: ${var.prefix}-role
    depends_on: [read]
    spec:
      auth_mount: __AUTH_MOUNT__
      token_policies: ["${var.prefix}-read"]
      token_ttl: 2m
      token_max_ttl: 5m
      secret_id_ttl: 2m
      secret_id_num_uses: "${var.uses}"
  - id: entity
    kind: entity
    name: ${var.prefix}-entity
    depends_on: [read]
    spec: {policies: [], disabled: "${var.disabled}"}
  - id: base-group
    kind: group
    name: ${var.prefix}-base
    depends_on: [read]
    spec:
      policies: ["${var.prefix}-read"]
      member_entities: [entity]
  - id: group
    kind: group
    name: ${var.prefix}-group
    spec: {member_groups: [base-group]}
'''.replace('__AUTH_MOUNT__', auth_mount)
    blueprint_file, vars_file = fixture / 'f07-blueprint.yaml', fixture / 'f07-vars.json'
    write_file(blueprint_file, source)
    write_file(vars_file, json.dumps({'storage': mount, 'prefix': prefix, 'uses': 5, 'disabled': False}))
    inputs = ['--file', str(blueprint_file), '--vars', str(vars_file)]

    STAGE = 'offline-schema-validation'
    offline = dict(environment, VAULT_ADDR='private-f07-invalid-address')
    schema = run('schema', ['blueprint', 'schema'], online=False, selected_environment=offline)
    require(schema.get('$id') == 'urn:secretwright:blueprint:v1' and '$schema' in schema, 'Blueprint schema was not the fixed local version.')
    validated = run('validate', ['blueprint', 'validate', *inputs], online=False, selected_environment=offline)
    require(validated.get('name') == prefix and validated.get('resources') == 6 and len(validated.get('order', [])) == 6, 'Offline validation did not expand typed variables or sort dependencies.')
    run('validate-missing-vars', ['blueprint', 'validate', '--file', str(blueprint_file)], expected=1, online=False, selected_environment=offline)
    unknown_vars = fixture / 'f07-unknown-vars.json'
    write_file(unknown_vars, json.dumps({'storage': mount, 'prefix': prefix, 'uses': 5, 'disabled': False, 'unknown': 'private-f07-unknown-variable'}))
    forbidden.append('private-f07-unknown-variable')
    run('validate-unknown-vars', ['blueprint', 'validate', '--file', str(blueprint_file), '--vars', str(unknown_vars)], expected=1, online=False, selected_environment=offline)
    offline_script = fixture / 'f07-offline-session.sw'
    write_file(offline_script, 'blueprint schema\nblueprint validate --file "' + str(blueprint_file) + '" --vars "' + str(vars_file) + '"\nhistory\n')
    offline_session = run('offline-session', ['shell', '--address', 'private-f07-invalid-address', '--token-file', str(fixture / 'missing-f07-token'), '--script', str(offline_script)], online=False, selected_environment=offline)
    require(isinstance(offline_session, list) and len(offline_session) == 3 and offline_session[1].get('resources') == 6 and offline_session[2] == [], 'Offline blueprint commands consulted session credentials or entered history.')

    STAGE = 'plan-create-idempotence'
    plan = run('plan', ['blueprint', 'plan', *inputs])
    require(len(plan.get('resources', [])) == 6 and len(plan.get('changes', [])) == 6 and all(item.get('action') == 'create' for item in plan['changes']), 'Blueprint plan did not identify only its declared creations.')
    require(mount + '/' not in request('sys/mounts', method='GET')['data'], 'Blueprint plan created its KV engine.')
    applied = run('apply', ['blueprint', 'apply', *inputs])
    require(len(applied.get('items', [])) == 6 and all(item.get('status') == 'created' for item in applied['items']), 'Blueprint apply did not create every declared resource.')
    ids = {item['id']: item.get('remote_id') for item in applied['items']}
    require(all(ids.get(key) for key in ['entity', 'base-group', 'group']), 'Blueprint apply did not expose identity IDs for its logical references.')
    base_group = request('identity/group/id/' + ids['base-group'], method='GET')['data']
    group = request('identity/group/id/' + ids['group'], method='GET')['data']
    require(base_group.get('member_entity_ids') == [ids['entity']] and group.get('member_group_ids') == [ids['base-group']], 'Blueprint group references did not resolve to actual Vault IDs.')
    original_policy = request('sys/policies/acl/' + policy, method='GET')['data']['policy']
    original_role = request('auth/' + auth_mount + '/role/' + role, method='GET')['data']
    empty = run('empty-plan', ['blueprint', 'plan', *inputs])
    require(empty.get('changes') == [] and len(empty.get('resources', [])) == 6, 'An applied blueprint did not produce an empty plan.')
    unchanged = run('apply-again', ['blueprint', 'apply', *inputs])
    require(len(unchanged.get('items', [])) == 6 and all(item.get('status') == 'unchanged' for item in unchanged['items']), 'Second blueprint apply was not idempotent.')
    require(request('auth/' + auth_mount + '/role/' + role, method='GET')['data'] == original_role, 'Idempotent apply changed an existing AppRole configuration.')

    STAGE = 'permissions-after-apply'
    for key in ['allowed/item', 'denied/item']:
        request(mount + '/data/' + key, {'data': {'value': 'private-f07-secret-value'}})
    bundle_file, token_file = fixture / 'f07-credentials.json', fixture / 'f07-application-token'
    run('credentials', ['approle', 'credentials', '--auth-mount', auth_mount, '--out', str(bundle_file), role])
    artifacts.append(bundle_file)
    credentials = json.loads(bundle_file.read_text())
    forbidden.extend(credentials.values())
    run('login', ['approle', 'login', '--auth-mount', auth_mount, '--file', str(bundle_file), '--out', str(token_file)])
    artifacts.append(token_file)
    token = token_file.read_text().strip()
    forbidden.append(token)
    value = request(mount + '/data/allowed/item', method='GET', token=token)
    require(value['data']['data'] == {'value': 'private-f07-secret-value'}, 'Blueprint-created access resources did not grant the declared permission.')
    require(request(mount + '/data/denied/item', method='GET', token=token, expected=403) is None, 'Blueprint application token gained an undeclared permission.')

    STAGE = 'conflict-preflight'
    extra_resource = '''  - id: a-uncreated
    kind: policy
    name: ${var.prefix}-uncreated
    spec: {policy: 'path "application/data/item" { capabilities = ["read"] }'}
'''
    conflicting = fixture / 'f07-conflicting-policy.yaml'
    write_file(conflicting, source.replace('/data/allowed/item', '/data/denied/item') + extra_resource)
    conflict_inputs = ['--file', str(conflicting), '--vars', str(vars_file)]
    conflict = run('conflict-plan', ['blueprint', 'plan', *conflict_inputs], expected=4)
    require(any(item.get('action') == 'conflict' for item in conflict.get('changes', [])), 'Existing different policy was not an explicit plan conflict.')
    run('conflict-apply', ['blueprint', 'apply', *conflict_inputs], expected=4)
    require(request('sys/policies/acl/' + policy, method='GET')['data']['policy'] == original_policy and request('sys/policies/acl/' + prefix + '-uncreated', method='GET', expected=404) is None, 'Blueprint conflict changed an existing resource or created another one.')
    wrong_version = fixture / 'f07-conflicting-version.yaml'
    write_file(wrong_version, source.replace('spec: {version: 2}', 'spec: {version: 1}') + extra_resource)
    run('version-conflict', ['blueprint', 'apply', '--file', str(wrong_version), '--vars', str(vars_file)], expected=4)
    require(request('sys/mounts', method='GET')['data'][mount + '/']['options']['version'] == '2' and request('sys/policies/acl/' + prefix + '-uncreated', method='GET', expected=404) is None, 'Blueprint migrated an engine or wrote after an engine conflict.')
    denied = run('denied-plan', ['blueprint', 'plan', *inputs], expected=2, token_path=token_file)
    require(denied == [], 'Denied blueprint preflight published a partial successful plan.')
    run('denied-apply', ['blueprint', 'apply', *inputs], expected=2, token_path=token_file)

    STAGE = 'shell-fixed-context'
    script = fixture / 'f07-session.sw'
    command_inputs = ' --file "' + str(blueprint_file) + '" --vars "' + str(vars_file) + '"'
    write_file(script, 'blueprint validate' + command_inputs + '\nblueprint plan' + command_inputs + '\nblueprint apply' + command_inputs + '\nhistory\n')
    session = run('session', ['shell', '--cwd', '/unrelated/logical/path', '--script', str(script)])
    require(isinstance(session, list) and len(session) == 4 and session[0].get('resources') == 6 and session[1].get('changes') == [] and all(item.get('status') == 'unchanged' for item in session[2].get('items', [])) and session[3] == [], 'Blueprint shell commands lost fixed context, inherited cwd or entered history.')

    STAGE = 'artifact-audit'
    for path in artifacts + captures:
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, 'Blueprint smoke created a non-private artifact or capture.')
    for path in captures:
        data = path.read_text()
        require(all(value not in data for value in forbidden), 'Blueprint smoke exposed configuration contents or credentials.')
    require(set(fixture.iterdir()) - before_files == set(artifacts + captures), 'Blueprint commands wrote an unexpected state or plan artifact.')
    print('CLI blueprint smoke passed: offline schema/validation, typed variables, dependent resources, empty repeat plans, conflicts and permissions.')


if __name__ == '__main__':
    try:
        main()
    except SmokeFailure as error:
        raise SystemExit(str(error) + ' [stage=' + STAGE + ']') from None
    except Exception as error:
        raise SystemExit('Private blueprint smoke fixture failed: ' + safe_exception_details(error)) from None
