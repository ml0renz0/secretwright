#!/usr/bin/env python3
"""Private executable acceptance checks for managed blueprint reconciliation."""

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


def documents(source):
    decoder, result = json.JSONDecoder(), []
    while source.strip():
        source = source.lstrip()
        value, end = decoder.raw_decode(source)
        result.append(value)
        source = source[end:]
    return result


def main():
    global STAGE
    binary, fixture = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    before = set(fixture.iterdir())
    address, root_file = os.environ['VAULT_ADDR'], fixture / 'root-token'
    root_token = root_file.read_text().strip()
    environment = dict(os.environ, VAULT_TOKEN='private-f09-inherited-token', VAULT_NAMESPACE='private-f09-inherited-namespace')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    artifacts, captures = [], []
    forbidden = [root_token, 'private-f09-inherited-token', 'private-f09-secret', 'private-f09-policy-body']

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
            with opener.open(message, timeout=5) as response:
                body = response.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            if error.code == expected:
                return None
            raise

    def run(name, args, expected=0):
        depth = 2 if args[0] in ['blueprint', 'approle'] else 1
        injected = ['--address', address, '--namespace', '', '--timeout', '1m']
        if args[:2] != ['approle', 'login']:
            injected += ['--token-file', str(root_file)]
        command = [str(binary), *args[:depth], *injected, *args[depth:]]
        # Captures have their own namespace so a check cannot reuse an input
        # inventory filename reserved by the fixture.
        output, error = fixture / ('f09-capture-' + name + '.json'), fixture / ('f09-capture-' + name + '.err')
        descriptors = [os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600) for path in [output, error]]
        captures.extend([output, error])
        with os.fdopen(descriptors[0], 'w') as stdout, os.fdopen(descriptors[1], 'w') as stderr:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=environment, cwd=fixture, timeout=30)
        body, diagnostics = output.read_text(), error.read_text()
        require(result.returncode == expected, 'Managed CLI returned an unexpected exit code [check=' + name + '].')
        require((not diagnostics) if expected == 0 else bool(diagnostics), 'Managed CLI emitted unexpected diagnostics.')
        require(all(value not in body + diagnostics for value in forbidden), 'Managed CLI exposed credentials, policy contents or secret data.')
        require(all(value not in body for value in ['"baseline_sha256"', '"identity_sha256"', '"spec"']), 'Managed CLI dumped its private inventory or specifications.')
        decoded = documents(body)
        return decoded[0] if len(decoded) == 1 else decoded

    STAGE = 'initial-installation-and-adoption'
    mount, auth, name = 'f09-smoke-kv', 'f09-smoke-auth', 'f09-smoke'
    policy, role = name + '-access', name + '-role'
    request('sys/auth/' + auth, {'type': 'approle'})
    source = {'api_version': 'secretwright/v1', 'name': name, 'resources': [
        {'id': 'storage', 'kind': 'kv_mount', 'name': mount, 'spec': {'version': 2}},
        {'id': 'access', 'kind': 'policy', 'name': policy, 'depends_on': ['storage'], 'spec': {'policy': '# private-f09-policy-body\npath "' + mount + '/data/allowed/item" { capabilities = ["read"] }'}},
        {'id': 'role', 'kind': 'approle', 'name': role, 'depends_on': ['access'], 'spec': {'auth_mount': auth, 'token_policies': [policy], 'token_ttl': '2m', 'token_max_ttl': '5m', 'secret_id_ttl': '2m', 'secret_id_num_uses': 5}},
    ]}
    original, desired_file, state_file = fixture / 'f09-original.json', fixture / 'f09-desired.json', fixture / 'f09-state.json'
    write_file(original, json.dumps(source))
    applied = run('initial-apply', ['blueprint', 'apply', '--file', str(original)])
    require(len(applied.get('items', [])) == 3 and all(item.get('status') == 'created' for item in applied['items']), 'Could not prepare the pre-F09 installation.')
    run('adopt', ['blueprint', 'adopt', '--file', str(original), '--state', str(state_file)])
    artifacts.append(state_file)
    state = json.loads(state_file.read_text())
    require(state.get('api_version') == 'secretwright/state/v1' and len(state.get('resources', [])) == 3 and state.get('revision') == 1, 'Adoption did not create a complete versioned inventory.')
    require(all(not item.get('pending') for item in state['resources']), 'Adoption invented a pending mutation.')
    digest = hashlib.sha256(state_file.read_bytes()).digest()
    plan = run('initial-plan', ['blueprint', 'plan', '--file', str(original), '--state', str(state_file)])
    require(plan.get('changes') == [] and hashlib.sha256(state_file.read_bytes()).digest() == digest, 'Read-only managed plan changed state or lost equivalence.')
    for key in ['allowed/item', 'denied/item']:
        request(mount + '/data/' + key, {'data': {'value': 'private-f09-secret'}})
    bundle, token_file = fixture / 'f09-bundle.json', fixture / 'f09-token'
    run('credentials', ['approle', 'credentials', '--auth-mount', auth, '--out', str(bundle), role])
    artifacts.append(bundle)
    forbidden.extend(json.loads(bundle.read_text()).values())
    run('login', ['approle', 'login', '--auth-mount', auth, '--file', str(bundle), '--out', str(token_file)])
    artifacts.append(token_file)
    token = token_file.read_text().strip()
    forbidden.append(token)
    require(request(mount + '/data/allowed/item', method='GET', token=token)['data']['data'] == {'value': 'private-f09-secret'}, 'Initial credential lost its original permission.')

    STAGE = 'intentional-updates-and-idempotence'
    source['resources'][1]['spec']['policy'] = 'path "' + mount + '/data/denied/item" { capabilities = ["read"] }'
    source['resources'][2]['spec']['token_ttl'] = '1m'
    write_file(desired_file, json.dumps(source))
    planned = run('update-plan', ['blueprint', 'plan', '--file', str(desired_file), '--state', str(state_file)])
    require(len(planned.get('changes', [])) == 2 and all(item.get('action') == 'update' for item in planned['changes']), 'Managed plan did not identify its intentional policy and role updates.')
    updated = run('update-apply', ['blueprint', 'apply', '--file', str(desired_file), '--state', str(state_file)])
    require(sum(item.get('status') == 'updated' for item in updated.get('items', [])) == 2, 'Managed apply did not report both declared updates.')
    require(request(mount + '/data/allowed/item', method='GET', token=token, expected=403) is None, 'Existing token retained a removed ACL grant.')
    require(request(mount + '/data/denied/item', method='GET', token=token)['data']['data'] == {'value': 'private-f09-secret'}, 'Existing token did not gain its updated ACL permission.')
    digest = hashlib.sha256(state_file.read_bytes()).digest()
    require(run('empty-plan', ['blueprint', 'plan', '--file', str(desired_file), '--state', str(state_file)]).get('changes') == [], 'Confirmed managed application did not produce an empty plan.')
    repeated = run('repeat-apply', ['blueprint', 'apply', '--file', str(desired_file), '--state', str(state_file)])
    require(all(item.get('status') == 'unchanged' for item in repeated.get('items', [])) and hashlib.sha256(state_file.read_bytes()).digest() == digest, 'Idempotent managed apply rewrote its resource or inventory baseline.')

    STAGE = 'external-drift-and-explicit-repair'
    request('sys/policies/acl/' + policy, {'policy': 'path "' + mount + '/data/allowed/item" { capabilities = ["read"] }'})
    drift = run('drift-plan', ['blueprint', 'plan', '--file', str(desired_file), '--state', str(state_file)], expected=4)
    require(any(item.get('action') == 'drift' and item.get('drift') for item in drift.get('changes', [])), 'External policy drift was not explicit in the plan.')
    run('drift-blocked', ['blueprint', 'apply', '--file', str(desired_file), '--state', str(state_file)], expected=4)
    require(hashlib.sha256(state_file.read_bytes()).digest() == digest and request(mount + '/data/allowed/item', method='GET', token=token) is not None, 'Conflicting preflight advanced state or overwrote external ACL changes.')
    run('repair', ['blueprint', 'apply', '--file', str(desired_file), '--state', str(state_file), '--repair'])
    require(request(mount + '/data/allowed/item', method='GET', token=token, expected=403) is None and request(mount + '/data/denied/item', method='GET', token=token) is not None, 'Explicit repair did not restore the desired effective permissions.')

    STAGE = 'target-binding-retention-and-recovery'
    retained_file = fixture / 'f09-retained.json'
    retained = dict(source, resources=source['resources'][:2])
    write_file(retained_file, json.dumps(retained))
    retained_plan = run('retained-plan', ['blueprint', 'plan', '--file', str(retained_file), '--state', str(state_file)])
    require(retained_plan.get('changes') == [] and any(item.get('id') == 'role' and item.get('action') == 'retain' for item in retained_plan.get('resources', [])), 'Removed resource was not retained explicitly.')
    run('retained-apply', ['blueprint', 'apply', '--file', str(retained_file), '--state', str(state_file)])
    require(request('auth/' + auth + '/role/' + role, method='GET') is not None, 'Managed application deleted a resource omitted from its descriptor.')
    current = json.loads(state_file.read_text())
    wrong_file = fixture / 'f09-wrong-target.json'
    wrong = json.loads(json.dumps(current))
    wrong['target']['address_sha256'] = '0' * 64
    write_file(wrong_file, json.dumps(wrong))
    require(run('wrong-target', ['blueprint', 'plan', '--file', str(desired_file), '--state', str(wrong_file)], expected=4) == [], 'Wrong-target inventory emitted an apparently successful plan.')
    pending_file = fixture / 'f09-pending.json'
    pending = json.loads(json.dumps(current))
    next(item for item in pending['resources'] if item['id'] == 'access')['pending'] = 'update'
    pending['revision'] += 1
    write_file(pending_file, json.dumps(pending))
    run('pending-blocked', ['blueprint', 'apply', '--file', str(desired_file), '--state', str(pending_file)], expected=4)
    policy_before = request('sys/policies/acl/' + policy, method='GET')['data']['policy']
    run('recover', ['blueprint', 'recover', '--file', str(desired_file), '--state', str(pending_file)])
    recovered = json.loads(pending_file.read_text())
    require(all(not item.get('pending') for item in recovered['resources']) and recovered['revision'] == pending['revision'] + 1, 'Explicit recovery did not confirm its pending checkpoint.')
    require(request('sys/policies/acl/' + policy, method='GET')['data']['policy'] == policy_before, 'Read-only recovery replayed a Vault mutation.')
    session_file = fixture / 'f09-session.sw'
    write_file(session_file, 'blueprint plan --file "' + str(desired_file) + '" --state "' + str(state_file) + '"\nhistory\n')
    session = run('session', ['shell', '--no-prompt', '--script', str(session_file)])
    require(isinstance(session, list) and len(session) == 2 and session[0].get('changes') == [] and session[1] == [], 'Managed shell command lost its fixed connection or entered history.')

    STAGE = 'privacy-audit'
    for path in artifacts + captures:
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, 'Managed smoke created a non-private file.')
    for path in captures + [state_file, pending_file]:
        require(all(value not in path.read_text() for value in forbidden), 'Managed smoke exposed credentials, secrets or policy contents.')
    require(set(fixture.iterdir()) - before == set(artifacts + captures), 'Managed commands left unexpected state, lock or temporary artifacts.')
    print('CLI reconciliation smoke passed: explicit adoption, managed updates, drift protection/repair, private checkpoints, recovery, retention and shell.')


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
        raise SystemExit('Private reconciliation fixture failed [stage=' + STAGE + '; class=' + type(error).__name__ + '; script_lines=' + ','.join(frames) + ']') from None
