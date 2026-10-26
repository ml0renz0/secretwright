#!/usr/bin/env python3
"""Private CLI acceptance checks for offline architecture templates."""

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


def decode_documents(source):
    decoder, documents = json.JSONDecoder(), []
    while source.strip():
        source = source.lstrip()
        value, end = decoder.raw_decode(source)
        documents.append(value)
        source = source[end:]
    return documents


def main():
    global STAGE
    binary, fixture = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    before = set(fixture.iterdir())
    address, root_file = os.environ['VAULT_ADDR'], fixture / 'root-token'
    root_token = root_file.read_text().strip()
    artifacts, captures = [], []
    forbidden = [root_token, 'private-f08-secret-value', 'private-f08-unknown-value', 'private-f08-inherited-token']
    environment = dict(os.environ, VAULT_TOKEN='private-f08-inherited-token', VAULT_NAMESPACE='private-f08-inherited-namespace')
    offline = dict(environment, VAULT_ADDR='private-f08-invalid-address', VAULT_CLIENT_TIMEOUT='private-f08-invalid-timeout')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def write_file(path, source):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as target:
            target.write(source)
        artifacts.append(path)

    def run(name, arguments, expected=0, online=False, json_output=True):
        output, diagnostic = fixture / ('f08-' + name + '.json'), fixture / ('f08-' + name + '.err')
        command = [str(binary), *arguments]
        if online:
            injected = ['--address', address, '--namespace', '', '--timeout', '1m']
            if arguments[:2] != ['approle', 'login']:
                injected += ['--token-file', str(root_file)]
            command = command[:3] + injected + command[3:]
        descriptors = [os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600) for path in [output, diagnostic]]
        captures.extend([output, diagnostic])
        with os.fdopen(descriptors[0], 'w') as stdout, os.fdopen(descriptors[1], 'w') as stderr:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=environment if online else offline, cwd=fixture, timeout=30)
        body, errors = output.read_text(), diagnostic.read_text()
        require(result.returncode == expected, 'Architecture CLI returned an unexpected exit code [check=' + name + '].')
        require((not errors) if expected == 0 else bool(errors), 'Architecture CLI emitted unexpected diagnostics.')
        require(all(value not in body + errors for value in forbidden), 'Architecture CLI exposed a credential, secret, or rejected input.')
        if not json_output:
            require(expected == 0 or not body, 'Rejected architecture command emitted partial successful output.')
            return None, body
        documents = decode_documents(body)
        require(expected == 0 or not documents, 'Rejected architecture command emitted partial successful JSON.')
        return (documents[0] if len(documents) == 1 else documents), body

    def request(path, payload=None, method='POST', token=root_token, expected=None):
        body = None if payload is None else json.dumps(payload).encode()
        message = urllib.request.Request(address + '/v1/' + urllib.parse.quote(path, safe='/'), data=body, method=method)
        message.add_header('Content-Type', 'application/json')
        message.add_header('X-Vault-Token', token)
        try:
            with opener.open(message, timeout=5) as response:
                value = response.read()
                return json.loads(value) if value else None
        except urllib.error.HTTPError as error:
            if error.code == expected:
                return None
            raise

    STAGE = 'offline-catalog'
    expected_catalog = ['multi-app', 'multi-env', 'multi-user', 'saas', 'single-app', 'single-user']
    catalog, _ = run('catalog', ['template', 'list'])
    require([item.get('name') for item in catalog] == expected_catalog and all(item.get('description') for item in catalog), 'Architecture catalog is incomplete or unstable.')
    schema, _ = run('schema', ['template', 'schema'])
    require(schema.get('$id') == 'urn:secretwright:architecture:v1' and '$schema' in schema, 'Architecture schema is not the published local version.')
    for name in expected_catalog:
        example, source = run('show-' + name, ['template', 'show', '--format', 'json', name])
        require(example.get('api_version') == 'secretwright/architecture/v1' and example.get('instances', [{}])[0].get('template') == name, 'Architecture show did not return an editable complete manifest.')
        path = fixture / ('f08-example-' + name + '.json')
        write_file(path, source)
        rendered, first = run('render-' + name, ['template', 'render', '--format', 'json', '--file', str(path)])
        _, second = run('repeat-' + name, ['template', 'render', '--format', 'json', '--file', str(path)])
        require(first == second and rendered.get('api_version') == 'secretwright/v1' and rendered.get('resources'), 'Architecture output is not a deterministic F07 descriptor.')
        blueprint_file = fixture / ('f08-blueprint-' + name + '.json')
        write_file(blueprint_file, first)
        validated, _ = run('validate-' + name, ['blueprint', 'validate', '--file', str(blueprint_file)])
        require(validated.get('resources') == len(rendered['resources']), 'Architecture output was rejected by F07 offline validation.')

        _, yaml_source = run('show-default-yaml-' + name, ['template', 'show', name], json_output=False)
        _, explicit_yaml = run('show-explicit-yaml-' + name, ['template', 'show', '--format', 'yaml', name], json_output=False)
        require(yaml_source == explicit_yaml and not yaml_source.lstrip().startswith('{') and yaml_source.endswith('\n'), 'Architecture show did not default to deterministic editable YAML.')
        yaml_path = fixture / ('f08-example-' + name + '.yaml')
        write_file(yaml_path, yaml_source)
        yaml_as_json, _ = run('yaml-input-json-output-' + name, ['template', 'render', '--format', 'json', '--file', str(yaml_path)])
        require(yaml_as_json == rendered, 'Default YAML manifest changed typed configuration or policy contents.')
        _, yaml_blueprint = run('render-default-yaml-' + name, ['template', 'render', '--file', str(yaml_path)], json_output=False)
        _, repeated_yaml = run('repeat-default-yaml-' + name, ['template', 'render', '--file', str(yaml_path)], json_output=False)
        require(yaml_blueprint == repeated_yaml and not yaml_blueprint.lstrip().startswith('{') and yaml_blueprint.endswith('\n'), 'Architecture render did not default to deterministic YAML.')
        yaml_blueprint_file = fixture / ('f08-blueprint-' + name + '.yaml')
        write_file(yaml_blueprint_file, yaml_blueprint)
        validated_yaml, _ = run('validate-yaml-' + name, ['blueprint', 'validate', '--file', str(yaml_blueprint_file)])
        require(validated_yaml == validated, 'Default YAML blueprint did not preserve complete validated resource specifications.')

    STAGE = 'offline-errors-and-shell'
    invalid = fixture / 'f08-invalid.json'
    write_file(invalid, json.dumps({'api_version': 'secretwright/architecture/v1', 'name': 'example', 'instances': [{'id': 'main', 'template': 'single-user', 'mount': 'example', 'users': ['alice'], 'unknown': 'private-f08-unknown-value'}]}))
    run('reject-unknown-field', ['template', 'render', '--file', str(invalid)], expected=1)
    run('reject-stdin', ['template', 'render', '--file', '-'], expected=1)
    run('reject-connection', ['template', 'render', '--file', str(invalid), '--token-file', str(fixture / 'missing-f08-token')], expected=1)
    run('reject-unknown-template', ['template', 'show', 'private-f08-unknown-value'], expected=1)
    run('reject-format', ['template', 'show', '--format', 'private-f08-unknown-value', 'single-app'], expected=1)
    run('reject-catalog-format', ['template', 'list', '--format', 'yaml'], expected=1)
    offline_script = fixture / 'f08-offline-session.sw'
    example_file = fixture / 'f08-example-single-user.json'
    write_file(offline_script, 'template list\ntemplate schema\ntemplate show --format json single-user\ntemplate render --format json --file "' + str(example_file) + '"\nhistory\n')
    session, _ = run('offline-session', ['shell', '--address', 'private-f08-invalid-address', '--token-file', str(fixture / 'missing-f08-token'), '--script', str(offline_script)])
    require(isinstance(session, list) and len(session) == 5 and session[3].get('api_version') == 'secretwright/v1' and session[4] == [], 'Architecture shell commands consulted connection credentials or entered history.')

    STAGE = 'compose-apply-and-isolate'
    mount, auth, name = 'f08-smoke-kv', 'f08-smoke-auth', 'f08-smoke'
    request('sys/auth/' + auth, {'type': 'approle'})
    manifest = {'api_version': 'secretwright/architecture/v1', 'name': name, 'instances': [
        {'id': 'front', 'template': 'multi-app', 'mount': mount, 'auth_mount': auth, 'applications': ['api', 'worker'], 'access': 'read'},
        {'id': 'back', 'template': 'saas', 'mount': mount, 'auth_mount': auth, 'tenants': ['acme', 'acme-extra'], 'environments': ['prod'], 'applications': ['api'], 'access': 'read-write'},
    ]}
    manifest_file = fixture / 'f08-composition.json'
    write_file(manifest_file, json.dumps(manifest))
    rendered, body = run('composition-render', ['template', 'render', '--format', 'json', '--file', str(manifest_file)])
    require(sum(item.get('kind') == 'kv_mount' for item in rendered['resources']) == 1 and len(rendered['resources']) == 9, 'Architecture composition did not coalesce its shared mount.')
    blueprint_file = fixture / 'f08-composed-blueprint.json'
    write_file(blueprint_file, body)
    plan, _ = run('plan', ['blueprint', 'plan', '--file', str(blueprint_file)], online=True)
    require(len(plan.get('changes', [])) == 9 and mount + '/' not in request('sys/mounts', method='GET')['data'], 'Architecture plan did not remain read-only.')
    applied, _ = run('apply', ['blueprint', 'apply', '--file', str(blueprint_file)], online=True)
    require(len(applied.get('items', [])) == 9 and all(item.get('status') == 'created' for item in applied['items']), 'Rendered architecture did not apply every declared resource.')
    empty, _ = run('empty-plan', ['blueprint', 'plan', '--file', str(blueprint_file)], online=True)
    repeated, _ = run('apply-again', ['blueprint', 'apply', '--file', str(blueprint_file)], online=True)
    require(empty.get('changes') == [] and all(item.get('status') == 'unchanged' for item in repeated.get('items', [])), 'Rendered architecture was not idempotent.')
    own, foreign = name + '/back/tenants/acme/envs/prod/apps/api', name + '/back/tenants/acme-extra/envs/prod/apps/api'
    for scope in [own, foreign, name + '/front/apps/api']:
        request(mount + '/data/' + scope + '/item', {'data': {'value': 'private-f08-secret-value'}})
    digest = hashlib.sha256(own.encode()).hexdigest()[:16]
    role = next(item['name'] for item in rendered['resources'] if item['id'] == 'role_' + digest)
    bundle, token_file = fixture / 'f08-bundle.json', fixture / 'f08-token'
    run('credentials', ['approle', 'credentials', '--auth-mount', auth, '--out', str(bundle), role], online=True)
    artifacts.append(bundle)
    forbidden.extend(json.loads(bundle.read_text()).values())
    run('login', ['approle', 'login', '--auth-mount', auth, '--file', str(bundle), '--out', str(token_file)], online=True)
    artifacts.append(token_file)
    token = token_file.read_text().strip()
    forbidden.append(token)
    value = request(mount + '/data/' + own + '/item', method='GET', token=token)
    require(value['data']['data'] == {'value': 'private-f08-secret-value'}, 'Rendered SaaS role did not grant its declared scope.')
    for scope in [foreign, name + '/front/apps/api']:
        require(request(mount + '/data/' + scope + '/item', method='GET', token=token, expected=403) is None, 'Composed architecture leaked access across tenant or instance scopes.')

    STAGE = 'artifact-audit'
    for path in artifacts + captures:
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, 'Architecture smoke created a non-private capture or artifact.')
    for path in captures:
        require(all(value not in path.read_text() for value in forbidden), 'Architecture smoke exposed a credential or secret in captured output.')
    require(set(fixture.iterdir()) - before == set(artifacts + captures), 'Architecture commands wrote an unexpected state or plan artifact.')
    print('CLI architecture smoke passed: six offline templates, YAML defaults and JSON compatibility, deterministic rendering, shell, shared-mount composition, idempotence and tenant isolation.')


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
        raise SystemExit('Private architecture fixture failed [stage=' + STAGE + '; class=' + type(error).__name__ + '; script_lines=' + ','.join(frames) + ']') from None
