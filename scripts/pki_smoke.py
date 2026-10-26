#!/usr/bin/env python3
"""Private executable acceptance checks for native X.509 and Vault PKI."""

from pathlib import Path
import http.server
import json
import os
import socket
import ssl
import stat
import subprocess
import sys
import threading
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
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    environment = dict(os.environ, VAULT_TOKEN='private-f11-unselected-token', VAULT_NAMESPACE='private-f11-unselected-namespace')
    captures, artifacts = [], []
    forbidden = [root_token, 'private-f11-unselected-token', '-----BEGIN']

    def write_file(path, source):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            output.write(source)
        artifacts.append(path)

    def request(path, payload=None, method='POST'):
        body = None if payload is None else json.dumps(payload).encode()
        message = urllib.request.Request(address + '/v1/' + urllib.parse.quote(path, safe='/:'), data=body, method=method)
        message.add_header('Content-Type', 'application/json')
        message.add_header('X-Vault-Token', root_token)
        with opener.open(message, timeout=10) as response:
            body = response.read()
            return json.loads(body) if body else None

    def run(name, args, expected=0, offline=False, raw=False, token_file=None):
        depth = 1 if args[0] == 'shell' else 2
        injected = [] if offline else ['--address', address, '--namespace', '', '--timeout', '1m', '--token-file', str(token_file or operator_file)]
        command = [str(binary), *args[:depth], *injected, *args[depth:]]
        output, error = [fixture / ('f11-capture-' + name + suffix) for suffix in ['.json', '.err']]
        descriptors = [os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600) for path in [output, error]]
        captures.extend([output, error])
        selected_environment = environment
        if offline:
            selected_environment = dict(environment, VAULT_ADDR='private-f11-invalid-address', VAULT_CLIENT_TIMEOUT='private-f11-invalid-timeout')
        with os.fdopen(descriptors[0], 'w') as stdout, os.fdopen(descriptors[1], 'w') as stderr:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=selected_environment, cwd=fixture, timeout=60)
        body, diagnostics = output.read_text(), error.read_text()
        require(result.returncode == expected, 'PKI CLI returned an unexpected exit code [check=' + name + '].')
        require(not diagnostics if expected == 0 else bool(diagnostics), 'PKI CLI emitted unexpected diagnostics [check=' + name + '].')
        require(all(marker not in body + diagnostics for marker in forbidden if marker), 'PKI CLI exposed PEM material or Vault credentials.')
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

    def certificate_metadata(value):
        return next((item for item in dictionaries(value) if isinstance(item.get('serial'), str) and isinstance(item.get('sha256'), str)), {})

    STAGE = 'offline-schema-and-formats'
    schema = run('schema', ['pki', 'schema'], offline=True)
    require(schema.get('$id') == 'urn:secretwright:pki:v1', 'PKI schema lost its offline versioned identity.')
    example = run('example-yaml', ['pki', 'example'], offline=True, raw=True)
    require(example.lstrip().startswith('api_version:') and not example.lstrip().startswith('{'), 'PKI example did not default to YAML.')
    example_file = fixture / 'f11-example.yaml'
    write_file(example_file, example)
    run('validate-yaml', ['pki', 'validate', '--file', str(example_file)], offline=True)
    example_json = run('example-json', ['pki', 'example', '--format', 'json'], offline=True)
    require(example_json.get('api_version') == 'secretwright/pki/v1', 'PKI explicit JSON example lost its version.')

    STAGE = 'disposable-ca-and-role'
    mount, role, policy = 'f11-smoke-pki', 'application', 'f11-smoke-issuer'
    request('sys/mounts/' + mount, {'type': 'pki', 'config': {'max_lease_ttl': '1h', 'default_lease_ttl': '5m'}})
    request(mount + '/root/generate/internal', {'common_name': 'Secretwright F11 smoke root', 'ttl': '1h', 'key_type': 'ec', 'key_bits': 256, 'format': 'pem'})
    request(mount + '/roles/' + role, {'allowed_domains': ['fixture.test'], 'allow_subdomains': True, 'allow_bare_domains': False, 'allow_ip_sans': True, 'max_ttl': '5m', 'ttl': '2m', 'key_type': 'ec', 'key_bits': 256, 'server_flag': True, 'client_flag': False, 'code_signing_flag': False, 'use_csr_common_name': True, 'use_csr_sans': True, 'require_cn': False})
    acl = '\n'.join('path ' + json.dumps(mount + '/' + path) + ' { capabilities = [' + json.dumps(capability) + '] }' for path, capability in [('cert/*', 'read'), ('issue/application', 'update'), ('sign/application', 'update'), ('revoke', 'update')])
    request('sys/policies/acl/' + policy, {'policy': acl})
    token = request('auth/token/create', {'policies': [policy], 'no_default_policy': True, 'ttl': '5m', 'explicit_max_ttl': '10m', 'renewable': False})['auth']['client_token']
    forbidden.append(token)
    operator_file = fixture / 'f11-operator-token'
    write_file(operator_file, token + '\n')
    denied_policy = 'f11-smoke-denied'
    request('sys/policies/acl/' + denied_policy, {'policy': 'path "f11-unrelated/*" { capabilities = ["read"] }'})
    denied = request('auth/token/create', {'policies': [denied_policy], 'no_default_policy': True, 'ttl': '5m', 'explicit_max_ttl': '10m', 'renewable': False})['auth']['client_token']
    forbidden.append(denied)
    denied_file = fixture / 'f11-denied-token'
    write_file(denied_file, denied + '\n')
    request_file = fixture / 'f11-request.yaml'
    manifest = {'api_version': 'secretwright/pki/v1', 'name': 'application', 'common_name': 'app.fixture.test', 'dns_names': ['app.fixture.test'], 'ip_addresses': ['127.0.0.1'], 'ttl': '2m', 'usage': 'server-auth', 'key': {'type': 'ecdsa', 'bits': 256}}
    # YAML is the default user-facing format; JSON remains a valid YAML/JSON
    # request encoding and avoids a Python YAML dependency in this fixture.
    write_file(request_file, json.dumps(manifest) + '\n')

    STAGE = 'issue-and-private-identity'
    roots = fixture / 'f11-ca.pem'
    run('ca', ['pki', 'ca', '--mount', mount, '--out', str(roots)])
    artifacts.append(roots)
    identity = fixture / 'f11-identity.pem'
    issued = run('issue', ['pki', 'issue', '--mount', mount, '--role', role, '--file', str(request_file), '--ca-file', str(roots), '--out', str(identity)])
    artifacts.append(identity)
    metadata = certificate_metadata(issued)
    require(metadata.get('is_ca') is False and 0 < metadata.get('ttl_seconds', 0) <= 120 and metadata.get('serial'), 'PKI issue did not report the real finite leaf validity.')
    inspect = run('cert-inspect', ['pki', 'cert', 'inspect', '--file', str(identity)], offline=True)
    require(inspect.get('contains_private_key') is True and inspect.get('certificates'), 'PKI inspection did not recognize its private identity bundle.')
    run('key-inspect', ['pki', 'key', 'inspect', '--file', str(identity)], offline=True)
    matched = run('key-match', ['pki', 'cert', 'match', '--file', str(identity), '--key', str(identity)], offline=True)
    require(matched.get('match') is True, 'Issued identity key does not match its certificate.')
    verified = run('cert-verify', ['pki', 'cert', 'verify', '--file', str(identity), '--ca-file', str(roots), '--hostname', 'app.fixture.test'], offline=True)
    require(verified.get('valid') is True and verified.get('revocation_checked') is False, 'PKI verification failed or falsely claimed a revocation check.')
    run('wrong-hostname', ['pki', 'cert', 'verify', '--file', str(identity), '--ca-file', str(roots), '--hostname', 'wrong.fixture.test'], expected=4, offline=True)
    public = fixture / 'f11-public.pem'
    readback = run('read', ['pki', 'read', '--mount', mount, '--serial', metadata['serial'], '--out', str(public)])
    artifacts.append(public)
    require(certificate_metadata(readback).get('sha256') == metadata.get('sha256') and 'PRIVATE KEY' not in public.read_text(), 'PKI certificate read changed the leaf or exported a private key.')
    before = identity.read_bytes()
    run('existing-output', ['pki', 'issue', '--mount', mount, '--role', role, '--file', str(request_file), '--ca-file', str(roots), '--out', str(identity)], expected=4)
    require(identity.read_bytes() == before, 'PKI issuance overwrote an existing private identity.')
    denied_output = fixture / 'f11-denied-identity.pem'
    run('denied', ['pki', 'issue', '--mount', mount, '--role', role, '--file', str(request_file), '--ca-file', str(roots), '--out', str(denied_output)], expected=2, token_file=denied_file)
    require(not denied_output.exists(), 'Denied PKI issuance retained an output placeholder.')

    STAGE = 'native-tls-consumer'
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'fixture-pki-ready')

        def log_message(self, *_):
            pass

    server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(identity), str(identity))
    server.socket = server_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client_context = ssl.create_default_context(cafile=str(roots))
        with socket.create_connection(server.server_address, timeout=5) as connection:
            with client_context.wrap_socket(connection, server_hostname='app.fixture.test') as secure:
                secure.sendall(b'GET / HTTP/1.0\r\nHost: app.fixture.test\r\n\r\n')
                response = bytearray()
                while True:
                    chunk = secure.recv(4096)
                    if not chunk:
                        break
                    response.extend(chunk)
                require(b'200 OK' in response and b'fixture-pki-ready' in response, 'The TLS consumer could not authenticate and use the issued identity.')
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    STAGE = 'local-key-csr-and-sign'
    csr, key, signed = [fixture / name for name in ['f11-local.csr', 'f11-local.key', 'f11-signed.pem']]
    run('csr-create', ['pki', 'csr', 'create', '--file', str(request_file), '--out', str(csr), '--key-out', str(key)], offline=True)
    artifacts.extend([csr, key])
    csr_report = run('csr-inspect', ['pki', 'csr', 'inspect', '--file', str(csr)], offline=True)
    require(csr_report.get('signature_valid') is True and 'PRIVATE KEY' not in csr.read_text(), 'Generated CSR omitted its valid signature or included private material.')
    key_before = key.read_bytes()
    run('sign', ['pki', 'sign', '--mount', mount, '--role', role, '--file', str(request_file), '--csr', str(csr), '--ca-file', str(roots), '--out', str(signed)])
    artifacts.append(signed)
    require(key.read_bytes() == key_before and 'PRIVATE KEY' not in signed.read_text(), 'CSR signing changed the local key or returned private material.')
    match = run('signed-match', ['pki', 'cert', 'match', '--file', str(signed), '--key', str(key)], offline=True)
    require(match.get('match') is True, 'Signed certificate does not match the retained local key.')
    run('signed-verify', ['pki', 'cert', 'verify', '--file', str(signed), '--ca-file', str(roots), '--hostname', 'app.fixture.test'], offline=True)

    STAGE = 'fixed-shell-connection-and-revocation'
    session = fixture / 'f11-session.sw'
    shell_ca = fixture / 'f11-shell-ca.pem'
    write_file(session, 'pki cert inspect --file ' + json.dumps(str(public)) + '\n'
               + 'pki ca --mount ' + mount + ' --out ' + json.dumps(str(shell_ca)) + '\n'
               + 'history\n')
    shell_output = run('shell', ['shell', '--no-prompt', '--script', str(session)], raw=True)
    artifacts.append(shell_ca)
    decoder, reports = json.JSONDecoder(), []
    while shell_output.strip():
        shell_output = shell_output.lstrip()
        report, end = decoder.raw_decode(shell_output)
        reports.append(report)
        shell_output = shell_output[end:]
    require(len(reports) == 3 and reports[-1] == [], 'PKI shell lost command depth or retained a sensitive history entry.')
    run('revoke-no-force', ['pki', 'revoke', '--mount', mount, '--file', str(public)], expected=1)
    revoked = run('revoke', ['pki', 'revoke', '--mount', mount, '--file', str(public), '--force'])
    require(any(item.get('revoked') is True and item.get('revocation_time', 0) > 0 for item in dictionaries(revoked)), 'PKI revocation did not report a confirmed exact certificate revocation.')

    STAGE = 'privacy-and-permissions-audit'
    for path in artifacts + captures:
        require(path.is_file() and not path.is_symlink() and stat.S_IMODE(path.stat().st_mode) == 0o600, 'PKI smoke left a missing, linked or non-private artifact.')
    for path in captures:
        require(all(marker not in path.read_text() for marker in forbidden if marker), 'PKI metadata or diagnostics exposed private material.')
    print('CLI PKI smoke passed: offline YAML/JSON, private identity, native TLS, explicit chain/SAN verification, local CSR signing, exact revocation and shell privacy.')


try:
    main()
except (SmokeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, urllib.error.URLError, ssl.SSLError):
    raise SystemExit('PKI smoke failed at stage: ' + STAGE + '. Private diagnostics are withheld.') from None
