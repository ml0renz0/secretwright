#!/usr/bin/env python3
"""Private compiled-binary acceptance checks for recursive Vault operations."""

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
    binary = Path(sys.argv[1]).resolve()
    fixture = Path(sys.argv[2]).resolve()
    address = os.environ['VAULT_ADDR']
    root_token = (fixture / 'root-token').read_text().strip()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(path, payload=None, method='POST', missing=False):
        data = None if payload is None else json.dumps(payload).encode()
        encoded = urllib.parse.quote(path, safe='/')
        message = urllib.request.Request(address + '/v1/' + encoded, data=data, method=method)
        message.add_header('X-Vault-Token', root_token)
        message.add_header('Content-Type', 'application/json')
        try:
            with opener.open(message, timeout=5) as response:
                body = response.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            if missing and error.code == 404:
                return None
            raise

    def write_json(path, value):
        private_write(path, json.dumps(value, ensure_ascii=False).encode())

    first = {'value': 'private-f05-before', 'number': 1, 'identifier': '9007199254740993', 'nested': {'value': 'private-f05-nested'}}
    changed = dict(first, value='private-f05-after')
    other = dict(first, value='private-f05-other')
    keys = {'item': first, 'foo': other, 'foo/bar': first, 'nested/秘密': other}
    v1, v2 = 'f05-smoke-v1', 'f05-smoke-v2'
    STAGE = 'fixture-provision'
    for mount, version in [(v1, 1), (v2, 2)]:
        request('sys/mounts/' + mount, {'type': 'kv', 'options': {'version': str(version)}})
    for key, value in keys.items():
        request(v2 + '/data/allowed/source/' + key, {'data': value})

    policy = '\n'.join([
        'path "' + v1 + '/allowed/*" { capabilities = ["create","read","update","delete","list"] }',
        'path "' + v2 + '/data/allowed/*" { capabilities = ["create","read","update","delete"] }',
        'path "' + v2 + '/metadata/allowed" { capabilities = ["read","list"] }',
        'path "' + v2 + '/metadata/allowed/*" { capabilities = ["read","list"] }',
        'path "' + v2 + '/delete/allowed/*" { capabilities = ["update"] }',
        'path "' + v2 + '/data/allowed/denied-source/z" { capabilities = ["deny"] }',
    ])
    request('sys/policies/acl/f05-smoke', {'policy': policy})
    token = request('auth/token/create', {'policies': ['f05-smoke'], 'no_default_policy': True, 'ttl': '3m'})['auth']['client_token']
    token_file = fixture / 'f05-token'
    private_write(token_file, token.encode())
    environment = dict(os.environ)
    environment['VAULT_TOKEN'] = 'f05-deliberately-invalid-inherited-token'
    match_file, rule_file = fixture / 'f05-match.json', fixture / 'f05-rule.json'
    write_json(match_file, dict(first, number=1.0))
    write_json(rule_file, {'match': first, 'replacement': changed})
    root = '/' + v2 + '/allowed/source'
    captures = []

    def run(name, args, expected=0, token_path=token_file):
        output_path, error_path = fixture / ('f05-' + name + '-stdout.json'), fixture / ('f05-' + name + '-stderr.txt')
        with open(output_path, 'xb') as output, open(error_path, 'xb') as error:
            os.chmod(output_path, 0o600)
            os.chmod(error_path, 0o600)
            result = subprocess.run([str(binary), args[0], '--token-file', str(token_path), *args[1:]], stdin=subprocess.DEVNULL, stdout=output, stderr=error, env=environment, timeout=20)
        captures.extend([output_path, error_path])
        stdout, stderr = output_path.read_text(), error_path.read_text()
        require(result.returncode == expected, 'Advanced CLI command returned an unexpected exit code.')
        require((not stderr) if expected == 0 else bool(stderr), 'Advanced CLI command produced unexpected diagnostics.')
        require(token not in stdout + stderr and root_token not in stdout + stderr, 'Advanced CLI exposed a credential.')
        require('private-f05-' not in stdout + stderr and '9007199254740993' not in stdout + stderr, 'Advanced CLI exposed a secret value in its report.')
        require('f05-deliberately-invalid' not in stdout + stderr, 'Advanced CLI exposed an inherited credential.')
        documents = decode_documents(stdout)
        return documents[0] if len(documents) == 1 else documents

    def current(mount, key, version=2):
        response = request(mount + ('/data/' if version == 2 else '/') + key, method='GET', missing=True)
        if response is None:
            return None
        return response['data']['data'] if version == 2 else response['data']

    def require_values(mount, prefix, expected, version=2):
        for key, value in expected.items():
            require(current(mount, prefix + '/' + key, version) == value, 'Recursive CLI changed private values or relative key names.')

    STAGE = 'tree-find'
    tree = run('tree', ['tree', '--concurrency', '2', root])
    require(tree.get('root') == root and len(tree.get('entries', [])) == 6, 'Recursive tree omitted a directory or secret.')
    same_named = [entry.get('directory') for entry in tree['entries'] if entry.get('path') == root + '/foo']
    require(sorted(same_named) == [False, True], 'Recursive tree confused a key with its same-named directory.')
    matches = run('find', ['find', '--file', str(match_file), '--concurrency', '2', root])
    require(matches == [root + '/foo/bar', root + '/item'], 'Find did not match complete JSON objects with numeric equality.')

    STAGE = 'replace'
    dry = run('replace-plan', ['replace', '--file', str(rule_file), '--dry-run', root])
    require(dry.get('dry_run') is True and len(dry.get('items', [])) == 2 and all(item.get('status') == 'planned' for item in dry['items']), 'Replace dry-run did not return the expected plan.')
    require_values(v2, 'allowed/source', keys)
    report = run('replace', ['replace', '--file', str(rule_file), root])
    require(len(report.get('items', [])) == 2 and all(item.get('status') == 'written' for item in report['items']), 'Replace did not write exactly the matched secrets.')
    for key in ['foo/bar', 'item']:
        keys[key] = changed
    require_values(v2, 'allowed/source', keys)
    require(run('find-after', ['find', '--file', str(match_file), root]) == [], 'Replace left stale matching current values.')
    write_json(fixture / 'f05-equal-rule.json', {'match': changed, 'replacement': changed})
    equal = run('replace-equal', ['replace', '--file', str(fixture / 'f05-equal-rule.json'), root])
    require(len(equal.get('items', [])) == 2 and all(item.get('status') == 'unchanged' for item in equal['items']), 'Equal replacement created unnecessary writes.')
    for key in ['foo/bar', 'item']:
        history = request(v2 + '/metadata/allowed/source/' + key, method='GET')['data']
        require(history['current_version'] == 2, 'Dry-run or equal replacement created an extra revision.')

    STAGE = 'copy'
    copy_root = '/' + v2 + '/allowed/copy'
    copied = run('copy', ['cptree', '--concurrency', '2', root, copy_root])
    require(len(copied.get('items', [])) == 4, 'Recursive copy did not retain every relative key.')
    require_values(v2, 'allowed/copy', keys)
    require_values(v2, 'allowed/source', keys)
    run('copy-conflict', ['cptree', '--concurrency', '1', root, copy_root], expected=4)
    require_values(v2, 'allowed/copy', keys)

    STAGE = 'backup'
    archive_path = fixture / 'f05-backup.json'
    summary = run('backup', ['backup', '--file', str(archive_path), root])
    require(summary == {'root': root, 'entries': 4}, 'Backup summary included data or omitted its snapshot count.')
    require(stat.S_IMODE(archive_path.stat().st_mode) == 0o600, 'Backup did not produce a private archive.')
    archive = json.loads(archive_path.read_text())
    require(set(archive) == {'format', 'version', 'root', 'entries'} and archive['format'] == 'secretwright-kv' and archive['version'] == 1 and archive['root'] == root, 'Backup schema was not explicit and versioned.')
    require([entry['path'] for entry in archive['entries']] == sorted(keys) and all(set(entry) == {'path', 'data'} for entry in archive['entries']), 'Backup changed relative keys or included metadata.')
    require({entry['path']: entry['data'] for entry in archive['entries']} == keys, 'Backup did not retain the current private values.')
    digest = hashlib.sha256(archive_path.read_bytes()).digest()
    run('backup-existing', ['backup', '--file', str(archive_path), root], expected=1)
    require(hashlib.sha256(archive_path.read_bytes()).digest() == digest, 'Backup overwrote an existing archive.')
    link_path = fixture / 'f05-backup-link.json'
    link_path.symlink_to(archive_path)
    run('backup-symlink', ['backup', '--file', str(link_path), root], expected=1)
    require(link_path.is_symlink() and hashlib.sha256(archive_path.read_bytes()).digest() == digest, 'Backup followed or replaced an existing symlink.')

    STAGE = 'restore'
    restored_root = '/' + v2 + '/allowed/restored'
    restored = run('restore', ['restore', '--file', str(archive_path), '--concurrency', '2', restored_root])
    require(len(restored.get('items', [])) == 4, 'Restore omitted archived relative keys.')
    require_values(v2, 'allowed/restored', keys)
    run('restore-conflict', ['restore', '--file', str(archive_path), '--concurrency', '1', restored_root], expected=4)
    legacy_root = '/' + v1 + '/allowed/restored'
    run('restore-v1-guard', ['restore', '--file', str(archive_path), legacy_root], expected=1)
    require(current(v1, 'allowed/restored/item', 1) is None, 'Unguarded KV v1 restore already wrote a destination.')
    run('restore-v1', ['restore', '--file', str(archive_path), '--force', legacy_root])
    require_values(v1, 'allowed/restored', keys, 1)

    unsafe_archive = dict(archive, entries=[{'path': 'a', 'data': {'value': 'private-f05-safe-first'}}, {'path': 'z', 'data': {'number': 9007199254740993}}])
    unsafe_file = fixture / 'f05-unsafe-numeric.json'
    write_json(unsafe_file, unsafe_archive)
    run('restore-numeric-guard', ['restore', '--file', str(unsafe_file), '/' + v2 + '/allowed/numeric'], expected=1)
    require(current(v2, 'allowed/numeric/a') is None, 'Restore wrote data before validating every KV v2 number.')

    STAGE = 'remove'
    plan = run('remove-plan', ['rmtree', '--dry-run', copy_root])
    require(plan.get('dry_run') is True and len(plan.get('items', [])) == 4, 'Recursive remove did not plan every captured snapshot.')
    require_values(v2, 'allowed/copy', keys)
    removed = run('remove', ['rmtree', '--concurrency', '2', copy_root])
    require(len(removed.get('items', [])) == 4 and all(item.get('status') == 'deleted' for item in removed['items']), 'Recursive remove did not delete its planned snapshots.')
    require(all(current(v2, 'allowed/copy/' + key) is None for key in keys), 'Recursive remove retained a current snapshot.')
    require_values(v2, 'allowed/source', keys)

    STAGE = 'denied-preflight'
    for key in ['a', 'z']:
        request(v2 + '/data/allowed/denied-source/' + key, {'data': first})
    denied_root = '/' + v2 + '/allowed/denied-source'
    denied_tree = run('denied-tree', ['tree', denied_root])
    require(len(denied_tree.get('entries', [])) == 2, 'Tree required secret-value read permission.')
    run('denied-copy', ['cptree', denied_root, '/' + v2 + '/allowed/denied-copy'], expected=2)
    require(current(v2, 'allowed/denied-copy/a') is None, 'Denied copy preflight already wrote a destination.')
    denied_archive = fixture / 'f05-denied-backup.json'
    run('denied-backup', ['backup', '--file', str(denied_archive), denied_root], expected=2)
    require(not denied_archive.exists(), 'Failed backup published a partial archive.')

    STAGE = 'tombstone-preflight'
    for key in ['a', 'b']:
        request(v2 + '/data/allowed/tombstones/' + key, {'data': first})
    request(v2 + '/data/allowed/tombstones/b', method='DELETE')
    tombstone_root = '/' + v2 + '/allowed/tombstones'
    require(len(run('tombstone-tree', ['tree', tombstone_root]).get('entries', [])) == 2, 'Tree lost a listed tombstone name.')
    tombstone_archive = fixture / 'f05-tombstone-backup.json'
    run('tombstone-backup', ['backup', '--file', str(tombstone_archive), tombstone_root], expected=3)
    require(not tombstone_archive.exists(), 'Tombstone backup silently published an incomplete snapshot.')

    STAGE = 'shell'
    script_path = fixture / 'f05-session.sw'
    private_write(script_path, ('pwd\ntree\nfind --file "' + str(match_file) + '"\nhistory\n').encode())
    session = run('session', ['shell', '--script', str(script_path), '--cwd', root])
    require(isinstance(session, list) and len(session) == 4 and session[0] == {'path': root} and session[1].get('root') == root and session[2] == [] and session[3] == ['pwd', 'tree'], 'Advanced shell commands lost their fixed context or entered unsafe history.')

    STAGE = 'capture-audit'
    for path in captures:
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, 'Advanced smoke wrote a non-private capture.')
    require(not list(fixture.glob('.secretwright-*')), 'Backup left private temporary artifacts after completion.')
    print('CLI advanced smoke passed: tree, exact JSON search/replace, recursive copy/remove, private backup/restore and shell context.')


if __name__ == '__main__':
    try:
        main()
    except SmokeFailure as error:
        raise SystemExit(str(error) + ' [stage=' + STAGE + ']') from None
    except Exception as error:
        raise SystemExit('Private advanced smoke fixture failed: ' + safe_exception_details(error)) from None
