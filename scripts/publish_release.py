#!/usr/bin/env python3
"""Publish a previously validated bundle only after offline signing and remote guards."""

from pathlib import Path
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from urllib.parse import quote


SCRIPTS = Path(__file__).resolve().parent
MAX_API_RESPONSE = 4 << 20


class PublicationError(Exception):
    """Publication failures deliberately omit subprocess and input diagnostics."""


def fail():
    raise PublicationError('release publication failed; inspect any existing draft before retrying')


def checked_run(arguments, *, cwd, environment):
    result = subprocess.run(arguments, cwd=cwd, env=environment, capture_output=True, check=False, timeout=180)
    if result.returncode != 0 or len(result.stdout) > MAX_API_RESPONSE:
        fail()
    return result.stdout


def load_verifier():
    spec = importlib.util.spec_from_file_location('secretwright_publish_verifier', SCRIPTS / 'verify_release.py')
    if spec is None or spec.loader is None:
        fail()
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def expected_assets(version):
    names = set()
    for system in ('linux', 'darwin', 'windows'):
        for machine in ('amd64', 'arm64'):
            prefix = f'secretwright_{version}_{system}_{machine}'
            names.add(prefix + ('.zip' if system == 'windows' else '.tar.gz'))
            names.add(prefix + '.spdx.json')
    names.add(f'secretwright_{version}_linux_multiarch.oci.tar')
    for machine in ('amd64', 'arm64'):
        names.add(f'secretwright_{version}_linux_{machine}.image.spdx.json')
    names.update(f'secretwright_{version}_{suffix}' for suffix in
                 ('checksums.txt', 'checksums.sig', 'signing-key.pem'))
    return names


def file_evidence(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns


def copy_regular(source, destination):
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= (512 << 20):
        fail()
    source_fd = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(source_fd, 'rb') as reader, os.fdopen(destination_fd, 'wb') as writer:
        if file_evidence(before) != file_evidence(os.fstat(reader.fileno())):
            fail()
        total = 0
        while body := reader.read(1 << 20):
            total += len(body)
            if total > before.st_size or writer.write(body) != len(body):
                fail()
        writer.flush()
        if total != before.st_size or file_evidence(before) != file_evidence(os.fstat(reader.fileno())):
            fail()
    if file_evidence(before) != file_evidence(source.lstat()):
        fail()


def inventory(directory, names):
    result = {}
    for name in sorted(names):
        path = directory / name
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= (512 << 20):
            fail()
        digest = hashlib.sha256()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(descriptor, 'rb') as source:
            if file_evidence(before) != file_evidence(os.fstat(source.fileno())):
                fail()
            size = 0
            while body := source.read(1 << 20):
                size += len(body)
                digest.update(body)
            if size != before.st_size or file_evidence(before) != file_evidence(os.fstat(source.fileno())):
                fail()
        if file_evidence(before) != file_evidence(path.lstat()):
            fail()
        result[name] = {'size': size, 'digest': 'sha256:' + digest.hexdigest()}
    return result


def api_get(endpoint, *, cwd, environment):
    result = subprocess.run(
        ['gh', 'api', '--hostname', 'github.com', '--method', 'GET', '--include', endpoint],
        cwd=cwd, env=environment, capture_output=True, check=False, timeout=60,
    )
    if len(result.stdout) > MAX_API_RESPONSE:
        fail()
    response = result.stdout.replace(b'\r\n', b'\n')
    headers, separator, body = response.partition(b'\n\n')
    status = re.fullmatch(rb'HTTP/[0-9]+(?:\.[0-9]+)? ([0-9]{3})(?: [^\n]*)?', headers.split(b'\n')[0])
    if not separator or status is None:
        fail()
    code = int(status.group(1))
    if code == 404 and result.returncode != 0:
        return code, None
    if code != 200 or result.returncode != 0:
        fail()
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError):
        fail()
    if not isinstance(value, dict):
        fail()
    return code, value


def require_remote_tag(repository, tag, sha, *, cwd, environment):
    code, value = api_get(f'repos/{repository}/git/ref/tags/{quote(tag, safe="")}',
                          cwd=cwd, environment=environment)
    if code != 200:
        fail()
    target = value.get('object')
    visited = set()
    for _ in range(8):
        if not isinstance(target, dict) or re.fullmatch(r'[0-9a-f]{40}', str(target.get('sha', ''))) is None:
            fail()
        identity, kind = target['sha'], target.get('type')
        if kind == 'commit':
            if identity != sha:
                fail()
            return
        if kind != 'tag' or identity in visited:
            fail()
        visited.add(identity)
        code, value = api_get(f'repos/{repository}/git/tags/{identity}', cwd=cwd, environment=environment)
        if code != 200:
            fail()
        target = value.get('object')
    fail()


def require_draft(value, tag, local, prerelease):
    if value.get('tag_name') != tag or value.get('draft') is not True or value.get('prerelease') is not prerelease:
        fail()
    assets = value.get('assets')
    if not isinstance(assets, list) or len(assets) != len(local):
        fail()
    seen = set()
    for asset in assets:
        if not isinstance(asset, dict):
            fail()
        name = asset.get('name')
        if not isinstance(name, str) or name not in local or name in seen:
            fail()
        seen.add(name)
        if (type(asset.get('size')) is not int or asset['size'] != local[name]['size']
                or asset.get('digest') != local[name]['digest'] or asset.get('state') != 'uploaded'):
            fail()
    if seen != set(local):
        fail()


def publish(root, environment):
    root = Path(root).resolve()
    environment = dict(environment)
    repository = environment.get('GITHUB_REPOSITORY', '')
    tag, sha = environment.get('GITHUB_REF_NAME', ''), environment.get('GITHUB_SHA', '')
    key = environment.get('SECRETWRIGHT_SIGNING_KEY', '')
    password = environment.get('SECRETWRIGHT_SIGNING_PASSWORD', '')
    token = environment.get('GH_TOKEN', '')
    if (environment.get('GITHUB_REF_TYPE') != 'tag'
            or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*', repository) is None
            or not token.strip() or any(character in token for character in '\r\n\0')
            or not key or len(key.encode()) > 65536 or not password):
        fail()
    proof = checked_run([sys.executable, str(SCRIPTS / 'release_preflight.py'), '--tag=' + tag,
                         '--sha=' + sha, '--main-ref=origin/main'], cwd=root, environment=environment)
    try:
        preflight = json.loads(proof)
    except (ValueError, UnicodeError):
        fail()
    if preflight != {'tag': tag, 'version': tag[1:], 'sha': sha}:
        fail()
    version = preflight['version']
    names = expected_assets(version)
    bundle = root / 'release-bundle'
    verifier = load_verifier()
    verifier.verify_release(bundle, version)
    if {path.name for path in bundle.iterdir()} != names:
        fail()
    with tempfile.TemporaryDirectory(prefix='secretwright-publish-', dir=environment.get('RUNNER_TEMP') or None) as temporary:
        temporary = Path(temporary)
        if temporary.resolve().is_relative_to(root):
            fail()
        stage = temporary / 'assets'
        stage.mkdir(mode=0o700)
        for name in sorted(names):
            copy_regular(bundle / name, stage / name)
        verifier.verify_release(stage, version)
        # Only these two ephemeral CI sidecars are replaced, inside the isolated copy.
        for suffix in ('checksums.sig', 'signing-key.pem'):
            (stage / f'secretwright_{version}_{suffix}').unlink()
        key_path = temporary / 'selected-key.pem'
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            body = key.encode()
            if output.write(body) != len(body):
                fail()
        signing_environment = dict(environment)
        for name in ('GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN'):
            signing_environment.pop(name, None)
        checked_run(['bash', str(SCRIPTS / 'sign_release.sh'), str(stage), version, str(key_path)],
                    cwd=root, environment=signing_environment)
        checked_run(['bash', str(SCRIPTS / 'verify_signature.sh'), str(stage), version,
                     str(stage / f'secretwright_{version}_signing-key.pem')], cwd=root, environment=signing_environment)
        verifier.verify_release(stage, version)
        for path in stage.iterdir():
            path.chmod(0o444)
        local = inventory(stage, names)
        gh_environment = dict(environment)
        for name in ('SECRETWRIGHT_SIGNING_KEY', 'SECRETWRIGHT_SIGNING_PASSWORD', 'GITHUB_TOKEN',
                     'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN'):
            gh_environment.pop(name, None)
        gh_environment.update(GH_HOST='github.com', GH_PROMPT_DISABLED='1', GH_CONFIG_DIR=str(temporary / 'gh-config'))
        endpoint = f'repos/{repository}/releases/tags/{quote(tag, safe="")}'
        code, _ = api_get(endpoint, cwd=root, environment=gh_environment)
        if code != 404:
            fail()
        require_remote_tag(repository, tag, sha, cwd=root, environment=gh_environment)
        prerelease = '-' in version.split('+', 1)[0]
        notes = ('Contains six platform archives, SPDX SBOMs, a Linux multiarch OCI image and a signed SHA-256 manifest. '
                 'Verify the manifest signature with an independently trusted Ed25519 public key before checking every asset. '
                 'Linux amd64 runtime is tested; other native platforms are cross-built and inspected. '
                 'Windows private-file commands remain experimental because POSIX 0600/0700 checks do not establish Windows ACLs.')
        command = ['gh', 'release', 'create', tag, '--repo', repository, '--draft', '--verify-tag',
                   '--title', 'Secretwright ' + tag, '--notes', notes]
        if prerelease:
            command += ['--prerelease', '--latest=false']
        command += [str(stage / name) for name in sorted(names)]
        checked_run(command, cwd=root, environment=gh_environment)
        code, remote = api_get(endpoint, cwd=root, environment=gh_environment)
        if code != 200:
            fail()
        require_draft(remote, tag, local, prerelease)
        if inventory(stage, names) != local:
            fail()
        require_remote_tag(repository, tag, sha, cwd=root, environment=gh_environment)
        checked_run(['gh', 'release', 'edit', tag, '--repo', repository, '--draft=false'],
                    cwd=root, environment=gh_environment)
    return {'version': version, 'assets': len(names), 'published': True}


def main():
    try:
        if len(sys.argv) != 1:
            fail()
        result = publish(Path.cwd(), os.environ)
    except Exception:
        print('secretwright: release publication failed; inspect any existing draft before retrying', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
