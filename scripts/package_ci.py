#!/usr/bin/env python3
"""Exercise the exact distributable bundle without publishing any artifact."""

from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = [(system, architecture) for system in ('linux', 'darwin', 'windows')
             for architecture in ('amd64', 'arm64')]
STAGE = 'startup'


class PackageError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise PackageError(message)


def command(arguments, *, environment=None, accepted=(0,), capture=True):
    result = subprocess.run(arguments, cwd=ROOT, env=environment, check=False,
                            capture_output=capture)
    require(result.returncode in accepted, 'packaging command failed')
    return result.stdout if capture else b''


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        for body in iter(lambda: source.read(1024 * 1024), b''):
            result.update(body)
    return result.hexdigest()


def archive_name(version, system, architecture):
    extension = 'zip' if system == 'windows' else 'tar.gz'
    return f'secretwright_{version}_{system}_{architecture}.{extension}'


def package_version(environment):
    sha = command(['git', 'rev-parse', 'HEAD']).decode().strip()
    require(re.fullmatch('[0-9a-f]{40}', sha) is not None, 'invalid source commit')
    if environment.get('GITHUB_REF_TYPE') == 'tag':
        report = json.loads(command([
            sys.executable, str(ROOT / 'scripts' / 'release_preflight.py'),
            '--tag', environment.get('GITHUB_REF_NAME', ''),
            '--sha', environment.get('GITHUB_SHA', ''), '--main-ref', 'origin/main',
        ], environment=environment))
        require(report.get('sha') == sha, 'tag does not select the tested source')
        return report['version']
    return '0.0.0-snapshot.g' + sha[:12]


def write_manifest(directory, version, containers):
    names = []
    for system, architecture in PLATFORMS:
        names.extend([archive_name(version, system, architecture),
                      f'secretwright_{version}_{system}_{architecture}.spdx.json'])
    if containers:
        names.append(f'secretwright_{version}_linux_multiarch.oci.tar')
        names.extend(f'secretwright_{version}_linux_{architecture}.image.spdx.json'
                     for architecture in ('amd64', 'arm64'))
    body = ''.join(f'{digest(directory / name)}  {name}\n' for name in sorted(names))
    (directory / f'secretwright_{version}_checksums.txt').write_text(body, encoding='ascii')


def native_archive_checks(directory, version, environment):
    global STAGE
    STAGE = 'executable-build-metadata-and-native-offline-smoke'
    with tempfile.TemporaryDirectory(prefix='secretwright-native-package-') as temporary:
        native = None
        for system, architecture in PLATFORMS:
            filename = 'secretwright.exe' if system == 'windows' else 'secretwright'
            archive_path = directory / archive_name(version, system, architecture)
            if system == 'windows':
                with zipfile.ZipFile(archive_path) as archive:
                    body = archive.read(filename)
            else:
                with tarfile.open(archive_path, 'r:gz') as archive:
                    source = archive.extractfile(filename)
                    require(source is not None, 'archive executable is missing')
                    body = source.read()
            binary = Path(temporary) / f'{system}-{architecture}-{filename}'
            with binary.open('xb') as output:
                output.write(body)
            binary.chmod(0o755)
            build = command(['go', 'version', '-m', str(binary)], environment=environment).decode()
            require(all(setting in build for setting in
                        ('CGO_ENABLED=0', f'GOOS={system}', f'GOARCH={architecture}')),
                    'binary build settings do not match its platform')
            require('github.com/hashicorp/vault/api\tv1.23.0' in build,
                    'binary dependency metadata is missing')
            if system == 'linux' and architecture == 'amd64':
                native = binary
        require(native is not None, 'native executable is missing')
        offline = dict(environment, VAULT_ADDR='private-f13-invalid-address',
                       VAULT_TOKEN='private-f13-unused-token',
                       VAULT_CLIENT_TIMEOUT='private-f13-invalid-timeout')
        output = command([str(native), 'version'], environment=offline)
        require(output.decode().strip() == 'secretwright ' + version,
                'archive executable has an incorrect version')
        command([str(native), '--help'], environment=offline)
        for family in ('blueprint', 'pki', 'keytab'):
            schema = json.loads(command([str(native), family, 'schema'], environment=offline))
            require(isinstance(schema, dict) and schema.get('$schema') and schema.get('$id'),
                    'offline schema is invalid')
        example = command([str(native), 'keytab', 'example'], environment=offline)
        text = example.decode()
        require(any(line.startswith('api_version:') for line in text.splitlines())
                and not text.lstrip().startswith('{'), 'policy example did not default to YAML')
        policy = Path(temporary) / 'policy.yaml'
        policy.write_bytes(example)
        keytab = Path(temporary) / 'empty.keytab'
        keytab.write_bytes(b'\x05\x02')
        keytab.chmod(0o600)
        report = json.loads(command([str(native), 'keytab', 'validate', '--file', str(keytab),
                                     '--policy', str(policy)], environment=offline, accepted=(4,)))
        require(report.get('valid') is False and report.get('reason') == 'principal_missing'
                and report.get('policy_checked') is True
                and report.get('authentication_checked') is False,
                'generated YAML policy did not retain its meaning')


def sign_ephemeral(directory, version, environment):
    global STAGE
    STAGE = 'offline-signature-and-tamper-acceptance'
    with tempfile.TemporaryDirectory(prefix='secretwright-release-signing-') as temporary:
        root = Path(temporary)
        selected = dict(environment, SECRETWRIGHT_SIGNING_PASSWORD=os.urandom(32).hex())
        key = root / 'ephemeral-encrypted-key.pem'
        command(['openssl', 'genpkey', '-algorithm', 'ED25519', '-aes-256-cbc',
                 '-pass', 'env:SECRETWRIGHT_SIGNING_PASSWORD', '-out', str(key)],
                environment=selected)
        key.chmod(0o600)
        command(['bash', str(ROOT / 'scripts' / 'sign_release.sh'),
                 str(directory), version, str(key)], environment=selected)
        public = directory / f'secretwright_{version}_signing-key.pem'
        command(['bash', str(ROOT / 'scripts' / 'verify_signature.sh'),
                 str(directory), version, str(public)], environment=selected)
        manifest = directory / f'secretwright_{version}_checksums.txt'
        original = manifest.read_bytes()
        try:
            changed = (b'0' if original[:1] != b'0' else b'1') + original[1:]
            manifest.write_bytes(changed)
            command(['bash', str(ROOT / 'scripts' / 'verify_signature.sh'),
                     str(directory), version, str(public)], environment=selected, accepted=(1,))
        finally:
            manifest.write_bytes(original)
        other = root / 'other-encrypted-key.pem'
        wrong_public = root / 'other-public-key.pem'
        command(['openssl', 'genpkey', '-algorithm', 'ED25519', '-aes-256-cbc',
                 '-pass', 'env:SECRETWRIGHT_SIGNING_PASSWORD', '-out', str(other)],
                environment=selected)
        command(['openssl', 'pkey', '-in', str(other), '-passin',
                 'env:SECRETWRIGHT_SIGNING_PASSWORD', '-pubout', '-out', str(wrong_public)],
                environment=selected)
        command(['bash', str(ROOT / 'scripts' / 'verify_signature.sh'),
                 str(directory), version, str(wrong_public)], environment=selected, accepted=(1,))


def main():
    global STAGE
    require(len(sys.argv) == 1, 'package acceptance does not accept arguments')
    environment = dict(os.environ)
    tools = Path(environment.get('RUNNER_TEMP', environment.get('TMPDIR', '/tmp'))) / 'secretwright-release-tools'
    environment['PATH'] = str(tools) + os.pathsep + environment.get('PATH', '')
    environment.update(SYFT_CHECK_FOR_APP_UPDATE='false', SYFT_ENRICH='-all',
                       SYFT_GOLANG_SEARCH_REMOTE_LICENSES='false')
    version = package_version(environment)
    environment['SECRETWRIGHT_PACKAGE_VERSION'] = version
    directory = ROOT / 'release-bundle'
    work = ROOT / '.package-work'
    require(not directory.exists() and not directory.is_symlink(),
            'distribution output already exists')
    directory.mkdir(mode=0o755)
    STAGE = 'goreleaser-config-and-first-six-platform-build'
    command(['goreleaser', 'check', '--config', '.goreleaser.yaml'], environment=environment, capture=False)
    build = ['goreleaser', 'release', '--snapshot', '--clean', '--skip=publish,sign,sbom',
             '--config', '.goreleaser.yaml', '--parallelism', '2']
    command(build, environment=environment, capture=False)
    for system, architecture in PLATFORMS:
        name = archive_name(version, system, architecture)
        shutil.copyfile(work / name, directory / name)
    STAGE = 'second-build-and-byte-reproducibility'
    command(build, environment=environment, capture=False)
    for system, architecture in PLATFORMS:
        name = archive_name(version, system, architecture)
        require(digest(work / name) == digest(directory / name),
                'archive build is not byte reproducible')
    shutil.rmtree(work)
    STAGE = 'archive-spdx-and-complete-checksums'
    for system, architecture in PLATFORMS:
        source = directory / archive_name(version, system, architecture)
        destination = directory / f'secretwright_{version}_{system}_{architecture}.spdx.json'
        command(['syft', 'scan', str(source), '--enrich=-all', '--source-name', 'secretwright',
                 '--source-version', version, '--output', 'spdx-json=' + str(destination)],
                environment=environment, capture=False)
    write_manifest(directory, version, False)
    command([sys.executable, str(ROOT / 'scripts' / 'verify_release.py'), str(directory),
             '--version', version, '--without-containers'], environment=environment)
    native_archive_checks(directory, version, environment)
    STAGE = 'multiarch-container-and-spdx'
    command(['bash', str(ROOT / 'scripts' / 'build_container.sh'), str(directory), version],
            environment=environment, capture=False)
    oci = directory / f'secretwright_{version}_linux_multiarch.oci.tar'
    for architecture in ('amd64', 'arm64'):
        destination = directory / f'secretwright_{version}_linux_{architecture}.image.spdx.json'
        command(['syft', 'scan', 'oci-archive:' + str(oci), '--platform', 'linux/' + architecture,
                 '--enrich=-all', '--source-name', 'secretwright', '--source-version', version,
                 '--output', 'spdx-json=' + str(destination)], environment=environment, capture=False)
    write_manifest(directory, version, True)
    command([sys.executable, str(ROOT / 'scripts' / 'verify_release.py'),
             str(directory), '--version', version], environment=environment)
    STAGE = 'native-container-acceptance'
    command([sys.executable, str(ROOT / 'scripts' / 'container_smoke.py'),
             'secretwright:packaging-test', '--version', version], environment=environment, capture=False)
    sign_ephemeral(directory, version, environment)
    STAGE = 'final-complete-bundle'
    command([sys.executable, str(ROOT / 'scripts' / 'verify_release.py'),
             str(directory), '--version', version], environment=environment)
    require(len(list(directory.iterdir())) == 18, 'unexpected distribution output')
    print(json.dumps({'version': version, 'archives': 6, 'sboms': 8, 'oci_images': 2,
                      'files': 18, 'archive_reproducibility_checked': True,
                      'native_runtime': 'linux/amd64', 'published': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Packaging acceptance failed [stage=' + STAGE + '].') from None
