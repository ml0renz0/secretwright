#!/usr/bin/env python3
"""Install and purge the native Debian package in an isolated Debian fixture."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import uuid


STAGE = 'inputs'
MAX_OUTPUT = 4 << 20
DOCKERFILE = '''FROM debian:13-slim
RUN printf '%s\\n' \\
        'path-include=/usr/share/doc/secretwright' \\
        'path-include=/usr/share/doc/secretwright/*' \\
        > /etc/dpkg/dpkg.cfg.d/zz-secretwright-acceptance \\
    && apt-get update \\
    && apt-get install -y --no-install-recommends ca-certificates \\
    && rm -rf /var/lib/apt/lists/*
'''


class SmokeFailure(Exception):
    pass


def require(condition):
    if not condition:
        raise SmokeFailure()


def helpers():
    spec = importlib.util.spec_from_file_location('secretwright_debian_smoke_names',
                                                  Path(__file__).with_name('verify_deb.py'))
    require(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def docker(arguments, *, timeout=90, check=True):
    environment = dict(os.environ)
    # Keep registry/proxy configuration while pinning this Linux CI fixture to
    # its local daemon, regardless of inherited remote endpoint selectors.
    for name in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
        environment.pop(name, None)
    result = subprocess.run(['docker', '--host=unix:///var/run/docker.sock', *arguments],
                            env=environment, stdin=subprocess.DEVNULL, capture_output=True,
                            check=False, timeout=timeout)
    if check:
        require(result.returncode == 0 and len(result.stdout) <= MAX_OUTPUT)
    return result.stdout


def evidence(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns


def smoke(directory, version):
    global STAGE
    names = helpers()
    mapped_version = names.debian_version(version)
    package = Path(directory).resolve() / names.deb_name(version, 'amd64')
    info = package.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 128 << 20)
    require(not any(character in str(package) for character in ',\r\n'))
    identity = uuid.uuid4().hex
    image = 'secretwright-debian-fixture:' + identity
    container = 'secretwright-debian-acceptance-' + identity

    def execute(arguments, *, user=None):
        words = ['exec']
        if user:
            words += ['--user', user]
        return docker([*words, container, *arguments])

    def cli(arguments, *, user=None):
        words = ['exec']
        if user:
            words += ['--user', user]
        words += ['--env', 'VAULT_ADDR=private-debian-invalid-address',
                  '--env', 'VAULT_TOKEN=private-debian-unused-token',
                  '--env', 'VAULT_CLIENT_TIMEOUT=private-debian-invalid-timeout']
        return docker([*words, container, '/usr/bin/secretwright', *arguments])

    with tempfile.TemporaryDirectory(prefix='secretwright-debian-fixture-') as context:
        (Path(context) / 'Dockerfile').write_text(DOCKERFILE, encoding='ascii')
        try:
            STAGE = 'prepare-debian-13-with-system-ca'
            docker(['build', '--load', '--pull', '--tag', image, context], timeout=300)
            STAGE = 'start-offline-debian-fixture'
            docker(['run', '--detach', '--name', container, '--network', 'none',
                    '--security-opt', 'no-new-privileges', '--mount',
                    f'type=bind,src={package},dst=/packages/secretwright.deb,readonly',
                    image, 'sleep', '600'])
            STAGE = 'install-package-and-dependencies'
            execute(['dpkg', '--install', '/packages/secretwright.deb'])
            STAGE = 'installed-debian-metadata'
            metadata = execute(['dpkg-query', '--show',
                                '--showformat=${Package}\n${Version}\n${Architecture}\n${Status}\n',
                                'secretwright']).decode().splitlines()
            require(metadata == ['secretwright', mapped_version, 'amd64', 'install ok installed'])
            require(execute(['stat', '-c', '%u:%g:%a', '/usr/bin/secretwright']).decode().strip() == '0:0:755')
            STAGE = 'installed-file-integrity'
            require(execute(['dpkg', '--verify', 'secretwright']) == b'')
            STAGE = 'installed-version-root-and-unprivileged'
            expected = 'secretwright ' + version
            require(cli(['version']).decode().strip() == expected)
            require(cli(['version'], user='65534:65534').decode().strip() == expected)
            cli(['--help'])
            STAGE = 'installed-offline-schemas-and-yaml'
            for family in ('blueprint', 'pki', 'keytab'):
                schema = json.loads(cli([family, 'schema']))
                require(isinstance(schema, dict) and schema.get('$schema') and schema.get('$id'))
            example = cli(['keytab', 'example']).decode()
            require(any(line.startswith('api_version:') for line in example.splitlines())
                    and not example.lstrip().startswith('{'))
            core = version.partition('+')[0]
            if '-' in core:
                STAGE = 'debian-prerelease-ordering'
                execute(['dpkg', '--compare-versions', mapped_version, 'lt', core.split('-', 1)[0]])
            STAGE = 'reinstall-same-package'
            execute(['dpkg', '--install', '/packages/secretwright.deb'])
            require(execute(['dpkg', '--verify', 'secretwright']) == b'')
            STAGE = 'purge-installed-package'
            execute(['dpkg', '--purge', 'secretwright'])
            execute(['test', '!', '-e', '/usr/bin/secretwright'])
            execute(['test', '!', '-e', '/usr/share/doc/secretwright'])
            require(evidence(package.lstat()) == evidence(info))
        finally:
            # Names are unique to this invocation; no shared images/containers
            # or host packages are removed by acceptance cleanup.
            for arguments in (['rm', '--force', container], ['image', 'rm', '--force', image]):
                try:
                    docker(arguments, timeout=30, check=False)
                except Exception:
                    pass
    return {'version': version, 'debian_version': mapped_version, 'debian_release': '13',
            'native_architecture': 'amd64', 'installed': True, 'reinstalled': True,
            'file_integrity_verified': True, 'offline_schemas_and_yaml': True,
            'unprivileged_version_checked': True, 'purged': True}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise SmokeFailure()


def main():
    try:
        parser = Parser(description=__doc__)
        parser.add_argument('directory', type=Path)
        parser.add_argument('--version', required=True)
        options = parser.parse_args()
        report = smoke(options.directory, options.version)
    except Exception:
        print('Debian package acceptance failed [stage=' + STAGE + '].', file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
