#!/usr/bin/env bash
# Offline Ed25519 signing. The passphrase is selected only through the environment.
set -euo pipefail
exec python3 - "$@" <<'PY'
from pathlib import Path
import os
import re
import stat
import subprocess
import sys
import tempfile


class SigningError(Exception):
    pass


def checked_file(path, maximum, private=False):
    before = os.lstat(path)
    if (not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > maximum
            or private and stat.S_IMODE(before.st_mode) != 0o600):
        raise SigningError()
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if evidence(before) != evidence(opened):
            raise SigningError()
        with os.fdopen(descriptor, 'rb', closefd=False) as source:
            body = source.read(maximum + 1)
        after = os.fstat(descriptor)
        current = os.lstat(path)
        if len(body) != before.st_size or len(body) > maximum or evidence(before) != evidence(after) or evidence(before) != evidence(current):
            raise SigningError()
        return body, before
    finally:
        os.close(descriptor)


def evidence(value):
    return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns


def openssl(arguments, body=None):
    result = subprocess.run(['openssl', *arguments], input=body, capture_output=True, check=False, timeout=30)
    if result.returncode != 0:
        raise SigningError()
    return result.stdout


def private_write(path, body):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        if output.write(body) != len(body):
            raise SigningError()


def main():
    if len(sys.argv) != 4:
        raise SigningError()
    directory, version, key_path = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    numeric = r'(?:0|[1-9][0-9]*)'
    identifier = r'(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
    version_pattern = (numeric + r'\.' + numeric + r'\.' + numeric
                       + r'(?:-' + identifier + r'(?:\.' + identifier + r')*)?'
                       + r'(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?')
    if not re.fullmatch(version_pattern, version) or len(version) > 256:
        raise SigningError()
    if not os.environ.get('SECRETWRIGHT_SIGNING_PASSWORD'):
        raise SigningError()
    key, _ = checked_file(key_path, 65536, private=True)
    if key.splitlines()[0] != b'-----BEGIN ENCRYPTED PRIVATE KEY-----':
        raise SigningError()
    manifest_path = directory / ('secretwright_' + version + '_checksums.txt')
    manifest, manifest_evidence = checked_file(manifest_path, 1 << 20)
    signature_path = directory / ('secretwright_' + version + '_checksums.sig')
    public_path = directory / ('secretwright_' + version + '_signing-key.pem')
    if os.path.lexists(signature_path) or os.path.lexists(public_path):
        raise SigningError()
    public = openssl(['pkey', '-passin', 'env:SECRETWRIGHT_SIGNING_PASSWORD', '-pubout'], key)
    public_der = openssl(['pkey', '-pubin', '-outform', 'DER'], public)
    # SubjectPublicKeyInfo for Ed25519 is a fixed algorithm OID plus 32 bytes.
    if len(public_der) != 44 or not public_der.startswith(bytes.fromhex('302a300506032b6570032100')):
        raise SigningError()
    with tempfile.TemporaryDirectory(prefix='secretwright-signing-') as temporary:
        temporary = Path(temporary)
        private_write(temporary / 'key.pem', key)
        private_write(temporary / 'manifest.txt', manifest)
        private_write(temporary / 'public.pem', public)
        signature = openssl([
            'pkeyutl', '-sign', '-rawin', '-inkey', str(temporary / 'key.pem'),
            '-passin', 'env:SECRETWRIGHT_SIGNING_PASSWORD', '-in', str(temporary / 'manifest.txt'),
        ])
        if len(signature) != 64:
            raise SigningError()
        private_write(temporary / 'signature.bin', signature)
        openssl([
            'pkeyutl', '-verify', '-pubin', '-rawin', '-inkey', str(temporary / 'public.pem'),
            '-sigfile', str(temporary / 'signature.bin'), '-in', str(temporary / 'manifest.txt'),
        ])
    if evidence(os.lstat(manifest_path)) != evidence(manifest_evidence):
        raise SigningError()
    created = []
    complete = False
    try:
        # Reserve both names before publishing either body. O_EXCL includes symlinks.
        for path in [signature_path, public_path]:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            created.append((path, descriptor, os.fstat(descriptor)))
        for (path, descriptor, expected), body in zip(created, [signature, public]):
            with os.fdopen(descriptor, 'wb', closefd=False) as output:
                if output.write(body) != len(body):
                    raise SigningError()
                output.flush()
                os.fsync(descriptor)
            current = os.lstat(path)
            if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
                raise SigningError()
        if evidence(os.lstat(manifest_path)) != evidence(manifest_evidence):
            raise SigningError()
        complete = True
    finally:
        for path, descriptor, expected in created:
            os.close(descriptor)
            if not complete:
                try:
                    current = os.lstat(path)
                    if (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino):
                        path.unlink()
                except OSError:
                    pass


try:
    main()
except Exception:
    print('secretwright: release signing failed', file=sys.stderr)
    sys.exit(1)
PY
