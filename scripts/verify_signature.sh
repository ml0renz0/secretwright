#!/usr/bin/env bash
# The caller selects a trusted public key; a key from the same download is not trust.
set -euo pipefail
exec python3 - "$@" <<'PY'
from pathlib import Path
import os
import re
import stat
import subprocess
import sys
import tempfile


class VerificationError(Exception):
    pass


def checked_file(path, maximum):
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > maximum:
        raise VerificationError()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        opened = os.fstat(descriptor)
        if evidence(before) != evidence(opened):
            raise VerificationError()
        with os.fdopen(descriptor, 'rb', closefd=False) as source:
            body = source.read(maximum + 1)
        if len(body) != before.st_size or evidence(before) != evidence(os.fstat(descriptor)) or evidence(before) != evidence(os.lstat(path)):
            raise VerificationError()
        return body
    finally:
        os.close(descriptor)


def evidence(value):
    return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns


def openssl(arguments, body=None):
    result = subprocess.run(['openssl', *arguments], input=body, capture_output=True, check=False, timeout=30)
    if result.returncode != 0:
        raise VerificationError()
    return result.stdout


def private_write(path, body):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        if output.write(body) != len(body):
            raise VerificationError()


def main():
    if len(sys.argv) != 4:
        raise VerificationError()
    directory, version, public_path = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    numeric = r'(?:0|[1-9][0-9]*)'
    identifier = r'(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
    version_pattern = (numeric + r'\.' + numeric + r'\.' + numeric
                       + r'(?:-' + identifier + r'(?:\.' + identifier + r')*)?'
                       + r'(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?')
    if not re.fullmatch(version_pattern, version) or len(version) > 256:
        raise VerificationError()
    manifest = checked_file(directory / ('secretwright_' + version + '_checksums.txt'), 1 << 20)
    signature = checked_file(directory / ('secretwright_' + version + '_checksums.sig'), 64)
    public = checked_file(public_path, 65536)
    if len(signature) != 64:
        raise VerificationError()
    public_der = openssl(['pkey', '-pubin', '-outform', 'DER'], public)
    if len(public_der) != 44 or not public_der.startswith(bytes.fromhex('302a300506032b6570032100')):
        raise VerificationError()
    with tempfile.TemporaryDirectory(prefix='secretwright-verification-') as temporary:
        temporary = Path(temporary)
        private_write(temporary / 'manifest.txt', manifest)
        private_write(temporary / 'signature.bin', signature)
        private_write(temporary / 'public.pem', public)
        openssl([
            'pkeyutl', '-verify', '-pubin', '-rawin', '-inkey', str(temporary / 'public.pem'),
            '-sigfile', str(temporary / 'signature.bin'), '-in', str(temporary / 'manifest.txt'),
        ])


try:
    main()
except Exception:
    print('secretwright: release signature verification failed', file=sys.stderr)
    sys.exit(1)
PY
