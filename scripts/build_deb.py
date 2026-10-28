#!/usr/bin/env python3
"""Build a deterministic Debian package from the verified Linux archive bytes."""

import argparse
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile


MAX_ARCHIVE = 128 << 20
MAX_DOCUMENT = 4 << 20


class BuildError(Exception):
    pass


def require(condition):
    if not condition:
        raise BuildError()


def read_regular(path, maximum):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as source:
        opened = os.fstat(source.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns))
        body = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        require(len(body) == before.st_size and
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns))
    current = path.lstat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns))
    return body


def archive_payload(path, architecture):
    import io
    from verify_release import verify_elf
    body = read_regular(path, MAX_ARCHIVE)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        for member in archive:
            require(member.name in {'secretwright', 'README.md', 'LICENSE'} and member.name not in files)
            require(member.isfile() and member.mode == (0o755 if member.name == 'secretwright' else 0o644))
            require(0 < member.size <= (MAX_ARCHIVE if member.name == 'secretwright' else MAX_DOCUMENT))
            source = archive.extractfile(member)
            require(source is not None)
            content = source.read(member.size + 1)
            require(len(content) == member.size)
            files[member.name] = content
    require(set(files) == {'secretwright', 'README.md', 'LICENSE'})
    verify_elf(files['secretwright'], architecture)
    return files


def build_deb(archive_path, output_path, version, architecture, epoch):
    from verify_deb import deb_name, debian_version, verify_deb
    archive_path, output_path = Path(archive_path), Path(output_path)
    require(architecture in ('amd64', 'arm64') and type(epoch) is int and 0 <= epoch <= 9999999999)
    selected_version = debian_version(version)
    require(output_path.name == deb_name(version, architecture)
            and output_path.parent.is_dir() and not os.path.lexists(output_path))
    files = archive_payload(archive_path, architecture)
    payload = {'usr/bin/secretwright': (files['secretwright'], 0o755),
               'usr/share/doc/secretwright/README.md': (files['README.md'], 0o644),
               'usr/share/doc/secretwright/copyright': (files['LICENSE'], 0o644)}
    with tempfile.TemporaryDirectory(prefix='secretwright-deb-build-') as temporary:
        temporary = Path(temporary)
        root = temporary / 'root'
        root.mkdir(mode=0o755)
        control_directory = root / 'DEBIAN'
        control_directory.mkdir(mode=0o755)
        for name, (body, mode) in payload.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as destination:
                require(destination.write(body) == len(body))
            target.chmod(mode)
        installed_size = max(1, (sum(len(body) for body, _ in payload.values()) + 1023) // 1024)
        control = ('Package: secretwright\nVersion: ' + selected_version + '\nSection: utils\nPriority: optional\n'
                   'Architecture: ' + architecture + '\n'
                   'Maintainer: Secretwright maintainers <ml0renz0@users.noreply.github.com>\n'
                   'Installed-Size: ' + str(installed_size) + '\nDepends: ca-certificates\n'
                   'Homepage: https://github.com/ml0renz0/secretwright\n'
                   'Description: Vault automation and secret lifecycle command-line tool\n')
        (control_directory / 'control').write_text(control, encoding='utf-8')
        sums = ''.join(hashlib.md5(body, usedforsecurity=False).hexdigest() + '  ' + name + '\n'
                       for name, (body, _) in sorted(payload.items()))
        (control_directory / 'md5sums').write_text(sums, encoding='ascii')
        for path in [root, *root.rglob('*')]:
            if path.is_dir():
                path.chmod(0o755)
            elif path.parent == control_directory:
                path.chmod(0o644)
            os.utime(path, (epoch, epoch), follow_symlinks=False)
        generated = temporary / 'package.deb'
        selected = {'PATH': os.defpath, 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'SOURCE_DATE_EPOCH': str(epoch)}
        result = subprocess.run(['dpkg-deb', '--build', '--root-owner-group', '--threads-max=1',
                                 '-Zgzip', '-z9', '--uniform-compression', str(root), str(generated)],
                                env=selected, capture_output=True, check=False, timeout=180)
        require(result.returncode == 0)
        package = read_regular(generated, MAX_ARCHIVE)
        require(verify_deb(package, version, architecture) == files['secretwright'])
        descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(descriptor, 'wb') as destination:
            require(destination.write(package) == len(package))
    return {'version': version, 'debian_version': selected_version, 'architecture': architecture,
            'binary_sha256': hashlib.sha256(files['secretwright']).hexdigest()}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise BuildError()


def main():
    try:
        parser = Parser(description=__doc__)
        parser.add_argument('archive', type=Path)
        parser.add_argument('output', type=Path)
        parser.add_argument('--version', required=True)
        parser.add_argument('--arch', required=True)
        parser.add_argument('--epoch', type=int, required=True)
        arguments = parser.parse_args()
        report = build_deb(arguments.archive, arguments.output, arguments.version, arguments.arch, arguments.epoch)
    except Exception:
        print('Debian package build failed.', file=sys.stderr)
        return 1
    import json
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
