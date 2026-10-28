"""Inspect real dpkg packages and hostile containers without installing them."""

from pathlib import Path
import copy
import gzip
import hashlib
import importlib.util
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('verify_deb_subject', ROOT / 'scripts' / 'verify_deb.py')
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)
VERSION = '1.2.3-rc.4'
DEBIAN_VERSION = '1.2.3~rc.4'
EXECUTABLE = b'private-deb-fixture-executable'
FILES = {
    'usr/bin/secretwright': (EXECUTABLE, 0o755),
    'usr/share/doc/secretwright/README.md': (b'# Secretwright\n', 0o644),
    'usr/share/doc/secretwright/copyright': (b'MIT License\nCopyright 2026\n', 0o644),
}


def real_package(directory):
    stage = directory / 'root'
    (stage / 'DEBIAN').mkdir(parents=True)
    for name, (body, mode) in FILES.items():
        path = stage / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(mode)
    control = ('Package: secretwright\nVersion: ' + DEBIAN_VERSION + '\nArchitecture: amd64\n'
               'Maintainer: Secretwright maintainers <ml0renz0@users.noreply.github.com>\n'
               'Section: utils\nPriority: optional\nInstalled-Size: 1\nDepends: ca-certificates\n'
               'Homepage: https://github.com/ml0renz0/secretwright\n'
               'Description: Vault automation CLI\n')
    (stage / 'DEBIAN/control').write_text(control)
    (stage / 'DEBIAN/md5sums').write_text(''.join(
        hashlib.md5(body, usedforsecurity=False).hexdigest() + '  ' + name + '\n'
        for name, (body, _) in sorted(FILES.items())))
    for path in stage.rglob('*'):
        if path.is_dir():
            path.chmod(0o755)
        elif path.parent.name == 'DEBIAN':
            path.chmod(0o644)
    stage.chmod(0o755)
    destination = directory / 'fixture.deb'
    subprocess.run(['dpkg-deb', '--build', '--root-owner-group', '-Zgzip', '--uniform-compression',
                    str(stage), str(destination)], check=True, capture_output=True,
                   env=dict(os.environ, SOURCE_DATE_EPOCH='1700000000'))
    return destination.read_bytes()


def ar_members(body):
    members, position = [], 8
    while position < len(body):
        header = body[position:position + 60]
        size = int(header[48:58])
        members.append((header[:16].decode().strip().rstrip('/'), body[position + 60:position + 60 + size]))
        position += 60 + size + size % 2
    return members


def ar_container(members):
    result = b'!<arch>\n'
    for name, body in members:
        header = (name.ljust(16) + '1700000000'.ljust(12) + '0'.ljust(6) + '0'.ljust(6)
                  + '100644'.ljust(8) + str(len(body)).ljust(10) + '`\n').encode()
        result += header + body + (b'\n' if len(body) % 2 else b'')
    return result


def tar_members(body):
    result = []
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as source:
        for item in source:
            result.append((copy.copy(item), source.extractfile(item).read() if item.isfile() else b''))
    return result


def tar_container(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for original, body in members:
            item = copy.copy(original)
            item.size = len(body) if item.isfile() else 0
            archive.addfile(item, io.BytesIO(body) if item.isfile() else None)
    return gzip.compress(output.getvalue(), mtime=0)


class DebianVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='secretwright-deb-verifier-test-')
        self.addCleanup(self.temporary.cleanup)
        self.body = real_package(Path(self.temporary.name))

    def verify(self, body=None, *, version=VERSION, architecture='amd64'):
        return VERIFY.verify_deb(self.body if body is None else body, version, architecture)

    def reject(self, body, **options):
        with self.assertRaises(VERIFY.VerificationError) as caught:
            self.verify(body, **options)
        self.assertNotIn('private-deb-fixture', str(caught.exception))
        self.assertNotIn(self.temporary.name, str(caught.exception))

    def mutate_tar(self, member_name, mutate):
        members = ar_members(self.body)
        replaced = []
        for name, body in members:
            replaced.append((name, tar_container(mutate(tar_members(body)))) if name == member_name else (name, body))
        return ar_container(replaced)

    def change_control(self, transform):
        def mutate(items):
            return [(item, transform(body.decode()).encode() if item.name.rstrip('/') in ('./control', 'control') else body)
                    for item, body in items]
        return self.mutate_tar('control.tar.gz', mutate)

    def test_real_dpkg_package_returns_exact_binary_and_orders_rc_before_stable(self):
        self.assertEqual(self.verify(), EXECUTABLE)
        subprocess.run(['dpkg', '--compare-versions', VERIFY.debian_version(VERSION), 'lt', '1.2.3'], check=True)

    def test_helpers_preserve_build_metadata_and_encode_only_prerelease_separator(self):
        cases = {'1.2.3': '1.2.3', '1.2.3-rc.4': '1.2.3~rc.4',
                 '0.0.0-snapshot.gabc123': '0.0.0~snapshot.gabc123',
                 '1.2.3+build-x': '1.2.3+build-x',
                 '1.2.3-rc-foo+build-x': '1.2.3~rc-foo+build-x'}
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(VERIFY.debian_version(source), expected)
                self.assertEqual(VERIFY.deb_name(source, 'arm64'), 'secretwright_' + expected + '_arm64.deb')
                self.assertEqual(VERIFY.deb_sbom_name(source, 'amd64'), 'secretwright_' + expected + '_amd64.deb.spdx.json')

    def test_helpers_reject_invalid_versions_and_architectures(self):
        for version in ('v1.2.3', '01.2.3', '1.2.3-rc.01', '1.2.3/../../x', '', '1.2.3\n', '1.2.3-' + 'x' * 129):
            with self.subTest(version=version), self.assertRaises(VERIFY.VerificationError):
                VERIFY.debian_version(version)
        for arch in ('all', 'x86_64', '../../x', ''):
            with self.subTest(architecture=arch), self.assertRaises(VERIFY.VerificationError):
                VERIFY.deb_name(VERSION, arch)

    def test_control_version_and_architecture_must_match_selected_package(self):
        self.reject(self.body, version='1.2.3')
        self.reject(self.body, architecture='arm64')
        self.reject(self.change_control(lambda text: text.replace('Package: secretwright', 'Package: replacement')))

    def test_control_rejects_duplicate_fields_and_additional_paragraphs(self):
        for suffix in ('Version: ' + DEBIAN_VERSION + '\n', 'pAcKaGe: secretwright\n', '\nDescription: second paragraph\n'):
            with self.subTest(suffix=suffix):
                self.reject(self.change_control(lambda text: text + suffix))

    def test_control_rejects_dependency_changes_and_behavioral_metadata(self):
        self.reject(self.change_control(lambda text: text.replace('ca-certificates', 'unexpected-package')))
        for field in ('Essential: yes', 'Protected: yes', 'Pre-Depends: unexpected', 'Replaces: dpkg',
                      'Conflicts: dpkg', 'Breaks: dpkg', 'Provides: dpkg', 'Multi-Arch: foreign'):
            with self.subTest(field=field):
                self.reject(self.change_control(lambda text: text + field + '\n'))

    def test_control_rejects_missing_identity_and_size_fields(self):
        for field in ('Maintainer', 'Description', 'Installed-Size'):
            with self.subTest(field=field):
                self.reject(self.change_control(lambda text: ''.join(line for line in text.splitlines(True)
                                                                     if not line.startswith(field + ':'))))
        for value in ('0', '-1', 'huge'):
            self.reject(self.change_control(lambda text: text.replace('Installed-Size: 1', 'Installed-Size: ' + value)))

    def test_maintainer_scripts_triggers_conffiles_and_unknown_control_files_rejected(self):
        for name in ('./preinst', './postinst', './prerm', './postrm', './triggers', './conffiles', './unknown'):
            with self.subTest(name=name):
                def mutate(items):
                    item = tarfile.TarInfo(name)
                    item.mode, item.uid, item.gid = 0o644, 0, 0
                    return items + [(item, b'private-deb-fixture')]
                self.reject(self.mutate_tar('control.tar.gz', mutate))

    def test_data_rejects_traversal_absolute_and_noncanonical_names(self):
        for name in ('../../escape', '/usr/bin/secretwright', './usr/../bin/secretwright',
                     './usr//bin/secretwright', './usr/bin/./secretwright', './usr\\bin\\secretwright'):
            with self.subTest(name=name):
                def mutate(items):
                    items[2][0].name = name
                    return items
                self.reject(self.mutate_tar('data.tar.gz', mutate))

    def test_directory_normalization_cannot_hide_absolute_or_duplicate_slashes(self):
        for index, name in ((0, '/'), (1, './usr//'), (1, 'usr//')):
            with self.subTest(name=name):
                def mutate(items):
                    items[index][0].name = name
                    return items
                self.reject(self.mutate_tar('data.tar.gz', mutate))

    def test_symbolic_links_hard_links_and_special_members_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                def mutate(items):
                    item = items[-1][0]
                    item.type, item.linkname = kind, 'private-deb-fixture-link-target'
                    return items
                self.reject(self.mutate_tar('data.tar.gz', mutate))

    def test_data_rejects_wrong_permissions_and_nonroot_owners(self):
        for attribute, value in (('mode', 0o777), ('mode', 0o4755), ('uid', 1), ('gid', 1)):
            with self.subTest(attribute=attribute, value=value):
                def mutate(items):
                    for item, _ in items:
                        if item.isfile():
                            setattr(item, attribute, value)
                            break
                    return items
                self.reject(self.mutate_tar('data.tar.gz', mutate))

    def test_data_requires_all_files_and_normal_parent_directories(self):
        self.reject(self.mutate_tar('data.tar.gz', lambda items: items[:-1]))
        self.reject(self.mutate_tar('data.tar.gz', lambda items: [(item, body) for item, body in items if item.name != './usr/bin']))
        def unexpected(items):
            item = tarfile.TarInfo('./usr/share/unexpected')
            item.mode, item.uid, item.gid = 0o644, 0, 0
            return items + [(item, b'extra')]
        self.reject(self.mutate_tar('data.tar.gz', unexpected))

    def test_duplicate_entries_include_canonical_aliases(self):
        self.reject(self.mutate_tar('data.tar.gz', lambda items: items + [items[-1]]))
        def alias(items):
            item, body = items[-1]
            item = copy.copy(item)
            item.name = item.name.removeprefix('./')
            return items + [(item, body)]
        self.reject(self.mutate_tar('data.tar.gz', alias))

    def test_md5_inventory_requires_exact_coverage_and_matching_bytes(self):
        def wrong(items):
            return [(item, b'0' * 32 + body[32:] if item.name == './md5sums' else body) for item, body in items]
        self.reject(self.mutate_tar('control.tar.gz', wrong))
        def duplicate(items):
            return [(item, body + body.splitlines(True)[0] if item.name == './md5sums' else body) for item, body in items]
        self.reject(self.mutate_tar('control.tar.gz', duplicate))
        self.reject(self.mutate_tar('control.tar.gz', lambda items: [(item, body) for item, body in items if item.name != './md5sums']))

    def test_ar_requires_exact_members_versions_order_and_numeric_headers(self):
        members = ar_members(self.body)
        variants = [members[:-1], members + [('extra', b'extra')], members + [members[-1]], members[::-1],
                    [('debian-binary', b'3.0\n'), *members[1:]]]
        for variant in variants:
            with self.subTest(names=[name for name, _ in variant]):
                self.reject(ar_container(variant))
        self.reject(self.body[:48] + b'invalid!' + self.body[56:])

    def test_ar_and_gzip_reject_truncation_and_trailing_bytes(self):
        for body in (b'', self.body[:-1], self.body[:70], self.body + b'extra'):
            self.reject(body)
        members = ar_members(self.body)
        for suffix in (b'extra', gzip.compress(b'extra', mtime=0)):
            altered = [(name, body + suffix if name == 'data.tar.gz' else body) for name, body in members]
            self.reject(ar_container(altered))

    def test_tar_rejects_nonzero_trailing_data_and_extended_headers(self):
        members = ar_members(self.body)
        bad = [(name, gzip.compress(gzip.decompress(body) + b'X' * 512, mtime=0)
                if name == 'data.tar.gz' else body) for name, body in members]
        self.reject(ar_container(bad))
        def extended(items):
            header = tarfile.TarInfo('./pax')
            header.type, header.mode, header.uid, header.gid = tarfile.XHDTYPE, 0o644, 0, 0
            return [(header, b'')] + items
        self.reject(self.mutate_tar('data.tar.gz', extended))

    def test_decompression_is_bounded_before_tar_parsing(self):
        with mock.patch.object(VERIFY, 'MAX_DATA_TAR', 1024):
            self.reject(self.body)


if __name__ == '__main__':
    unittest.main()
