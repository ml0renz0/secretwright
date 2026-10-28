"""Exercise real dpkg-deb output independently of the release verifier."""

from pathlib import Path
import hashlib
import importlib.util
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / 'scripts' / 'build_deb.py'
SPEC = importlib.util.spec_from_file_location('deb_builder_archive_fixtures', Path(__file__).with_name('test_verify_release.py'))
FIXTURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURES)
VERSION = '1.2.3-rc.4'
EPOCH = 1700000000


class DebianBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='secretwright-deb-build-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = FIXTURES.write_archive(self.root, 'linux', 'amd64', version=VERSION)
        self.output = self.root / 'secretwright_1.2.3-rc.4_amd64.deb'

    def invoke(self, *, architecture='amd64', version=VERSION, output=None, archive=None, epoch=EPOCH):
        return subprocess.run([sys.executable, str(BUILD), str(archive or self.archive), str(output or self.output),
                               '--version', version, '--arch', architecture, '--epoch', str(epoch)],
                              capture_output=True, check=False, text=True)

    def reject(self, **options):
        result = self.invoke(**options)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(str(self.root), result.stdout + result.stderr)
        self.assertNotIn('private-deb-builder-marker', result.stdout + result.stderr)
        self.assertFalse(self.output.exists())

    def test_real_package_metadata_payload_permissions_and_md5sums(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        fields = subprocess.check_output(['dpkg-deb', '--field', str(self.output), 'Package', 'Version', 'Architecture', 'Depends'], text=True)
        for field in ('Package: secretwright', 'Version: 1.2.3~rc.4', 'Architecture: amd64', 'Depends: ca-certificates'):
            self.assertIn(field, fields)
        extracted = self.root / 'extracted'
        subprocess.run(['dpkg-deb', '--extract', str(self.output), str(extracted)], check=True)
        control = self.root / 'control'
        subprocess.run(['dpkg-deb', '--control', str(self.output), str(control)], check=True)
        expected = {'usr/bin/secretwright': (FIXTURES.binary_fixture('linux', 'amd64'), 0o755),
                    'usr/share/doc/secretwright/README.md': (b'# Secretwright\n', 0o644),
                    'usr/share/doc/secretwright/copyright': (b'MIT License\n', 0o644)}
        actual = {str(path.relative_to(extracted)) for path in extracted.rglob('*') if path.is_file()}
        self.assertEqual(actual, set(expected))
        for name, (body, mode) in expected.items():
            self.assertEqual((extracted / name).read_bytes(), body)
            self.assertEqual((extracted / name).stat().st_mode & 0o777, mode)
        sums = dict((line.split('  ', 1)[1], line.split('  ', 1)[0]) for line in (control / 'md5sums').read_text().splitlines())
        self.assertEqual(sums, {name: hashlib.md5(body, usedforsecurity=False).hexdigest() for name, (body, _) in expected.items()})
        self.assertEqual({p.name for p in control.iterdir()}, {'control', 'md5sums'})

    def test_builds_are_byte_reproducible_across_staging_directories(self):
        self.assertEqual(self.invoke().returncode, 0)
        directory = self.root / 'other'
        directory.mkdir()
        other = directory / self.output.name
        self.assertEqual(self.invoke(output=other).returncode, 0)
        self.assertEqual(self.output.read_bytes(), other.read_bytes())

    def test_arm64_package_contains_the_exact_arm64_archive_binary(self):
        archive = FIXTURES.write_archive(self.root, 'linux', 'arm64', version=VERSION)
        output = self.root / 'secretwright_1.2.3-rc.4_arm64.deb'
        self.assertEqual(self.invoke(architecture='arm64', archive=archive, output=output).returncode, 0)
        self.assertEqual(subprocess.check_output(['dpkg-deb', '--field', str(output), 'Architecture'], text=True).strip(), 'arm64')
        extracted = self.root / 'arm-extracted'
        subprocess.run(['dpkg-deb', '--extract', str(output), str(extracted)], check=True)
        self.assertEqual((extracted / 'usr/bin/secretwright').read_bytes(), FIXTURES.binary_fixture('linux', 'arm64'))

    def test_debian_prerelease_orders_before_final_version(self):
        self.assertEqual(self.invoke().returncode, 0)
        actual = subprocess.check_output(['dpkg-deb', '--field', str(self.output), 'Version'], text=True).strip()
        self.assertEqual(subprocess.run(['dpkg', '--compare-versions', actual, 'lt', '1.2.3']).returncode, 0)

    def test_wrong_architecture_is_rejected_without_an_output(self):
        output = self.root / 'secretwright_1.2.3-rc.4_arm64.deb'
        result = self.invoke(architecture='arm64', output=output)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())

    def test_existing_output_is_never_overwritten(self):
        self.output.write_bytes(b'private-deb-builder-marker')
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_bytes(), b'private-deb-builder-marker')
        self.assertNotIn('private-deb-builder-marker', result.stdout + result.stderr)

    def test_symlink_source_and_unexpected_members_are_rejected(self):
        link = self.root / 'linked.tar.gz'
        link.symlink_to(self.archive)
        self.reject(archive=link)
        FIXTURES.write_archive(self.root, 'linux', 'amd64', version=VERSION,
                               members=[('../private-deb-builder-marker', b'bad', 0o755)])
        self.reject()

    def test_version_and_epoch_inputs_are_validated_before_building(self):
        for options in ({'version': '1.2.3\nprivate-deb-builder-marker'}, {'epoch': -1}):
            with self.subTest(options=options):
                self.reject(**options)


if __name__ == '__main__':
    unittest.main()
