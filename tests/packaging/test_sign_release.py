"""Acceptance tests for offline release signatures using real OpenSSL keys."""

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SIGN = ROOT / 'scripts' / 'sign_release.sh'
VERIFY = ROOT / 'scripts' / 'verify_signature.sh'
VERSION = '1.2.3'
PASSWORD = 'private-f13-signing-password-marker'


class ReleaseSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory(prefix='secretwright-signing-fixtures-')
        cls.key_root = Path(cls.keys.name)
        cls.environment = dict(os.environ, SECRETWRIGHT_SIGNING_PASSWORD=PASSWORD)
        for name in ['selected', 'other']:
            key = cls.key_root / (name + '.pem')
            result = subprocess.run(
                ['openssl', 'genpkey', '-algorithm', 'ED25519', '-aes-256-cbc',
                 '-pass', 'env:SECRETWRIGHT_SIGNING_PASSWORD', '-out', str(key)],
                env=cls.environment, capture_output=True, check=False,
            )
            if result.returncode != 0:
                raise RuntimeError('could not create ephemeral signature fixture')
            key.chmod(0o600)
            public = cls.key_root / (name + '.pub')
            result = subprocess.run(
                ['openssl', 'pkey', '-in', str(key), '-passin',
                 'env:SECRETWRIGHT_SIGNING_PASSWORD', '-pubout', '-out', str(public)],
                env=cls.environment, capture_output=True, check=False,
            )
            if result.returncode != 0:
                raise RuntimeError('could not create ephemeral public fixture')
        cls.plain_key = cls.key_root / 'plain.pem'
        result = subprocess.run(
            ['openssl', 'pkey', '-in', str(cls.key_root / 'selected.pem'),
             '-passin', 'env:SECRETWRIGHT_SIGNING_PASSWORD', '-out', str(cls.plain_key)],
            env=cls.environment, capture_output=True, check=False,
        )
        if result.returncode != 0:
            raise RuntimeError('could not create unencrypted negative fixture')
        cls.plain_key.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='secretwright-signature-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dist = self.root / 'dist'
        self.dist.mkdir(mode=0o700)
        self.manifest = self.dist / ('secretwright_' + VERSION + '_checksums.txt')
        self.manifest.write_text('a' * 64 + '  secretwright_1.2.3_linux_amd64.tar.gz\n')
        self.key = self.root / 'private-f13-key-path-marker.pem'
        shutil.copyfile(self.key_root / 'selected.pem', self.key)
        self.key.chmod(0o600)
        self.signature = self.dist / ('secretwright_' + VERSION + '_checksums.sig')
        self.public = self.dist / ('secretwright_' + VERSION + '_signing-key.pem')

    def invoke(self, script, *arguments, environment=None):
        result = subprocess.run(
            ['bash', str(script), *map(str, arguments)],
            env=self.environment if environment is None else environment,
            cwd=self.root, capture_output=True, check=False,
        )
        self.assert_private(result)
        return result

    def assert_private(self, result):
        output = result.stdout + result.stderr
        for marker in [PASSWORD.encode(), b'BEGIN ENCRYPTED PRIVATE KEY',
                       b'BEGIN PRIVATE KEY', b'private-f13-key-path-marker',
                       b'private-f13-rejected-input-marker', b'private-f13-wrong-password', b'Traceback']:
            self.assertFalse(marker in output, 'signature command exposed private diagnostics')

    def assert_rejected(self, result):
        self.assertNotEqual(result.returncode, 0, 'invalid signing operation succeeded')
        self.assertTrue(result.stderr, 'rejected signing operation omitted a safe diagnostic')

    def sign(self):
        result = self.invoke(SIGN, self.dist, VERSION, self.key)
        self.assertEqual(result.returncode, 0, 'valid encrypted Ed25519 key was rejected')
        self.assertTrue(self.signature.is_file(), 'signature output was not published')
        self.assertTrue(self.public.is_file(), 'public verification key was not published')

    def test_signs_exact_manifest_and_independent_openssl_verifies(self):
        original = self.manifest.read_bytes()
        self.sign()
        self.assertEqual(self.manifest.read_bytes(), original, 'signing changed the checksum manifest')
        self.assertEqual(len(self.signature.read_bytes()), 64, 'output is not an Ed25519 signature')
        self.assertIn(b'BEGIN PUBLIC KEY', self.public.read_bytes(), 'public output is not PEM')
        independent = subprocess.run(
            ['openssl', 'pkeyutl', '-verify', '-pubin', '-rawin', '-inkey',
             str(self.key_root / 'selected.pub'), '-sigfile', str(self.signature),
             '-in', str(self.manifest)], capture_output=True, check=False,
        )
        self.assertEqual(independent.returncode, 0, 'signature did not cover the exact manifest')
        result = self.invoke(VERIFY, self.dist, VERSION, self.key_root / 'selected.pub')
        self.assertEqual(result.returncode, 0, 'trusted public key could not verify the release')

    def test_modified_manifest_and_signature_fail_verification(self):
        self.sign()
        original = self.manifest.read_bytes()
        self.manifest.write_bytes(original.replace(b'a', b'b', 1))
        self.assert_rejected(self.invoke(VERIFY, self.dist, VERSION, self.public))
        self.manifest.write_bytes(original)
        signature = self.signature.read_bytes()
        self.signature.write_bytes(bytes([signature[0] ^ 1]) + signature[1:])
        self.assert_rejected(self.invoke(VERIFY, self.dist, VERSION, self.public))

    def test_verification_uses_caller_trusted_key_without_bundled_key_fallback(self):
        self.sign()
        self.assert_rejected(self.invoke(VERIFY, self.dist, VERSION, self.key_root / 'other.pub'))
        self.public.unlink()
        result = self.invoke(VERIFY, self.dist, VERSION, self.key_root / 'selected.pub')
        self.assertEqual(result.returncode, 0, 'verification unnecessarily trusted the bundled key')

    def test_missing_wrong_password_and_unencrypted_keys_fail_before_outputs(self):
        wrong = dict(self.environment, SECRETWRIGHT_SIGNING_PASSWORD='private-f13-wrong-password')
        missing = dict(self.environment)
        missing.pop('SECRETWRIGHT_SIGNING_PASSWORD', None)
        cases = [
            (self.root / 'private-f13-rejected-input-marker', self.environment),
            (self.key, wrong), (self.key, missing), (self.plain_key, self.environment),
        ]
        for key, environment in cases:
            with self.subTest(case=cases.index((key, environment))):
                self.assert_rejected(self.invoke(SIGN, self.dist, VERSION, key, environment=environment))
                self.assertFalse(self.signature.exists(), 'failed signing retained a signature')
                self.assertFalse(self.public.exists(), 'failed signing retained public output')

    def test_public_or_symlink_private_key_is_rejected(self):
        self.key.chmod(0o644)
        self.assert_rejected(self.invoke(SIGN, self.dist, VERSION, self.key))
        self.key.chmod(0o600)
        link = self.root / 'selected-key-link.pem'
        link.symlink_to(self.key)
        self.assert_rejected(self.invoke(SIGN, self.dist, VERSION, link))
        self.assertFalse(self.signature.exists(), 'unsafe key published a signature')
        self.assertFalse(self.public.exists(), 'unsafe key published a public output')

    def test_signing_never_overwrites_existing_output_or_symlink(self):
        for output in [self.signature, self.public]:
            with self.subTest(output=output.name):
                output.write_bytes(b'existing-public-output')
                self.assert_rejected(self.invoke(SIGN, self.dist, VERSION, self.key))
                self.assertEqual(output.read_bytes(), b'existing-public-output', 'existing output was replaced')
                other = self.public if output == self.signature else self.signature
                self.assertFalse(other.exists(), 'output conflict left a partial release signature pair')
                output.unlink()
        outside = self.root / 'existing-target'
        outside.write_bytes(b'existing-public-output')
        self.signature.symlink_to(outside)
        self.assert_rejected(self.invoke(SIGN, self.dist, VERSION, self.key))
        self.assertTrue(self.signature.is_symlink(), 'existing symlink was removed')
        self.assertEqual(outside.read_bytes(), b'existing-public-output', 'symlink target was overwritten')
        self.assertFalse(self.public.exists(), 'symlink conflict left another output')

    def test_invalid_manifest_or_version_never_signs_an_outside_file(self):
        self.manifest.unlink()
        self.assert_rejected(self.invoke(SIGN, self.dist, VERSION, self.key))
        outside = self.root / 'outside-checksums.txt'
        outside.write_text('private-f13-rejected-input-marker')
        self.manifest.symlink_to(outside)
        self.assert_rejected(self.invoke(SIGN, self.dist, VERSION, self.key))
        for version in ['../private-f13-rejected-input-marker', '-private-f13-rejected-input-marker', '1.2.3\nprivate-f13-rejected-input-marker']:
            self.assert_rejected(self.invoke(SIGN, self.dist, version, self.key))
        self.assertFalse(self.signature.exists(), 'invalid manifest published a signature')
        self.assertFalse(self.public.exists(), 'invalid manifest published a public key')

    def test_missing_truncated_or_symlink_signature_is_rejected(self):
        self.sign()
        original = self.signature.read_bytes()
        self.signature.unlink()
        self.assert_rejected(self.invoke(VERIFY, self.dist, VERSION, self.public))
        self.signature.write_bytes(original[:8])
        self.assert_rejected(self.invoke(VERIFY, self.dist, VERSION, self.public))
        self.signature.unlink()
        outside = self.root / 'signature-copy'
        outside.write_bytes(original)
        self.signature.symlink_to(outside)
        self.assert_rejected(self.invoke(VERIFY, self.dist, VERSION, self.public))


if __name__ == '__main__':
    unittest.main()
