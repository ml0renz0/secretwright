"""Exercise release publication guards with real local artifacts and a fake GH client."""

from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
PUBLISH = ROOT / 'scripts' / 'publish_release.py'
PASSWORD = 'private-f13-publisher-password'
TOKEN = 'private-f13-publisher-token'


def fixture_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ARTIFACTS = fixture_module('publish_artifact_fixtures', 'test_verify_release.py')
OCI = fixture_module('publish_oci_fixtures', 'test_oci.py')


FAKE_GH = r'''#!/usr/bin/env python3
from pathlib import Path
import hashlib, json, os, sys
state_path = Path(os.environ['FAKE_GH_STATE'])
state = json.loads(state_path.read_text())
args = sys.argv[1:]
state.setdefault('calls', []).append({'args': args, 'signing_key_present': 'SECRETWRIGHT_SIGNING_KEY' in os.environ,
    'password_present': 'SECRETWRIGHT_SIGNING_PASSWORD' in os.environ, 'token_present': bool(os.environ.get('GH_TOKEN')),
    'host': os.environ.get('GH_HOST'), 'fallback_token_present': 'GITHUB_TOKEN' in os.environ})
def save(): state_path.write_text(json.dumps(state))
def reply(status, body, success=None):
    save()
    print('HTTP/2.0 ' + str(status) + ' Controlled Fixture\r\nContent-Type: application/json\r\n\r\n' + json.dumps(body))
    sys.exit((0 if status == 200 else 1) if success is None else success)
if args[0] == 'api':
    endpoint = args[-1]
    if '/git/ref/tags/' in endpoint:
        state['tag_checks'] = state.get('tag_checks', 0) + 1
        moved = state.get('move_tag') == 'before-create' or state.get('move_tag') == 'before-publish' and state['tag_checks'] >= 2
        sha = 'f' * 40 if moved else state['sha']
        target = {'type': 'tag', 'sha': 'b' * 40} if state.get('annotated') else {'type': 'commit', 'sha': sha}
        reply(200, {'object': target})
    if '/git/tags/' in endpoint:
        moved = state.get('move_tag') == 'before-create' or state.get('move_tag') == 'before-publish' and state.get('tag_checks', 0) >= 2
        target = {'type': 'tag', 'sha': 'b' * 40} if state.get('tag_cycle') else {'type': 'commit', 'sha': 'f' * 40 if moved else state['sha']}
        reply(200, {'object': target})
    if '/releases/tags/' in endpoint:
        if not state.get('created'):
            status = state.get('existing_status', 404)
            if status == 0:
                save(); print('private-f13-upstream-error', file=sys.stderr); sys.exit(1)
            reply(status, {'message': 'private-f13-upstream-error'})
        assets = [dict(asset) for asset in state['uploaded']]
        error = state.get('asset_error')
        if error == 'digest': assets[0]['digest'] = 'sha256:' + '0' * 64
        if error == 'size': assets[0]['size'] += 1
        if error == 'state': assets[0]['state'] = 'starter'
        if error == 'extra': assets.append({'name': 'unexpected.txt', 'size': 1, 'digest': 'sha256:' + '0'*64, 'state': 'uploaded'})
        if error == 'missing': assets.pop()
        if error == 'duplicate': assets[-1] = dict(assets[0])
        reply(200, {'tag_name': state['tag'] if error != 'tag' else 'v9.9.9', 'draft': error != 'not-draft',
                    'prerelease': state.get('prerelease', False), 'assets': assets})
if args[:2] == ['release', 'create']:
    paths = [Path(arg) for arg in args[2:] if arg.startswith('/') and Path(arg).is_file()]
    state['created'] = True
    state['prerelease'] = '--prerelease' in args
    state['uploaded'] = [{'name': path.name, 'size': path.stat().st_size,
                          'digest': 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest(), 'state': 'uploaded'} for path in paths]
    state['paths'] = [str(path) for path in paths]
    if state.get('modify_staged_asset'):
        path = paths[0]; before = path.stat(); path.chmod(0o600)
        body = path.read_bytes(); path.write_bytes(bytes([body[0] ^ 1]) + body[1:]); path.chmod(0o444)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    save()
    if state.get('create_error'):
        print('private-f13-upstream-error', file=sys.stderr); sys.exit(1)
    print('https://github.com/example/secretwright/releases/controlled'); sys.exit(0)
if args[:2] == ['release', 'edit']:
    state['published'] = True; save(); sys.exit(0)
save(); print('private-f13-upstream-error', file=sys.stderr); sys.exit(1)
'''


class ReleasePublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory(prefix='secretwright-publish-key-fixture-')
        key = Path(cls.keys.name) / 'encrypted.pem'
        result = subprocess.run(
            ['openssl', 'genpkey', '-algorithm', 'ED25519', '-aes-256-cbc', '-pass',
             'env:SECRETWRIGHT_SIGNING_PASSWORD', '-out', str(key)],
            env=dict(os.environ, SECRETWRIGHT_SIGNING_PASSWORD=PASSWORD), capture_output=True, check=False,
        )
        if result.returncode:
            raise RuntimeError('could not create ephemeral publication fixture')
        cls.private_key = key.read_text()
        result = subprocess.run(
            ['openssl', 'pkey', '-in', str(key), '-passin', 'env:SECRETWRIGHT_SIGNING_PASSWORD', '-pubout'],
            env=dict(os.environ, SECRETWRIGHT_SIGNING_PASSWORD=PASSWORD), capture_output=True, check=False,
        )
        if result.returncode:
            raise RuntimeError('could not derive publication verification fixture')
        cls.public_digest = 'sha256:' + hashlib.sha256(result.stdout).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='secretwright-publish-test-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / 'repository'
        self.root.mkdir()
        self.runner = self.base / 'runner'
        self.runner.mkdir(mode=0o700)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        fake = self.bin / 'gh'
        fake.write_text(FAKE_GH)
        fake.chmod(0o755)
        self.state_path = self.base / 'gh-state.json'
        self.environment = dict(
            os.environ, PATH=str(self.bin) + os.pathsep + os.environ.get('PATH', ''),
            GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
            GITHUB_REPOSITORY='example/secretwright', GITHUB_REF_TYPE='tag', GITHUB_REF_NAME='v1.2.3',
            GH_TOKEN=TOKEN, GITHUB_TOKEN='private-f13-unselected-fallback-token', GH_HOST='foreign.example.test',
            SECRETWRIGHT_SIGNING_KEY=self.private_key, SECRETWRIGHT_SIGNING_PASSWORD=PASSWORD,
            FAKE_GH_STATE=str(self.state_path), RUNNER_TEMP=str(self.runner), PYTHONDONTWRITEBYTECODE='1',
        )
        for arguments in [('init', '-q'), ('config', 'user.name', 'Publish Fixture'),
                          ('config', 'user.email', 'publish-fixture@example.test'),
                          ('config', 'commit.gpgsign', 'false'), ('config', 'tag.gpgsign', 'false')]:
            self.git(*arguments)
        (self.root / 'tracked').write_text('fixture\n')
        self.git('add', 'tracked')
        self.git('commit', '-qm', 'publication fixture')
        self.sha = self.git('rev-parse', 'HEAD')
        self.git('branch', '-M', 'main')
        self.git('update-ref', 'refs/remotes/origin/main', self.sha)
        self.environment['GITHUB_SHA'] = self.sha
        self.git('tag', 'v1.2.3')
        self.bundle = self.root / 'release-bundle'
        self.bundle.mkdir()
        self.version = '1.2.3'
        self.write_bundle(self.version)
        self.state = {'sha': self.sha, 'tag': 'v1.2.3'}
        self.save()

    def git(self, *arguments):
        result = subprocess.run(['git', *arguments], cwd=self.root, env=self.environment,
                                capture_output=True, check=False, text=True)
        self.assertEqual(result.returncode, 0, 'could not prepare isolated publication Git fixture')
        return result.stdout.strip()

    def write_bundle(self, version):
        for path in self.bundle.iterdir():
            path.unlink()
        ARTIFACTS.write_bundle(self.bundle, version)
        OCI.write_valid_oci(self.bundle / f'secretwright_{version}_linux_multiarch.oci.tar', version)
        for machine in ('amd64', 'arm64'):
            (self.bundle / ARTIFACTS.sbom_name('linux', machine, version, image=True)).write_text(json.dumps(ARTIFACTS.spdx_fixture(version)))
        ARTIFACTS.rewrite_manifest(self.bundle, version)
        (self.bundle / f'secretwright_{version}_checksums.sig').write_bytes(b'ephemeral-CI-signature')
        (self.bundle / f'secretwright_{version}_signing-key.pem').write_bytes(b'ephemeral-CI-public-key')

    def save(self):
        self.state_path.write_text(json.dumps(self.state))

    def invoke(self):
        self.save()
        result = subprocess.run([sys.executable, str(PUBLISH)], cwd=self.root, env=self.environment,
                                capture_output=True, check=False, text=True)
        self.state = json.loads(self.state_path.read_text())
        for marker in [PASSWORD, TOKEN, 'BEGIN ENCRYPTED PRIVATE KEY', 'private-f13-upstream-error',
                       'private-f13-rejected-key-body', 'Traceback', str(self.base)]:
            self.assertNotIn(marker, result.stdout + result.stderr, 'publication exposed secrets or private diagnostics')
        for call in self.state.get('calls', []):
            self.assertFalse(call['signing_key_present'] or call['password_present'], 'signing credentials entered a GH subprocess')
            self.assertFalse(call['fallback_token_present'], 'GH retained an unselected fallback credential')
            self.assertTrue(call['token_present'], 'GH did not select its explicit token')
            self.assertEqual(call['host'], 'github.com', 'GH inherited a different host selector')
        return result

    def rejected(self, *, created=False):
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0, 'unsafe publication unexpectedly succeeded')
        self.assertTrue(result.stderr, 'publication rejection omitted safe diagnostics')
        self.assertFalse(result.stdout, 'failed publication returned partial success metadata')
        self.assertEqual(bool(self.state.get('created')), created)
        self.assertFalse(self.state.get('published'), 'failed publication made a draft public')
        return result

    def test_verified_bundle_is_real_signed_then_uploaded_as_exact_immutable_set(self):
        original = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in self.bundle.iterdir()}
        result = self.invoke()
        self.assertEqual(result.returncode, 0, 'valid staged publication failed')
        self.assertEqual(json.loads(result.stdout), {'version': self.version, 'assets': 18, 'published': True})
        self.assertEqual(len(self.state['uploaded']), 18)
        self.assertEqual(len({item['name'] for item in self.state['uploaded']}), 18)
        uploaded_public = next(item for item in self.state['uploaded'] if item['name'].endswith('_signing-key.pem'))
        self.assertEqual(uploaded_public['digest'], self.public_digest, 'publication retained the CI key instead of the selected signing key')
        self.assertEqual(self.state['tag_checks'], 2)
        self.assertTrue(self.state['published'])
        self.assertEqual(original, {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in self.bundle.iterdir()}, 'publication altered the downloaded CI bundle')
        create = next(call['args'] for call in self.state['calls'] if call['args'][:2] == ['release', 'create'])
        self.assertIn('--draft', create)
        self.assertIn('--verify-tag', create)
        self.assertEqual(create[create.index('--repo') + 1], 'example/secretwright')
        self.assertTrue(all(not Path(path).is_relative_to(self.root) for path in self.state['paths']), 'uploaded staging included the source or a private key path')
        self.assertFalse(list(self.runner.iterdir()), 'private signing work files survived publication')

    def test_missing_token_invalid_secret_or_bad_bundle_never_starts_gh(self):
        for variable, replacement in [('GH_TOKEN', ''), ('SECRETWRIGHT_SIGNING_KEY', 'private-f13-rejected-key-body'),
                                      ('SECRETWRIGHT_SIGNING_PASSWORD', '')]:
            original = self.environment[variable]
            self.environment[variable] = replacement
            self.rejected()
            self.assertEqual(self.state.get('calls', []), [], 'GH ran before local signing preflight completed')
            self.environment[variable] = original
        archive = self.bundle / ARTIFACTS.archive_name('linux', 'amd64')
        archive.write_bytes(b'not the checked archive')
        self.rejected()
        self.assertEqual(self.state.get('calls', []), [])

    def test_existing_release_permission_failure_or_transport_failure_is_not_absence(self):
        for status in (200, 403, 500, 0):
            with self.subTest(status=status):
                self.state = {'sha': self.sha, 'tag': 'v1.2.3', 'existing_status': status}
                self.rejected()
                self.assertEqual(len(self.state['calls']), 1)

    def test_moved_remote_tag_is_rejected_before_create_and_before_undraft(self):
        for phase in ('before-create', 'before-publish'):
            with self.subTest(phase=phase):
                self.state = {'sha': self.sha, 'tag': 'v1.2.3', 'move_tag': phase}
                self.rejected(created=phase == 'before-publish')

    def test_remote_annotated_tag_is_peeled_and_cycles_fail_closed(self):
        self.state['annotated'] = True
        self.assertEqual(self.invoke().returncode, 0, 'valid annotated remote tag was rejected')
        self.state = {'sha': self.sha, 'tag': 'v1.2.3', 'annotated': True, 'tag_cycle': True}
        self.rejected()
        self.assertLessEqual(len(self.state['calls']), 10, 'annotated tag traversal was not bounded')

    def test_any_uploaded_asset_or_draft_metadata_mismatch_prevents_publication(self):
        for error in ('digest', 'size', 'state', 'extra', 'missing', 'duplicate', 'tag', 'not-draft'):
            with self.subTest(error=error):
                self.state = {'sha': self.sha, 'tag': 'v1.2.3', 'asset_error': error}
                self.rejected(created=True)
                self.assertFalse(any(call['args'][:2] == ['release', 'edit'] for call in self.state['calls']))

    def test_upload_failure_leaves_draft_without_retry_delete_or_clobber(self):
        self.state['create_error'] = True
        self.rejected(created=True)
        calls = [call['args'] for call in self.state['calls']]
        self.assertEqual(sum(arguments[:2] == ['release', 'create'] for arguments in calls), 1)
        self.assertFalse(any('delete' in arguments or '--clobber' in arguments for arguments in calls))

    def test_staged_content_tampering_is_detected_even_if_metadata_is_restored(self):
        self.state['modify_staged_asset'] = True
        self.rejected(created=True)

    def test_prerelease_is_not_marked_latest_and_plus_tag_is_url_encoded(self):
        version = '1.2.3-rc.1+fixture'
        tag = 'v' + version
        self.git('tag', tag)
        self.environment['GITHUB_REF_NAME'] = tag
        self.write_bundle(version)
        self.state = {'sha': self.sha, 'tag': tag}
        self.assertEqual(self.invoke().returncode, 0)
        create = next(call['args'] for call in self.state['calls'] if call['args'][:2] == ['release', 'create'])
        self.assertIn('--prerelease', create)
        self.assertIn('--latest=false', create)
        endpoints = [call['args'][-1] for call in self.state['calls'] if call['args'][0] == 'api']
        self.assertTrue(all('%2B' in endpoint for endpoint in endpoints if '/tags/' in endpoint))


if __name__ == '__main__':
    unittest.main()
