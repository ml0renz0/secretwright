"""Release tag policy is exercised against isolated real Git repositories."""

from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = ROOT / 'scripts' / 'release_preflight.py'


class ReleasePreflightTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='secretwright-release-policy-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.environment = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Release Fixture')
        self.git('config', 'user.email', 'release-fixture@example.test')
        self.git('config', 'commit.gpgsign', 'false')
        self.git('config', 'tag.gpgsign', 'false')
        (self.root / 'tracked.txt').write_text('first\n')
        self.git('add', 'tracked.txt')
        self.git('commit', '-q', '-m', 'fixture first commit')
        self.git('branch', '-M', 'main')
        self.sha = self.git('rev-parse', 'HEAD')
        self.git('update-ref', 'refs/remotes/origin/main', self.sha)

    def git(self, *arguments):
        result = subprocess.run(
            ['git', *arguments], cwd=self.root, env=self.environment,
            capture_output=True, check=False, text=True,
        )
        self.assertEqual(result.returncode, 0, 'could not prepare isolated Git fixture')
        return result.stdout.strip()

    def invoke(self, tag='v1.2.3', sha=None, main_ref='origin/main'):
        result = subprocess.run(
            [sys.executable, str(PREFLIGHT), '--tag=' + tag, '--sha=' + (sha or self.sha),
             '--main-ref=' + main_ref], cwd=self.root, env=self.environment,
            capture_output=True, check=False, text=True,
        )
        for marker in ['private-f13-rejected-tag-marker', 'Traceback', str(self.root)]:
            self.assertNotIn(marker, result.stdout + result.stderr, 'preflight echoed rejected input or local paths')
        return result

    def assert_rejected(self, result):
        self.assertNotEqual(result.returncode, 0, 'release outside the agreed tag policy succeeded')
        self.assertTrue(result.stderr, 'release policy rejection omitted a safe diagnostic')
        self.assertFalse(result.stdout, 'failed release policy returned partial metadata')

    def assert_valid(self, result, tag, sha=None):
        self.assertEqual(result.returncode, 0, 'valid release tag was rejected')
        self.assertFalse(result.stderr, 'valid release preflight emitted diagnostics')
        try:
            report = json.loads(result.stdout)
        except (ValueError, TypeError):
            self.fail('release preflight did not produce JSON metadata')
        self.assertEqual(report, {'tag': tag, 'version': tag[1:], 'sha': sha or self.sha})

    def test_accepts_exact_lightweight_or_annotated_semver_tag_on_main(self):
        for index, tag in enumerate(['v0.0.0', 'v1.2.3', 'v1.2.3-rc.1', 'v1.2.3-alpha.0+build.001']):
            if index % 2:
                self.git('tag', '-a', tag, '-m', 'annotated fixture release')
            else:
                self.git('tag', tag)
            self.assert_valid(self.invoke(tag=tag), tag)

    def test_detached_checkout_of_the_exact_tag_is_valid(self):
        self.git('tag', 'v1.2.3')
        self.git('checkout', '-q', '--detach', 'v1.2.3')
        self.assert_valid(self.invoke(), 'v1.2.3')

    def test_tagged_ancestor_is_valid_when_main_has_advanced(self):
        self.git('tag', 'v1.2.3')
        (self.root / 'tracked.txt').write_text('new main\n')
        self.git('commit', '-qam', 'fixture main advanced')
        newer = self.git('rev-parse', 'HEAD')
        self.git('update-ref', 'refs/remotes/origin/main', newer)
        self.git('checkout', '-q', '--detach', self.sha)
        self.assert_valid(self.invoke(), 'v1.2.3')

    def test_rejects_invalid_semver_and_ref_injection_without_echo(self):
        for tag in ['1.2.3', 'v1.2', 'v01.2.3', 'v1.02.3', 'v1.2.03', 'v1.2.3.4',
                    'v1.2.3-', 'v1.2.3-01', 'v1.2.3+!', 'v1.2.3 ',
                    '--private-f13-rejected-tag-marker', 'v1.2.3\nprivate-f13-rejected-tag-marker']:
            with self.subTest(tag_index=len(tag)):
                self.assert_rejected(self.invoke(tag=tag))
        self.git('tag', 'v1.2.3')
        for main_ref in ['--private-f13-rejected-tag-marker', 'origin/main^{commit}', 'origin/main\nprivate-f13-rejected-tag-marker']:
            self.assert_rejected(self.invoke(main_ref=main_ref))

    def test_rejects_missing_tag_or_branch_that_only_looks_like_a_release_tag(self):
        self.assert_rejected(self.invoke())
        self.git('branch', 'v1.2.3')
        self.assert_rejected(self.invoke())

    def test_rejects_wrong_or_abbreviated_commit_identity(self):
        self.git('tag', 'v1.2.3')
        for sha in ['0' * 40, self.sha[:12], '--private-f13-rejected-tag-marker']:
            self.assert_rejected(self.invoke(sha=sha))

    def test_rejects_tag_or_sha_that_differs_from_checked_out_head(self):
        self.git('tag', 'v1.2.3')
        (self.root / 'tracked.txt').write_text('second\n')
        self.git('commit', '-qam', 'fixture second commit')
        newer = self.git('rev-parse', 'HEAD')
        self.git('update-ref', 'refs/remotes/origin/main', newer)
        self.assert_rejected(self.invoke(sha=self.sha))
        self.assert_rejected(self.invoke(sha=newer))

    def test_rejects_commit_outside_main_or_unknown_main_ref(self):
        self.git('checkout', '-qb', 'feature')
        (self.root / 'tracked.txt').write_text('feature only\n')
        self.git('commit', '-qam', 'fixture feature')
        feature = self.git('rev-parse', 'HEAD')
        self.git('tag', 'v1.2.3')
        self.assert_rejected(self.invoke(sha=feature))
        self.assert_rejected(self.invoke(sha=feature, main_ref='origin/missing'))

    def test_rejects_modified_staged_or_deleted_tracked_files(self):
        self.git('tag', 'v1.2.3')
        tracked = self.root / 'tracked.txt'
        tracked.write_text('private-f13-rejected-tag-marker\n')
        self.assert_rejected(self.invoke())
        self.git('add', 'tracked.txt')
        self.assert_rejected(self.invoke())
        self.git('reset', '--hard', '-q', 'HEAD')
        tracked.unlink()
        self.assert_rejected(self.invoke())

    def test_untracked_ephemeral_files_do_not_change_clean_tracked_tree(self):
        self.git('tag', 'v1.2.3')
        (self.root / 'untracked.tmp').write_text('ephemeral file\n')
        self.assert_valid(self.invoke(), 'v1.2.3')


if __name__ == '__main__':
    unittest.main()
