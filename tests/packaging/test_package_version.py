"""Bind prospective release builds to a real, approved checkout."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('package_version_subject', ROOT / 'scripts/package_ci.py')
SUBJECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUBJECT)


class PackageVersionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='secretwright-version-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.original_root = SUBJECT.ROOT
        SUBJECT.ROOT = self.root
        self.addCleanup(setattr, SUBJECT, 'ROOT', self.original_root)
        for args in [('init', '-q'), ('config', 'user.name', 'Fixture'),
                     ('config', 'user.email', 'fixture@example.test'),
                     ('config', 'commit.gpgsign', 'false')]:
            self.git(*args)
        (self.root / 'source').write_text('first\n')
        self.git('add', 'source')
        self.git('commit', '-qm', 'first')
        self.sha = self.git('rev-parse', 'HEAD')
        self.git('update-ref', 'refs/remotes/origin/main', self.sha)
        self.environment = dict(os.environ, GITHUB_REF_TYPE='branch', GITHUB_SHA='f' * 40,
                                SECRETWRIGHT_RELEASE_SHA=self.sha,
                                SECRETWRIGHT_RELEASE_TAG='v0.1.0-rc.7')

    def git(self, *args):
        result = subprocess.run(['git', *args], cwd=self.root, capture_output=True, check=True, text=True)
        return result.stdout.strip()

    def test_prospective_rc_and_stable_use_source_sha_not_control_sha(self):
        self.assertEqual(SUBJECT.package_version(self.environment), '0.1.0-rc.7')
        self.environment['SECRETWRIGHT_RELEASE_TAG'] = 'v0.1.0'
        self.assertEqual(SUBJECT.package_version(self.environment), '0.1.0')

    def test_default_build_remains_snapshot(self):
        self.environment.pop('SECRETWRIGHT_RELEASE_SHA')
        self.environment.pop('SECRETWRIGHT_RELEASE_TAG')
        self.assertEqual(SUBJECT.package_version(self.environment), '0.0.0-snapshot.g' + self.sha[:12])

    def test_partial_or_invalid_release_selection_is_rejected(self):
        for change in [{'SECRETWRIGHT_RELEASE_SHA': ''}, {'SECRETWRIGHT_RELEASE_TAG': ''},
                       {'SECRETWRIGHT_RELEASE_SHA': 'a' * 40},
                       {'SECRETWRIGHT_RELEASE_TAG': 'v0.1.0-rc.01'},
                       {'SECRETWRIGHT_RELEASE_TAG': 'v0.1.0;echo unsafe'},
                       {'SECRETWRIGHT_RELEASE_TAG': 'v0.1.0-beta.1'}]:
            with self.subTest(change=change), self.assertRaises(Exception):
                SUBJECT.package_version(dict(self.environment, **change))

    def test_source_outside_main_is_rejected(self):
        (self.root / 'source').write_text('unapproved\n')
        self.git('commit', '-qam', 'unapproved')
        self.environment['SECRETWRIGHT_RELEASE_SHA'] = self.git('rev-parse', 'HEAD')
        with self.assertRaises(Exception):
            SUBJECT.package_version(self.environment)

    def test_dirty_source_is_rejected(self):
        (self.root / 'source').write_text('dirty\n')
        with self.assertRaises(Exception):
            SUBJECT.package_version(self.environment)


if __name__ == '__main__':
    unittest.main()
