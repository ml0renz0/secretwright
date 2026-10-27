"""Plan automatic candidates and stable promotions against real local Git history."""

from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
PLANNER = ROOT / 'scripts' / 'release_plan.py'

FAKE_GH = r'''#!/usr/bin/env python3
from pathlib import Path
import json, os, sys
path = Path(os.environ['FAKE_GH_STATE'])
state = json.loads(path.read_text())
args = sys.argv[1:]
state.setdefault('calls', []).append(args)
path.write_text(json.dumps(state))
status = state.get('status', 200)
endpoint = args[-1]
if '/git/ref/tags/' in endpoint:
    value = {'object': {'type': 'commit', 'sha': state.get('remote_sha', state['sha'])}}
elif '/releases/tags/' in endpoint:
    value = {'tag_name': state.get('remote_tag', state['tag']), 'draft': state.get('draft', False),
             'prerelease': state.get('prerelease', True), 'published_at': state.get('published_at', '2026-10-27T12:00:00Z')}
else:
    status, value = 404, {'message': 'fixture missing'}
print('HTTP/2.0 ' + str(status) + ' Fixture\r\nContent-Type: application/json\r\n\r\n' + json.dumps(value))
sys.exit(0 if status == 200 else 1)
'''


class ReleasePlanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='secretwright-release-plan-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / 'repository'
        self.root.mkdir()
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        fake = self.bin / 'gh'
        fake.write_text(FAKE_GH)
        fake.chmod(0o755)
        self.state_path = self.base / 'gh-state.json'
        self.output_path = self.base / 'github-output'
        self.environment = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ.get('PATH', ''),
                                GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                                GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/main',
                                GITHUB_REPOSITORY='example/secretwright', GITHUB_RUN_NUMBER='27',
                                GH_TOKEN='private-planner-unused-token', FAKE_GH_STATE=str(self.state_path),
                                GITHUB_OUTPUT=str(self.output_path), PYTHONDONTWRITEBYTECODE='1')
        for arguments in [('init', '-q'), ('config', 'user.name', 'Planner Fixture'),
                          ('config', 'user.email', 'planner-fixture@example.test'),
                          ('config', 'commit.gpgsign', 'false'), ('config', 'tag.gpgsign', 'false')]:
            self.git(*arguments)
        (self.root / 'tracked.txt').write_text('initial\n')
        self.git('add', 'tracked.txt')
        self.git('commit', '-qm', 'initial without release policy')
        self.git('branch', '-M', 'main')
        (self.root / '.github').mkdir()
        self.write_policy()
        self.commit('introduce release policy')
        self.candidate_sha = self.sha
        self.git('tag', 'v0.1.0-rc.1')
        self.state = {'sha': self.candidate_sha, 'tag': 'v0.1.0-rc.1'}
        self.state_path.write_text(json.dumps(self.state))

    def git(self, *arguments):
        result = subprocess.run(['git', *arguments], cwd=self.root, env=self.environment,
                                capture_output=True, check=False, text=True)
        self.assertEqual(result.returncode, 0, 'could not prepare isolated planner Git fixture')
        return result.stdout.strip()

    def write_policy(self, next_version='0.1.0', candidate='null'):
        (self.root / '.github' / 'release.yaml').write_text(
            f'next_version: {next_version}\npromote_candidate: {candidate}\n')

    def commit(self, message):
        self.git('add', '.')
        self.git('commit', '-qm', message)
        self.sha = self.git('rev-parse', 'HEAD')
        self.environment['GITHUB_SHA'] = self.sha
        self.git('update-ref', 'refs/remotes/origin/main', self.sha)

    def promotion(self, next_version='0.1.1', candidate='v0.1.0-rc.1'):
        self.write_policy(next_version, candidate)
        self.commit('promote approved candidate')

    def invoke(self, *, check=False):
        self.state_path.write_text(json.dumps(self.state))
        result = subprocess.run([sys.executable, str(PLANNER)] + (['--check'] if check else []),
                                cwd=self.root, env=self.environment, capture_output=True, check=False, text=True)
        self.state = json.loads(self.state_path.read_text())
        for marker in ['private-planner-unused-token', 'private-planner-rejected-input', 'Traceback', str(self.base)]:
            self.assertNotIn(marker, result.stdout + result.stderr, 'planner exposed private input or diagnostics')
        return result

    def report(self, result):
        self.assertEqual(result.returncode, 0, 'valid release plan was rejected')
        self.assertFalse(result.stderr)
        return json.loads(result.stdout)

    def rejected(self, result):
        self.assertNotEqual(result.returncode, 0, 'unsafe release plan was accepted')
        self.assertTrue(result.stderr)
        self.assertFalse(result.stdout)
        self.assertFalse(self.output_path.exists(), 'rejected plan wrote workflow outputs')

    def test_first_policy_merge_plans_candidate_with_workflow_run_number(self):
        self.assertEqual(self.report(self.invoke()), {'mode': 'rc', 'tag': 'v0.1.0-rc.27',
                         'version': '0.1.0-rc.27', 'sha': self.sha, 'candidate': '', 'control_sha': self.sha})
        self.assertFalse(self.state.get('calls'), 'candidate planning performed a remote mutation or read')
        outputs = dict(line.split('=', 1) for line in self.output_path.read_text().splitlines())
        self.assertEqual(outputs['sha'], self.sha)
        self.assertEqual(outputs['tag'], 'v0.1.0-rc.27')

    def test_stable_selects_candidate_commit_when_main_has_advanced(self):
        (self.root / 'tracked.txt').write_text('new unapproved feature on main\n')
        self.commit('main advanced after candidate')
        self.promotion()
        control = self.sha
        self.assertNotEqual(control, self.candidate_sha)
        self.assertEqual(self.report(self.invoke()), {'mode': 'stable', 'tag': 'v0.1.0', 'version': '0.1.0',
                         'sha': self.candidate_sha, 'candidate': 'v0.1.0-rc.1', 'control_sha': control})
        self.assertTrue(self.state.get('calls'))
        self.assertTrue(all('--method' in call and call[call.index('--method') + 1] == 'GET'
                            for call in self.state['calls']), 'planner mutated GitHub')

    def test_unchanged_promotion_marker_does_not_publish_stable_again(self):
        self.promotion()
        (self.root / 'tracked.txt').write_text('development for next release\n')
        self.commit('continue development')
        report = self.report(self.invoke())
        self.assertEqual(report['tag'], 'v0.1.1-rc.27')
        self.assertEqual(report['sha'], self.sha)
        self.assertEqual(report['candidate'], '')
        self.assertFalse(self.state.get('calls'))

    def test_check_validates_policy_transition_without_remote_credentials_or_outputs(self):
        self.promotion()
        self.environment.pop('GH_TOKEN')
        self.environment['GITHUB_EVENT_NAME'] = 'pull_request'
        self.environment['GITHUB_REF'] = 'refs/pull/10/merge'
        self.assertEqual(self.report(self.invoke(check=True)), {'valid': True})
        self.assertFalse(self.state.get('calls'))
        self.assertFalse(self.output_path.exists())

    def test_rejects_promotion_mixed_with_code_changes(self):
        (self.root / 'tracked.txt').write_text('mixed change\n')
        self.promotion()
        self.rejected(self.invoke())
        self.rejected(self.invoke(check=True))
        self.assertFalse(self.state.get('calls'))

    def test_rejects_promotion_without_advancing_next_version(self):
        self.promotion(next_version='0.1.0')
        self.rejected(self.invoke())
        self.assertFalse(self.state.get('calls'))

    def test_rejects_candidate_from_different_release_line(self):
        self.git('tag', 'v0.0.9-rc.1')
        self.promotion(candidate='v0.0.9-rc.1')
        self.rejected(self.invoke())
        self.assertFalse(self.state.get('calls'))

    def test_rejects_regressing_next_version(self):
        self.write_policy(next_version='0.0.9')
        self.commit('invalid version regression')
        self.rejected(self.invoke())

    def test_rejects_missing_or_non_ancestor_candidate_tag(self):
        self.promotion(candidate='v0.1.0-rc.2')
        self.rejected(self.invoke())
        self.git('checkout', '-qb', 'outside', self.candidate_sha)
        (self.root / 'tracked.txt').write_text('unmerged candidate\n')
        self.git('commit', '-qam', 'outside main')
        self.git('tag', 'v0.1.0-rc.2')
        self.git('checkout', '-q', 'main')
        self.rejected(self.invoke())
        self.assertFalse(self.state.get('calls'))

    def test_rejects_moved_remote_candidate_tag(self):
        self.promotion()
        self.state['remote_sha'] = 'f' * 40
        self.rejected(self.invoke())

    def test_rejects_unpublished_draft_non_candidate_or_wrong_release(self):
        self.promotion()
        for fields in [{'draft': True}, {'prerelease': False}, {'published_at': None},
                       {'remote_tag': 'v0.1.0-rc.999'}, {'status': 404}, {'status': 403}]:
            with self.subTest(fields=fields):
                self.state = {'sha': self.candidate_sha, 'tag': 'v0.1.0-rc.1', **fields}
                self.rejected(self.invoke())

    def test_rejects_missing_remote_credentials_for_stable(self):
        self.promotion()
        self.environment.pop('GH_TOKEN')
        self.rejected(self.invoke())
        self.assertFalse(self.state.get('calls'))

    def test_rejects_non_main_or_non_push_runtime_events(self):
        for key, value in [('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_REF', 'refs/heads/feature'),
                           ('GITHUB_REF', 'refs/tags/v0.1.0'), ('GITHUB_EVENT_NAME', 'workflow_dispatch')]:
            with self.subTest(key=key, value=value):
                before = self.environment[key]
                self.environment[key] = value
                self.rejected(self.invoke())
                self.environment[key] = before

    def test_rejects_invalid_sha_run_number_or_repository_without_echo(self):
        for key, values in {'GITHUB_SHA': ['0' * 40, self.sha[:12], 'private-planner-rejected-input'],
                            'GITHUB_RUN_NUMBER': ['0', '01', '-1', '1\nprivate-planner-rejected-input'],
                            'GITHUB_REPOSITORY': ['owner/repo/extra', '--private-planner-rejected-input']}.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    before = self.environment[key]
                    self.environment[key] = value
                    self.rejected(self.invoke())
                    self.environment[key] = before

    def test_rejects_dirty_tracked_checkout(self):
        (self.root / 'tracked.txt').write_text('dirty\n')
        self.rejected(self.invoke())
        self.git('add', 'tracked.txt')
        self.rejected(self.invoke())

    def test_rejects_yaml_extensions_duplicates_unknown_keys_and_invalid_versions(self):
        invalid = ['next_version: 01.1.0\npromote_candidate: null\n',
                   'next_version: 0.1.0\npromote_candidate: v0.1.0-rc.01\n',
                   'next_version: 0.1.0\npromote_candidate: null\nnext_version: 9.0.0\n',
                   'next_version: 0.1.0\npromote_candidate: null\nunknown: private-planner-rejected-input\n',
                   'next_version: &version 0.1.0\npromote_candidate: null\n',
                   'next_version: [0.1.0]\npromote_candidate: null\n',
                   'next_version: "0.1.0"\npromote_candidate: null\n',
                   'next_version: 0.1.0\n',
                   'next_version: 0.1.0\npromote_candidate:\n  candidate: v0.1.0-rc.1\n']
        for body in invalid:
            with self.subTest(body_index=invalid.index(body)):
                (self.root / '.github' / 'release.yaml').write_text(body)
                self.rejected(self.invoke(check=True))

    def test_policy_allows_comments_and_blank_lines(self):
        (self.root / '.github' / 'release.yaml').write_text(
            '# Política de publicación\n\nnext_version: 0.1.0 # próxima versión\npromote_candidate: null\n')
        self.assertEqual(self.report(self.invoke(check=True)), {'valid': True})


if __name__ == '__main__':
    unittest.main()
