"""Exercise CI test selection with real commits, tags, and local bare remotes."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class CITestSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='authcrunch-ci-selection-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'work'
        self.remote = Path(self.temp.name) / 'origin.git'
        self.root.mkdir()
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('GIT_', 'GITHUB_'))}
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_AUTHOR_NAME='CI Fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
                        GIT_COMMITTER_NAME='CI Fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid',
                        PYTHONDONTWRITEBYTECODE='1')
        for name in ('version.py', 'select_ci_tests.py', 'change_tests.py'):
            dest = self.root / 'assets/scripts' / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / 'assets/scripts' / name, dest)
        (self.root / 'VERSION').write_text('1.2.0\n')
        api = self.root / 'assets/openapi/content/openapi.yaml'
        api.parent.mkdir(parents=True, exist_ok=True)
        api.write_text('openapi: 3.1.1\ninfo:\n  title: Fixture\n  version: 1.2.0\n  description: Fixture API\n')
        for name in ('cmd/authdb/main.go', 'cmd/authdbctl/main.go', 'pkg/identity/database.go'):
            dest = self.root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text('app.SetVersion(appVersion, "1.2.0")\n'
                            'app.SetGitBranch(gitBranch, "")\n'
                            'app.SetGitCommit(gitCommit, "")\n')
        self.git('init', '-q', '-b', 'main')
        self.git('add', '.')
        self.git('commit', '-qm', 'ops: released v1.2.0')
        self.sha = self.git('rev-parse', 'HEAD').strip()
        self.git('init', '--bare', '-q', str(self.remote))
        self.git('remote', 'add', 'origin', str(self.remote))
        self.git('push', '-q', 'origin', 'main')

    def git(self, *args):
        result = subprocess.run(['git', *args], cwd=self.root, env=self.env,
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def select(self, event='push', ref='refs/heads/main', sha=None, payload=None, extra=()):
        output = Path(self.temp.name) / 'github-output'
        output.write_text('existing=value\n')
        env = dict(self.env, GITHUB_EVENT_NAME=event, GITHUB_REF=ref,
                   GITHUB_SHA=sha or self.sha, GITHUB_OUTPUT=str(output))
        if payload is not None:
            event_path = Path(self.temp.name) / 'event.json'
            event_path.write_text(json.dumps(payload))
            env['GITHUB_EVENT_PATH'] = str(event_path)
        result = subprocess.run(['python3', 'assets/scripts/select_ci_tests.py', *extra], cwd=self.root,
                                env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = output.read_text().splitlines()
        self.assertEqual(lines[0], 'existing=value')
        self.outputs = dict(line.split('=', 1) for line in lines)
        self.assertIn(self.outputs['run_tests'], ('true', 'false'))
        return self.outputs['run_tests'] == 'true'

    def tag_release(self, tag='v1.2.0', annotated=True):
        if annotated:
            self.git('tag', '-a', tag, '-m', tag)
        else:
            self.git('tag', tag)
        self.git('push', '--atomic', '-q', 'origin', 'HEAD:refs/heads/main', f'refs/tags/{tag}')

    def test_atomic_release_push_runs_only_tag_tests(self):
        self.git('commit', '--allow-empty', '-qm', 'ops: release candidate')
        self.sha = self.git('rev-parse', 'HEAD').strip()
        self.tag_release()
        branch_run = self.select()
        tag_run = self.select(ref='refs/tags/v1.2.0')
        self.assertFalse(branch_run)
        self.assertTrue(tag_run)
        self.assertEqual(sum((branch_run, tag_run)), 1)
        self.assertEqual(self.git('rev-parse', 'HEAD').strip(), self.sha)
        self.assertEqual(self.git('status', '--porcelain'), '')
        self.assertEqual(self.git('--git-dir', str(self.remote), 'rev-parse', 'main').strip(), self.sha)

    def test_commit_message_without_remote_tag_runs_tests(self):
        self.assertTrue(self.select())
        self.git('tag', '-a', 'v1.2.0', '-m', 'local tag only')
        self.assertTrue(self.select())

    def test_other_events_always_run_tests_for_tagged_commit(self):
        self.tag_release()
        for event, ref in (('pull_request', 'refs/pull/1/merge'),
                           ('workflow_dispatch', 'refs/heads/main'),
                           ('push', 'refs/heads/feature'),
                           ('push', 'refs/tags/v1.2.0'),
                           ('workflow_call', 'refs/heads/main')):
            with self.subTest(event=event, ref=ref):
                self.assertTrue(self.select(event=event, ref=ref))

    def test_lightweight_and_wrong_version_tags_run_tests(self):
        self.tag_release(annotated=False)
        self.assertTrue(self.select())
        self.tag_release(tag='v1.2.1')
        self.assertTrue(self.select())

    def test_tag_on_another_commit_runs_tests(self):
        self.tag_release()
        self.git('commit', '--allow-empty', '-qm', 'authn: subsequent change')
        self.sha = self.git('rev-parse', 'HEAD').strip()
        self.git('push', '-q', 'origin', 'main')
        self.assertTrue(self.select())

    def test_wrong_checkout_runs_tests(self):
        self.tag_release()
        self.assertTrue(self.select(sha='a' * 40))

    def test_invalid_or_unsynchronized_version_runs_tests(self):
        self.tag_release()
        for version in ('invalid', '1.2.1'):
            with self.subTest(version=version):
                (self.root / 'VERSION').write_text(version + '\n')
                self.assertTrue(self.select())

    def test_remote_lookup_failure_runs_tests(self):
        self.tag_release()
        self.git('remote', 'set-url', 'origin', str(Path(self.temp.name) / 'missing.git'))
        self.assertTrue(self.select())

    def commit_file(self, path, text):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)
        self.git('add', '--', path)
        self.git('commit', '-qm', 'fixture change')
        self.sha = self.git('rev-parse', 'HEAD').strip()

    def test_push_uses_entire_range_and_docs_only_skips(self):
        before = self.sha
        self.commit_file('.codex/skills/example/SKILL.md', 'guidance')
        self.commit_file('plugins/secrets/.gitkeep', '')
        self.assertFalse(self.select(payload={'before': before}))
        self.assertEqual(self.outputs['mode'], 'none')
        self.commit_file('pkg/example/value.go', 'package example\n')
        self.commit_file('README.md', 'prose')
        self.assertTrue(self.select(payload={'before': before}))
        self.assertEqual(self.outputs['mode'], 'focused')
        self.assertEqual(self.outputs['base'], before)
        self.assertEqual(self.outputs['head'], self.sha)

    def test_pr_uses_merge_base_and_tests_merge_checkout(self):
        ancestor = self.sha
        self.git('checkout', '-qb', 'feature')
        self.commit_file('README.md', 'feature prose')
        feature = self.sha
        self.git('checkout', '-q', 'main')
        self.commit_file('pkg/base/change.go', 'package base\n')
        base = self.sha
        self.git('merge', '--no-ff', '-qm', 'synthetic PR merge', 'feature')
        self.sha = self.git('rev-parse', 'HEAD').strip()
        payload = {'pull_request': {'base': {'sha': base}, 'head': {'sha': feature}}}
        self.assertFalse(self.select(event='pull_request', ref='refs/pull/1/merge', payload=payload))
        self.assertEqual(self.outputs['base'], ancestor)
        self.assertEqual(self.outputs['head'], feature)
        self.assertEqual(self.git('rev-parse', 'HEAD').strip(), self.sha)

    def test_new_branch_missing_history_and_bad_payload_run_full(self):
        for payload in ({'before': '0' * 40}, {'before': 'a' * 40}, {},
                        {'before': '--help'}, {'before': None}):
            with self.subTest(payload=payload):
                self.assertTrue(self.select(payload=payload))
                self.assertEqual(self.outputs['mode'], 'full')

    def test_global_changes_tag_manual_schedule_and_independent_analysis(self):
        before = self.sha
        self.commit_file('go.mod', 'module fixture\n')
        self.assertTrue(self.select(payload={'before': before}))
        self.assertEqual(self.outputs['mode'], 'full')
        self.tag_release()
        for event, ref in [('push', 'refs/tags/v1.2.0'), ('workflow_dispatch', 'refs/heads/main'),
                           ('schedule', 'refs/heads/main')]:
            self.assertTrue(self.select(event=event, ref=ref, payload={'before': self.sha}))
            self.assertEqual(self.outputs['mode'], 'full')
        self.assertTrue(self.select(payload={'before': before}, extra=('--no-release-dedup',)))


if __name__ == '__main__':
    unittest.main()
