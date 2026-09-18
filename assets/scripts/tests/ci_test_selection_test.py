"""Exercise CI test selection with real commits, tags, and local bare remotes."""

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
        for name in ('version.py', 'select_ci_tests.py'):
            dest = self.root / 'assets/scripts' / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / 'assets/scripts' / name, dest)
        (self.root / 'VERSION').write_text('1.2.0\n')
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

    def select(self, event='push', ref='refs/heads/main', sha=None):
        output = Path(self.temp.name) / 'github-output'
        output.write_text('existing=value\n')
        env = dict(self.env, GITHUB_EVENT_NAME=event, GITHUB_REF=ref,
                   GITHUB_SHA=sha or self.sha, GITHUB_OUTPUT=str(output))
        result = subprocess.run(['python3', 'assets/scripts/select_ci_tests.py'], cwd=self.root,
                                env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = output.read_text().splitlines()
        self.assertEqual(lines[0], 'existing=value')
        self.assertEqual(len(lines), 2)
        self.assertIn(lines[1], ('run_tests=true', 'run_tests=false'))
        return lines[1] == 'run_tests=true'

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


if __name__ == '__main__':
    unittest.main()
