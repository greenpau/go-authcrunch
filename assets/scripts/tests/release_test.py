"""Execute release orchestration with real Git/versioned and local-only remotes."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='authcrunch-release-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'work'
        self.remote = Path(self.temp.name) / 'origin.git'
        self.root.mkdir()
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith('GIT_') and key not in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL')}
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_AUTHOR_NAME='Release Fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
                        GIT_COMMITTER_NAME='Release Fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid',
                        PYTHONDONTWRITEBYTECODE='1')
        for name in ('assets/scripts/version.py', 'assets/scripts/release.sh',
                     'assets/scripts/verify_release.sh', 'go.mod', 'go.sum'):
            dest = self.root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)
        for name in ('cmd/authdbctl/main.go', 'pkg/identity/database.go'):
            dest = self.root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text('package main\nimport "github.com/greenpau/versioned"\n'
                            'var appVersion, gitBranch, gitCommit string\nfunc init() {\n'
                            'app := versioned.NewPackageManager("fixture")\n'
                            'app.SetVersion(appVersion, "1.1.41")\n'
                            'app.SetGitBranch(gitBranch, "")\n'
                            'app.SetGitCommit(gitCommit, "")\n}\n')
        (self.root / 'VERSION').write_text('1.1.41\n')
        (self.root / '.gitignore').write_text('.fixture/\n__pycache__/\n')
        (self.root / '.fixture').mkdir()
        (self.root / 'Makefile').write_text(
            '.PHONY: version-check version-sync ci-check\n'
            'version-check:\n\t@python3 assets/scripts/version.py check\n'
            'version-sync:\n\t@python3 assets/scripts/version.py sync\n'
            'ci-check: version-check\n\t@python3 gate.py\n')
        (self.root / 'gate.py').write_text(
            'import os\nfrom pathlib import Path\n'
            'with Path(".fixture/gates").open("a") as log:\n'
            '    log.write(Path("VERSION").read_text().strip()+"\\n")\n'
            'if os.environ.get("DIRTY_GATE") == "1": Path("unexpected").write_text("change")\n'
            'if os.environ.get("FAIL_GATE") == "1": raise SystemExit(1)\n')
        self.run_command('git', 'init', '-q', '-b', 'main')
        self.run_command('git', 'add', '.')
        self.run_command('git', 'commit', '-qm', 'ops: fixture baseline')
        self.initial = self.run_command('git', 'rev-parse', 'HEAD').stdout.strip()
        self.run_command('git', 'init', '--bare', '-q', str(self.remote))
        self.run_command('git', 'remote', 'add', 'origin', str(self.remote))
        self.run_command('git', 'push', '-q', '-u', 'origin', 'main')

    def run_command(self, *args, ok=True, env=None):
        result = subprocess.run(args, cwd=self.root, env=env or self.env,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout)
        return result

    def release(self, kind='patch', ok=True, **variables):
        return self.run_command('bash', 'assets/scripts/release.sh', kind, ok=ok,
                                env=dict(self.env, **variables))

    def remote_head(self):
        return self.run_command('git', '--git-dir', str(self.remote), 'rev-parse', 'main').stdout.strip()

    def verify_release(self, ok=True, **variables):
        env = dict(self.env, GITHUB_REF_NAME='v1.1.41', GITHUB_SHA=self.initial)
        env.update(variables)
        return self.run_command('bash', 'assets/scripts/verify_release.sh', ok=ok, env=env)

    def test_ci_verification_restores_annotation_after_checkout(self):
        self.run_command('git', 'tag', '-a', 'v1.1.41', '-m', 'v1.1.41')
        self.run_command('git', 'push', '-q', 'origin', 'refs/tags/v1.1.41')
        annotation = self.run_command('git', 'rev-parse', 'refs/tags/v1.1.41').stdout.strip()
        # Reproduce checkout's fallback fetch from the failed release log.
        self.run_command('git', 'fetch', '--no-tags', 'origin',
                         f'+{self.initial}:refs/tags/v1.1.41')
        self.assertEqual(self.run_command('git', 'cat-file', '-t', 'refs/tags/v1.1.41').stdout.strip(),
                         'commit')
        self.run_command('git', 'checkout', '--detach', '-q', 'refs/tags/v1.1.41')
        self.verify_release()
        self.assertEqual(self.run_command('git', 'cat-file', '-t', 'refs/tags/v1.1.41').stdout.strip(), 'tag')
        self.assertEqual(self.run_command('git', 'rev-parse', 'refs/tags/v1.1.41').stdout.strip(), annotation)
        self.assertEqual(self.run_command('git', 'rev-parse', 'HEAD').stdout.strip(), self.initial)
        self.assertEqual(self.remote_head(), self.initial)
        self.assertEqual(self.run_command('git', '--git-dir', str(self.remote),
                                          'rev-parse', 'refs/tags/v1.1.41').stdout.strip(), annotation)

    def test_ci_verification_rejects_lightweight_remote_tag(self):
        self.run_command('git', 'tag', 'v1.1.41')
        self.run_command('git', 'push', '-q', 'origin', 'refs/tags/v1.1.41')
        result = self.verify_release(ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('not annotated on origin', result.stdout)

    def test_ci_verification_rejects_tag_at_another_commit(self):
        self.run_command('git', 'commit', '--allow-empty', '-qm', 'ops: another commit')
        self.run_command('git', 'tag', '-a', 'v1.1.41', '-m', 'v1.1.41')
        self.run_command('git', 'push', '-q', 'origin', 'refs/tags/v1.1.41')
        self.run_command('git', 'checkout', '--detach', '-q', self.initial)
        result = self.verify_release(ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('does not point to the workflow commit', result.stdout)
        self.assertEqual(self.run_command('git', 'rev-parse', 'HEAD').stdout.strip(), self.initial)

    def test_ci_verification_rejects_wrong_checkout(self):
        self.run_command('git', 'tag', '-a', 'v1.1.41', '-m', 'v1.1.41')
        self.run_command('git', 'push', '-q', 'origin', 'refs/tags/v1.1.41')
        self.run_command('git', 'commit', '--allow-empty', '-qm', 'ops: another checkout')
        result = self.verify_release(ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('HEAD does not match the workflow commit', result.stdout)

    def test_ci_verification_rejects_missing_remote_tag_and_wrong_version(self):
        self.run_command('git', 'tag', '-a', 'v1.1.41', '-m', 'local only')
        self.assertNotEqual(self.verify_release(ok=False).returncode, 0)
        self.assertNotEqual(self.verify_release(ok=False, GITHUB_REF_NAME='v1.1.42').returncode, 0)

    def test_patch_release_publishes_only_exact_annotated_tag(self):
        self.run_command('git', 'tag', 'unrelated-local-tag')
        self.release()
        self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.1.42')
        self.assertEqual((self.root / '.fixture/gates').read_text(), '1.1.42\n')
        self.assertEqual(self.run_command('git', 'status', '--porcelain').stdout, '')
        head = self.run_command('git', 'rev-parse', 'HEAD').stdout.strip()
        self.assertEqual(self.remote_head(), head)
        self.assertEqual(self.run_command('git', '--git-dir', str(self.remote), 'tag').stdout.strip(), 'v1.1.42')
        self.assertEqual(self.run_command('git', 'cat-file', '-t', 'v1.1.42').stdout.strip(), 'tag')
        self.assertEqual(self.run_command('git', 'show', '--format=%s', '--no-patch').stdout.strip(),
                         'ops: released v1.1.42')

    def test_minor_release_resets_patch(self):
        self.release('minor')
        self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.2.0')
        self.assertEqual((self.root / '.fixture/gates').read_text(), '1.2.0\n')
        self.assertEqual(self.run_command('git', '--git-dir', str(self.remote), 'tag').stdout.strip(), 'v1.2.0')

    def test_release_check_does_not_bump_or_run_gate(self):
        self.release('check')
        self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.1.41')
        self.assertFalse((self.root / '.fixture/gates').exists())
        self.assertEqual(self.run_command('git', 'status', '--porcelain').stdout, '')
        self.assertEqual(self.run_command('git', 'rev-parse', 'HEAD').stdout.strip(), self.initial)
        self.assertEqual(self.remote_head(), self.initial)

    def test_dirty_staged_untracked_and_wrong_branch_are_rejected(self):
        for mode in ('untracked', 'staged', 'tracked', 'branch', 'detached'):
            with self.subTest(mode=mode):
                if mode == 'untracked':
                    (self.root / 'extra').write_text('dirty')
                elif mode == 'staged':
                    (self.root / 'extra').write_text('dirty')
                    self.run_command('git', 'add', 'extra')
                elif mode == 'tracked':
                    (self.root / 'VERSION').write_text('1.1.40')
                elif mode == 'branch':
                    self.run_command('git', 'checkout', '-qb', 'feature')
                else:
                    self.run_command('git', 'checkout', '--detach', '-q')
                self.assertNotEqual(self.release(ok=False).returncode, 0)
                self.assertEqual(self.remote_head(), self.initial)
                self.assertFalse((self.root / '.fixture/gates').exists())
                # Fixture-only cleanup; no command here targets the working repository.
                self.run_command('git', 'reset', '--hard', '-q', self.initial)
                (self.root / 'extra').unlink(missing_ok=True)
                self.run_command('git', 'checkout', '-q', 'main')

    def test_version_drift_fails_before_bump(self):
        (self.root / 'VERSION').write_text('1.1.40\n')
        self.run_command('git', 'add', 'VERSION')
        self.run_command('git', 'commit', '-qm', 'ops: fixture version drift')
        head = self.run_command('git', 'rev-parse', 'HEAD').stdout.strip()
        self.assertNotEqual(self.release(ok=False).returncode, 0)
        self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.1.40')
        self.assertFalse((self.root / '.fixture/gates').exists())
        self.assertEqual(self.run_command('git', 'rev-parse', 'HEAD').stdout.strip(), head)
        self.assertEqual(self.remote_head(), self.initial)

    def test_gate_failure_keeps_reviewable_changes_unpublished(self):
        self.assertNotEqual(self.release(ok=False, FAIL_GATE='1').returncode, 0)
        self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.1.42')
        self.assertEqual((self.root / '.fixture/gates').read_text(), '1.1.42\n')
        self.assertEqual(self.run_command('git', 'rev-parse', 'HEAD').stdout.strip(), self.initial)
        self.assertEqual(self.remote_head(), self.initial)
        self.assertEqual(self.run_command('git', 'tag').stdout, '')
        self.assertEqual(self.run_command('git', '--git-dir', str(self.remote), 'tag').stdout, '')
        self.assertEqual(self.run_command('git', 'diff', '--cached', '--name-only').stdout, '')
        self.assertEqual(self.run_command('git', 'diff', '--name-only').stdout.splitlines(),
                         ['VERSION', 'cmd/authdbctl/main.go', 'pkg/identity/database.go'])
        # A blind retry must not increment again or publish the failed candidate.
        self.assertNotEqual(self.release(ok=False).returncode, 0)
        self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.1.42')
        self.assertEqual((self.root / '.fixture/gates').read_text(), '1.1.42\n')

    def test_unexpected_gate_output_is_not_committed(self):
        self.assertNotEqual(self.release(ok=False, DIRTY_GATE='1').returncode, 0)
        self.assertEqual(self.run_command('git', 'rev-parse', 'HEAD').stdout.strip(), self.initial)
        self.assertEqual(self.remote_head(), self.initial)

    def test_existing_local_or_remote_tag_fails_before_bump(self):
        self.run_command('git', 'tag', 'v1.1.42')
        self.assertNotEqual(self.release(ok=False).returncode, 0)
        self.run_command('git', 'push', '-q', 'origin', 'v1.1.42')
        self.run_command('git', 'tag', '-d', 'v1.1.42')
        self.assertNotEqual(self.release(ok=False).returncode, 0)
        self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.1.41')
        self.assertFalse((self.root / '.fixture/gates').exists())
        self.assertEqual(self.remote_head(), self.initial)

    def test_stale_main_is_rejected_before_bump(self):
        (self.root / 'advance').write_text('remote advancement')
        self.run_command('git', 'add', 'advance')
        self.run_command('git', 'commit', '-qm', 'ops: advance remote')
        self.run_command('git', 'push', '-q')
        remote = self.remote_head()
        self.run_command('git', 'reset', '--hard', '-q', self.initial)
        self.assertNotEqual(self.release(ok=False).returncode, 0)
        self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.1.41')
        self.assertFalse((self.root / '.fixture/gates').exists())
        self.assertEqual(self.remote_head(), remote)

    def test_atomic_push_cannot_publish_main_without_tag(self):
        hook = self.remote / 'hooks/update'
        hook.write_text('#!/bin/sh\ncase "$1" in refs/tags/*) exit 1 ;; esac\nexit 0\n')
        hook.chmod(0o755)
        self.assertNotEqual(self.release(ok=False).returncode, 0)
        self.assertEqual(self.remote_head(), self.initial)
        self.assertEqual(self.run_command('git', '--git-dir', str(self.remote), 'tag').stdout, '')
        self.assertEqual(self.run_command('git', 'tag').stdout.strip(), 'v1.1.42')


if __name__ == '__main__':
    unittest.main()
