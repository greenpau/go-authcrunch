"""Exercise ACL generation through Make in a self-contained fixture checkout."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
GENERATED = ('condition.go', 'condition_test.go', 'rule.go', 'rule_test.go')


class GenerateACLTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='authcrunch-acl-')
        self.addCleanup(self.temp.cleanup)
        # Exercise paths with spaces and invocation outside the repository root.
        self.outside = Path(self.temp.name)
        self.root = self.outside / 'checkout with spaces'
        self.script = self.root / 'assets/scripts/generate_acl.py'
        self.script.parent.mkdir(parents=True)
        shutil.copy2(ROOT / 'assets/scripts/generate_acl.py', self.script)
        for name in ('Makefile', 'VERSION', 'go.mod', 'go.sum'):
            shutil.copy2(ROOT / name, self.root / name)
        for name in ('pkg/acl', 'pkg/errors', 'pkg/util/cfg', 'pkg/util/log', 'internal/tests'):
            shutil.copytree(ROOT / name, self.root / name)
        self.acl = self.root / 'pkg/acl'
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith('GIT_') and key not in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL')}
        self.env['PYTHONDONTWRITEBYTECODE'] = '1'
        self.env['GOWORK'] = 'off'

    def command(self, *args, env=None):
        return subprocess.run(args, cwd=self.outside, env=self.env if env is None else env,
                              capture_output=True, text=True, timeout=180)

    def make(self):
        return self.command('make', '--no-print-directory', '-C', str(self.root), 'generate-acl',
                            'PYTHON=' + sys.executable, 'GIT_COMMIT=fixture', 'GIT_BRANCH=main')

    def snapshot(self):
        return {path.relative_to(self.root): (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
                for path in self.root.rglob('*') if path.is_file()}

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_e2e_make_regenerates_missing_files_and_runs_acl_tests(self):
        # No sibling repository, global versioned/autopep8, or existing generated
        # Go source is needed to reconstruct the checked-in artifacts.
        for name in GENERATED:
            (self.acl / name).unlink()
        untouched = self.snapshot()
        # A file named after the target must not prevent this maintenance action.
        (self.root / 'generate-acl').touch()
        self.assert_success(self.make())
        after = self.snapshot()
        for path, original in untouched.items():
            self.assertEqual(after[path], original, str(path))
        for name in GENERATED:
            self.assertEqual((self.acl / name).read_bytes(), (ROOT / 'pkg/acl' / name).read_bytes(), name)
        self.assert_success(self.command('go', '-C', str(self.root), 'test', '-mod=readonly', '-count=1', './pkg/acl'))

    def test_e2e_repeat_generation_and_check_do_not_rewrite_files(self):
        before = self.snapshot()
        self.assert_success(self.make())
        self.assert_success(self.command(sys.executable, str(self.script)))
        self.assert_success(self.command(sys.executable, str(self.script), '--check'))
        self.assertEqual(self.snapshot(), before)

    def test_e2e_check_reports_drift_and_missing_files_without_writing(self):
        (self.acl / 'condition.go').write_text('stale content\n')
        (self.acl / 'rule_test.go').unlink()
        before = self.snapshot()
        result = self.command(sys.executable, str(self.script), '--check')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('pkg/acl/condition.go', result.stderr)
        self.assertIn('pkg/acl/rule_test.go', result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assert_success(self.make())
        self.assert_success(self.command(sys.executable, str(self.script), '--check'))

    def test_e2e_format_failure_preserves_all_destinations(self):
        # Break the third artifact so earlier files have already been rendered
        # and formatted when the real gofmt process reports a syntax error.
        source = self.script.read_text()
        old = 'type ruleVerdict int'
        self.assertEqual(source.count(old), 1)
        self.script.write_text(source.replace(old, 'type ruleVerdict ='))
        (self.acl / 'condition.go').write_text('keep this pending edit\n')
        before = self.snapshot()
        result = self.make()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('gofmt failed for rule.go', result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_e2e_missing_gofmt_preserves_all_destinations(self):
        empty_path = self.outside / 'empty-path'
        empty_path.mkdir()
        before = self.snapshot()
        result = self.command(sys.executable, str(self.script), env={**self.env, 'PATH': str(empty_path)})
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('gofmt', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
