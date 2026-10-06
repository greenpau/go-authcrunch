"""Exercise the real lint target against source and temporary checkout files."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CLEAN = 'package fixture\n'
WARNING = ('package fixture\n\nfunc value(ok bool) int {\n'
           '\tif ok { return 1 } else { return 2 }\n}\n')


class LinterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='authcrunch-linter-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'checkout with spaces'
        self.root.mkdir()
        for name in ('Makefile', 'VERSION', 'go.mod', 'go.sum'):
            shutil.copy2(ROOT / name, self.root / name)
        self.sources = ('fixture.go', 'cmd/example/main.go',
                        'internal/example/nested/fixture.go', 'pkg/example/nested/fixture.go',
                        'pkg/example/tests/fixture_test.go',
                        'plugins/claims-enrichment/static/fixture.go',
                        'plugins/claims-enrichment/static/parser/fixture_test.go')
        for name in self.sources:
            self.write(name, CLEAN)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith('GIT_') and key not in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL')}
        self.env.update(PYTHONDONTWRITEBYTECODE='1', GOWORK='off', GOFLAGS='-mod=readonly')
        subprocess.run(['git', 'init', '-q', '-b', 'main'], cwd=self.root,
                       env=self.env, check=True, timeout=30)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def make(self):
        return subprocess.run(
            ['make', '--no-print-directory', '-C', str(self.root), 'linter',
             'GIT_COMMIT=fixture', 'GIT_BRANCH=main'],
            cwd=self.temp.name, env=self.env, capture_output=True, text=True, timeout=120)

    def test_e2e_ignores_temporary_checkouts_and_generated_artifacts(self):
        for directory in ('tmp/ci/consumer', 'tmp/scratch', '.tmp/scratch',
                          'bin', 'dist', '.coverage', '.doc'):
            self.write(directory + '/fixture.go', WARNING)
        self.write('tmp/ci/consumer/go.mod', 'module example.invalid/consumer\n\ngo 1.26.0\n')
        before = {path.relative_to(self.root): path.read_bytes()
                  for path in self.root.rglob('*') if path.is_file()}
        result = self.make()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = {path.relative_to(self.root): path.read_bytes()
                 for path in self.root.rglob('*') if path.is_file()}
        self.assertEqual(after, before)

    def test_e2e_source_and_test_warnings_still_fail(self):
        for name in self.sources:
            self.write(name, WARNING)
        result = self.make()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        for name in self.sources:
            self.assertIn(name + ':', result.stdout)
        self.assertIn('drop this else', result.stdout)
        for name in self.sources:
            self.write(name, CLEAN)
        result = self.make()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
