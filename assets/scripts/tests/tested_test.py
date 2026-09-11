"""Verify Make preserves real test/build failures and tested evidence freshness."""

import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class TestedLifecycleTests(unittest.TestCase):
    def test_success_filter_failure_and_build_failure_keep_honest_reports(self):
        with tempfile.TemporaryDirectory(prefix='authcrunch-tested-') as directory:
            root = Path(directory)
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith('GIT_') and key not in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL')}
            env.update(PYTHONDONTWRITEBYTECODE='1', TEST='.', TEST_DIR='./...',
                       COVERAGE_DIR='.coverage', MINIMUM_COVERAGE='1')
            shutil.copyfile(ROOT / 'Makefile', root / 'Makefile')
            (root / 'VERSION').write_text('1.0.0\n')
            pinned = re.search(r'github.com/greenpau/tested (v\S+)', (ROOT / 'go.mod').read_text()).group(1)
            (root / 'go.mod').write_text('module example.invalid/testedfixture\n\ngo 1.25.0\n\n'
                                        f'require github.com/greenpau/tested {pinned}\n\n'
                                        'tool github.com/greenpau/tested\n')
            (root / 'go.sum').write_text(''.join(line for line in (ROOT / 'go.sum').read_text().splitlines(True)
                                              if line.startswith('github.com/greenpau/tested ')))
            (root / 'fixture.go').write_text('package fixture\nfunc Value() int { return 42 }\n')
            test = root / 'fixture_test.go'
            test.write_text('package fixture\nimport "testing"\n'
                            'func TestSelected(t *testing.T) { if Value()!=42 { t.Fatal("value") } }\n'
                            'func TestExcluded(t *testing.T) { t.Fatal("must be filtered out") }\n')
            subprocess.run(['git', 'init', '-q', '-b', 'main'], cwd=root, env=env, check=True)
            source = {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}

            def make(*arguments):
                return subprocess.run(['make', *arguments], cwd=root, env=env, text=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            result = make('test', 'TEST=^TestSelected$')
            self.assertEqual(result.returncode, 0, result.stdout)
            report = root / '.coverage'
            for name in ('index.html', 'test_output.html', 'coverage.html', 'coverage.out',
                         'summary.json', 'junit.xml', 'test_output.jsonl', 'stderr.log',
                         'run.json', 'manifest.json'):
                self.assertTrue((report / name).is_file(), name)
            for name, content in source.items():
                self.assertEqual((root / name).read_bytes(), content, name)
            first_run = json.loads((report / 'run.json').read_text())
            first_profile = (report / 'coverage.out').read_bytes()
            self.assertIn('TestSelected', (report / 'test_output.jsonl').read_text())
            self.assertNotIn('TestExcluded', (report / 'test_output.jsonl').read_text())
            quick = make('qtest', 'QUICK_TEST_DIR=.', 'TEST=^TestSelected$')
            self.assertEqual(quick.returncode, 0, quick.stdout)
            self.assertTrue((report / 'quick/manifest.json').is_file())
            self.assertEqual(json.loads((report / 'run.json').read_text()), first_run)

            result = make('test')
            self.assertNotEqual(result.returncode, 0, result.stdout)
            events = [json.loads(line) for line in (report / 'test_output.jsonl').read_text().splitlines()]
            self.assertTrue(any(e.get('Action') == 'fail' and e.get('Test') == 'TestExcluded' for e in events))
            self.assertNotEqual(json.loads((report / 'run.json').read_text()), first_run)
            self.assertNotEqual(make('run-reports').returncode, 0)

            test.write_text('package fixture\nfunc broken(\n')
            result = make('test')
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertTrue((report / 'run.json').is_file())
            # Go 1.26 emits build diagnostics as JSON stdout; earlier Go may use stderr.
            evidence = (report / 'test_output.jsonl').read_text() + (report / 'stderr.log').read_text()
            self.assertIn('fixture_test.go', evidence)
            failed_summary = json.loads((report / 'summary.json').read_text())
            self.assertNotEqual(failed_summary['outcome'], 'passed')
            self.assertNotEqual(json.loads((report / 'run.json').read_text())['exit_code'], 0)
            # A valid empty profile can have fresh HTML even after compilation fails.
            if (report / 'coverage.out').exists():
                self.assertNotEqual((report / 'coverage.out').read_bytes(), first_profile)
                self.assertNotIn('fixture.go', (report / 'coverage.out').read_text())
            self.assertNotIn('TestSelected', (report / 'test_output.jsonl').read_text())


if __name__ == '__main__':
    unittest.main()
