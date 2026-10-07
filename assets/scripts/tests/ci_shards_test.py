"""Exercise CI sharding, complete coverage, and failure gates through real workflows."""

import itertools
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SHARDS = ('portal', 'identity', 'other')
MODULE = 'example.invalid/cishards'


class CIShardsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='authcrunch CI shards ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('GIT_', 'GITHUB_', 'TEST_', 'TESTED_', 'CHANGE_', 'CI_'))
                    and key not in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'COVERAGE_DIR', 'GOFLAGS',
                                    'GOWORK', 'MINIMUM_COVERAGE')}
        self.env.update(PYTHONDONTWRITEBYTECODE='1', GOWORK='off',
                        COVERAGE_DIR='reports with spaces', TEST='^MustNotExcludeTests$',
                        TEST_DIR='./missing', GIT_COMMIT='fixture', GIT_BRANCH='main')
        shutil.copyfile(ROOT / 'Makefile', self.root / 'Makefile')
        scripts = self.root / 'assets/scripts'
        scripts.mkdir(parents=True)
        for name in ('ci_tests.py', 'change_tests.py', 'test_guard.py'):
            shutil.copyfile(ROOT / 'assets/scripts' / name, scripts / name)
        (self.root / 'VERSION').write_text('1.0.0\n')
        pinned = re.search(r'github.com/greenpau/tested (v\S+)', (ROOT / 'go.mod').read_text()).group(1)
        (self.root / 'go.mod').write_text('module ' + MODULE + '\n\ngo 1.26.0\n\n'
                                        f'require github.com/greenpau/tested {pinned}\n\n'
                                        'tool github.com/greenpau/tested\n')
        (self.root / 'go.sum').write_text(''.join(
            line for line in (ROOT / 'go.sum').read_text().splitlines(True)
            if line.startswith('github.com/greenpau/tested ')))

    def package(self, directory, tested=True):
        destination = self.root / directory
        destination.mkdir(parents=True, exist_ok=True)
        (destination / 'value.go').write_text('package fixture\nfunc Value() int { return 42 }\n')
        if tested:
            (destination / 'value_test.go').write_text(
                'package fixture\nimport ("os"; "testing")\n'
                'func TestE2EValue(t *testing.T) {\n'
                ' if Value() != 42 { t.Fatal("incorrect value") }\n'
                f' if os.Getenv("SHARD_FAIL") == "fail:{directory}" {{ t.Fatal("fixture failure") }}\n'
                '}\n')

    def command(self, *args, success=True, env=None, cwd=None):
        result = subprocess.run(args, cwd=cwd or self.root, env=env or self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def cli(self, *args, **kwargs):
        return self.command('python3', 'assets/scripts/ci_tests.py', *args, **kwargs)

    def test_e2e_complete_disjoint_shards_reports_and_failed_rerun(self):
        expected = {
            'portal': ['pkg/authn', 'pkg/authn/child'],
            'identity': ['pkg/identity', 'pkg/identity/parser'],
            'other': ['', 'pkg/authn_extra', 'pkg/future', 'pkg/enums'],
        }
        for directory in itertools.chain.from_iterable(expected.values()):
            self.package(directory, tested=directory != 'pkg/enums')
        source = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        plan = json.loads(self.cli('plan').stdout)
        expected = {shard: sorted(MODULE + ('/' + path if path else '') for path in paths)
                    for shard, paths in expected.items()}
        self.assertEqual(plan, expected)
        base = self.root / 'reports with spaces'
        for shard in SHARDS:
            if shard == 'portal':
                # Direct invocation from outside the checkout must place the plan
                # beside the reports produced by the nested Make invocation.
                self.command('python3', str(self.root / 'assets/scripts/ci_tests.py'),
                             'run', shard, cwd=self.root.parent,
                             env=dict(self.env, TEST_PACKAGE_PARALLELISM='2'))
            else:
                self.command('make', 'ci-test-shard', 'CI_SHARD=' + shard,
                             'TEST_PACKAGE_PARALLELISM=2')
            output = base / 'shards' / shard
            run = json.loads((output / 'run.json').read_text())
            command = run['command']
            self.assertIn('-race', command)
            self.assertIn('-count=1', command)
            self.assertEqual(command[command.index('-p') + 1], '2')
            self.assertEqual(command[command.index('-run') + 1], '.')
            self.assertEqual(command[-len(plan[shard]):], plan[shard])
            self.assertTrue((output / 'manifest.json').is_file())
            self.cli('summarize', shard)
            timing = json.loads((output / 'timing.json').read_text())
            self.assertEqual({p['package'] for p in timing['packages']}, set(plan[shard]))
            self.assertTrue(timing['slowest_tests'])
        self.cli('merge')
        combined = base / 'combined'
        summary = json.loads((combined / 'summary.json').read_text())
        self.assertEqual(summary['packages'], 8)
        self.assertEqual(summary['covered'], 7)
        self.assertEqual(summary['statements'], 8)
        self.assertEqual(summary['percent'], 87.5)
        # The aggregate is a real Go coverage profile, usable by standard tooling.
        coverage = self.command('go', 'tool', 'cover', '-func', str(combined / 'coverage.out'))
        self.assertIn('87.5%', coverage.stdout)
        self.command('go', 'tool', 'cover', '-html', str(combined / 'coverage.out'),
                     '-o', str(combined / 'source.html'))
        for shard in SHARDS:
            self.assertIn(f'../shards/{shard}/index.html', (combined / 'index.html').read_text())
        for path, original in source.items():
            self.assertEqual(path.read_bytes(), original, str(path))

        # Reject incomplete/overlapping/failed evidence without replacing the last good aggregate.
        good_profile = (combined / 'coverage.out').read_bytes()
        portal = base / 'shards/portal'
        corruptions = [
            ('run.json', lambda data: dict(data, capture_complete=False)),
            ('run.json', lambda data: dict(data, exit_code=1)),
            ('resource-usage.json', lambda data: dict(data, status='aborted')),
            ('selection.json', lambda data: dict(data, packages=[])),
            ('selection.json', lambda data: dict(data, all_shards={**data['all_shards'], 'other': []})),
        ]
        for name, mutate in corruptions:
            with self.subTest(corruption=name):
                path = portal / name
                original = path.read_bytes()
                path.write_text(json.dumps(mutate(json.loads(original))))
                self.cli('merge', success=False)
                path.write_bytes(original)
                self.assertEqual((combined / 'coverage.out').read_bytes(), good_profile)
        events_path = portal / 'test_output.jsonl'
        original = events_path.read_bytes()
        events = [json.loads(line) for line in original.splitlines()]
        terminal = next(e for e in events if e['Action'] == 'pass' and not e.get('Test'))
        for changed in ([e for e in events if e != terminal], events + [terminal],
                        events + [dict(terminal, Action='fail')]):
            events_path.write_text(''.join(json.dumps(e) + '\n' for e in changed))
            self.cli('merge', success=False)
        events_path.write_bytes(original)
        profile = portal / 'coverage.out'
        original = profile.read_bytes()
        profile.write_bytes(original + original.splitlines(keepends=True)[1])
        self.cli('merge', success=False)
        profile.write_bytes(original)
        for name in ('manifest.json', 'index.html'):
            path = portal / name
            original = path.read_bytes()
            path.unlink()
            self.cli('merge', success=False)
            path.write_bytes(original)
        path = portal / 'index.html'
        original = path.read_bytes()
        path.write_bytes(original + b'corrupted report')
        self.cli('merge', success=False)
        path.write_bytes(original)
        self.cli('merge')

        other = {p: p.read_bytes() for p in (base / 'shards/other').iterdir() if p.is_file()}
        env = dict(self.env, SHARD_FAIL='fail:pkg/authn')
        self.command('make', 'ci-test-shard', 'CI_SHARD=portal', env=env, success=False)
        self.cli('summarize', 'portal')
        timing = json.loads((portal / 'timing.json').read_text())
        self.assertTrue(any(p['outcome'] == 'fail' for p in timing['packages']))
        self.cli('merge', success=False)
        self.command('make', 'run-reports', 'COVERAGE_DIR=' + str(portal), success=False)
        for path, content in other.items():
            self.assertEqual(path.read_bytes(), content)
        # A compilation failure must also propagate through the public shard entry point.
        (self.root / 'pkg/authn/value_test.go').write_text('package fixture\nfunc broken(\n')
        self.command('make', 'ci-test-shard', 'CI_SHARD=portal', success=False)
        self.cli('merge', success=False)

    def test_gate_rejects_failure_skip_cancellation_and_missing_selection(self):
        outcomes = ('success', 'failure', 'cancelled', 'skipped')
        for go_result, quality_result in itertools.product(outcomes, repeat=2):
            env = dict(self.env, SELECTION_RESULT='success', SELECTION_MODE='focused',
                       GO_RESULT=go_result, QUALITY_RESULT=quality_result)
            self.cli('gate', env=env, success=(go_result == quality_result == 'success'))
        for mode in ('none', 'full', 'focused', '', 'unexpected'):
            for result in ('success', 'skipped'):
                env = dict(self.env, SELECTION_RESULT='success', SELECTION_MODE=mode,
                           GO_RESULT=result, QUALITY_RESULT=result)
                success = ((mode == 'none' and result == 'skipped')
                           or (mode in ('full', 'focused') and result == 'success'))
                self.cli('gate', env=env, success=success)
        for selection in ('failure', 'cancelled', 'skipped', ''):
            env = dict(self.env, SELECTION_RESULT=selection, SELECTION_MODE='none',
                       GO_RESULT='skipped', QUALITY_RESULT='skipped')
            self.cli('gate', env=env, success=False)

    def test_missing_graph_unknown_shard_and_incomplete_reports_fail(self):
        self.cli('plan', success=False)
        self.command('make', 'ci-test-shard', 'CI_SHARD=typo', success=False)
        self.cli('merge', success=False)
        self.assertFalse((self.root / 'reports with spaces/combined').exists())
        self.cli('summarize', 'portal')
        timing = json.loads((self.root / 'reports with spaces/shards/portal/timing.json').read_text())
        self.assertTrue(timing['incomplete'])
        self.assertEqual(timing['packages'], [])


if __name__ == '__main__':
    unittest.main()
