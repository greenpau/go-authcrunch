"""Exercise change-test with real Git histories, Go graphs, Make, and tested."""

import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('change_tests', ROOT / 'assets/scripts/change_tests.py')
SELECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SELECTOR)
MODULE = 'example.invalid/changes'


class ChangeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='authcrunch changes ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('GIT_', 'GITHUB_', 'CHANGE_', 'TEST_', 'TESTED_'))
                    and key not in {'MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'COVERAGE_DIR',
                                    'TEST', 'TEST_DIR', 'MINIMUM_COVERAGE'}}
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_AUTHOR_NAME='Change Fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
                        GIT_COMMITTER_NAME='Change Fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid',
                        PYTHONDONTWRITEBYTECODE='1')
        self.write('Makefile', (ROOT / 'Makefile').read_text())
        for name in ('change_tests.py', 'test_guard.py'):
            self.write('assets/scripts/' + name, (ROOT / 'assets/scripts' / name).read_text())
        self.write('VERSION', '1.0.0\n')
        self.write('.gitignore', '.coverage/\n')
        pinned = re.search(r'github.com/greenpau/tested (v\S+)', (ROOT / 'go.mod').read_text()).group(1)
        self.write('go.mod', f'module {MODULE}\n\ngo 1.26.0\n\n'
                   f'require github.com/greenpau/tested {pinned}\n\ntool github.com/greenpau/tested\n')
        self.write('go.sum', ''.join(line for line in (ROOT / 'go.sum').read_text().splitlines(True)
                                    if line.startswith('github.com/greenpau/tested ')))
        self.write('pkg/lib/lib.go', 'package lib\nfunc Value() int { return 42 }\n')
        self.write('pkg/lib/lib_test.go', 'package lib\nimport "testing"\n'
                   'func TestValue(t *testing.T) { if Value()!=42 { t.Fatal(Value()) } }\n')
        self.write('pkg/bridge/value.go', f'package bridge\nimport "{MODULE}/pkg/lib"\n'
                   'func Value() int { return lib.Value() }\n')
        self.write('pkg/consumer/value.go', f'package consumer\nimport "{MODULE}/pkg/bridge"\n'
                   'func Value() int { return bridge.Value() }\n')
        self.write('pkg/consumer/value_test.go', 'package consumer\nimport "testing"\n'
                   'func TestE2EConsumer(t *testing.T) { if Value()!=42 { t.Fatal(Value()) } }\n')
        self.write('pkg/testconsumer/value.go', 'package testconsumer\nfunc Value() int { return 42 }\n')
        self.write('pkg/testconsumer/value_test.go', f'package testconsumer_test\n'
                   f'import ("testing"; "{MODULE}/pkg/lib"; "{MODULE}/pkg/testconsumer")\n'
                   'func TestE2EExternalConsumer(t *testing.T) { '
                   'if testconsumer.Value()!=lib.Value() { t.Fatal("consumer") } }\n')
        self.write('pkg/unrelated/value.go', f'package unrelated\nimport "{MODULE}/pkg/testconsumer"\n'
                   'func Value() int { return testconsumer.Value() }\n')
        self.write('pkg/unrelated/value_test.go', 'package unrelated\nimport "testing"\n'
                   'func TestMustNotRun(t *testing.T) { t.Fatal("unrelated test ran") }\n')
        self.write('internal/tag/tag.go', 'package tag\n')
        self.write('README.md', 'prose\n')
        self.git('init', '-q', '-b', 'main')
        self.git('add', '.')
        self.git('commit', '-qm', 'baseline')

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def git(self, *args):
        result = subprocess.run(['git', *args], cwd=self.root, env=self.env, text=True,
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def make(self, *args, success=True):
        result = subprocess.run(['make', '--no-print-directory', 'change-test', *args],
                                cwd=self.root, env=self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        self.assertEqual(result.returncode == 0, success, result.stdout)
        return result

    def plan(self, *args):
        result = self.make('CHANGE_DRY_RUN=1', *args)
        return json.JSONDecoder().raw_decode(result.stdout[result.stdout.index('{'):])[0]

    def test_policy_covers_non_code_runtime_assets_and_global_inputs(self):
        cases = {
            'README.md': 'none', '.codex/skills/x/SKILL.md': 'none',
            '.codex/skills/x/agents/openai.yaml': 'none', 'plugins/secrets/.gitkeep': 'none',
            'assets/cla/signatures.json': 'none', '.vscode/settings.json': 'none',
            '.github/FUNDING.yml': 'none', '.github/ISSUE_TEMPLATE/issue.yml': 'none',
            'pkg/authn/ui/core/README.md': 'go', 'testdata/input.md': 'go',
            'pkg/messaging/email_templates/input.md': 'go', 'pkg/translate/data/input.md': 'go',
            'assets/scripts/testdata/input.md': 'automation',
            'pkg/example/testdata/input.md': 'go', 'pkg/example/source_windows.go': 'go',
            'pkg/example/template.html': 'go', 'assets/scripts/tool.sh': 'automation',
            '.github/workflows/test.yml': 'automation', '.goreleaser.yaml': 'automation',
            'assets/branding/palette.json': 'automation', 'Makefile': 'full',
            'go.mod': 'full', 'go.sum': 'full', 'VERSION': 'full',
            'plugins/example/go.mod': 'full', 'new-build-input': 'full',
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(SELECTOR.classify(path), expected)

    def test_clean_and_document_changes_do_not_need_go_or_create_reports(self):
        self.assertEqual(self.plan()['mode'], 'none')
        self.write('README.md', 'staged prose')
        self.git('add', 'README.md')
        self.write('.codex/skills/new\tname\n/SKILL.md', 'untracked prose')
        # If selection starts a Go tool, fail visibly, without affecting Git/Make.
        self.write('.coverage/tools/go', '#!/bin/sh\nexit 99\n')
        (self.root / '.coverage/tools/go').chmod(0o755)
        self.env['PATH'] = str(self.root / '.coverage/tools') + os.pathsep + self.env['PATH']
        result = self.make()
        selected = json.JSONDecoder().raw_decode(result.stdout[result.stdout.index('{'):])[0]
        self.assertEqual(selected['mode'], 'none')
        self.assertIn('.codex/skills/new\tname\n/SKILL.md', selected['files'])
        self.assertFalse((self.root / '.coverage/changes').exists())

    def test_staged_unstaged_and_untracked_union_and_test_only_scope(self):
        self.write('pkg/lib/lib_test.go', 'package lib\n// staged\n')
        self.git('add', 'pkg/lib/lib_test.go')
        # Undo only the working copy: comparing HEAD to worktree would miss it.
        original = self.git('show', 'HEAD:pkg/lib/lib_test.go')
        self.write('pkg/lib/lib_test.go', original + '\n')
        self.write('pkg/consumer/new_test.go', 'package consumer\n')
        self.write('README.md', 'unstaged prose')
        selected = self.plan()
        self.assertEqual(selected['packages'], [MODULE + '/pkg/consumer', MODULE + '/pkg/lib'])
        self.assertEqual(set(selected['files']), {'pkg/lib/lib_test.go', 'pkg/consumer/new_test.go', 'README.md'})

    def test_production_changes_include_transitive_and_test_import_consumers(self):
        self.write('pkg/lib/lib.go', 'package lib\nfunc Value() int { return 42 }\n// changed\n')
        self.assertEqual(self.plan()['packages'], [MODULE + '/internal/tag', MODULE + '/pkg/bridge',
                                                 MODULE + '/pkg/consumer', MODULE + '/pkg/lib',
                                                 MODULE + '/pkg/testconsumer'])

    def test_deletion_and_cross_package_rename_keep_both_owners(self):
        self.git('mv', 'pkg/lib/lib_test.go', 'pkg/consumer/moved_test.go')
        self.write('pkg/consumer/moved_test.go', 'package consumer\n')
        self.assertEqual(self.plan()['packages'], [MODULE + '/pkg/consumer', MODULE + '/pkg/lib'])
        self.git('rm', 'pkg/lib/lib.go')
        self.assertEqual(self.plan()['mode'], 'full')

    def test_fixtures_embedded_assets_and_automation(self):
        self.write('pkg/authn/ui/ui.go', 'package ui\nimport "embed"\n'
                   '//go:embed core\nvar Files embed.FS\n')
        self.write('pkg/authn/ui/core/page.html', '<p>page</p>')
        self.git('add', '.')
        self.git('commit', '-qm', 'embedded UI')
        self.write('pkg/authn/ui/core/page.html', '<p>changed</p>')
        selected = self.plan()
        self.assertEqual(selected['packages'], [MODULE + '/pkg/authn/ui'])
        self.assertTrue(selected['ui'])
        self.write('assets/scripts/new.py', '# automation\n')
        self.assertTrue(self.plan()['automation'])
        self.write('testdata/shared.json', '{}')
        self.assertEqual(self.plan()['packages'], ['./...'])

    def test_unknown_inputs_and_graph_errors_fall_back_to_all_tests(self):
        self.write('unknown-input', 'new')
        self.assertEqual(self.plan()['mode'], 'full')
        (self.root / 'unknown-input').unlink()
        self.write('pkg/lib/lib.go', 'package lib\nimport "missing.invalid/module"\n')
        selected = self.plan()
        self.assertEqual(selected['mode'], 'full')
        self.assertIn('Cannot determine Go impact', selected['reason'])

    def test_committed_range_excludes_uncommitted_edits_and_bad_base_fails(self):
        base = self.git('rev-parse', 'HEAD')
        self.write('README.md', 'committed prose')
        self.git('add', 'README.md')
        self.git('commit', '-qm', 'prose')
        self.write('pkg/lib/lib.go', 'broken working copy')
        self.assertEqual(self.plan('CHANGE_BASE=' + base)['mode'], 'none')
        self.make('CHANGE_BASE=missing-revision', success=False)
        self.make('CHANGE_HEAD=HEAD', success=False)

    def test_unborn_repository_selects_staged_inputs(self):
        shutil.rmtree(self.root / '.git')
        self.git('init', '-q', '-b', 'main')
        self.git('add', '.')
        self.assertEqual(self.plan()['mode'], 'full')

    def test_e2e_selected_make_runs_real_tested_and_preserves_failures(self):
        self.write('pkg/lib/lib.go', 'package lib\nfunc Value() int { return 42 }\n// edit\n')
        # Inherited manual filters must not silently narrow applicable tests.
        self.env.update(TEST='^Nothing$', TEST_DIR='./pkg/unrelated')
        result = self.make('COVERAGE_DIR=.coverage/reports with spaces', 'TEST_TIMEOUT=1m')
        report = self.root / '.coverage/reports with spaces/changes'
        self.assertTrue((report / 'selection.json').is_file(), result.stdout)
        events = (report / 'go/test_output.jsonl').read_text()
        self.assertIn('TestValue', events)
        self.assertIn('TestE2EConsumer', events)
        self.assertIn('TestE2EExternalConsumer', events)
        self.assertNotIn('TestMustNotRun', events)
        command = json.loads((report / 'go/run.json').read_text())['command']
        self.assertEqual(command[command.index('-timeout') + 1], '1m')
        self.assertIn('-race', command)
        self.assertTrue((report / 'go/resource-usage.json').is_file())
        self.write('pkg/lib/lib.go', 'package lib\nfunc Value() int { return 41 }\n')
        self.make('COVERAGE_DIR=.coverage/failure', success=False)
        failed = json.loads((self.root / '.coverage/failure/changes/go/run.json').read_text())
        self.assertNotEqual(failed['exit_code'], 0)

    def test_e2e_automation_only_runs_automation_and_propagates_failure(self):
        # Real unittest discovery through the public Make entry point.
        self.write('assets/scripts/tests/fixture_test.py',
                   'import unittest\nclass Fixture(unittest.TestCase):\n'
                   '    def test_entry_point(self):\n        self.assertEqual(2 + 2, 4)\n')
        self.make()
        self.assertFalse((self.root / '.coverage/changes/go').exists())
        self.write('assets/scripts/tests/fixture_test.py',
                   'import unittest\nclass Fixture(unittest.TestCase):\n'
                   '    def test_failure(self):\n        self.fail("automation failure")\n')
        self.make(success=False)

    def test_e2e_global_change_runs_all_suites_and_keeps_full_go_failure(self):
        self.write('assets/scripts/tests/fixture_test.py',
                   'import unittest\nclass Fixture(unittest.TestCase):\n'
                   '    def test_automation_entry(self):\n        pass\n')
        self.write('pkg/authn/ui/testdata/fixture_client_test.cjs',
                   'require("node:test")("node selection fixture", () => {});\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'test entry points')
        self.write('VERSION', '1.0.1\n')
        result = self.make(success=False)
        self.assertIn('test_automation_entry', result.stdout)
        self.assertIn('node selection fixture', result.stdout)
        events = (self.root / '.coverage/changes/go/test_output.jsonl').read_text()
        self.assertIn('TestMustNotRun', events)  # Full fallback must include this failing test.
        failed = json.loads((self.root / '.coverage/changes/go/run.json').read_text())
        self.assertNotEqual(failed['exit_code'], 0)


if __name__ == '__main__':
    unittest.main()
