"""Exercise resource refusal and process cleanup through the real Make workflow."""

import importlib.util
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('test_guard', ROOT / 'assets/scripts/test_guard.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class TestGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='authcrunch-guard-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'checkout with spaces'
        (self.root / 'assets/scripts').mkdir(parents=True)
        for name in ('Makefile', 'VERSION', 'assets/scripts/test_guard.py'):
            shutil.copyfile(ROOT / name, self.root / name)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('TEST_', 'GIT_')) and key not in
                    ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'COVERAGE_DIR')}
        self.env.update(PATH=str(self.root) + os.pathsep + self.env['PATH'],
                        COVERAGE_DIR='reports with spaces', TEST_MEMORY_MB='192',
                        TEST_WALL_TIMEOUT='10', PYTHONDONTWRITEBYTECODE='1')
        self.tool('print("fixture complete")')

    def tool(self, body):
        path = self.root / 'go'
        path.write_text(f'#!{sys.executable}\n' + body + '\n')
        path.chmod(0o755)

    def command(self, *args):
        return ['make', '--no-print-directory', 'GIT_COMMIT=fixture', 'GIT_BRANCH=main',
                'PYTHON=' + sys.executable, *args]

    def make(self, *args):
        return subprocess.run(self.command(*args), cwd=self.root, env=self.env,
                              capture_output=True, text=True, timeout=20)

    def status(self):
        return json.loads((self.root / 'reports with spaces/resource-usage.json').read_text())

    def assert_stopped(self, result, reason):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(reason, result.stderr)
        self.assertEqual(self.status()['status'], 'aborted')

    def wait_file(self, path):
        deadline = time.monotonic() + 5
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(path.exists(), str(path))

    def assert_dead(self, pid):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            result = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)],
                                    capture_output=True, text=True, timeout=5)
            if not result.stdout.strip() or result.stdout.strip().startswith('Z'):
                return
            time.sleep(0.02)
        self.fail(f'owned child {pid} survived cleanup')

    def test_e2e_environment_and_make_overrides_reach_nested_go(self):
        self.tool('import json, os, sys\n'
                  'from pathlib import Path\n'
                  'Path("observed.json").write_text(json.dumps({"args":sys.argv[1:],'
                  '"procs":os.environ["GOMAXPROCS"],"memory":os.environ["GOMEMLIMIT"],'
                  '"flags":os.environ["GOFLAGS"]}))')
        self.env.update(TEST_PACKAGE_PARALLELISM='3', TEST_PARALLELISM='4',
                        TEST_GOMAXPROCS='3', TEST_GO_MEMORY_MB='128', GOFLAGS='-mod=readonly')
        result = self.make('qtest', 'TEST_GOMAXPROCS=1', 'TEST_PACKAGE_PARALLELISM=2')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        observed = json.loads((self.root / 'observed.json').read_text())
        self.assertEqual(observed['procs'], '1')
        self.assertEqual(observed['memory'], '128MiB')
        self.assertEqual(observed['flags'], '-mod=readonly -p=2')
        args = observed['args']
        self.assertEqual(args[args.index('-p') + 1], '2')
        self.assertEqual(args[args.index('-parallel') + 1], '4')

    def test_e2e_memory_in_new_session_child_is_counted_and_killed(self):
        # Safe reproduction: a 64 MiB allocation exceeds a 48 MiB tree budget.
        worker = self.root / 'worker.py'
        worker.write_text('import os, signal, time\nfrom pathlib import Path\n'
                          'signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
                          'Path("worker.pid").write_text(str(os.getpid()))\n'
                          'payload=bytearray(64*1024*1024)\ntime.sleep(30)\n')
        self.tool('import subprocess, sys, time\n'
                  'subprocess.Popen([sys.executable,"worker.py"], start_new_session=True)\n'
                  'time.sleep(30)')
        result = self.make('test', 'TEST_MEMORY_MB=48')
        self.assert_stopped(result, 'memory budget')
        self.assert_dead(int((self.root / 'worker.pid').read_text()))
        # Aborted evidence must never become a passing offline report.
        report = self.make('run-reports')
        self.assertNotEqual(report.returncode, 0)
        self.assertIn('previous run was interrupted', report.stderr)
        self.assertEqual(self.status()['status'], 'aborted')

    def test_e2e_timeout_process_limit_and_artifact_limit(self):
        cases = (
            ('import time\ntime.sleep(30)', 'TEST_WALL_TIMEOUT=1', 'exceeded 1 seconds'),
            ('import subprocess,sys,time\n'
             'subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"])\n'
             'time.sleep(30)', 'TEST_MAX_PROCESSES=1', 'exceeded 1 processes'),
            ('from pathlib import Path\nimport time\n'
             'Path("reports with spaces/test_output.jsonl").write_bytes(b"x"*(2*1024*1024))\n'
             'time.sleep(30)', 'TEST_ARTIFACT_MB=1', 'artifacts exceeded'),
        )
        for body, setting, reason in cases:
            with self.subTest(setting=setting):
                self.tool(body)
                self.assert_stopped(self.make('test', setting), reason)

    def test_e2e_console_is_bounded_and_failure_exit_survives(self):
        self.tool('import os, sys\n'
                  'for _ in range(128): os.write(1,b"x"*8192)\n'
                  'sys.exit(7)')
        result = self.make('test')
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(len(result.stdout), 270000)
        self.assertTrue('Console limit reached' in result.stdout, result.stdout[-1000:])
        self.assertEqual(self.status()['exit_code'], 7)
        self.assertEqual(self.status()['status'], 'failed')

    def test_e2e_quiet_work_reports_progress_before_completion(self):
        self.tool('import time\ntime.sleep(12)\nprint("fixture complete")')
        first = subprocess.Popen(self.command('test', 'TEST_WALL_TIMEOUT=15'),
                                 cwd=self.root, env=self.env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            output = bytearray()
            deadline = time.monotonic() + 14
            with selectors.DefaultSelector() as selector:
                selector.register(first.stdout, selectors.EVENT_READ)
                while b'[test guard] Elapsed ' not in output:
                    remaining = deadline - time.monotonic()
                    self.assertGreater(remaining, 0, output.decode())
                    self.assertTrue(selector.select(remaining), output.decode())
                    chunk = os.read(first.stdout.fileno(), 4096)
                    self.assertTrue(chunk, output.decode())
                    output.extend(chunk)
            self.assertIsNone(first.poll(), output.decode())
            self.assertNotIn(b'fixture complete', output)
            self.assertIn(b'/192 MiB;', output)
            self.assertIn(b'processes', output)
            tail, stderr = first.communicate(timeout=10)
            self.assertEqual(first.returncode, 0, stderr.decode())
            self.assertIn(b'fixture complete', tail)
            self.assertEqual(self.status()['status'], 'passed')
        finally:
            if first.poll() is None:
                first.kill()
                first.communicate(timeout=5)

    def test_e2e_concurrent_runs_refused_and_interrupt_cleans_child(self):
        self.tool('import os,time\nfrom pathlib import Path\n'
                  'Path("tool.pid").write_text(str(os.getpid()))\n'
                  'time.sleep(30)')
        first = subprocess.Popen(self.command('test'), cwd=self.root, env=self.env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.wait_file(self.root / 'tool.pid')
            second = self.make('qtest', 'COVERAGE_DIR=other-reports')
            self.assertNotEqual(second.returncode, 0)
            self.assertIn('another guarded test/report run', second.stderr)
            pid = int((self.root / 'tool.pid').read_text())
            # Signal the watchdog itself, as an IDE cancellation does. Make is
            # deliberately left alive to verify it observes a nonzero exit.
            table = guard.processes()
            supervisor = table[pid][0]
            os.kill(supervisor, signal.SIGTERM)
            stdout, stderr = first.communicate(timeout=10)
            self.assertNotEqual(first.returncode, 0, stdout + stderr)
            self.assertIn('interrupted by signal', stderr)
            self.assert_dead(pid)
        finally:
            if first.poll() is None:
                first.kill()
                first.communicate(timeout=5)

    def test_e2e_invalid_limits_fail_before_tool_starts(self):
        self.tool('from pathlib import Path\nPath("started").touch()')
        for setting in ('TEST_MEMORY_MB=0', 'TEST_MEMORY_MB=999999999',
                        'TEST_GO_MEMORY_MB=-1', 'TEST_PARALLELISM=bad',
                        'TEST_MAX_PROCESSES=0', 'TEST_WALL_TIMEOUT=0'):
            with self.subTest(setting=setting):
                result = self.make('test', setting)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / 'started').exists())

    def test_e2e_killed_make_does_not_leave_tests_running(self):
        self.tool('import os,time\nfrom pathlib import Path\n'
                  'Path("tool.pid").write_text(str(os.getpid()))\ntime.sleep(30)')
        first = subprocess.Popen(self.command('test'), cwd=self.root, env=self.env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.wait_file(self.root / 'tool.pid')
            pid = int((self.root / 'tool.pid').read_text())
            first.kill()
            _, stderr = first.communicate(timeout=10)
            self.assertIn('test launcher exited', stderr)
            self.assert_dead(pid)
            self.assertEqual(self.status()['status'], 'aborted')
        finally:
            if first.poll() is None:
                first.kill()
                first.communicate(timeout=5)

    def test_e2e_blocked_terminal_does_not_block_watchdog(self):
        self.tool('import os,time\nfrom pathlib import Path\n'
                  'Path("tool.pid").write_text(str(os.getpid()))\n'
                  'for _ in range(256): os.write(1,b"x"*8192)\n'
                  'time.sleep(30)')
        first = subprocess.Popen(self.command('test', 'TEST_WALL_TIMEOUT=1'),
                                 cwd=self.root, env=self.env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.wait_file(self.root / 'tool.pid')
            pid = int((self.root / 'tool.pid').read_text())
            # Deliberately don't consume stdout until the child is terminated.
            self.assert_dead(pid)
            stdout, stderr = first.communicate(timeout=10)
            self.assertNotEqual(first.returncode, 0, stdout[-1000:] + stderr)
            self.assertIn('exceeded 1 seconds', stderr)
        finally:
            if first.poll() is None:
                first.kill()
                first.communicate(timeout=5)

    def test_e2e_monitor_failure_still_kills_work(self):
        real_ps = shutil.which('ps')
        fake_ps = self.root / 'ps'
        fake_ps.write_text(f'#!{sys.executable}\n'
                           'import os,sys\nfrom pathlib import Path\n'
                           'p=Path("ps.calls")\n'
                           'n=int(p.read_text())+1 if p.exists() else 1\n'
                           'p.write_text(str(n))\n'
                           'if n>=3: sys.exit(1)\n'
                           f'os.execv({real_ps!r},["ps",*sys.argv[1:]])\n')
        fake_ps.chmod(0o755)
        self.tool('import os,time\nfrom pathlib import Path\n'
                  'Path("tool.pid").write_text(str(os.getpid()))\ntime.sleep(30)')
        result = self.make('test')
        self.assert_stopped(result, 'non-zero exit status')
        self.assert_dead(int((self.root / 'tool.pid').read_text()))

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS pressure interface')
    def test_e2e_system_pressure_refuses_work_before_start(self):
        fake_sysctl = self.root / 'sysctl'
        fake_sysctl.write_text(f'#!{sys.executable}\nimport sys\n'
                              'print(8589934592 if sys.argv[-1]=="hw.memsize" else 4)\n')
        fake_sysctl.chmod(0o755)
        self.tool('from pathlib import Path\nPath("started").touch()')
        result = self.make('test')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('system memory pressure is critical', result.stderr)
        self.assertFalse((self.root / 'started').exists())

    def test_linux_pressure_accounts_for_available_memory(self):
        with mock.patch.object(guard.sys, 'platform', 'linux'):
            for available, fails in ((100000, True), (2000000, False)):
                with self.subTest(available=available), mock.patch.object(
                        Path, 'read_text', return_value=f'MemTotal: 8000000 kB\nMemAvailable: {available} kB\n'):
                    if fails:
                        with self.assertRaisesRegex(RuntimeError, 'safety reserve'):
                            guard.check_host_pressure()
                    else:
                        guard.check_host_pressure()

    def test_reparented_children_retained_but_reused_pids_excluded(self):
        table = {10: (1, 0, 'leader'), 11: (10, 0, 'child'),
                 12: (1, 0, 'orphan'), 13: (1, 0, 'reused'), 14: (11, 0, 'new')}
        owned = guard.descendants(table, 10, {12: 'orphan', 13: 'old'})
        self.assertEqual(set(owned), {10, 11, 12, 14})


if __name__ == '__main__':
    unittest.main()
