"""Exercise resource refusal and process cleanup through the real Make workflow."""

import errno
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

    def test_e2e_openapi_target_uses_guarded_reports_and_stops_on_failure(self):
        self.tool('import json, os, sys\nfrom pathlib import Path\n'
                  'args = sys.argv[1:]\n'
                  'destination = args[args.index("--output-dir") + 1]\n'
                  'with Path("observed.jsonl").open("a") as out:\n'
                  '    out.write(json.dumps({"args": args, "memory": os.environ["GOMEMLIMIT"]}) + "\\n")\n'
                  'sys.exit(7 if destination.endswith(os.environ["FAIL_PHASE"]) else 0)\n')
        node = self.root / 'node'
        node.write_text(f'#!{sys.executable}\nfrom pathlib import Path\n'
                        'Path("bootstrap-ran").touch()\n')
        node.chmod(0o755)
        for phase, expected_runs in [('openapi-tools', 1), ('openapi-contracts', 2), ('none', 2)]:
            with self.subTest(phase=phase):
                self.env['FAIL_PHASE'] = phase
                observed = self.root / 'observed.jsonl'
                observed.unlink(missing_ok=True)
                result = self.make('openapi-test')
                self.assertEqual(result.returncode == 0, phase == 'none', result.stdout + result.stderr)
                runs = [json.loads(line) for line in observed.read_text().splitlines()]
                self.assertEqual(len(runs), expected_runs)
                for run, suffix in zip(runs, ['openapi-tools', 'openapi-contracts']):
                    self.assertEqual(run['args'][:3], ['tool', 'tested', 'run'])
                    self.assertEqual(run['memory'], '512MiB')
                    destination = run['args'][run['args'].index('--output-dir') + 1]
                    self.assertEqual(destination, 'reports with spaces/' + suffix)
                    evidence = json.loads((self.root / destination / 'resource-usage.json').read_text())
                    self.assertEqual(evidence['status'], 'failed' if suffix == phase else 'passed')
                if expected_runs == 2:
                    args = runs[1]['args']
                    self.assertEqual(args[args.index('-run') + 1], '^TestE2EOpenAPIContract')
                    self.assertEqual(args[-2:], ['.', './pkg/authn'])
                self.assertEqual((self.root / 'bootstrap-ran').exists(), phase == 'none')

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
        windows = int(self.status()['elapsed_seconds'] / guard.CONSOLE_WINDOW_SECONDS) + 1
        self.assertLess(len(result.stdout), windows * (guard.CONSOLE_BYTES + 256) + 1000)
        self.assertTrue('Output rate limit reached' in result.stdout, result.stdout[-1000:])
        self.assertGreater(self.status()['console_dropped_bytes'], 0)
        self.assertEqual(self.status()['exit_code'], 7)
        self.assertEqual(self.status()['status'], 'failed')

    def test_e2e_pending_notice_survives_child_exit(self):
        for exit_code in (0, 7):
            with self.subTest(exit_code=exit_code):
                (self.root / 'reports with spaces/resource-usage.json').unlink(missing_ok=True)
                self.tool('import os,sys\n'
                          'for _ in range(128): os.write(1,b"x"*8192)\n'
                          f'sys.exit({exit_code})')
                first = subprocess.Popen(self.command('test'), cwd=self.root, env=self.env,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    # Keep the pipe full until cleanup and evidence finalization.
                    # This forces the last notice retry to happen after child exit.
                    deadline = time.monotonic() + 5
                    status = {}
                    while 'exit_code' not in status:
                        self.assertLess(time.monotonic(), deadline, status)
                        time.sleep(.02)
                        try:
                            status = self.status()
                        except FileNotFoundError:
                            pass
                    self.assertEqual(status['exit_code'], exit_code)
                    self.assertEqual(status['status'], 'passed' if exit_code == 0 else 'failed')
                    self.assertGreater(status['console_dropped_bytes'], 0)
                    stdout, stderr = first.communicate(timeout=5)
                    self.assertEqual(first.returncode == 0, exit_code == 0, stderr)
                    notice = ('Output rate limit reached; live output resumes in the next second. '
                              'Full logs remain in the tested evidence.')
                    self.assertTrue(notice in stdout, stdout[-1000:])
                    self.assertEqual(stdout.count(notice), 1)
                    self.assertLess(stdout.index(notice), stdout.index('[test guard] Omitted'))
                finally:
                    if first.poll() is None:
                        first.kill()
                    first.communicate(timeout=5)

    def test_console_rate_recovers_and_preserves_heartbeat(self):
        output = bytearray()

        def write(fd, block):
            output.extend(block)
            return len(block)

        with mock.patch.object(guard.time, 'monotonic', return_value=0) as clock, \
                mock.patch.object(guard.os, 'write', side_effect=write):
            console = guard.ConsoleOutput(1)
            console.forward(b'x' * (guard.CONSOLE_BYTES + 100))
            console.forward(b'dropped')
            console.progress(b'\nheartbeat\n')
            self.assertIn(b'Output rate limit reached', output)
            self.assertEqual(output.count(b'Output rate limit reached'), 1)
            self.assertIn(b'heartbeat', output)
            self.assertTrue(output.startswith(b'x' * guard.CONSOLE_BYTES + b'\n[test guard]'))
            self.assertEqual(console.dropped_bytes, 107)
            clock.return_value = guard.CONSOLE_WINDOW_SECONDS
            console.forward(b'later test passed\n')
            self.assertTrue(output.endswith(b'later test passed\n'))

    def test_console_counts_short_and_blocked_writes(self):
        with mock.patch.object(guard.os, 'write', side_effect=[2, BlockingIOError(), BrokenPipeError()]):
            console = guard.ConsoleOutput(1)
            console.forward(b'partial')
            console.forward(b'blocked')
            console.forward(b'closed')
            self.assertEqual(console.dropped_bytes, 18)

    def test_console_retries_notice_before_later_progress(self):
        with mock.patch.object(guard.os, 'write', side_effect=[guard.CONSOLE_BYTES,
                                                             BlockingIOError(), 5]) as write:
            console = guard.ConsoleOutput(1)
            console.forward(b'x' * (guard.CONSOLE_BYTES + 1))
            notice = console.pending_notice
            self.assertIn(b'Output rate limit reached', notice)
            console.flush_notice()
            self.assertEqual(console.pending_notice, notice[5:])
            write.side_effect = lambda fd, block: len(block)
            console.progress(b'heartbeat')
            self.assertEqual(console.pending_notice, b'')
            self.assertEqual(write.call_args_list[-2].args[1], notice[5:])
            self.assertEqual(write.call_args_list[-1].args[1], b'heartbeat')

    def test_e2e_output_resumes_and_heartbeat_survives_flood(self):
        self.tool('import os,time\nfrom pathlib import Path\n'
                  'for _ in range(128): os.write(1,b"x"*8192)\n'
                  'time.sleep(1.2)\nprint("progress after burst",flush=True)\n'
                  'deadline=time.monotonic()+15\n'
                  'while not Path("release").exists() and time.monotonic()<deadline: time.sleep(.02)\n'
                  'print("fixture complete",flush=True)')
        first = subprocess.Popen(self.command('test', 'TEST_WALL_TIMEOUT=20'),
                                 cwd=self.root, env=self.env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            output = bytearray()
            deadline = time.monotonic() + 14
            with selectors.DefaultSelector() as selector:
                selector.register(first.stdout, selectors.EVENT_READ)
                while b'[test guard] Elapsed ' not in output:
                    remaining = deadline - time.monotonic()
                    self.assertGreater(remaining, 0, output[-1000:].decode())
                    self.assertTrue(selector.select(remaining), output[-1000:].decode())
                    chunk = os.read(first.stdout.fileno(), 16384)
                    self.assertTrue(chunk, output[-1000:].decode())
                    output.extend(chunk)
            self.assertIsNone(first.poll())
            notice = output.index(b'Output rate limit reached')
            progress = output.index(b'progress after burst')
            heartbeat = output.index(b'[test guard] Elapsed ')
            self.assertLess(notice, progress)
            self.assertLess(progress, heartbeat)
            self.assertNotIn(b'fixture complete', output)
            (self.root / 'release').touch()
            tail, stderr = first.communicate(timeout=10)
            self.assertEqual(first.returncode, 0, stderr.decode())
            self.assertIn(b'fixture complete', tail)
            self.assertGreater(self.status()['console_dropped_bytes'], 0)
        finally:
            if first.poll() is None:
                first.kill()
                first.communicate(timeout=5)
            first.stdout.close()
            first.stderr.close()

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
            notice = ('Output rate limit reached; live output resumes in the next second. '
                      'Full logs remain in the tested evidence.')
            self.assertTrue(notice in stdout, stdout[-1000:])
            self.assertEqual(stdout.count(notice), 1)
            self.assertEqual(self.status()['status'], 'aborted')
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

    def test_linux_memory_accounts_for_swap_and_exited_processes(self):
        with mock.patch.object(guard.sys, 'platform', 'linux'):
            usage = guard.MemoryUsage()
        for status, expected in (('VmRSS: 128 kB\nVmSwap: 32 kB\n', 160 * 1024),
                                 ('Name: zombie\n', 128 * 1024)):
            with self.subTest(status=status), mock.patch.object(Path, 'read_text', return_value=status):
                self.assertEqual(usage.bytes(123, 128 * 1024), expected)
        for code in (errno.ENOENT, errno.ESRCH):
            with self.subTest(errno=code), mock.patch.object(
                    Path, 'read_text', side_effect=OSError(code, os.strerror(code))):
                self.assertEqual(usage.bytes(123, 128 * 1024), 0)

    def test_linux_memory_preserves_other_monitoring_errors(self):
        with mock.patch.object(guard.sys, 'platform', 'linux'):
            usage = guard.MemoryUsage()
        for code in (errno.EACCES, errno.EPERM, errno.EIO):
            error = OSError(code, os.strerror(code))
            with self.subTest(errno=code), mock.patch.object(Path, 'read_text', side_effect=error):
                with self.assertRaises(OSError) as caught:
                    usage.bytes(123, 1024)
                self.assertIs(caught.exception, error)
        with mock.patch.object(Path, 'read_text', return_value='VmSwap: invalid kB\n'):
            with self.assertRaises(ValueError):
                usage.bytes(123, 1024)

    def test_e2e_linux_proc_errors_preserve_results_and_cleanup(self):
        # Inject Linux proc-read failures at the syscall boundary on either host;
        # retain the real Make entry point, supervisor, process tree and cleanup.
        launcher = self.root / 'proc_fixture.py'
        launcher.write_text('import importlib.util, os, sys\nfrom pathlib import Path\n'
                            'spec=importlib.util.spec_from_file_location("guard",sys.argv.pop(1))\n'
                            'guard=importlib.util.module_from_spec(spec)\nspec.loader.exec_module(guard)\n'
                            'usage=guard.MemoryUsage()\nusage.libproc=None\n'
                            'guard.MemoryUsage=lambda: usage\n'
                            'read_text=Path.read_text\n'
                            'def proc_read(path,*args,**kwargs):\n'
                            '    if str(path).startswith("/proc/") and path.name=="status":\n'
                            '        pid=Path("tool.pid")\n'
                            '        if pid.exists() and path.parent.name==read_text(pid):\n'
                            '            Path("probe-error").touch()\n'
                            '            code=int(os.environ["PROC_ERROR"])\n'
                            '            raise OSError(code,os.strerror(code))\n'
                            '        return "VmSwap: 0 kB\\n"\n'
                            '    return read_text(path,*args,**kwargs)\n'
                            'Path.read_text=proc_read\nsys.exit(guard.main())\n')
        cases = ((errno.ENOENT, 0), (errno.ESRCH, 0), (errno.ESRCH, 7),
                 (errno.EACCES, None), (errno.EIO, None))
        for code, exit_code in cases:
            with self.subTest(errno=code, exit_code=exit_code):
                for name in ('tool.pid', 'probe-error'):
                    (self.root / name).unlink(missing_ok=True)
                self.env['PROC_ERROR'] = str(code)
                self.tool('import os,sys,time\nfrom pathlib import Path\n'
                          'Path("tool.pid").write_text(str(os.getpid()))\n'
                          'deadline=time.monotonic()+5\n'
                          'while not Path("probe-error").exists():\n'
                          '    if time.monotonic()>deadline: sys.exit(99)\n'
                          '    time.sleep(.02)\n'
                          + ('time.sleep(30)' if exit_code is None else
                             f'time.sleep(.5)\nprint("fixture complete",flush=True)\nsys.exit({exit_code})'))
                result = self.make('test', 'PYTHON=' + sys.executable + ' proc_fixture.py')
                self.assertTrue((self.root / 'probe-error').exists(), result.stdout + result.stderr)
                if exit_code is None:
                    self.assert_stopped(result, os.strerror(code))
                    self.assert_dead(int((self.root / 'tool.pid').read_text()))
                else:
                    self.assertEqual(result.returncode == 0, exit_code == 0,
                                     result.stdout + result.stderr)
                    self.assertIn('fixture complete', result.stdout)
                    self.assertEqual(self.status()['exit_code'], exit_code)
                    self.assertEqual(self.status()['status'], 'passed' if exit_code == 0 else 'failed')

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
