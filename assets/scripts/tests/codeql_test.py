"""Local CodeQL command failures and checkout/output isolation."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "run_codeql_scan.sh"
FAKE_CODEQL = '''#!/usr/bin/env python3
import os
from pathlib import Path
import sys

operation = " ".join(sys.argv[1:3])
with open(os.environ["CODEQL_TEST_CALLS"], "a") as log:
    log.write(operation + "\\n")
if operation == os.environ.get("CODEQL_TEST_FAIL"):
    sys.exit(23)
if operation == "database create":
    Path(sys.argv[3]).mkdir()
elif operation in ("database analyze", "database interpret-results"):
    output = next(arg.split("=", 1)[1] for arg in sys.argv if arg.startswith("--output="))
    Path(output).write_text("synthetic report")
'''


class CodeQLScanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="authcrunch codeql ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.script = self.root / "checkout/assets/scripts/run_codeql_scan.sh"
        self.script.parent.mkdir(parents=True)
        shutil.copy2(SCRIPT, self.script)
        self.codeql = self.root / "fake codeql"
        self.codeql.write_text(FAKE_CODEQL)
        self.codeql.chmod(0o755)
        self.calls = self.root / "calls"
        self.env = {**os.environ, "CODEQL": str(self.codeql),
                    "CODEQL_TEST_CALLS": str(self.calls), "CODEQL_OUTPUT_DIR": "reports with spaces"}
        self.env.pop("CODEQL_TEST_FAIL", None)
        self.output = self.root / "checkout/reports with spaces"

    def command(self):
        return subprocess.run(["bash", str(self.script)], cwd=self.root, env=self.env,
                              capture_output=True, text=True, timeout=10)

    def test_e2e_scan_uses_own_checkout_and_quoted_output_paths(self):
        result = self.command()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.output / "results.sarif").is_file())
        self.assertTrue((self.output / "results.csv").is_file())
        self.assertFalse((self.root / "reports with spaces").exists())

    def test_missing_cli_fails_without_creating_reports(self):
        self.env["CODEQL"] = str(self.root / "missing cli")
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CodeQL CLI not found", result.stderr)
        self.assertFalse(self.output.exists())

    def test_command_failure_is_preserved_and_stops_following_steps(self):
        operations = ["pack install", "pack download", "database create",
                      "database analyze", "database interpret-results"]
        for index, operation in enumerate(operations):
            with self.subTest(operation=operation):
                self.calls.unlink(missing_ok=True)
                if self.output.exists():
                    shutil.rmtree(self.output)
                self.env["CODEQL_TEST_FAIL"] = operation
                result = self.command()
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertEqual(self.calls.read_text().splitlines(), operations[:index + 1])
                self.assertNotIn("CodeQL scan results:", result.stdout)
                self.assertFalse((self.output / "results.csv").exists())


if __name__ == "__main__":
    unittest.main()
