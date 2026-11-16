"""Local CodeQL command failures and checkout/output isolation."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
FAKE_CODEQL = f'#!{sys.executable}\n' + '''import os
import json
from pathlib import Path
import sys

operation = " ".join(sys.argv[1:3])
with open(os.environ["CODEQL_TEST_CALLS"], "a") as log:
    log.write(operation + "\\n")
with open(os.environ["CODEQL_TEST_ARGS"], "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
if operation == os.environ.get("CODEQL_TEST_FAIL"):
    sys.exit(23)
if operation == "database create":
    Path(sys.argv[3]).mkdir()
elif operation in ("database analyze", "database interpret-results"):
    output = next(arg.split("=", 1)[1] for arg in sys.argv if arg.startswith("--output="))
    Path(output).write_text("synthetic report")
'''


class CodeQLScanTests(unittest.TestCase):
    script_name = "run_codeql_scan.sh"
    language = "go"
    query_pack = "queries"
    config_name = "codeql-config.yml"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="authcrunch codeql ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.script = self.root / "checkout/assets/scripts" / self.script_name
        self.script.parent.mkdir(parents=True)
        shutil.copy2(SCRIPTS / self.script_name, self.script)
        self.codeql = self.root / "fake codeql"
        self.codeql.write_text(FAKE_CODEQL)
        self.codeql.chmod(0o755)
        self.calls = self.root / "calls"
        self.args = self.root / "args.jsonl"
        self.env = {**os.environ, "PYTHON": sys.executable, "CODEQL": str(self.codeql),
                    "CODEQL_TEST_CALLS": str(self.calls), "CODEQL_TEST_ARGS": str(self.args),
                    "CODEQL_OUTPUT_DIR": "reports with spaces"}
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
        calls = [json.loads(line) for line in self.args.read_text().splitlines()]
        self.assertEqual(calls[0], ["pack", "install", ".github/codeql/" + self.query_pack])
        self.assertEqual(calls[1], ["pack", "download", f"codeql/{self.language}-queries"])
        create = calls[2]
        self.assertIn("--language=" + self.language, create)
        self.assertIn("--source-root=" + str(self.root / "checkout"), create)
        self.assertIn("--codescanning-config=" + str(self.root / "checkout/.github/codeql" / self.config_name), create)
        self.assertEqual(any(arg.startswith("--command=") for arg in create), self.language == "go")

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


class CodeQLJavaScriptScanTests(CodeQLScanTests):
    script_name = "run_codeql_javascript_scan.sh"
    language = "javascript"
    query_pack = "javascript-queries"
    config_name = "javascript-config.yml"


class CodeQLWorkflowTests(unittest.TestCase):
    def test_language_configuration_and_verification_precede_upload(self):
        workflow = (SCRIPTS.parents[1] / ".github/workflows/codeql.yml").read_text()
        self.assertIn("language: [go, javascript-typescript, python, actions]", workflow)
        steps = {}
        for step in workflow.split("      - name: ")[1:]:
            name, _, body = step.partition("\n")
            steps[name] = body
        js = steps["Initialize JavaScript analysis"]
        self.assertIn("id: init-javascript", js)
        self.assertIn("if: matrix.language == 'javascript-typescript'", js)
        self.assertIn("config-file: ./.github/codeql/javascript-config.yml", js)
        self.assertIn("config-file: ./.github/codeql/codeql-config.yml", steps["Initialize Go analysis"])
        self.assertIn("matrix.language != 'go' && matrix.language != 'javascript-typescript'",
                      steps["Initialize other language analysis"])
        verify = steps["Verify JavaScript query exceptions"]
        self.assertIn("if: matrix.language == 'javascript-typescript'", verify)
        self.assertIn("steps.init-javascript.outputs.codeql-path", verify)
        self.assertIn("run: make test-codeql-javascript", verify)
        self.assertIn("upload: false", steps["Analyze"])
        names = list(steps)
        for name in ["Verify Go query exceptions", "Verify JavaScript query exceptions"]:
            self.assertLess(names.index("Analyze"), names.index(name))
            self.assertLess(names.index(name), names.index("Upload verified analysis"))


if __name__ == "__main__":
    unittest.main()
