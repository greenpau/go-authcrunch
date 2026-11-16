"""Verify the Documents test-driver exception with real extraction and SARIF."""

import os
from pathlib import Path
import shutil
import tempfile

from test_scan import results_by_rule, rule_ids, run


REPO = Path(__file__).resolve().parents[2]
RULE = "js/regex-injection"
DRIVER = "pkg/authn/ui/testdata/documents_browser_e2e.cjs"
REGEX_FIXTURE = '''const pattern = process.argv[2];
new RegExp(pattern).test("fixture"); // retain: regex
'''
FIXTURES = {
    "app.cjs": REGEX_FIXTURE,
    "pkg/authn/ui/testdata/neighbor.cjs": REGEX_FIXTURE,
    "pkg/authn/ui/documents_browser_e2e.cjs": REGEX_FIXTURE,
    "nested/" + DRIVER: REGEX_FIXTURE,
    DRIVER + ".extra.cjs": REGEX_FIXTURE,
    "pkg/authn/ui/regex_consumer.cjs": '''const fixture = require("./testdata/documents_browser_e2e.cjs");
new RegExp(fixture.untrustedPattern).test("fixture"); // retain: cross-file regex
''',
}
OTHER_RULE_CONTROL = '''
// Scanner-only controls appended to the copied driver, never to production.
exports.untrustedPattern = process.argv[2];
const fixtureApp = require("express")();
fixtureApp.get("/codeql-control", (request, response) => {
    response.send(eval(request.query.code)); // other: code-injection
});
'''


def main():
    codeql = shutil.which(os.environ.get("CODEQL", "codeql"))
    if not codeql:
        raise SystemExit("CodeQL CLI is required; set CODEQL to its executable path.")
    codeql = str(Path(codeql).resolve())
    coverage = REPO / ".coverage" / "codeql"
    coverage.mkdir(parents=True, exist_ok=True)
    # Preserve failed databases and reports; use an isolated source root so prior
    # scanner fixtures and local artifacts cannot enter this extraction.
    root = Path(tempfile.mkdtemp(prefix="javascript-exception-e2e-", dir=coverage))
    print(f"CodeQL JavaScript exception E2E fixture: {root}", flush=True)
    for name in ("assets/scripts/run_codeql_javascript_scan.sh",
                 ".github/codeql/javascript-config.yml"):
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / name, destination)
    shutil.copytree(REPO / ".github/codeql/javascript-queries",
                    root / ".github/codeql/javascript-queries",
                    ignore=shutil.ignore_patterns("*.qlx", "*.bqrs", ".cache"))
    sources = {**FIXTURES, DRIVER: (REPO / DRIVER).read_text() + OTHER_RULE_CONTROL}
    for name, source in sources.items():
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(source)
    expected = {(name, line) for name, source in FIXTURES.items()
                for line, text in enumerate(source.splitlines(), 1) if "// retain:" in text}
    other = {(DRIVER, line) for line, text in enumerate(sources[DRIVER].splitlines(), 1)
             if "// other:" in text}
    output = root / ".coverage" / "scan"
    env = {**os.environ, "CODEQL": codeql, "CODEQL_OUTPUT_DIR": str(output)}
    run(["bash", "assets/scripts/run_codeql_javascript_scan.sh"], root, env)
    filtered = results_by_rule(output / "results.sarif")
    if filtered.get(RULE, set()) != expected:
        raise AssertionError(f"Expected retained regex sinks {sorted(expected)}; "
                             f"received {sorted(filtered.get(RULE, set()))}")
    # Compare the complete upstream default suite on the very same database.
    run([codeql, "database", "analyze", str(output / "database"),
         "codeql/javascript-queries", "--threads=2", "--ram=5922",
         "--format=sarif-latest", f"--output={output / 'upstream.sarif'}"], root)
    baseline = results_by_rule(output / "upstream.sarif")
    excluded = {point for point in baseline.get(RULE, set()) if point[0] == DRIVER}
    if len(excluded) != 1 or baseline.get(RULE, set()) != expected | excluded:
        raise AssertionError("Upstream scan must report the actual driver and all control sinks")
    if not other <= filtered.get("js/code-injection", set()):
        raise AssertionError("Other default rules must still inspect the excepted test file")
    if rule_ids(output / "results.sarif") != rule_ids(output / "upstream.sarif"):
        raise AssertionError("Configured scan must retain every default rule ID")
    if ({key: value for key, value in filtered.items() if key != RULE} !=
            {key: value for key, value in baseline.items() if key != RULE}):
        raise AssertionError("The exception changed results from another default query")
    print(f"PASS: actual Documents test-driver regex excepted; {len(expected)} "
          "neighboring, runtime, lookalike and cross-file sinks retained; all default "
          "rules and other findings in the same test file retained.")


if __name__ == "__main__":
    main()
