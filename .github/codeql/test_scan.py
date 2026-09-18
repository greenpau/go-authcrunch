"""Exercise the real local scan, query configuration and SARIF diagnostic boundary."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


REPO = Path(__file__).resolve().parents[2]
RULE = "go/clear-text-logging"
FIXTURE = '''package fixture

import (
    "log"
    "net/http"
    "os"

    "go.uber.org/zap"
)

func getPassword() string { return os.Getenv("SYNTHETIC_PASSWORD") }

type diagnosticWriter struct{}
func (diagnosticWriter) Debug(value string) {
    log.Print(value) // retain: unrelated-debug-method
}

func diagnostics(logger *zap.Logger, request *http.Request) {
    password := getPassword()
    claims := map[string]interface{}{"password": password}
    logger.Debug("claims", zap.Any("user", claims)) // exempt: claims
    logger.Debug("credential", zap.String("token", password)) // exempt: credential
    logger.Debug("request", zap.Any("headers", request.Header)) // exempt: headers
    logger.Sugar().Debug(password) // exempt: sugared
    logger.Sugar().Debugf("claims: %s", password) // exempt: formatted
    logger.Sugar().Debugw("claims", "user", claims) // exempt: structured
    logger.Info("claims", zap.Any("user", claims)) // retain: info
    logger.Warn("claims", zap.Any("user", claims)) // retain: warn
    logger.Error("claims", zap.Any("user", claims)) // retain: error
    logger.DPanic("claims", zap.Any("user", claims)) // retain: dpanic
    logger.Sugar().Infow("claims", "user", claims) // retain: sugared-info
    logger.Sugar().Warnf("claims: %s", password) // retain: formatted-warn
    logger.With(zap.Any("user", claims)).Debug("claims") // retain: attached-field
    logger.WithOptions(zap.Fields(zap.Any("user", claims))).Debug("claims") // retain: attached-option
    log.Print(password) // retain: standard-logger
    diagnosticWriter{}.Debug(password)
    logger.Debug(request.URL.Query().Get("message")) // injection: debug-log-injection
}

func panicDiagnostic(logger *zap.Logger) {
    password := getPassword()
    logger.Panic("claims", zap.String("token", password)) // retain: panic
}

func fatalDiagnostic(logger *zap.Logger) {
    password := getPassword()
    logger.Fatal("claims", zap.String("token", password)) // retain: fatal
}
'''

ADJACENT_FIXTURE = '''package acl

import "go.uber.org/zap"

func adjacentDiagnostic(logger *zap.Logger) {
    password := getPassword()
    logger.Info("claims", zap.String("token", password)) // retain: adjacent-file
}
'''

# The exact ACL file accepts all levels. Neighboring files and a nested path
# with the same suffix retain the normal debug-only exception. The adjacent
# file receives its sensitive value from the exempt file to test sink scoping.
FIXTURES = {
    "main.go": FIXTURE,
    "pkg/acl/rule.go": FIXTURE.replace("package fixture", "package acl", 1)
                              .replace("// retain:", "// exempt:"),
    "pkg/acl/rule_extra.go": ADJACENT_FIXTURE,
    "nested/pkg/acl/rule.go": FIXTURE,
}


def run(command, cwd, env=None):
    subprocess.run(command, cwd=cwd, env=env, check=True, timeout=1200)


def results_by_rule(path):
    results = {}
    document = json.loads(path.read_text())
    for scan in document["runs"]:
        for result in scan.get("results", []):
            location = result["locations"][0]["physicalLocation"]
            point = (location["artifactLocation"]["uri"], location["region"]["startLine"])
            results.setdefault(result["ruleId"], set()).add(point)
    return results


def rule_ids(path):
    document = json.loads(path.read_text())
    return {rule["id"] for scan in document["runs"]
            for component in [scan["tool"]["driver"], *scan["tool"].get("extensions", [])]
            for rule in component.get("rules", [])}


def main():
    codeql = shutil.which(os.environ.get("CODEQL", "codeql"))
    if not codeql:
        raise SystemExit("CodeQL CLI is required; set CODEQL to its executable path.")
    codeql = str(Path(codeql).resolve())
    coverage = REPO / ".coverage" / "codeql"
    coverage.mkdir(parents=True, exist_ok=True)
    # Keep failed scans and their SARIF evidence for diagnosis.
    root = Path(tempfile.mkdtemp(prefix="exception-e2e-", dir=coverage))
    print(f"CodeQL exception E2E fixture: {root}", flush=True)
    for name in ("assets/scripts/run_codeql_scan.sh", ".github/codeql/codeql-config.yml"):
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / name, destination)
    shutil.copytree(REPO / ".github/codeql/queries", root / ".github/codeql/queries",
                    ignore=shutil.ignore_patterns("*.qlx", "*.bqrs", ".cache"))
    for name, source in FIXTURES.items():
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(source)
    # Use the same Zap dependency as the library, without changing its manifests.
    module = (REPO / "go.mod").read_text()
    zap_version = re.search(r"go\.uber\.org/zap (v\S+)", module).group(1)
    go_version = re.search(r"(?m)^go (\S+)", module).group(1)
    (root / "go.mod").write_text(
        f"module example.com/authcrunch-codeql-fixture\n\ngo {go_version}\n\n"
        f"require go.uber.org/zap {zap_version}\n")
    run(["go", "mod", "tidy"], root)
    run(["gofmt", "-w", *FIXTURES], root)
    expected = {
        kind: {(name, line) for name in FIXTURES
               for line, text in enumerate((root / name).read_text().splitlines(), 1)
               if f"// {kind}:" in text}
        for kind in ("exempt", "retain", "injection")
    }
    output = root / ".coverage" / "scan"
    env = {**os.environ, "CODEQL": codeql, "CODEQL_OUTPUT_DIR": str(output)}
    run(["bash", "assets/scripts/run_codeql_scan.sh"], root, env)
    filtered = results_by_rule(output / "results.sarif")
    if filtered.get(RULE, set()) != expected["retain"]:
        raise AssertionError(f"Expected reportable locations {sorted(expected['retain'])}; "
                             f"received {sorted(filtered.get(RULE, set()))}")
    # Compare the complete unmodified default suite on the same database.
    run([codeql, "database", "analyze", str(output / "database"),
         "codeql/go-queries",
         "--threads=2", "--ram=5922", "--format=sarif-latest",
         f"--output={output / 'upstream.sarif'}"], root)
    baseline = results_by_rule(output / "upstream.sarif")
    if baseline.get(RULE, set()) != expected["retain"] | expected["exempt"]:
        raise AssertionError(f"Upstream query did not cover the fixture: {baseline}")
    if rule_ids(output / "results.sarif") != rule_ids(output / "upstream.sarif"):
        raise AssertionError("Configured scan must retain every default rule ID")
    if ({key: value for key, value in filtered.items() if key != RULE} !=
            {key: value for key, value in baseline.items() if key != RULE}):
        raise AssertionError("The exception changed results from another default query")

    # Log injection belongs to the extended suite. Select it explicitly alongside
    # the replacement to verify debug and ACL-file sinks stay intact when enabled.
    run([codeql, "database", "analyze", str(output / "database"),
         str(root / ".github/codeql/queries/CleartextLoggingWithDebugDiagnostics.ql"),
         "codeql/go-queries:Security/CWE-117/LogInjection.ql",
         "--threads=2", "--ram=5922", "--format=sarif-latest",
         f"--output={output / 'log-injection.sarif'}"], root)
    extra = results_by_rule(output / "log-injection.sarif")
    if not expected["injection"] <= extra.get("go/log-injection", set()):
        raise AssertionError("Debug and ACL logging must remain subject to log injection")
    print(f"PASS: {len(expected['exempt'])} debug/ACL cases excepted; "
          f"{len(expected['retain'])} other logging cases, all default rules and "
          "explicitly selected debug/ACL log injection retained.")


if __name__ == "__main__":
    main()
