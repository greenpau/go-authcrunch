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

    "github.com/greenpau/go-authcrunch/pkg/user"
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
    logger.Info("claims", zap.Any("payload", claims)) // retain: info
    logger.Warn("claims", zap.Any("payload", claims)) // retain: warn
    logger.Error("claims", zap.Any("payload", claims)) // retain: error
    logger.DPanic("claims", zap.Any("payload", claims)) // retain: dpanic
    logger.Sugar().Infow("claims", "user", claims) // retain: sugared-info
    logger.Sugar().Warnf("claims: %s", password) // retain: formatted-warn
    logger.With(zap.Any("payload", claims)).Debug("claims") // retain: attached-field
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

type realmRequest struct {
    Realm string
    Password string
}

type realmFieldFactory struct{}
func (realmFieldFactory) String(key, value string) zap.Field {
    return zap.String(key, value)
}

func realmDiagnostics(logger *zap.Logger, request *http.Request) {
    // Synthetic taint proves the exception is a sink policy, not an absence
    // of upstream data flow. Production Realm fields hold routing metadata.
    r := &realmRequest{Realm: request.Header.Get("Authorization"), Password: getPassword()}
    logger.Info("realm", zap.String("realm", r.Realm)) // exempt: realm-info
    logger.Warn("realm", zap.String("realm", r.Realm)) // exempt: realm-warn
    logger.Error("realm", zap.String("auth_realm", r.Realm)) // exempt: auth-realm-error
    logger.DPanic("realm", zap.String("realm", r.Realm)) // exempt: realm-dpanic
    logger.With(zap.String("realm", r.Realm)).Info("realm") // exempt: realm-attached-field
    logger.Error("realm and credentials",
        zap.String("realm", r.Realm), // exempt: mixed-realm
        zap.String("password", r.Password), // retain: mixed-password
    )
    logger.Warn("credential", zap.String("realm", r.Password)) // retain: mislabeled-password
    logger.Warn("claims", zap.Any("realm", r)) // retain: realm-object
    logger.Warn("combined", zap.String("realm", r.Realm + r.Password)) // retain: realm-expression
    logger.Warn("realm", zap.String("token", r.Realm)) // retain: other-field-same-value
    logger.Warn("realm", zap.String(request.URL.Query().Get("key"), r.Realm)) // retain: dynamic-realm-key
    logger.Warn("realm", realmFieldFactory{}.String("realm", r.Realm)) // retain: unrelated-string-method
    logger.Sugar().Warnw("realm", "realm", r.Realm) // retain: sugared-realm
    log.Print(r.Realm) // retain: standard-realm
    log.Print(zap.String("realm", r.Realm)) // retain: standard-zap-field
}

func panicRealmDiagnostic(logger *zap.Logger, request *http.Request) {
    r := &realmRequest{Realm: request.Header.Get("Authorization")}
    logger.Panic("realm", zap.String("realm", r.Realm)) // exempt: realm-panic
}

func fatalRealmDiagnostic(logger *zap.Logger, request *http.Request) {
    r := &realmRequest{Realm: request.Header.Get("Authorization")}
    logger.Fatal("realm", zap.String("realm", r.Realm)) // exempt: realm-fatal
}

func realmLogInjection(logger *zap.Logger, request *http.Request) {
    r := &realmRequest{Realm: request.URL.Query().Get("realm")}
    logger.Warn("realm", zap.String("realm", r.Realm)) // injection: realm-log-injection
}

// Keep the synthetic error tainted so the upstream query must report it.
type diagnosticError struct { message string }
func (e *diagnosticError) Error() string { return e.message }

type errorFieldFactory struct{}
func (errorFieldFactory) Any(key string, value interface{}) zap.Field {
    return zap.Any(key, value)
}

func errorDiagnostics(logger *zap.Logger, request *http.Request) {
    concrete := &diagnosticError{message: getPassword()}
    var err error = concrete
    logger.Info("failure", zap.Any("error", err)) // exempt: error-info
    logger.Warn("failure", zap.Any("error", concrete)) // exempt: concrete-error-warn
    logger.Error("failure", zap.Error(err)) // exempt: idiomatic-error
    logger.DPanic("failure", zap.NamedError("error", err)) // exempt: named-error-dpanic
    logger.With(zap.Any("error", err)).Info("failure") // exempt: attached-error
    logger.Warn("failure and credentials",
        zap.Any("error", err), // exempt: mixed-error
        zap.String("password", getPassword()), // retain: error-neighbor-password
    )
    logger.Warn("credential", zap.Any("error", getPassword())) // retain: mislabeled-error-string
    logger.Warn("claims", zap.Any("error", map[string]string{"password": getPassword()})) // retain: mislabeled-error-map
    logger.Warn("credential", zap.String("error", getPassword())) // retain: error-string-field
    logger.Warn("failure", zap.Any("detail", err)) // retain: other-error-key
    logger.Warn("failure", zap.NamedError("detail", err)) // retain: other-named-error-key
    logger.Warn("failure", zap.Any(request.URL.Query().Get("key"), err)) // retain: dynamic-error-key
    logger.Warn("failure", errorFieldFactory{}.Any("error", err)) // retain: unrelated-any-method
    logger.Sugar().Warnw("failure", "error", err) // retain: sugared-error
    logger.WithOptions(zap.Fields(zap.Any("error", err))).Info("failure") // retain: error-attached-option
    var opaque interface{} = err
    logger.Warn("failure", zap.Any("error", opaque)) // retain: untyped-error-value
    log.Print(err) // retain: standard-error
    log.Print(zap.Any("error", err)) // retain: standard-zap-error-field
}

func panicErrorDiagnostic(logger *zap.Logger) {
    var err error = &diagnosticError{message: getPassword()}
    logger.Panic("failure", zap.Any("error", err)) // exempt: error-panic
}

func fatalErrorDiagnostic(logger *zap.Logger) {
    var err error = &diagnosticError{message: getPassword()}
    logger.Fatal("failure", zap.Error(err)) // exempt: error-fatal
}

// A string-based error preserves the upstream log-injection flow through the
// error value; unlike cleartext logging, that query does not taint whole structs.
type diagnosticMessage string
func (e diagnosticMessage) Error() string { return string(e) }

func errorLogInjection(logger *zap.Logger, request *http.Request) {
    var err error = diagnosticMessage(request.URL.Query().Get("message"))
    logger.Warn("failure", zap.Any("error", err)) // injection: error-log-injection
}

func userDiagnostics(logger *zap.Logger, request *http.Request) {
    payload := map[string]interface{}{"password": getPassword()}
    logger.Info("user", zap.Any("user", payload)) // exempt: user-info
    logger.Warn("user", zap.Any("user", payload)) // exempt: user-warn
    logger.Error("user", zap.Any("user", payload)) // exempt: user-error
    logger.DPanic("user", zap.Any("user", payload)) // exempt: user-dpanic
    logger.With(zap.Any("user", payload)).Info("user") // exempt: user-attached-field
    logger.Warn("user and credentials",
        zap.String("realm", (&realmRequest{Realm: request.Header.Get("Authorization")}).Realm), // exempt: user-neighbor-realm
        zap.Any("error", &diagnosticError{message: getPassword()}), // exempt: user-neighbor-error
        zap.Any("user", payload), // exempt: mixed-user
        zap.String("password", getPassword()), // retain: user-neighbor-password
    )
    logger.Warn("user", zap.Any("user", &realmRequest{Password: getPassword()})) // exempt: user-object
    logger.Warn("claims", zap.Any("payload", payload)) // retain: other-user-key
    logger.Warn("user", zap.Any(request.URL.Query().Get("key"), payload)) // retain: dynamic-user-key
    logger.Warn("user", errorFieldFactory{}.Any("user", payload)) // retain: unrelated-user-method
    logger.Warn("credential", zap.String("user", getPassword())) // retain: user-string-field
    logger.Sugar().Warnw("user", "user", payload) // retain: sugared-user
    log.Print(zap.Any("user", payload)) // retain: standard-zap-user-field
}

func panicUserDiagnostic(logger *zap.Logger) {
    logger.Panic("user", zap.Any("user", map[string]string{"password": getPassword()})) // exempt: user-panic
}

func fatalUserDiagnostic(logger *zap.Logger) {
    logger.Fatal("user", zap.Any("user", map[string]string{"password": getPassword()})) // exempt: user-fatal
}

func userLogInjection(logger *zap.Logger, request *http.Request) {
    logger.Warn("user", zap.Any("user", request.URL.Query().Get("user"))) // injection: user-log-injection
}

// The canonical qualified Claims type matters, not a matching field/type name.
type Claims struct { ID string }
type unrelatedClaimsUser struct { Claims *Claims }

func claimsDiagnostics(logger *zap.Logger, request *http.Request) {
    claims := &user.Claims{
        ID: request.Header.Get("Authorization"),
        Email: getPassword(),
        Roles: []string{getPassword()},
        Metadata: map[string]interface{}{"nested": map[string]interface{}{"value": getPassword()}},
        AccessList: &user.AccessListClaim{Paths: map[string]interface{}{"path": getPassword()}},
    }
    usr := &user.User{Claims: claims}
    logger.Info("claims", zap.Any("claims", map[string]interface{}{"password": getPassword()})) // exempt: claims-map
    logger.Info("claims", zap.Any("details", usr.Claims)) // exempt: typed-claims
    logger.Warn("jti session not found", zap.String("jti", usr.Claims.ID)) // exempt: profile-jti
    logger.Error("claims", zap.String("email", claims.Email)) // exempt: claims-error
    logger.DPanic("claims", zap.Strings("roles", claims.Roles)) // exempt: claims-dpanic
    logger.With(zap.String("jti", claims.ID)).Warn("claims") // exempt: claims-attached-field
    logger.With(zap.Any("claims", map[string]interface{}{"password": getPassword()})).Info("claims") // exempt: claims-map-attached
    logger.Warn("claims", zap.String("role", claims.Roles[0])) // exempt: claims-slice-element
    logger.Warn("claims", zap.Strings("roles", claims.Roles[:1])) // exempt: claims-slice
    logger.Warn("claims", zap.Stringp("jti", &claims.ID)) // exempt: claims-field-address
    logger.Warn("claims", zap.String("metadata", claims.Metadata["nested"].(map[string]interface{})["value"].(string))) // exempt: claims-nested-map
    logger.Warn("claims", zap.Any("path", claims.AccessList.Paths["path"])) // exempt: claims-nested-struct
    logger.Warn("claims", zap.Reflect("details", *claims)) // exempt: claims-dereference
    logger.Warn("claims and credentials",
        zap.String("jti", usr.Claims.ID), // exempt: claims-mixed-jti
        zap.String("password", getPassword()), // retain: claims-neighbor-password
    )
    logger.Warn("credential", zap.String("jti", getPassword())) // retain: mislabeled-jti
    logger.Warn("credential", zap.String("claims", getPassword())) // retain: mislabeled-claims-string
    logger.Warn("claims", zap.String("jti", (&unrelatedClaimsUser{Claims: &Claims{ID: getPassword()}}).Claims.ID)) // retain: unrelated-claims-type
    logger.Warn("combined", zap.String("value", claims.ID + getPassword())) // retain: mixed-claims-expression
    logger.Warn("claims", zap.String(request.URL.Query().Get("key"), claims.ID)) // retain: dynamic-claim-key
    logger.Warn("claims", realmFieldFactory{}.String("jti", claims.ID)) // retain: unrelated-claims-constructor
    logger.WithOptions(zap.Fields(zap.String("jti", claims.ID))).Warn("claims") // retain: claims-attached-option
    logger.Sugar().Warnw("claims", "jti", claims.ID) // retain: sugared-claims
    log.Print(zap.String("jti", claims.ID)) // retain: standard-claims-field
    log.Print(claims.ID) // retain: standard-claims-value
}

func panicClaimsDiagnostic(logger *zap.Logger) {
    claims := &user.Claims{ID: getPassword()}
    logger.Panic("claims", zap.String("jti", claims.ID)) // exempt: claims-panic
}

func fatalClaimsDiagnostic(logger *zap.Logger) {
    logger.Fatal("claims", zap.Any("claims", map[string]string{"password": getPassword()})) // exempt: claims-fatal
}

func claimsLogInjection(logger *zap.Logger, request *http.Request) {
    claims := &user.Claims{ID: request.URL.Query().Get("jti")}
    logger.Warn("claims", zap.String("jti", claims.ID)) // injection: claims-field-log-injection
    logger.Warn("claims", zap.Any("claims", request.URL.Query().Get("claims"))) // injection: claims-map-log-injection
}
'''

# Minimal fixture-owned models reproduce the real qualified type and nested
# reads without pulling the entire application into the scanner fixture.
USER_FIXTURE = '''package user

type User struct { Claims *Claims }
type Claims struct {
    ID string
    Email string
    Roles []string
    Metadata map[string]interface{}
    AccessList *AccessListClaim
}
type AccessListClaim struct { Paths map[string]interface{} }
'''

ADJACENT_FIXTURE = '''package acl

import "go.uber.org/zap"

func adjacentDiagnostic(logger *zap.Logger) {
    password := getPassword()
    logger.Info("claims", zap.String("token", password)) // retain: adjacent-file
}
'''

# The exact ACL file accepts all levels. Neighboring files and a nested path
# with the same suffix retain only the ordinary diagnostic exceptions. The adjacent
# file receives its sensitive value from the exempt file to test sink scoping.
FIXTURES = {
    "main.go": FIXTURE,
    "pkg/user/claims.go": USER_FIXTURE,
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
        f"module github.com/greenpau/go-authcrunch\n\ngo {go_version}\n\n"
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
    # the replacement to verify debug, structured and ACL-file sinks stay intact.
    run([codeql, "database", "analyze", str(output / "database"),
         str(root / ".github/codeql/queries/CleartextLoggingWithDebugDiagnostics.ql"),
         "codeql/go-queries:Security/CWE-117/LogInjection.ql",
         "--threads=2", "--ram=5922", "--format=sarif-latest",
         f"--output={output / 'log-injection.sarif'}"], root)
    extra = results_by_rule(output / "log-injection.sarif")
    if not expected["injection"] <= extra.get("go/log-injection", set()):
        raise AssertionError("Debug, structured and ACL logging must remain subject to log injection")
    print(f"PASS: {len(expected['exempt'])} debug/realm/error/user/claims/ACL cases excepted; "
          f"{len(expected['retain'])} other logging cases, all default rules and "
          "explicitly selected debug/realm/error/user/claims/ACL log injection retained.")


if __name__ == "__main__":
    main()
