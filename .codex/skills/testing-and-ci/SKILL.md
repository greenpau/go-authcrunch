---
name: testing-and-ci
description: Require corresponding tests for every Go code change, E2E coverage whenever developing tests, and immediate diagnostic remediation while agents edit code; select, run, and maintain AuthCrunch tests through pinned tested, browser tests, automation fixtures, coverage artifacts, and CI gates.
---

# Testing and CI

## Corresponding Tests

Every Go code change must have corresponding automated tests. Identify the
tests that exercise each changed behavior or contract before marking the work
complete. This applies to library code, CLI code, internal helpers, configuration,
serialization, and refactors; a small change is not a reason to omit coverage.

Add or update tests in the same change when adding or changing behavior. Cover
the intended result and meaningful error or boundary cases. Bug fixes require a
regression test that demonstrates the defect and passes with the fix. For package
extraction or rewiring, cover both the reusable API and the caller integration.

For changes that preserve behavior, identify and run existing tests that directly
exercise the affected contract, adding coverage wherever it is missing. Do not
add redundant tests solely to produce a test-file diff. For test-helper or
test-only changes, run the tests that use the changed code.

Assertions must verify observable behavior or invariants rather than mirror the
implementation. A successful build, lint check, unrelated test run, or aggregate
coverage percentage does not establish corresponding test coverage. Run the
relevant tests through the lifecycle below and report the commands and results.
If execution is blocked, report the exact blocker and the tests left unverified;
do not claim validation passed.

## Required End-to-End Coverage

Whenever developing tests, also add or extend E2E tests for the affected
behavior in the same change. This includes test-only work, regression tests,
and changes to test helpers. Run the E2E cases before marking the work complete;
unit tests, handler recorders, and coverage percentages alone do not satisfy
this requirement.

Exercise the supported consumer entry point through the real production
components to an observable result. For portal HTTP features, use a local TLS
listener, a temporary identity database, real login and authorization, and a
client that cannot access portal internals. For CLI behavior, run the built
executable. For library or automation behavior, exercise the owning public
workflow with real temporary files or local processes as appropriate.

Cover the main successful journey and relevant rejection or persistence
boundaries. Extend an existing E2E scenario when it can verify the new behavior;
do not relabel an isolated mock or add an unrelated smoke test. Use independent
consumer assertions where possible, such as signature verification from fetched
keys or reopening an exported file in a fresh runtime.

Keep local E2E tests in the default suite, named `TestE2E...` in Go, without
opt-in build tags or live-service credentials. Bound network calls, close
listeners and response bodies, release runtime workers, isolate filesystem
state, and keep secrets out of failures and reports. If a required E2E run is
blocked, report the exact blocker and leave that validation explicitly
incomplete rather than silently substituting unit coverage.

## Test Lifecycle

The root Go module declares Go `1.26.0`. Repository coverage uses the pinned
`github.com/greenpau/tested` tool in `go.mod`, invoked through `go tool tested`.
It owns `-json`, `-coverprofile`, child-process status, and coherent reports.
Do not reintroduce `go test | tee`, log-grep success detection, richgo, tparse,
or go-test-report into the lifecycle.

```sh
make test
make test TEST_DIR='./pkg/authn/...' TEST='TestPortalRefresh'
make test TEST_DIR='./pkg/authn' TEST='^TestE2EPortalJWKS' COVERAGE_DIR='.coverage/jwks-e2e'
make qtest QUICK_TEST_DIR='./pkg/authn/refresh'
make test-ui
make test-automation
make ci-check
```

Go lifecycle runs use `-mod=readonly -race -count=1 -v`. `TEST` is a test regex
(default `.`); `TEST_DIR` accepts package patterns (default `./...`). Reports
land in `.coverage`, or `.coverage/quick` for `qtest`. Use `COVERAGE_DIR` to
separate independent concurrent runs. `MINIMUM_COVERAGE` defaults to 1 percent
as a nonzero-profile check, matching the reference tested workflow; it is not a
claim of a substantial coverage target. Raise it only with an intentional
coverage policy and measured baseline.

Direct `go test` is appropriate for a narrow debugging iteration, compile-only
check, or fuzzing; it is not the report lifecycle. Browser tests use Node's spec
reporter, and automation uses verbose Python unittest discovery. Both use only
standard-library facilities. Loopback `httptest` listeners are expected.

## Diagnostics in Agent Changes

Diagnostic remediation is part of editing code. After each coherent edit,
inspect the affected code's compiler, editor/language-server, lint, and static
analysis findings using the applicable tools. Fix confirmed problems in the
same iteration, before moving to unrelated work or presenting the change as
complete. Do not wait for the user to notice them or defer them to final testing.
This applies across diagnostic types, including correctness, resource handling,
deprecated APIs, unused code, inefficiency, and style.

Establish ownership before editing: inspect the initial staged, unstaged, and
untracked changes, and track the code the agent creates or edits during the
task, including earlier turns. A Git diff helps locate changes but does not
prove the agent authored them. Check every agent-created or edited code file,
including tests and new untracked files. Inspect each finding against the
agent's actual changes. Fix a problem in a statement the agent is rewriting
even if it existed before that edit. Leave unrelated existing or user-authored
code alone; editing one line does not authorize cleanup of the entire file,
package, or repository.

Inspect the full diagnostic output for affected code, not just one named
warning or a matching text pattern. Review errors, warnings, and actionable
informational/hint diagnostics; severity alone is not a reason to ignore a
confirmed problem. For Go, use available editor diagnostics or run gopls from
the module root with an explicit list of affected files, for example:

```sh
gopls version
gopls check -severity=hint pkg/example/changed.go pkg/example/changed_test.go
```

Use an installed, compatible version and check `gopls help check` for supported
flags. Inspect the diagnostic output, not only the exit status: `gopls check`
can exit zero while reporting problems. If editor and CLI results differ,
verify the analyzer version/settings before declaring a reported issue absent.
For other languages, use their applicable repository-supported diagnostics.
Passing tests or one analysis tool does not clear findings from another;
the current `make ci-check` does not run gopls. Do not silently substitute a
regex search or a linter that lacks the relevant analysis. If a required check
cannot run, report the blocker and leave that validation explicitly incomplete.

Fix the cause within the agent's code and the minimal supporting changes it
requires, preserving behavior unless the task calls for a behavior change.
Evaluate optional refactoring suggestions for applicability rather than
applying every suggestion blindly. Explain false positives or concrete
compatibility reasons for retaining flagged code. Do not suppress diagnostics,
lower the reporting severity, or disable checks to obtain a clean result.
Avoid repository-wide autofixes or toolchain, dependency, and editor-setting
changes just to remove diagnostics.

After a fix, format the edited code and rerun the affected diagnostics until
confirmed in-scope problems are resolved. Run the corresponding tests and
required E2E coverage under the rules above. At completion, record the
tool/version, checked files, results, and any unresolved findings with ownership
and reason; distinguish unrelated findings from blocked in-scope work. A clear
result for agent changes is not a claim that the whole repository has no
diagnostics.

## Evidence and Reports

`make test` returns tested's failure status for test, build, and coverage-policy
failures. An offline `make run-reports` preserves recorded failure status.
Inspect `run.json`, `stderr.log`, and `test_output.jsonl` before rerunning a
failed command; do not replace failed evidence with a passing summary.

A coherent full coverage run produces:

```text
.coverage/index.html
.coverage/test_output.html
.coverage/coverage.html
.coverage/coverage.out
.coverage/summary.json
.coverage/junit.xml
.coverage/test_output.jsonl
.coverage/stderr.log
.coverage/run.json
.coverage/manifest.json
```

The manifest is published last for a coherent generation; build/coverage failures
can leave partial evidence without every report. Upload that evidence too.
Raw test output and coverage source are unredacted: use synthetic fixtures and
never print real credentials. Ignore all report artifacts in Git.

Tests and builds do not run license rewrites, version synchronization, or
module tidy. `make ci-check` serializes version checks, automation fixtures,
existing golint, full Go coverage, browser tests, and the CLI build. Use
`scripts-and-automation` for maintenance side effects and
`release-and-versioning` for release/tag operations.

Refresh changes use `refresh-token-implementation`, `refresh-token-identity`,
and `refresh-token-transports` according to their affected boundaries.

## Test Helpers

Prefer existing test helpers before adding new ones:

- `internal/tests` provides `Unpack`, `UnpackDict`, `UnpackJSON`,
  `EvalErr`, `EvalErrWithLog`, `EvalErrPhaseWithLog`, `EvalObjects`,
  `EvalObjectsWithLog`, `CustomEvalObjectsWithLog`, `TempDir`, random strings,
  and reusable identity constants.
- `internal/testutils` provides test identity databases, authz users, ACLs,
  crypto key stores, injected tokens, and token validator options.
- Many config tests normalize structs and JSON strings through `tests.Unpack`
  or `tests.UnpackDict` before comparing with `cmp.Diff`.
- Error-path tests usually use `shouldErr`, an expected `err`, and exact error
  string comparison. Keep expected errors specific when behavior is stable.
- When adding environment-variable tests, prefer `t.Setenv`; when touching
  existing `os.Setenv` tests, make sure values are restored or isolated.

Use `t.TempDir()` for new isolated temporary filesystem tests unless the code
under test already follows `tests.TempDir`, which writes below
`/tmp/testdata/go-authcrunch/<test-name>/`.

## Test Surfaces

Top-level `config_test.go` and `server_test.go` exercise composed AuthCrunch
config and server construction across credentials, messaging, identity stores,
identity providers, authentication portals, authorization policies, OAuth keys,
and validation phases. Use these when a change affects cross-package wiring.

Authentication tests live under `pkg/authn`, including HTTP login/logout,
external logout, response handling, cache sandbox behavior, cookie settings,
transformers, icons, and embedded UI pages/static assets. Use `httptest` and
`internal/testutils` helpers for request/response and token-driven behavior.

Reusable login-client tests live under `pkg/authclient`, including E2E tests
against a real local TLS portal and identity store in the default test suite;
CLI tests live under `cmd/authdbctl`, including executable E2E against a real
portal and local database plus Python-backed pseudo-terminal tests. Use
`authentication-client` for reusable protocol/credential coverage and its 100%
gate; use `authdbctl` for command coverage, terminal fixtures, and CLI E2E
validation. The CLI subprocess is separate from the parent coverage profile.

Authorization tests live under `pkg/authz`, including gatekeeper behavior,
authentication requests, redirect handlers, cache behavior, options, and token
validator sources. `pkg/authz/validator` and related tests use `httptest`,
test crypto key stores, test users, ACL helpers, and exact source/match
expectations.

Identity and store tests live under `pkg/identity`, `pkg/ids`,
`pkg/ids/local`, `pkg/ids/ldap`, and `pkg/registry`. They rely on temporary
identity databases, registration/user JSON fixtures, domain restriction cases,
LDAP DN/config parsing, and table-driven success/error cases.
Use [local-password-authentication](../local-password-authentication/SKILL.md)
for the password-verifier regression matrix and controlled timing validation.

Identity provider and SSO tests live under `pkg/idp`, `pkg/idp/oauth`,
`pkg/idp/saml`, and `pkg/sso`. OAuth tests cover request parsing, state,
provider setup, JWKS, GitHub email lookup, and provider HTTP interactions.
Use [oauth-identity-provider](../oauth-identity-provider/SKILL.md) for upstream
JWT/JWKS, static key provisioning, rotation, and real portal OAuth E2E coverage.
SAML/SSO tests use metadata, certificate, and key fixtures from
`testdata/saml` and `testdata/sso`.

KMS and credential tests live under `pkg/kms` and `pkg/credentials`. They use
RSA, ECDSA, GPG, OAuth, malformed PEM, missing-key, and mixed-key fixtures
under `testdata`. Preserve package-relative paths such as
`../../testdata/rskeys/test_2_pri.pem` when adding cases.
Use [authentication-portal-jwks](../authentication-portal-jwks/SKILL.md) for
public signing-key export, admin private-key export authorization, and portal
endpoint tests that independently verify issued JWT signatures.

Embedded UI tests live under `pkg/authn/ui`. `static_test.go` asserts the
static asset count, sorted paths, and content types; `pages_test.go` and
`ui_test.go` exercise built-in templates, page rendering, and filesystem
template parity. Update these tests deliberately when embedded assets or
templates change.

Utilities and policy primitives have focused table-driven tests under
`pkg/acl`, `pkg/apiauth`, `pkg/authchal`, `pkg/messaging`, `pkg/redirects`,
`pkg/tagging`, `pkg/translate`, `pkg/user`, `pkg/util`, and `pkg/waf`. Add new
cases in the nearest package-level test before creating a broader integration
test.

## Adding Coverage

Register new exported structs in `internal/tag/tag_test.go`'s
`TestTagCompliance` table. `TestStructTagCompliance` scans source files for
missing entries. Keep JSON/XML/YAML tags consistent; mark runtime-only fields
with `-` and scope exceptions for intentionally preserved serialized fields.

When changing config parsing or validation, add table-driven cases in the
nearest `*_test.go` file. Include the successful normalized config shape and a
malformed input when the parser has a meaningful error path.

When changing cross-package config or server wiring, add or update top-level
`config_test.go` or `server_test.go` so the full AuthCrunch object graph is
covered.

When changing authn/authz HTTP behavior, use `httptest.NewRecorder`,
`httptest.NewRequest`, or `httptest.NewTLSServer` instead of live services.
Use `internal/testutils` token, user, ACL, and crypto helpers.

When changing identity database behavior, prefer the existing temp database
helpers and assert both success state and failure messages. Do not commit temp
files from `/tmp/testdata/go-authcrunch`.

When changing embedded UI assets, templates, or page mappings, update expected
asset counts, paths, content types, and rendering expectations in
`pkg/authn/ui` tests. If assets were regenerated, review source diffs
separately from test/report artifacts.

Run the focused package test first, then a broader command:

```bash
go test ./pkg/<package> -run <TestName>
go test ./...
```

Use `make test` for the repository coverage lifecycle after a narrow diagnostic
iteration. Use `make test-ui` for embedded refresh-client JavaScript.

## CI Workflow

`.github/workflows/test.yml` runs on pushes/PRs to main, manual dispatch, and
reusable workflow calls. It selects Ubuntu 24.04, Go 1.26.0, Node 24, Python 3,
and the existing NSS test utilities. It resolves versioned artifact identity,
runs `make dep` and `make ci-check`, checks that tracked source did not change,
and always uploads `.coverage/` after the gate was attempted, including hidden
files. Missing artifacts fail the upload; test failures remain failures.

The complete local reproduction is `make dep` followed by `make ci-check`.
The workflow uses read-only contents permission and immutable action pins.
The release workflow calls the same gate before GoReleaser; the exact version
and tag contract belongs to `release-and-versioning`. CLA automation remains
separate.

Automation changes run `make test-automation`. Its version tests exercise
namespace rejection, synchronization drift, and exact artifact tag binding;
release tests use isolated fixture repositories and local bare remotes to
verify patch/minor bumps, failure gates, exact tags, and atomic push behavior.
Never test publishing against this checkout's remote. When changing tested
or its invocation, also exercise an intentional Go test failure and build
failure in an isolated fixture and verify a nonzero status with fresh evidence.

Skill changes use `skill-authoring-patterns` and the default skill-creator quick
validator. Inspect routing, exact code names, and links as well as frontmatter.
Do not treat prose-matching tests as behavioral validation.
