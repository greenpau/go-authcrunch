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

For external consumers, exercise the reusable library API from
E2E fixtures in this module. Never create, change, or run tests in sibling
project checkouts to validate work here. Consumer test fixes and integration
updates are separate work, even when this library changes their expected output.
Follow the
[repository scope](../coding-directives/SKILL.md#repository-scope) when selecting
validation commands.

For every new or changed configuration surface, verify its dedicated public
`parser` package under the
[configuration parser contract](../coding-directives/references/configuration-parsers.md).
This applies to small settings and existing parsers as well as extractions.
Keep unit tests in `package parser_test` and exercise each public constructor in
an executable Go example. Have consumer E2E fixtures import that parser directly
and pass its typed result to the production configuration API. Verify the
configured behavior through the real consumer workflow; a build-only import
check or a fixture which bypasses parsing with a manually built config is
insufficient coverage for a parser change.

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
make qtest QUICK_TEST_DIR='./pkg/authn/token_refresh/...'
make test-ui
make test-automation
make ci-check
```

Go lifecycle runs use `-mod=readonly -race -count=1 -timeout 20m -v`.
`TEST_TIMEOUT` overrides the per-package limit through the quoted Go flag.
The expanded real-login suite exceeds Go's implicit ten-minute limit under race
instrumentation; the explicit limit remains below the CI job's thirty-minute
bound. Keep individual network/browser timeouts and diagnose timed-out stacks
before changing the package limit. Never disable deadlines or skip E2E to clear
a timeout. `TEST` is a test regex
(default `.`); `TEST_DIR` accepts package patterns (default `./...`). Reports
land in `.coverage`, or `.coverage/quick` for `qtest`. Use `COVERAGE_DIR` to
separate independent concurrent runs. `MINIMUM_COVERAGE` defaults to 1 percent
as a nonzero-profile check, matching the reference tested workflow; it is not a
claim of a substantial coverage target. Raise it only with an intentional
coverage policy and measured baseline.

Direct `go test` is appropriate for a narrow debugging iteration, compile-only
check, or fuzzing; it is not the report lifecycle. `make test-ui` discovers
`pkg/authn/ui/testdata/*_client_test.cjs` and runs Node's spec reporter for login/QR
and refresh-client simulations. Automation uses verbose Python unittest
discovery. Both use standard-library facilities. The default Go suite also runs
`TestE2ERefreshBrowserBootstrap` with Node 24 and headless Chrome, using a temporary
profile and actual TLS portal. Supply `AUTHCRUNCH_TEST_BROWSER` when the executable
is not discoverable. Missing browsers are a validation failure; the Node VM
suite does not substitute for this E2E. The default suite also runs
`TestE2EOIDCThemedBrowser` with the same browser discovery and startup helpers.
Use `refresh-token-transports` for the refresh fixture and the
[OIDC browser-page owner](../authentication-portal-oidc/references/browser-pages.md#validation)
for consent/continuation assertions, browser isolation, and screenshot capture.
Loopback `httptest` listeners are expected.

### Browser Engine

Use headless Google Chrome (`--headless=new`) for repository browser tests,
theme previews, and screenshot validation. Do not use Firefox or switch to it
when a Chrome check fails. Set `AUTHCRUNCH_TEST_BROWSER` to the Chrome executable
when discovery is unavailable; report a missing Chrome installation as a
validation blocker. Keep the existing isolated profiles, fixture certificate
trust, bounded execution, and process cleanup. Node DOM simulations complement
the real Chrome E2E tests and do not replace them.

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

Do not assume that a separate analyzer honors a compiler `-overlay`. Verify
that its locations and source match the candidate being checked. If an overlay
experiment leaves stale Staticcheck results, preserve the output and rerun the
applied source with a fresh absolute `STATICCHECK_CACHE` path inside `.coverage`.
Keep all checks enabled; this isolates cached analysis rather than suppressing
findings. Do not clear unrelated global caches to obtain a clean result.

Fix the cause within the agent's code and the minimal supporting changes it
requires, preserving behavior unless the task calls for a behavior change.
Evaluate optional refactoring suggestions for applicability rather than
applying every suggestion blindly. Explain false positives or concrete
compatibility reasons for retaining flagged code. Do not suppress diagnostics,
lower the reporting severity, or disable checks to obtain a clean result.
Avoid repository-wide autofixes or toolchain, dependency, and editor-setting
changes just to remove diagnostics.

The explicit [diagnostic logging exceptions](../threat-hunting/references/debug-logging.md)
define accepted behavior with specific rule and sink boundaries. Changes
to their CodeQL implementation require `make test-codeql`, which exercises the
real scanner and checks both excepted and retained findings. Follow the
[CodeQL workflow](../scripts-and-automation/references/codeql.md) for activation
and evidence; passing local scans do not prove GitHub accepted an upload.

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
existing golint, full Go coverage, browser tests, and both executable builds. Use
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

For repeated portal fixture provisioning, use `tests.TestPwd1Hash(t)` and
`tests.TestPwd2Hash(t)` as password imports, and send `tests.TestPwd1` and
`tests.TestPwd2` as plaintext during login. These helpers lazily hash each
synthetic password once per process at `bcrypt.DefaultCost`; database records
and authentication checks remain independent. Avoid repeating password
generation in each TLS fixture: race instrumentation made that setup dominate
the authentication package's CI budget. Keep plaintext creation and mutation
in tests that exercise those operations, and retain real bcrypt comparisons,
the production cost, and all request/package deadlines. Helper regressions
live in `internal/tests/password_test.go`; the real TLS isolation journey is
`pkg/authn/password_fixture_e2e_test.go`.

## Test Placement and Filenames

Choose test directories and filenames by the production surface and behavior
being verified. Parser unit tests belong in the public parser package's external
test package. Tests of root `authcrunch.Config` assembly or `NewServer` wiring
belong at the module root, including when they use a parser to prepare inputs.
Portal HTTP and browser E2E tests belong with the portal's test suite.

Use existing `config_test.go` or `server_test.go` when appropriate. When adding
or renaming a focused test file, identify the owning surface and feature:
`server_oidc_config_test.go` describes OIDC configuration through `NewServer`;
`config_<feature>_test.go` describes root configuration behavior. A setup helper
such as a parser should not determine the filename of a server integration test.
Update maintained code, automation, and skill references when renaming files.
Keep assertions and package boundaries intact for a naming-only change.
Follow the [feature filename rule](../coding-directives/SKILL.md#package-boundaries)
for tests and shared fixture drivers too: portal token-refresh tests use
`token_refresh_<behavior>_test.go`, with `_e2e_test.go` for E2E coverage.

## Test Surfaces

Root configuration and server tests exercise composed AuthCrunch configuration
and server construction across credentials, messaging, identity stores,
identity providers, authentication portals, authorization policies, OAuth keys,
and validation phases. Use these when a change affects cross-package wiring.

Logging tests use [logging](../logging/SKILL.md) for the directive parser,
immutable Zap filter, and root TLS journeys that verify actual JSON log output
while preserving denial and successful authentication behavior.

Authentication tests live under `pkg/authn`, including HTTP login/logout,
external logout, response handling, cache sandbox behavior, cookie settings,
transformers, icons, and embedded UI pages/static assets. Use `httptest` and
`internal/testutils` helpers for request/response and token-driven behavior.

Standalone server tests live under `pkg/httpserver` and `cmd/authdb`, including
parser-based TLS refresh/OIDC journeys and the actual race-enabled executable.
Use [authdb](../authdb/SKILL.md) for listener lifecycle, routing, configuration,
subprocess cleanup, and targeted validation.

Reusable login-client tests live under `pkg/authclient`, including E2E tests
against a real local TLS portal and identity store in the default test suite;
CLI tests live under `cmd/authdbctl`, including executable E2E against a real
portal and local database plus Python-backed pseudo-terminal tests. Use
`authentication-client` for reusable protocol/credential coverage and its 100%
gate; use `authdbctl` for command coverage, terminal fixtures, and CLI E2E
validation. The CLI subprocess is separate from the parent coverage profile.

Authorization tests live under `pkg/authz`, including gatekeeper behavior,
authentication requests, redirect handlers, cache behavior, options, and token
validator sources. Path normalization and JWT path-claim changes use the TLS
consumer fixtures in `pkg/authz/path_e2e_test.go`; the
[authorization path owner](../threat-hunting/references/authorization-paths.md)
defines their adversarial matrix and unit/fuzz coverage.
`pkg/authz/validator` and related tests use `httptest`,
test crypto key stores, test users, ACL helpers, and exact source/match
expectations.
Authorization login return URLs also use the root
`TestE2EServerAuthorizationLoginRedirectProtocols` journey with real HTTP/1.1,
HTTP/2, and quic-go HTTP/3 transports. It requires loopback TCP and UDP sockets;
do not replace HTTP/3 with a modified HTTP/1 request or silently fall back to
another protocol. See the
[redirect owner](../threat-hunting/references/redirects.md#regression-ownership)
for the full login journey and request-target invariants.

Direct OAuth policy tests use [authorization-policy-oauth](../authorization-policy-oauth/SKILL.md).
Root `server_oauth_authorization_e2e_test.go` exercises both public parsers,
configuration restoration, shared provider dispatch and TLS gatekeeper journeys
without a portal or identity database. Keep callback consumption, ACL checks,
opaque sessions, logout cancellation and lifecycle distinct from portal JWT tests.

Persistent-state tests use [runtime-state](../runtime-state/SKILL.md), including
root TLS portal-free OAuth and portal/OIDC/refresh restart journeys and an actual
built `authdb` process killed without cleanup. Verify old credentials and replay
revocations after reopening; graceful Close alone is insufficient crash evidence.

Identity and store tests live under `pkg/identity`, `pkg/ids`,
`pkg/ids/local`, `pkg/ids/ldap`, and `pkg/registry`. They rely on temporary
identity databases, registration/user JSON fixtures, domain restriction cases,
LDAP DN/config parsing, and table-driven success/error cases.
Use [local-password-authentication](../local-password-authentication/SKILL.md)
for the password-verifier regression matrix and controlled timing validation.

Local transaction changes use [local-identity-database](../local-identity-database/SKILL.md)
and the two-realm TLS journeys in `pkg/authn/identity_alias_e2e_test.go`.
Profile credential changes use [authentication-portal-profile](../authentication-portal-profile/SKILL.md),
including transformed-account, revoked-evidence and cross-origin persistence
checks. Factor enrollment and replay use
[authentication-portal-mfa](../authentication-portal-mfa/SKILL.md).

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

When changing configuration, pair the supported settings with corresponding
public parser coverage. Keep typed validation/default tests with the config
owner and directive grammar tests in its parser package. Cover success,
omitted/empty/disabled semantics, quoted token boundaries, arity, empty values,
unknown settings, duplicate/conflicting states, malformed records, and error
redaction. Verify `nil` results on failure and unchanged caller inputs. Exercise
named-reference resolution and persistence/reload behavior when the feature
uses them. Check that new config fields are reachable through the parser and
have observable consumer coverage; a struct tag or assignment test alone does
not establish directive support.

For a feature parser with a shared-dispatch adapter, test both public
constructors and run the consumer E2E journey through the adapter. Cover
normalized defaults, nested settings, relevant numeric conversion boundaries,
and rejection of fields supported only by the direct typed API. Check that
serialization and revalidation preserve the settings being exercised. Reuse
the feature parser's grammar tests; adapter tests should focus on conversion,
dispatch validation, independent results, and error redaction.

For typed application methods, test preservation of unrelated settings,
independent snapshots, and failure without mutation. When a parser is extracted,
run existing typed-config callers as well as the new parser's consumer E2E
journey to verify compatibility. Serialization round trips belong in that
journey when consumers persist the configuration.

When changing cross-package config or server wiring, add or update the root
package's tests so the full AuthCrunch object graph is covered. Follow
[test placement and filenames](#test-placement-and-filenames) for focused files.

For shared login/session changes, add composition coverage beyond feature-local
fixtures: access-only behavior with features disabled, claim transformations,
selected and unselected realms, browser JSON account replacement, and public
login-client compatibility. Exercise small capacity limits through logout and
relogin. Test cross-tab initialization with a stale session ID as well as two
tabs from the same session. A passing aggregate suite does not establish these
cross-feature contracts when all fixtures use the same happy-path setup.

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
iteration. Use `make test-ui` for embedded login/QR and refresh-client JavaScript;
it complements the Chrome E2E journeys and does not replace them.

## CI Workflow

`.github/workflows/test.yml` runs on pushes/PRs to main, manual dispatch, and
reusable workflow calls. Its selection job avoids duplicate branch tests for an
exact annotated release tag; `release-and-versioning` owns that decision and
its fallback rules. It selects Ubuntu 24.04, Go 1.26.8, Node 24, Python 3,
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
failure and an intentional short test timeout in an isolated fixture; verify
nonzero status, fresh evidence, and failed offline reports.

Skill changes use `skill-authoring-patterns` and the default skill-creator quick
validator. Inspect routing, exact code names, and links as well as frontmatter.
Do not treat prose-matching tests as behavioral validation.
