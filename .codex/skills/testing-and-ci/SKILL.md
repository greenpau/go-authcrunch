---
name: testing-and-ci
description: Select, run, and maintain AuthCrunch Go tests through pinned tested, browser refresh-client tests, automation fixtures, coverage artifacts, and GitHub CI gates.
---

# Testing and CI

## Test Lifecycle

The root Go module declares Go `1.25.0`. Repository coverage uses the pinned
`github.com/greenpau/tested` tool in `go.mod`, invoked through `go tool tested`.
It owns `-json`, `-coverprofile`, child-process status, and coherent reports.
Do not reintroduce `go test | tee`, log-grep success detection, richgo, tparse,
or go-test-report into the lifecycle.

```sh
make test
make test TEST_DIR='./pkg/authn/...' TEST='TestPortalRefresh'
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

Authorization tests live under `pkg/authz`, including gatekeeper behavior,
authentication requests, redirect handlers, cache behavior, options, and token
validator sources. `pkg/authz/validator` and related tests use `httptest`,
test crypto key stores, test users, ACL helpers, and exact source/match
expectations.

Identity and store tests live under `pkg/identity`, `pkg/ids`,
`pkg/ids/local`, `pkg/ids/ldap`, and `pkg/registry`. They rely on temporary
identity databases, registration/user JSON fixtures, domain restriction cases,
LDAP DN/config parsing, and table-driven success/error cases.

Identity provider and SSO tests live under `pkg/idp`, `pkg/idp/oauth`,
`pkg/idp/saml`, and `pkg/sso`. OAuth tests cover request parsing, state,
provider setup, JWKS, GitHub email lookup, and provider HTTP interactions.
SAML/SSO tests use metadata, certificate, and key fixtures from
`testdata/saml` and `testdata/sso`.

KMS and credential tests live under `pkg/kms` and `pkg/credentials`. They use
RSA, ECDSA, GPG, OAuth, malformed PEM, missing-key, and mixed-key fixtures
under `testdata`. Preserve package-relative paths such as
`../../testdata/rskeys/test_2_pri.pem` when adding cases.

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
