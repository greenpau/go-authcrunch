---
name: testing-and-ci
description: go-authcrunch repository testing and CI workflow guidance, including Go test command selection, Makefile report targets, shared test helpers, package-specific authn/authz/identity/idp/kms/UI fixture patterns, generated coverage/build artifacts, and GitHub Actions test/release/CLA behavior. Use when choosing or running tests, adding or updating test coverage, interpreting CI failures, reproducing GitHub Actions locally, or documenting validation for this Go AuthCrunch library.
---

# Testing and CI

## Overview

Use this skill for go-authcrunch test selection, coverage additions, fixture
maintenance, and CI reproduction. Prefer the narrowest direct `go test` command
while editing, then use Makefile targets when the user asks for the repository
workflow, report artifacts, or CI-like validation.

The Go module is rooted at the repository top level and declares Go `1.25.0`.
If the task becomes release, dependency, embedded UI asset refresh, or general
automation work rather than testing/CI work, also use the repo-local
`scripts-and-automation` skill.

## Command Selection

Use direct Go tests for quick feedback:

```bash
go test ./...
go test ./pkg/authn -run TestServeHTTP
go test ./pkg/authz/validator -run TestValidate
go test ./pkg/idp/oauth -run TestConfiguredQueryParamsArePreserved
go test ./pkg/kms -run TestGetKeysFromConfig
go test ./pkg/system -run TestEncryptorRoundTrip
```

Use `go test ./pkg/<name> -run <TestName>` or `go test -run <TestName> ./...`
for focused validation. Do not rely on `make test TEST=...` for focused runs;
the Makefile passes the command-line `TEST` value directly to `go test`.

Use `make qtest` only when the current Makefile quick-test scope is desired.
The current `QUICK_TEST_DIR` is `./pkg/system`; quick-test pattern variables are
commented out.

Use `make test` for the full local report workflow. It runs `templates`,
`covdir`, `linter`, `install-test-tools`, `run-tests`, and `run-reports`; writes
`.coverage/coverage.out`, `.coverage/test_output.jsonl`,
`.coverage/test_output.html`, and `.coverage/coverage.html`; then fails if any
JSON test action failed. On a fresh checkout, run `make dep` first because
`linter` expects `golint` before `install-test-tools` runs.

Use `make` or `make build` when validation needs the `cmd/authdbctl` binary or
when reproducing the GitHub Actions build step. `build` depends on `templates`
and `mod-tidy`, compiles `bin/authdbctl`, and runs `bin/authdbctl --version`
and `bin/authdbctl --help`.

`make dep`, `make install-test-tools`, `make`, `make build`, `go mod tidy`,
`go mod verify`, `go get`, and `go install` may require network access.

## Makefile Side Effects

Treat Makefile workflows as potentially mutating commands.

- `templates` runs `license`.
- `license` installs or invokes `versioned`, applies the repository license
  header to Go files, and regenerates the table of contents in
  `cmd/authdbctl/README.md`.
- `build` runs `versioned -sync ./pkg/identity/database.go`.
- `mod-tidy` runs `go mod tidy` and `go mod verify`.
- `test` and `qtest` replace `.coverage/` report files.

Review the diff after Makefile targets before keeping source changes. Generated
license, README table-of-contents, version metadata, `go.mod`, or `go.sum`
changes are intentional only when the user asked for that workflow.

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

Use `make test` after direct Go tests when the user wants the local report
workflow or CI-like validation.

## CI Workflow

`.github/workflows/test.yml` runs on pushes and pull requests to `main` and on
manual dispatch. It uses Ubuntu, Go `1.25.x`, sets `GOBIN` to
`/home/runner/.local/bin`, installs `make` and `libnss3-tools`, creates
`.coverage`, runs `make dep`, runs `make test`, always lists `.coverage`, runs
`make`, and uploads `.coverage/` as `Test Coverage Artifacts`.

For local CI reproduction, use:

```bash
make dep
make test
make
```

If CI fails in `make test`, inspect `.coverage/test_output.jsonl` first. The
Makefile fails after `run-reports` when the JSON stream contains
`"Action":"fail"`, so the original package/test failure is usually earlier in
that file.

`.github/workflows/release.yml` runs GoReleaser on `v*` tags with Go `~1.25`.
Treat releases, tags, pushes, and release Makefile targets as human-operator
actions unless the user explicitly requests them.

`.github/workflows/cla.yml` uses CLA Assistant and may update
`assets/cla/signatures.json` through GitHub automation. Do not edit CLA
signature or consent artifacts unless the user asks.

## Generated Artifacts

Treat these as generated outputs unless the user explicitly asks to preserve or
commit them:

```text
bin/authdbctl
.coverage/coverage.html
.coverage/coverage.out
.coverage/test_output.jsonl
.coverage/test_output.html
.doc/index.txt
/tmp/testdata/go-authcrunch/
```

Also review source diffs from automation carefully:

```text
cmd/authdbctl/README.md
pkg/identity/database.go
go.mod
go.sum
```
