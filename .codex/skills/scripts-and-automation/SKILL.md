---
name: scripts-and-automation
description: Maintain go-authcrunch Make targets, pinned Go tools, build/test orchestration, maintenance scripts, generated artifacts, and embedded UI refresh workflows.
---

# Scripts and Automation

Use [openapi-generation](../openapi-generation/SKILL.md) to maintain `make openapi`, `make serve-openapi`, source-review checks and Scalar tooling.

The root Makefile is the public automation surface. Helper scripts live under
`assets/scripts/`. Apply `testing-and-ci` for test selection and report evidence.
Use [release-and-versioning](../release-and-versioning/SKILL.md) to maintain the
fixed `1.<minor>.<patch>` version namespace, synchronize versions, validate CI
artifact identity, and publish requested patch/minor releases.
Use [skill-authoring](../skill-authoring/SKILL.md) to update the instructions
that own an automation workflow after changing its commands, tool requirements,
side effects, artifacts, or validation procedure. Include those skill updates
in the same task before reporting the automation change complete.

## Command Selection

Run this module's automation for work here. Never run sibling-repository build,
test, formatting, license, dependency, or cleanup commands, or invoke tools that
write into sibling directories. Those projects are updated separately. The
[repository scope](../coding-directives/SKILL.md#repository-scope) is an absolute
boundary for these workflows.

| Command | Behavior |
| --- | --- |
| `make` / `make build` | Check version projections, compile `bin/authdb` and `bin/authdbctl`, print version/help |
| `make dep` | Download/verify modules and resolve pinned `go tool` commands |
| `make linter` | Run pinned golint on the root package and `cmd`, `internal`, `pkg`, and `plugins` trees |
| `make test` | Race-enabled, uncached Go tests and complete tested reports |
| `make change-test` | Tests selected from staged, unstaged, and untracked changes; `CHANGE_DRY_RUN=1` previews selection |
| `make test TEST_DIR='./pkg/authn/...' TEST='TestPortalRefresh'` | Same lifecycle with selected packages/test pattern |
| `make qtest QUICK_TEST_DIR='./pkg/authn/token_refresh/...'` | Token engine and public parser lifecycle under `.coverage/quick`; default scope is `./pkg/system` |
| `make run-reports` | Rebuild presentations from the existing tested evidence bundle |
| `make openapi` / `make serve-openapi` | Validate/bundle YAML or serve the Scalar reference at loopback port 8080 |
| `make openapi-check` / `make openapi-test` | Check source/freshness or run unit/native HTTP/CLI/bootstrap contracts |
| `make openapi-artifact` | Export standalone JSON/YAML specifications for the separate CI artifact |
| `make openapi-browser-test` | Qualify the real pinned Scalar viewer in Chrome |
| `make test-ui` | Node spec-reported login and refresh client tests (`*_client_test.cjs`) |
| `make test-automation` | Verbose Python automation/version/release fixture tests |
| `make test-codeql` | Real CodeQL fixture scan verifying scoped query exceptions and retained alerts; requires CodeQL CLI |
| `make brand-assets` / `make brand-assets-check` | Regenerate SVG branding and shared colors from the palette, or check drift without writes |
| `make generate-acl` | Regenerate the four ACL condition/rule source and test files from the local Python generator |
| `make ci-check` | Complete sequential quality gates and full Go tests |
| `make ci-quality` | Version, OpenAPI/source review/bootstrap, brand assets, automation, lint, UI tests, and both executable builds |
| `make ci-test-shard CI_SHARD=portal-core` | Run one of eight portal-test or package shards; see parallel CI validation |
| `make version-check` / `make version-sync` | Check or explicitly synchronize Go metadata and OpenAPI YAML with VERSION |
| `make artifact-id` | Validate and print the versioned artifact identity |
| `make docs` | Generate ignored `.doc/index.txt` from `go doc -all` |

`make test` owns test execution and reporting; it never runs license rewrites,
module tidy, or version synchronization. `run-tests` aliases the same tested
lifecycle. `run-quick-tests` underlies `qtest`. There is no `ctest` target.
`COVERAGE_DIR` selects output; use separate directories to retain independent
bundles. Test and report runs in one checkout are serialized by a nonblocking
lock, including invocations from other terminals or agents. Read
[test resource controls](references/test-resources.md) when running or changing
the memory watchdog, concurrency, cancellation, output limits, or diagnosing a
resource abort. Do not start additional expensive validation alongside a test
run or bypass the guard to force an over-budget suite to finish.

Read [change-based testing](references/change-tests.md) when maintaining change
classification, Git ranges, affected-package selection, local `change-test`,
or GitHub's decision to require validation. Keep CI and local classification shared;
unknown impact retains validation. `make test` and `make ci-check` remain full
validation entry points.

Read [parallel CI validation](references/ci-shards.md) when changing Actions
jobs, package shards, cache keys, combined coverage, or the required check.
CI runs the full Go suite once across disjoint shards alongside `ci-quality`;
local `change-test` remains available for faster development feedback.

`TEST` is a regex, not a fragment of Go flags. `TEST_TIMEOUT` is a quoted
Go per-package duration (default `30m`) forwarded through tested; use it instead
of embedding flags in `TEST`. Environment overrides apply to both full and quick
runs; a Make command-line assignment takes precedence and survives recursive
quick-test invocations. CI explicitly allows 45 minutes per package, a 90-minute
guard, and 100 minutes per Go job, including setup and evidence upload. Local
defaults remain conservative. Follow the
[timeout diagnosis](../testing-and-ci/SKILL.md#test-lifecycle) before changing
these budgets. Preserve individual request/process deadlines.

`assets/scripts/tests/test_timeout_test.py` checks default and override argument
forwarding for all four test entry points at the tool boundary.
`assets/scripts/tests/test_guard_test.py` exercises real Make invocations with
bounded subprocess fixtures: memory, process, time and artifact limits, output
flooding, monitoring failures, cancellation, descendant cleanup, overlapping
runs, override forwarding, host memory pressure refusal, and live progress
during quiet work before the child finishes. Output fixtures verify recovery
after rate-limited bursts, visible throttling notices, and continued heartbeats.
They also hold stdout unread through child exit and evidence finalization to
verify queued notices survive shutdown without delaying cleanup or changing
the child result.
Linux proc-read fixtures distinguish normal process exits from accounting
failures and verify child results and cleanup through Make on either host.
The OpenAPI target fixture verifies both Go phases use guarded tested reports,
preserve output paths containing spaces, and stop before later phases on failure.
`assets/scripts/tests/tested_test.py` exercises pinned tested and real Go tests:
live log forwarding before a test can finish, default forwarding, a recursive
quick-run override, and a short environment deadline that remains a failed run
in live and offline reports.

Let pinned `tested` clean up its managed artifacts inside the selected
`COVERAGE_DIR`. Do not recursively delete `.coverage` or the selected directory
in `run-tests`: quick runs must preserve the parent full-suite bundle, full
runs must preserve the quick bundle, and custom-output runs must preserve
other output directories. Unrelated files in a report directory also survive.
The lifecycle fixture in `assets/scripts/tests/tested_test.py` checks this
isolation alongside fresh evidence and nonzero exits after test/build failures.
Whole-directory cleanup belongs to the explicitly requested `make clean`.

`make linter` scopes golint to the root package and the `cmd`, `internal`, `pkg`, and
`plugins` source trees. Golint's recursive filesystem scan does not honor nested
Go modules or Git ignores; using `./...` also scans temporary consumer checkouts
under `tmp/` and generated output. Keep new source trees in the explicit lint
scope. `assets/scripts/tests/linter_test.py` exercises the real Make target with
temporary checkouts and verifies that source and test-file warnings still fail.

The Go module minimum is `1.26.0`; CI and release builds select Go `1.26.8`, Node 24, and Python
3. Use Python 3.9+ locally. `go.mod` and `go.sum` pin `tested` v1.1.0, `versioned`, and
`golint`; never replace the pinned lifecycle with global tools installed at
`@latest`. `make install-test-tools` resolves `go tool tested` without modifying
module manifests or global executable directories. Go dependency/tool downloads
may need network access. Node browser tests and Python automation use only their
standard libraries and need no npm/pip installation.

`test-ui` discovers `pkg/authn/ui/testdata/*_client_test.cjs`; the current files
cover login/QR state transitions and the refresh client. Keep browser drivers
under their `*_browser_e2e.cjs` names so they are launched by their Go fixtures,
not the Node unit-test glob. For CSS, responsive layouts, and QR presentation,
use the [theme validation workflow](../authentication-portal-themes/references/basic-theme.md#validation)
and its headless Chrome journey in addition to any affected client tests.

## Explicit Maintenance

`make templates` runs `make license`. That command applies license headers to
Go files and refreshes `cmd/authdbctl/README.md`'s table of contents using the
pinned versioned tool. Run it when that maintenance is intended and review its
diff; it is not a prerequisite for builds/tests.

`make mod-tidy` runs `go mod tidy` and `go mod verify`; `make upgrade` runs
`go get -u ./...` and tidy. Dependency upgrades need an explicit request.
`make clean` removes `.doc`, `.coverage`, and `bin`; run it when cleanup is
requested. Keep diagnostic reports until the user has the needed evidence.

## Asset and Security Scripts

### ACL Generation

`assets/scripts/generate_acl.py` owns `pkg/acl/condition.go`,
`condition_test.go`, `rule.go`, and `rule_test.go`. Edit its field/match/action
tables and Go templates, then run `make generate-acl` and commit the generator
and regenerated files together. The generator includes the Apache license and
generated-file notice; it does not run license maintenance on other ACL files.
Handwritten tests, including `pkg/acl/generation_e2e_test.go`, remain independent
of the generated test matrices.

Generation requires Python 3.9+ (override Make's `PYTHON` when needed) and
`gofmt` on PATH. It uses only the Python standard library and this checkout;
no sibling repository, autopep8, or global versioned binary is needed. Direct
invocation resolves the repository from the script path, regardless of the
working directory. Run `python3 assets/scripts/generate_acl.py --check` to
detect missing or stale files without writing (exit 1 for drift, 2 for tool or
filesystem failures). Generation renders and formats all four files before
staging replacements, so rendering/formatting/staging failures preserve existing
outputs. Replacements are atomic per file, not a transaction across all four.
Unchanged files retain their timestamps and permissions.

Preserve the current ACL behavior when changing templates, including `amr` as
a list-valued field and condition-level `match any`. Negative regex conditions
with list expressions or list inputs accept any nonmatching pair when that
modifier is present; their default rejects any matching pair. Unconditional
`match any` must evaluate even when its legacy compiled `exp` field is absent.
Keep ordinary field-presence guards and explicit existence checks intact across
all generated rule variants; the [ACL owner](../authorization-policy-acl/SKILL.md)
owns the evaluation contract and regression coverage.

Typed custom ACL fields pass per-list types into generated constructors; they
must not modify the standard global field table. The handwritten empty-list
guard applies only to custom list comparisons. The
[ACL owner](../authorization-policy-acl/SKILL.md) defines claim projection,
type validation, public parser APIs, and independent runtime coverage.

Run `make test-automation` and
`make test TEST_DIR='./pkg/acl' COVERAGE_DIR='.coverage/acl'` after changes.
`assets/scripts/tests/generate_acl_test.py` exercises the real Make target in an
isolated checkout with spaces in its path, reconstructs all four deleted files,
compares them byte-for-byte with committed outputs, and runs the resulting Go
tests. It also covers idempotence, read-only drift checks, a missing formatter,
and a real formatting failure after earlier artifacts rendered successfully.
This reproducibility check runs in `ci-check` through `test-automation`;
build/test commands never regenerate the working checkout's ACL files.

### Other Assets and Security Scripts

`assets/scripts/update_brand_assets.py` owns the palette-driven core/profile
SVG artwork, the marked color block in `basic.css`, and profile theme metadata.
Run it through `make brand-assets` after editing `assets/branding/palette.json`
or the source mark. `make brand-assets-check` is read-only and runs in the CI
gate. Its unit and executable regeneration tests run under `test-automation`.
Use the [theme owner](../authentication-portal-themes/references/basic-theme.md#changing-the-default-palette-and-svg-artwork)
for palette fields, output ownership, and deployment overrides.

`assets/scripts/update_ui_apps.sh` rewrites `pkg/authn/ui/apps.go`, replaces
`pkg/authn/ui/profile`, and formats the asset inventory. Run it only for an
explicit embedded-profile asset refresh with a frontend build available at
`../../authcrunch/authcrunch-ui/frontend/profile/build` relative to this root.
It does not own the handwritten login or refresh scripts under
`pkg/authn/ui/core/js` or the shared portal theme styles.

`assets/scripts/run_codeql_scan.sh` scans this checkout with the same Go query
configuration as `.github/workflows/codeql.yml`. It uses `CODEQL` or `codeql`
on PATH and writes database/SARIF/CSV evidence under `.coverage/codeql` by
default. Read the [CodeQL workflow](references/codeql.md) when running or changing
scans, query exceptions, regression fixtures, or GitHub default/advanced setup.

## Generated Output

Ignore `bin/`, `.coverage/`, `.doc/`, GoReleaser `dist/`, Python bytecode/cache,
and `.DS_Store` at every level. Generated coverage and release distributions
are workflow artifacts, not source changes. `go.mod`/`go.sum`, version
projections, embedded asset manifests, and license/TOC diffs are source changes
only when their explicit maintenance operation is in scope. CLA automation owns
`assets/cla/signatures.json`; do not edit it for build or test work.

This repository has no general `docs/` directory. Keep durable instructions in
the owning skill and its linked references, with README links for onboarding.

Local release-toolchain qualification and snapshot isolation are defined in
[release validation](../release-and-versioning/SKILL.md#validation).
