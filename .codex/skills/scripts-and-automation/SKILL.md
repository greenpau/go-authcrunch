---
name: scripts-and-automation
description: Maintain go-authcrunch Make targets, pinned Go tools, build/test orchestration, maintenance scripts, generated artifacts, and embedded UI refresh workflows.
---

# Scripts and Automation

The root Makefile is the public automation surface. Helper scripts live under
`assets/scripts/`. Use `testing-and-ci` for test selection and report evidence;
use `release-and-versioning` for the fixed-major version contract, version
synchronization, artifact identity, and patch/minor publication. Use
`skill-authoring-patterns` when updating the instructions that own a workflow.

## Command Selection

| Command | Behavior |
| --- | --- |
| `make` / `make build` | Check version projections, compile `bin/authdbctl`, print version/help |
| `make dep` | Download/verify modules and resolve pinned `go tool` commands |
| `make test` | Race-enabled, uncached Go tests and complete tested reports |
| `make test TEST_DIR='./pkg/authn/...' TEST='TestPortalRefresh'` | Same lifecycle with selected packages/test pattern |
| `make qtest QUICK_TEST_DIR='./pkg/authn/refresh'` | Focused lifecycle under `.coverage/quick`; default scope is `./pkg/system` |
| `make run-reports` | Rebuild presentations from the existing tested evidence bundle |
| `make test-ui` | Node spec-reported embedded refresh-client tests |
| `make test-automation` | Verbose Python automation/version/release fixture tests |
| `make ci-check` | Sequential version, automation, lint, Go tests, UI tests, and build gates |
| `make version-check` / `make version-sync` | Check or explicitly synchronize version-bearing Go defaults |
| `make artifact-id` | Validate and print the versioned artifact identity |
| `make docs` | Generate ignored `.doc/index.txt` from `go doc -all` |

`make test` owns test execution and reporting; it never runs license rewrites,
module tidy, or version synchronization. `run-tests` aliases the same tested
lifecycle. `run-quick-tests` underlies `qtest`. There is no `ctest` target.
`COVERAGE_DIR` selects output; concurrent independent invocations must use
separate directories. `TEST` is a regex, not a fragment of Go flags.

Let pinned `tested` clean up its managed artifacts inside the selected
`COVERAGE_DIR`. Do not recursively delete `.coverage` or the selected directory
in `run-tests`: quick runs must preserve the parent full-suite bundle, full
runs must preserve the quick bundle, and custom-output runs must preserve
other output directories. Unrelated files in a report directory also survive.
The lifecycle fixture in `assets/scripts/tests/tested_test.py` checks this
isolation alongside fresh evidence and nonzero exits after test/build failures.
Whole-directory cleanup belongs to the explicitly requested `make clean`.

The Go module minimum is `1.25.0`; CI selects Go `1.26.0`, Node 24, and Python
3. Use Python 3.9+ locally. `go.mod` and `go.sum` pin `tested`, `versioned`, and
`golint`; never replace the pinned lifecycle with global tools installed at
`@latest`. `make install-test-tools` resolves `go tool tested` without modifying
module manifests or global executable directories. Go dependency/tool downloads
may need network access. Node browser tests and Python automation use only their
standard libraries and need no npm/pip installation.

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

`assets/scripts/update_ui_apps.sh` rewrites `pkg/authn/ui/apps.go`, replaces
`pkg/authn/ui/profile`, and formats the asset inventory. Run it only for an
explicit embedded-profile asset refresh with a frontend build available at
`../../authcrunch/authcrunch-ui/frontend/profile/build` relative to this root.
It does not own the handwritten refresh client under `pkg/authn/ui/core/js`.

`assets/scripts/run_codeql_scan.sh` assumes CodeQL CLI/query packs under
`$HOME/.local/codeql`, uses the GOPATH checkout, and writes its database/results
under that tool directory. Use it for an explicit local CodeQL scan.

## Generated Output

Ignore `bin/`, `.coverage/`, `.doc/`, GoReleaser `dist/`, Python bytecode/cache,
and `.DS_Store` at every level. Generated coverage and release distributions
are workflow artifacts, not source changes. `go.mod`/`go.sum`, version
projections, embedded asset manifests, and license/TOC diffs are source changes
only when their explicit maintenance operation is in scope. CLA automation owns
`assets/cla/signatures.json`; do not edit it for build or test work.

This repository has no general `docs/` directory. Keep durable instructions in
the owning skill and its linked references, with README links for onboarding.
