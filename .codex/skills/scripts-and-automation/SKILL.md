---
name: scripts-and-automation
description: go-authcrunch repository automation, Makefile target selection, local build/test/report commands, authdbctl build workflow, asset and embedded UI update scripts, CodeQL scan script, release/version workflows, generated artifact handling, stale documentation command correction, and guardrails for dependency, license, cleanup, and release actions. Use when choosing, running, documenting, or updating repository scripts and Make targets; troubleshooting CI/build/test automation; refreshing embedded UI assets; deciding whether generated outputs belong in a change; or preparing releases for this Go module.
---

# Scripts and Automation

## Overview

Use the Makefile as the primary automation surface for this Go module, but
prefer direct `go test` commands for ordinary validation while editing. The
Makefile builds the `authdbctl` management CLI from `cmd/authdbctl`; this
repository does not have a top-level `scripts/` directory.

## Command Selection

- Use `go test ./...` for a fast all-package check without coverage reports,
  linting, license rewrites, or report generation.
- Use `go test -run <TestName> ./...` or `go test ./pkg/<name> -run
  <TestName>` for focused validation. Do not rely on `make test TEST=...` for
  focused runs; command-line `TEST` overrides the Makefile variable in a way
  that passes the raw value to `go test`.
- Use `make qtest` only when the current Makefile quick-test scope is desired.
  The current `QUICK_TEST_DIR` is `./pkg/system`; the quick-test pattern
  variables are commented out.
- Use `make test` for the full local report workflow only when broad
  side effects are acceptable. It runs `templates`, `linter`,
  `install-test-tools`, `run-tests`, and `run-reports`. On a fresh checkout,
  run `make dep` first because `linter` expects `golint` before
  `install-test-tools` runs.
- Use `make` when the user asks for the default build. It runs `info` and
  `build`; `build` depends on `templates` and `mod-tidy`.
- Use `make build` to compile `cmd/authdbctl/*.go` into `bin/authdbctl`, inject
  version metadata from `VERSION`, git, user, and date values, then run
  `bin/authdbctl --version` and `bin/authdbctl --help`.
- Use `make run-reports` only after `.coverage/test_output.jsonl` and
  `.coverage/coverage.out` exist.
- Use `make docs` to write `.doc/index.txt` from `go doc -all` and print it.
- Use `make clean` only when cleanup is requested; it removes `.doc`,
  `.coverage`, and `bin/`.

If documentation mentions `make ctest`, treat it as stale for this repository.
There is no `ctest` target; choose `go test ./...`, a focused `go test`, or
`make qtest`/`make test` based on scope.

## Makefile Side Effects

Treat `make`, `make build`, and `make test` as potentially mutating commands,
not pure validation commands.

- `templates` runs `license`.
- `license` installs or invokes `versioned`, applies the repository license
  header to every Go file, and regenerates the table of contents in
  `cmd/authdbctl/README.md`.
- `build` runs `versioned -sync ./pkg/identity/database.go` before compiling.
- `mod-tidy` runs `go mod tidy` and `go mod verify`.
- `test` writes `.coverage/coverage.out`, `.coverage/test_output.jsonl`,
  `.coverage/coverage.html`, and `.coverage/test_output.html`.

Before keeping generated diffs from these targets, review whether the user
actually asked for license, version, docs, module, or coverage artifact updates.

## Tooling and Dependencies

The module declares Go `1.25.0`.

- `make dep` installs or checks `golint`, `richgo`, and `versioned`.
- `make install-test-tools` installs `richgo`, `tparse`, and `go-test-report`
  when they are missing.
- `make linter` runs `golint -set_exit_status ./...`.
- `make upgrade` runs `go get -u ./...` and `go mod tidy`; use it only for an
  explicit dependency upgrade.
- `go mod tidy`, `go mod verify`, `go get`, `go install`, and GoReleaser may
  require network access.

When a dependency or module command fails because of sandboxed network access,
rerun it with the normal escalation flow instead of replacing the repository
workflow with an ad hoc workaround.

## Asset and UI Scripts

`assets/scripts/update_ui_apps.sh` refreshes embedded profile UI assets. It
rewrites `pkg/authn/ui/apps.go`, removes and replaces `pkg/authn/ui/profile`,
and runs `go fmt` on `apps.go`.

Run it only when the user explicitly asks to refresh embedded UI assets and the
expected frontend build exists at:

```bash
../../authcrunch/authcrunch-ui/frontend/profile/build
```

The script assumes that path relative to the repository root, so verify the
checkout layout before running it.

`assets/scripts/run_codeql_scan.sh` is a local CodeQL helper. It assumes the
CodeQL CLI and query packs exist under `$HOME/.local/codeql`, uses
`$GOPATH/src/github.com/greenpau/go-authcrunch` as the source root, and writes
databases and results under `$HOME/.local/codeql`. Run it only for an explicit
local CodeQL request.

## Release and Version Targets

Treat release targets as human-operator actions unless the user explicitly asks
for a release workflow.

- `make release-git-check` runs `mod-tidy`, requires the current branch to be
  `main`, and requires a clean git worktree.
- `make release-update-version` runs `versioned -patch`, syncs prerelease
  metadata into `cmd/authdbctl/main.go` and `pkg/identity/database.go`, and
  stages `VERSION`, `cmd/authdbctl/main.go`, and `pkg/identity/database.go`.
- `make release-git-commit` creates a release commit, creates an annotated tag,
  pushes commits, and pushes tags.
- `make release` chains `release-git-check`, `release-update-version`, and
  `release-git-commit`.
- `.github/workflows/release.yml` runs GoReleaser on `v*` tags.
- `.goreleaser.yaml` builds `./cmd/authdbctl` for Linux, Windows, and Darwin
  on `amd64` and `arm64` with `-mod=readonly`.

Never push commits or tags, create release tags, or run `make release` or
`make release-git-commit` unless the user has explicitly requested that action.

## Generated Artifacts

Do not treat generated outputs as source changes unless the user explicitly
asks to update or commit them.

- `bin/authdbctl` is produced by `make build` and ignored by git.
- `.coverage/coverage.html`, `.coverage/coverage.out`,
  `.coverage/test_output.jsonl`, and `.coverage/test_output.html` are produced
  by `make test`, `make qtest`, and report targets; `.coverage/` is ignored.
- `.doc/index.txt` is produced by `make docs`; `.doc/` is ignored.
- `pkg/authn/ui/profile` and `pkg/authn/ui/apps.go` can be regenerated by
  `assets/scripts/update_ui_apps.sh`.
- `VERSION`, `cmd/authdbctl/main.go`, and `pkg/identity/database.go` are
  touched by release/version workflows.
- `go.mod` and `go.sum` can change after `mod-tidy`, `upgrade`, or dependency
  commands.
- `assets/cla/signatures.json` is maintained by the CLA workflow; do not edit
  it unless the user asks.

## CI Notes

The test workflow runs on Ubuntu with Go `1.25.x`. It installs `make` and
`libnss3-tools`, creates `.coverage`, runs `make dep`, runs `make test`, runs
`make`, and uploads `.coverage/` as an artifact.

Because CI uses `make test`, CI exercises the license, lint, test, and report
pipeline rather than a plain `go test ./...` command.
