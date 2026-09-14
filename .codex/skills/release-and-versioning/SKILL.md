---
name: release-and-versioning
description: Maintain AuthCrunch VERSION authority, versioned synchronization, patch/minor release commands, CI artifact identities, and GoReleaser publication. Use for version checks, release automation, or release preparation.
---

# Release and Versioning

## Authority and Projections

`VERSION` is exactly `1.<minor>.<patch>`, optionally terminated by one newline,
with no leading zeros or prerelease/build suffixes. The major stays `1`.
Expose patch and minor operations only; do not add a major bump. Adding a
feature does not itself authorize bumping or publishing a release.

`assets/scripts/version.py` validates that namespace and the fallback metadata
in `cmd/authdbctl/main.go` and `pkg/identity/database.go`. `make version-check`
is read-only. `make version-sync` invokes the pinned `go tool versioned
-release -sync` for both projections, then checks them. Committed branch/commit
fallbacks are empty; actual build metadata comes from linker flags. Ordinary
builds/tests never synchronize source or run `go mod tidy` implicitly.

The `go.mod` tool block and its requirements pin `tested`, `versioned`, and
`golint`; use `go tool` so a globally installed binary cannot silently change
repository behavior. Tool upgrades are explicit dependency changes.

## Artifact Identity and CI

`make artifact-id` validates projections and produces
`v<VERSION>_<UTC YYYYMMDDTHHMMSSZ>_<12-character SHA>` for branch, pull-request,
and manual builds. An exact `v<VERSION>` tag produces `v<VERSION>`; any other
tag fails. `GITHUB_SHA` binds the identity to the actual checked commit, and
`GITHUB_OUTPUT` receives validated `version` and `artifact_id` values.

`.github/workflows/test.yml` is reusable by the release workflow. It runs
`make ci-check` and uploads the complete ignored `.coverage/` bundle, including
failure evidence, as `go-authcrunch_coverage_<artifact-id>`. Coverage is a
workflow diagnostic artifact, separate from published distributions.

The test workflow first runs `assets/scripts/select_ci_tests.py`. A `push` to
`refs/heads/main` skips its full test job only when version projections are
synchronized, HEAD matches `GITHUB_SHA`, and origin has the exact annotated
`v<VERSION>` tag peeled to that same commit. The atomic release push therefore
gets one full Actions gate, owned by the tag's release workflow. Missing,
lightweight, mismatched, or unconfirmed remote tags retain branch testing;
commit messages do not authorize skipping tests. PR, manual, and tag-triggered
runs always retain their full gate. The selection job runs for every invocation
and emits `run_tests` through `GITHUB_OUTPUT`; `core` depends on that successful
selection. Its Git queries are read-only and bounded. Local Git/process fixtures
in `assets/scripts/tests/ci_test_selection_test.py` cover both release events
and conservative fallback behavior.

`.github/workflows/release.yml` requires the reusable test job before publishing,
checks the exact annotated tag and synchronized version, then runs pinned
GoReleaser with write permission confined to that job. `.goreleaser.yaml` owns
Linux/Windows/Darwin amd64/arm64 `authdbctl` builds, checksums, and linker
metadata. Preserve immutable action pins and avoid publishing every local tag.

`assets/scripts/verify_release.sh` fetches only the event's exact tag from origin
before checking its annotation: `actions/checkout` can replace the runner's local
tag with the event commit SHA. Verification requires both HEAD and the peeled
remote tag to match `GITHUB_SHA`, as well as the version/tag contract. Restore
only the runner's local tag; do not move remote release tags or change HEAD to
make verification pass. Automation fixtures reproduce the checkout fallback
with a real Git fetch and reject lightweight, missing, and mismatched tags.

The library's minimum Go version and the final executable's build toolchain are
separate contracts. Inspect both reusable-test and GoReleaser setup-go pins when
qualifying a release; the current workflows explicitly select Go 1.26.8 with
`GOTOOLCHAIN=local`. Check the official Go release history and vulnerability
database for a supported patched toolchain before shipping binaries. A local
upgrade does not update CI, and changing only `go.mod` does not update explicit
workflow pins. Record `go version` for validation and `go version -m` for the
packaged executable. Follow [threat-hunting](../threat-hunting/SKILL.md) for
stdlib versus library findings and scanner precision for stripped binaries.
Do not raise the module's minimum Go version solely to clear a local stdlib scan.

## Release Execution

Only execute a publishing command when the user requests an actual release:

- `make release`: patch bump, e.g. `1.1.41` to `1.1.42`.
- `make minor-release`: minor bump/reset, e.g. `1.1.41` to `1.2.0`.
- `make release-git-check`: read-only local branch/clean-tree/version checks.

Both publish paths invoke `assets/scripts/release.sh` sequentially, including
under `make -j`. Before bumping, they check `main`, a clean worktree/index
including untracked files, synchronized versions, local main containing
`origin/main`, and absence of the next tag locally and on origin. They bump and
synchronize only declared projections, then run `make ci-check` exactly once
against the release contents. Only a passing gate permits the
`ops: released v<VERSION>` commit, one annotated tag, and the atomic push of main
and that exact tag to origin. No force push or broad `git push --tags` belongs
in this workflow. Partial legacy release targets deliberately fail with a
pointer to the complete workflow.

A gate failure leaves the bumped, synchronized version files uncommitted and
unstaged, with no new local commit/tag or remote update. Automation fixtures
record the version seen by every gate invocation and assert a single invocation
at the new patch/minor version. They also verify preflight rejection before the
gate and preservation of the failed candidate without another bump on retry.

If a gate or push fails, inspect the worktree, local tag/commit, and remote refs
before taking another step. Leave diagnostic state for review. Do not reset,
delete tags, increment again, or retry publication blindly. An atomic-push
failure leaves both remote refs unchanged; a transport failure can still be
ambiguous and requires a read-only remote check.

## Validation

Run `make test-automation` for fixed-major/version drift, artifact identity,
and release behavior against disposable repositories and local bare remotes.
These fixtures use the real pinned `versioned` tool and Git but a small fixture
quality gate; they do not publish this repository. Use `make ci-check` for the
actual repository gate. For packaging changes, run the pinned GoReleaser
`check` and `build --snapshot --clean` without a GitHub token. Never run a real
release as an automation test.

For local qualification with an explicit patched toolchain, keep `GOROOT`, `PATH`,
and `GOTOOLCHAIN=local` consistent in the child process. A shell-exported older
`GOROOT` can make a newer compiler reject the standard library. Preserve the
failed evidence and correct the invocation; do not alter module minimums or
global Go configuration to mask that environment mismatch. Snapshot builds use
a separate ignored distribution directory and never receive publishing tokens.
