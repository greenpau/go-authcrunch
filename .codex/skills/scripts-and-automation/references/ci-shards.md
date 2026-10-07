# Parallel CI validation

The Actions test workflow retains full validation for every code change,
manual invocation, and release tag. Selection still skips known non-code
changes and duplicate branch validation owned by an exact annotated release
tag. It does not run an overlapping selected suite before the full suite.

`assets/scripts/ci_tests.py` discovers the current Go package graph using the
shared read-only discovery in `change_tests.py`. It assigns every package once:

| Shard | Packages |
| --- | --- |
| `portal` | `pkg/authn` and its descendants |
| `identity` | `pkg/identity` and its descendants |
| `other` | Every remaining package, including future additions |

These boundaries isolate the longest suites without filtering tests by name.
Race detection, uncached test execution, examples, fuzz seeds, browser/CLI
journeys, public-consumer E2E tests, and coverage stay in the default suite.
Graph errors or empty shards fail. Each shard invokes the ordinary Make/guard/
tested lifecycle, explicitly replacing inherited `TEST` and `TEST_DIR` filters.
All shards run on separate Ubuntu VMs; never emulate this by starting several
test processes in one local checkout or bypassing its resource lock.

`make ci-quality` runs version, brand-asset, automation, lint, Node client, and
executable-build gates on another runner. `make ci-check` remains the complete,
serial local gate: `ci-quality` then full Go tests. The stable Actions job name
`Tests and coverage` waits for selection, quality, and the entire Go matrix.
Only explicit `none` selection permits skipped work. Failed, cancelled, or
unexpectedly skipped dependencies cannot become a successful required check.
The release workflow continues to depend on this reusable workflow.

## Resources and caches

The CI Go jobs use the explicit profile in [test resource controls](test-resources.md).
The higher memory/CPU budgets belong to 4-CPU, 16-GB public Ubuntu runners.
Local defaults continue to fit an 8-GB developer machine. Individual browser,
network, and subprocess timeouts are unchanged. The longer package, guard,
and job deadlines are backstops, not expected durations or hang remediation.
Inspect the reported stop reason before changing them: healthy packages can
all fit their individual limits while the entire serialized run hits its guard.

Module caches are shared by runner OS/architecture, toolchain, and `go.sum`.
Every Go job downloads and verifies the complete module graph before offline
consumer E2E tests. Build caches additionally include the shard (or quality job) and commit
SHA. A matching prefix restores the latest build cache for that workload and
dependency graph; a successful new commit saves updated compilation outputs.
Broader toolchain/workload prefixes seed caches after dependency changes, so
unchanged modules and compilations can still be reused.
Do not key mutable build outputs only by `go.sum`: an exact immutable cache hit
otherwise keeps restoring an old partial build cache and never updates it.
The first run after a toolchain/dependency change can still compile from cold.
Go's own content hashes validate cached build outputs; `-count=1` prevents
cached test results. Per-commit caches consume storage and can be evicted by
GitHub's cache quota; correctness must not depend on a warm cache.

## Evidence and reruns

Each shard writes `.coverage/shards/<shard>/` with the usual tested bundle,
`selection.json`, resource measurements, and `timing.json`. The job summary
shows elapsed time, peak memory, and slow packages; timing JSON also includes
the twenty slowest top-level tests without double-counting subtests.
Failed/interrupted runs upload their available evidence. Matrix fail-fast is
disabled so another shard's failure does not discard running diagnostics.

Selection computes the versioned artifact identity once. All shard artifacts
share it and end in `_shard_<name>`. Uploads replace the same shard on rerun;
rerunning only failed jobs can reuse successful sibling artifacts. Downloads
match this exact identity and shard prefix, excluding previous full attempts
and the combined bundle. Keep this distinction when changing artifact names.

The final check downloads the shards and verifies matching plans, nonoverlapping
packages, successful resource/test status, complete package terminal events,
disjoint atomic coverage blocks, and each tested manifest's file hashes.
Missing, failed, truncated, corrupted, or overlapping
evidence fails the check. It then publishes `.coverage/combined/index.html`,
`summary.json`, and a standard merged `coverage.out` alongside the intact
individual tested reports. The summary uses statement counts across all
packages, not an average of shard percentages. It enforces the existing
1-percent nonempty-profile policy; this is not a substantial coverage target.
The combined report has its own schema and never fabricates a tested manifest.

## Reproduction and validation

```sh
python3 assets/scripts/ci_tests.py plan
make ci-quality
make ci-test-shard CI_SHARD=portal
make ci-test-shard CI_SHARD=identity
make ci-test-shard CI_SHARD=other
python3 assets/scripts/ci_tests.py merge
go tool cover -html=.coverage/combined/coverage.out -o .coverage/combined/source.html
```

Run the shards sequentially locally. Use a fresh `COVERAGE_DIR` to retain
incident evidence; the shard subdirectories are appended automatically.
Relative output paths resolve against the checkout, including direct script
invocations from another working directory.
For exact CI resource reproduction use a separate VM with sufficient RAM,
then pass the workflow's explicit `TEST_*` settings. Do not apply its 7-GiB
budget to an 8-GiB laptop. `make ci-check` is still a simpler local full gate.

Run `make test-automation` and actionlint after workflow changes.
`ci_shards_test.py` exercises real temporary Go packages through Make, the
guard, and pinned tested; it verifies future-package inclusion, disjoint
execution, valid merged coverage, source preservation, failure/build-failure
propagation, incomplete evidence rejection, and the required-check status
matrix. Selection/release fixtures cover documentation skips, missing history,
PR merge bases, and annotated-tag ownership. Full hosted duration and the
higher CI resource profile require a subsequent Actions run to measure.
