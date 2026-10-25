# Parallel CI validation

The Actions test workflow retains full validation for every code change,
manual invocation, and release tag. Selection still skips known non-code
changes and duplicate branch validation owned by an exact annotated release
tag. It does not run an overlapping selected suite before the full suite.

`assets/scripts/ci_tests.py matrix` owns the ten Go jobs; selection emits it
for the Actions matrix so the workflow and runner cannot drift. Package discovery
uses the shared read-only Go graph in `change_tests.py`.

| Shard | Scope |
| --- | --- |
| `portal-challenges` | Top-level `pkg/authn` tests containing `AuthenticationChallenge` |
| `portal-sessions` | Remaining portal tests containing `Refresh`, `Session`, or `Cookie` |
| `portal-protocols` | Remaining portal tests containing `OIDC`, `OAuth`, `SAML`, `JWKS`, or `PrivateKeys` |
| `portal-contracts` | Remaining portal tests containing `OpenAPI` or `I18N` |
| `portal-accounts` | Remaining portal tests containing `Connected`, `Profile`, `MFA`, `TOTP`, `WebAuthn`, `Password`, `Argon2`, `Identity`, or `Credential` |
| `portal-core` | Every remaining top-level portal test, example, and fuzz target |
| `identity` | `pkg/identity` and descendants |
| `other-server` | Root package, `cmd`, `pkg/authclient`, and `pkg/httpserver` trees |
| `other-providers` | `plugins`, `pkg/idp`, and `pkg/ids` trees |
| `other-core` | Every remaining package, including portal subpackages and future additions |

The portal package dominates its former shard, so splitting only subdirectories
would not shorten the critical path. Each portal job discovers its runnable
inventory with guarded `go test -list`, using the same race/atomic-coverage build
as execution. Discovery respects Go build constraints and includes external test
packages, runnable examples, and fuzz seeds. Its raw listing, inventory, and
resource status live under the shard's `discovery/` directory. Compilation/listing
has a five-minute deadline in addition to the normal resource guard.

Apply the portal categories in table order, then select exact anchored names
through the ordinary Make/guard/tested lifecycle. Keep each top-level test and
all its subtests together; semantic substring matches choose a group, never a
subtest filter. New names automatically enter an existing group or the fallback.
Do not use a hand-maintained test allowlist, silently drop unknown tests, or
split fixtures by parsing Go source with regular expressions.

Contracts and account/credential journeys run independently of the core fallback
to keep expensive integration tests from accumulating on one runner. Preserve
the earlier challenge/session/protocol ownership when names overlap these new
categories. Use hosted top-level timings to rebalance groups as the suite grows;
test counts alone do not predict duration. Keep the matrix unrestricted so its
independent jobs can start together subject to hosted runner availability.

Every other package runs once with all tests. Portal helper packages live in
`other-core`, where no portal name filter can omit their tests. Race detection,
uncached execution, examples, fuzz seeds, browser/CLI journeys, public-consumer
E2E tests, and coverage stay enabled. Graph errors, invalid inventories, and
empty shards fail. Every invocation invalidates prior selection evidence before
discovery and marks completion only after a successful test/report lifecycle.
Inherited `TEST` and `TEST_DIR` filters cannot narrow shard selection.
All shards run on separate Ubuntu VMs; never emulate this by starting several
test processes in one local checkout or bypassing its resource lock.

`make ci-quality` runs version, OpenAPI generation/source checks and Scalar
bootstrap tests, brand-asset, automation, lint, Node client, and executable-build
gates on another runner. `make ci-check` remains the complete,
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
Broader toolchain/workload prefixes seed caches after dependency changes. New
portal/other groups can also restore their original parent group cache, so
unchanged modules and compilations can still be reused.
`portal-contracts` and `portal-accounts` restore the `portal-core` build cache
when their own cache is cold; the matrix declares this parent explicitly.
Do not key mutable build outputs only by `go.sum`: an exact immutable cache hit
otherwise keeps restoring an old partial build cache and never updates it.
The first run after a toolchain/dependency change can still compile from cold.
Go's own content hashes validate cached build outputs; `-count=1` prevents
cached test results. Per-commit caches consume storage and can be evicted by
GitHub's cache quota; correctness must not depend on a warm cache.

## Evidence and reruns

After `ci-quality`, the quality job runs `make openapi-artifact`, verifies source
cleanliness, and uploads `go-authcrunch_openapi_<artifact-id>` separately. It
contains the standalone `openapi.json` and `openapi.yaml` from
`assets/openapi/generated/artifact/`. The export/upload must require successful
preceding steps, fail on missing output, and reuse selection's identity on rerun.
The existing coverage-only download pattern must not match this artifact.
The [OpenAPI owner](../../openapi-generation/SKILL.md) defines export semantics
and the executable fixture that verifies the workflow's actual packaging path.

Each shard writes `.coverage/shards/<shard>/` with the usual tested bundle,
`selection.json`, resource measurements, and `timing.json`. The job summary
shows elapsed time, peak memory, and slow packages; timing JSON also includes
the twenty slowest top-level tests without double-counting subtests.
Failed/interrupted runs upload their available evidence. Summaries flag an
unsuccessful attempt even when older successful test reports remain locally. Matrix fail-fast is
disabled so another shard's failure does not discard running diagnostics.

Selection computes the versioned artifact identity once. All shard artifacts
share it and end in `_shard_<name>`. Uploads replace the same shard on rerun;
rerunning only failed jobs can reuse successful sibling artifacts. Downloads
match this exact identity and shard prefix, excluding previous full attempts
and the combined bundle. Keep this distinction when changing artifact names.

The final check downloads all ten shards and verifies identical package plans,
successful resource/test status, complete package terminal events, and each
tested manifest's file hashes. Only the portal package may appear in multiple
shards. Its six inventories must match; their selections must be an exhaustive,
disjoint partition, and every selected top-level name must have exactly one
pass/skip terminal event in its assigned shard. A package-level pass alone does
not prove that a filtered run executed its assigned tests.

Atomic portal coverage profiles must have identical source blocks and statement
counts. Sum their execution counters while counting each block's statements once.
All other package profiles must remain disjoint. Reject within-profile duplicate
blocks, foreign-package coverage, mismatched portal source layouts, missing,
failed, truncated, or corrupted evidence. Validation failures preserve the last
good aggregate. Publish `.coverage/combined/index.html`, `summary.json`, and a
standard merged `coverage.out` alongside the intact individual tested reports.
The summary uses unique package and statement counts, includes the portal test
count, and uses schema `authcrunch/ci-coverage/v2`. It enforces the existing
1-percent nonempty-profile policy; this is not a substantial coverage target.
The combined report never fabricates a tested manifest.

## Reproduction and validation

```sh
python3 assets/scripts/ci_tests.py plan
make ci-quality
make ci-test-shard CI_SHARD=portal-challenges
make ci-test-shard CI_SHARD=portal-sessions
make ci-test-shard CI_SHARD=portal-protocols
make ci-test-shard CI_SHARD=portal-contracts
make ci-test-shard CI_SHARD=portal-accounts
make ci-test-shard CI_SHARD=portal-core
make ci-test-shard CI_SHARD=identity
make ci-test-shard CI_SHARD=other-server
make ci-test-shard CI_SHARD=other-providers
make ci-test-shard CI_SHARD=other-core
python3 assets/scripts/ci_tests.py merge
go tool cover -html=.coverage/combined/coverage.out -o .coverage/combined/source.html
```

These commands describe a full reproduction, not the default local validation
scope. For a contained change, select the affected fixtures or shard. When a
full reproduction is necessary, run the shards sequentially locally.
Use a fresh `COVERAGE_DIR` to retain
incident evidence; the shard subdirectories are appended automatically.
Relative output paths resolve against the checkout, including direct script
invocations from another working directory.
For exact CI resource reproduction use a separate VM with sufficient RAM,
then pass the workflow's explicit `TEST_*` settings. Do not apply its 7-GiB
budget to an 8-GiB laptop. `make ci-check` is still a simpler local full gate.

For shard runner or matrix changes, select
`python3 -m unittest discover -s assets/scripts/tests -p ci_shards_test.py -v`
and actionlint for workflow syntax. Include selection/release fixtures when
their contracts change; use `make test-automation` for automation-wide impact.
Honor user-requested test deferral and report hosted timing as unverified until
Actions runs.

`ci_shards_test.py` exercises real temporary Go packages through Make, the
guard, and pinned tested; it compares split coverage with an actual unsplit
run, verifies category priority and parent cache selection, complete discovery
(including examples, fuzz seeds, and external tests), exact test selection,
future-package inclusion, source preservation,
failure/build-failure propagation, stale rerun rejection, missing/duplicate test
rejection, coverage integrity, and the required-check status matrix.
Selection/release fixtures cover documentation skips, missing history,
PR merge bases, and annotated-tag ownership. Full hosted duration and the
higher CI resource profile require a subsequent Actions run to measure.
