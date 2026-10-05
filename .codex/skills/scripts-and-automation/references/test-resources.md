# Test resource controls

`make test`, `run-tests`, `qtest`, `run-quick-tests` and `run-reports` invoke
`assets/scripts/test_guard.py` around pinned tested. Python 3.9+, `ps`, and
macOS or Linux are required. The guard includes the tool build, Go compiler,
tests, browser/CLI subprocesses and report generation. It never terminates
VS Code or other unrelated applications.

| Setting | Default | Scope |
| --- | --- | --- |
| `TEST_PACKAGE_PARALLELISM` | `1` | Go package builds/tests; inherited by nested Go commands through `GOFLAGS` |
| `TEST_PARALLELISM` | `2` | Go tests using `t.Parallel` |
| `TEST_GOMAXPROCS` | `2` | Go execution threads per process |
| `TEST_GO_MEMORY_MB` | `512` | Go's soft memory target per process, in MiB |
| `TEST_MEMORY_MB` | smaller of `3072` and three-eighths of physical RAM | Aggregate sampled test process memory, in MiB |
| `TEST_WALL_TIMEOUT` | `2400` | Entire workflow duration in seconds, including build/report phases |
| `TEST_MAX_PROCESSES` | `128` | Observed processes in the owned tree |
| `TEST_ARTIFACT_MB` | `256` | Regular files directly inside the selected output directory, in MiB |
| `TEST_TIMEOUT` | `30m` | Existing Go timeout per package |

All numeric guard settings must be positive integers; zero never disables a
guard. `TEST_MEMORY_MB` may not exceed half of physical RAM. Make arguments
override environment values and survive recursive quick runs. The guard sets
`GOMAXPROCS` and `GOMEMLIMIT` from its `TEST_` settings; use those settings rather
than relying on unrelated inherited Go environment values. Race detection,
uncached execution, test selection and tested's authoritative exit status remain
enabled. On an 8 GiB host the default aggregate budget is 3 GiB, leaving 5 GiB
outside the test budget. Smaller hosts can legitimately refuse large fixtures.

## Monitoring and cleanup

The guard samples every 200 ms. macOS accounting takes the larger of RSS and
physical footprint, including compressed memory; Linux accounting adds swap to
RSS. Shared pages may be counted multiple times. Once per second it checks host
pressure: macOS critical pressure stops the tests, as does Linux available RAM
below the larger of 256 MiB and ten percent of total RAM. Pressure is checked
before launch too. Failures to monitor stop work rather than silently continuing.

The supervisor follows parent/child relationships and remembers process start
times, including observed children that create another process group/session
or become reparented. Budget violations, a disappearing launcher, and
SIGINT/SIGTERM/SIGHUP freeze and kill owned work, returning nonzero status.
Cleanup also removes observed
leftover children after normal completion. Do not use an address-space ulimit
for Go race binaries: their virtual mappings differ greatly from committed RAM.

These are sampled safeguards, not kernel-enforced memory isolation. Brief
overshoots, descendants that daemonize between samples, killing the supervisor
with SIGKILL, or unrelated editor/agent allocations cannot be fully contained.
Linux container/cgroup quotas are not detected; this workflow targets local
macOS/Linux hosts and the CI runner. Strict isolation requires an appropriately
limited VM or container. Do not claim an arbitrary application can never exhaust
the machine because this wrapper is enabled.

Only one guarded workflow can hold `.coverage/test-resource.lock` in a checkout,
even when output directories differ. The OS releases the advisory lock after
exit; an existing file alone is not a stale lock. Do not delete the lock or run
`make clean` during validation. Separate checkouts and direct unguarded commands
do not share this lock. Agents must serialize other expensive work too.

## Output and evidence

The guard prints elapsed time, current aggregate memory and process count every
10 seconds, including during compilation and report generation. Pinned tested
v1.1.0 also streams test activity and bounded log previews, identifies reporting
stages, and prints a heartbeat during quiet work. Keep its default live output
enabled; `--quiet` and `--format json` suppress it. Forwarded child output has a
256 KiB per-second burst limit, with a fresh allowance each second; there is no
lifetime console cutoff. A burst that exceeds the allowance emits a notice and
later test output resumes automatically. Guard heartbeats bypass this allowance
and continue every ten seconds. Writes remain nonblocking: a slow or disconnected
terminal may drop presentation bytes rather than block resource checks. Full
Go output remains in tested's raw evidence until an artifact or other resource
budget is reached. Workspace VS Code settings exclude generated reports/build
directories from watching/search and retain 2,000 terminal scrollback lines.

`resource-usage.json` records execution status, budget, peak memory/process
counts, recent largest process IDs, elapsed time and stop reason.
`console_dropped_bytes` counts child-output bytes omitted by throttling or a
blocked terminal; the guard reports that count at completion. Reporting uses
`resource-report-usage.json`. These files supplement tested's evidence; a killed
run can lack `run.json` or a completed manifest. Offline reporting refuses a
previous `running` or `aborted` guard record, including a supervisor interrupted
before finalization. Keep the evidence and rerun into a fresh output directory.
An ordinary test/build/coverage failure remains a failure in live and offline
reports. The guard does not remove unrelated files or other report bundles.

For investigation, start with a selected package/test under `make test`. For a
narrow command outside the report lifecycle, retain the same guard:

```sh
COVERAGE_DIR=.coverage/debug python3 assets/scripts/test_guard.py run go test -race -count=1 ./pkg/example -run '^TestExample$'
```

Check active processes and the recorded peak before changing any budget. A
capacity fixture may serialize many large snapshots; a package's elapsed time
and output size alone do not reveal its memory demand. The macOS Force Quit
application grouping does not establish which test, editor extension or agent
caused a historical spike. Preserve the original incident evidence.

The portal's HTML/JSON session-cache and gatekeeper OAuth capacity journeys use
`tests.IsolateCapacityTest` from `internal/tests/capacity.go` to run each in a
child of the same test binary with a five-minute deadline. Their real 64 MiB
persistence boundary creates large Go and race-detector allocations that can
remain resident after a test finishes. Process exit releases
that memory before Chrome starts later in the package. Keep race instrumentation,
the inherited resource controls, all capacity assertions, and child failures.
Forward `-test.gocoverdir` so the parent merges child counters into its profile;
never give a child the parent's `-test.coverprofile` output path.
Validate the sequence together, since testing the browser alone misses retained
memory from earlier capacity work:

```sh
make test TEST_DIR=./pkg/authn TEST='TestE2EHTMLSessionCacheCapacityRollback|TestTokenRefreshJSONSessionCacheCapacityRecovery|TestE2ECookieBrowserLogout' COVERAGE_DIR=.coverage/capacity-browser
make test TEST_DIR=./pkg/authz TEST='TestE2EOAuthPersistentCapacityRefusalPreservesAuthority|TestE2EAuthorizationRedirectBrowserOrigin' COVERAGE_DIR=.coverage/authorization-capacity-browser
```

`TestE2EIsolateCapacityTest` checks separate-process execution, child failure
propagation, and preservation of both wrapper and child coverage counters.

Validate changes with `make test-automation`, including the real tested success,
failure, build-failure, timeout and offline-report fixture. Also run the real
OIDC and portal capacity E2E tests under the guard; synthetic memory fixtures
alone do not establish that ordinary high-memory tests remain usable.
