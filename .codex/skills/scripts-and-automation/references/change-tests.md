# Change-based testing

`assets/scripts/change_tests.py` owns path classification, local Git changes,
Go impact analysis, and selected test execution. `select_ci_tests.py` supplies
GitHub event ranges and the existing annotated-release deduplication rule.
Keep one classification policy for local tests, Actions tests, and CodeQL.

## Local workflow

```sh
make change-test
make change-test CHANGE_DRY_RUN=1
make change-test CHANGE_BASE=HEAD~1 CHANGE_HEAD=HEAD
make change-test COVERAGE_DIR=.coverage/review TEST_TIMEOUT=10m
```

By default, select the union of staged changes, unstaged changes, and untracked
nonignored files. An edit staged and then reversed in the worktree still
selects tests. Tests execute the current worktree; the command does not stash,
check out, stage, or separately test the index snapshot. Ignored build/report
outputs do not count. NUL-delimited Git output and disabled rename detection
preserve unusual filenames and both sides of renames/deletions. Unborn Git
repositories are supported.

`CHANGE_BASE` compares two committed trees; `CHANGE_HEAD` defaults to HEAD and
requires a base. This mode excludes uncommitted edits from selection but still
executes the current checkout. Invalid explicit local revisions fail, rather
than claiming that there were no changes. Use `git merge-base` first when a
branch comparison needs three-dot semantics. A dry run prints the JSON plan
without running tests or creating reports; Go changes may require module
downloads to discover imports.

The plan lists changed paths, selected packages, automation/UI flags, mode,
and the reason. Actual runs save it under `COVERAGE_DIR/changes/selection.json`.
Go reports go under `COVERAGE_DIR/changes/go`, preserving full and quick bundles.
Selected tests retain pinned tested, race detection, uncached execution,
coverage, resource safeguards, deadline overrides, and failure exit status.
Existing `TEST` and `TEST_DIR` filters are deliberately replaced so they cannot
silently exclude affected tests. Automation and UI suites run before selected
Go packages; failure stops the command. This is test selection, not the full
lint/build/asset/version quality gate; use `make ci-check` for that gate.

## Selection rules

- Known guidance/editor/CLA metadata, Markdown/reStructuredText documentation,
  license/owners/ignore files, issue/funding metadata, and empty `.gitkeep`
  scaffolding skip tests. Embedded portal UI, email/translation assets, and
  test fixtures take precedence over file extensions.
- Go changes select the owning package. Production changes also select
  transitive production importers and consumers that import affected packages
  from internal or external tests. Test-file-only changes select their package.
  Test dependencies do not imply a change to the consumer's production API.
- Package-local assets/fixtures select their nearest owning package and its
  consumers. Root `testdata` selects all Go packages. Portal UI changes also
  run the Node client suite; branding changes run automation and Node tests.
- Production Go changes also select `internal/tag`, whose compliance tests
  discover source at runtime rather than through an import dependency.
- Automation, workflow, release configuration, and generator changes select
  `make test-automation`. The automation fixtures exercise their Go consumers
  where applicable. The separate CodeQL workflow retains its scan fixtures.
- Makefile, module/workspace manifests, VERSION, or unknown inputs select all
  test suites. Incomplete/erroring Go graphs and missing owners fall back to
  all tests. Deleting a package must not accidentally select only its parent.

Package discovery uses read-only `go list` metadata for the current host and
module; it does not compile tests or infer dependencies from filenames or test
names. Tests within an affected package all run, including its E2E cases.
This can remain expensive for a large package or a widely shared dependency.
It does not promise function-level coverage or validation of separate nested
modules. Extend ownership when introducing runtime file reads across package
boundaries that import metadata cannot represent. Keep full CI validation as
the backstop; do not use a selected run as release evidence.

## GitHub flow

The workflow always starts a small selection job; it does not use workflow
path filters, which can leave required checks pending. Checkouts used for
selection have complete history. Pushes compare the event's `before` commit
to its SHA, covering every commit in a multi-commit push. PRs compare the
merge base of the event's base/head SHAs to the PR head, while executing tests
on GitHub's merge checkout. Base-branch-only edits do not become PR changes.

Documentation-only changes skip expensive jobs. Both focused and full code
changes run the full Go suite once, partitioned into disjoint test/package shards,
alongside `make ci-quality`. Do not put a selected run ahead of a full run:
widely imported portal changes otherwise execute the slowest suites twice.
Local `make change-test` retains its impact analysis and selected execution.
The existing `Tests and coverage` check requires successful selection, all
shards, quality checks, and verified combined coverage. Failed or unexpectedly
skipped dependencies fail that check. Read [parallel CI validation](ci-shards.md)
for budgets, artifacts, caching, and the executable failure-gate fixtures.

Tag/manual/reusable invocations without a reliable change range run the full
gate. New branches, unavailable history, malformed payloads, and a checkout
that disagrees with GITHUB_SHA also retain full validation. Globally classified
changes also use the full gate. Go graph errors in shard discovery fail
validation; they must never produce an empty successful selection.

The release workflow calls this test workflow for every version tag. Only the
matching annotated tag can own an accompanying branch push's validation; the
[release owner](../../release-and-versioning/SKILL.md) defines that contract.
CodeQL uses the same change classification with release deduplication disabled,
since the release workflow does not own its scans. Scheduled and manual CodeQL
runs always analyze; docs-only pushes/PRs skip analysis and scan fixtures.

## Validation

Run `make test-automation`. `change_tests_test.py` exercises real temporary Git
repositories and Go import graphs, plus the real Make/guard/tested lifecycle,
selection isolation, report paths, and failure propagation. CI fixtures cover
multi-commit pushes, divergent PR bases/merge checkouts, missing history,
non-code scaffolding, full overrides, and release ownership with bare remotes.
Keep these fixtures independent of repository history or GitHub credentials.

Validate changed Actions syntax with actionlint and exercise the final required
check for successful, failed, skipped, and cancelled dependencies. A local
workflow lint is not evidence of a completed hosted Actions run.
