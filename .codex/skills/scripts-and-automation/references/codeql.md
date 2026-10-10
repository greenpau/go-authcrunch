# CodeQL scans and scoped query exceptions

## Query ownership

`.github/workflows/codeql.yml` is the advanced setup workflow for Go,
JavaScript/TypeScript, Python and Actions. Keep those languages when changing
the Go exceptions. Only the Go initialization loads
`.github/codeql/codeql-config.yml`; the other languages use the standard suite.
Go builds with the repository CI toolchain and `go build` rather than test,
release or maintenance targets.

Push/PR runs first apply the shared
[change classification](change-tests.md), skipping scans and their fixture tests
for known non-code changes. Scheduled and manual scans always run. Pass
`--no-release-dedup` to the selector: the release workflow owns full tests but
does not replace CodeQL analysis. Retain all four language jobs for code changes.

The Go configuration retains default queries and adds the local query pack. It
replaces only two upstream queries, matching both rule ID and upstream query
path so the local query with the same ID remains selected:

- `go/clear-text-logging` at
  `Security/CWE-312/CleartextLogging.ql`;
- `go/weak-sensitive-data-hashing` at
  `Security/CWE-327/WeakSensitiveDataHashing.ql`.

Each replacement has a different filename and retains the upstream rule ID,
severity, source/sink model, path evidence and message. An ID-only exclusion
would accidentally remove the replacement too.

`queries/DebugDiagnostics.qll` recognizes actual Zap method targets, not method
names or source-text matches. Only direct Logger.Debug and
SugaredLogger.Debug/Debugf/Debugw sinks qualify. A shared sink qualifies only
when all its logging uses qualify. The filter applies to the final logging
sink, never to the source claims or the upstream flow model. This preserves
non-debug uses of the same data and findings from other rules.

`queries/StructuredDiagnostics.qll` accepts four kinds of individual fields:

- Direct `zap.String` sinks with constant key `realm` or `auth_realm` and a
  direct struct `Realm` field read.
- Direct `zap.Any("error", err)`, `zap.NamedError("error", err)`, or
  `zap.Error(err)` sinks whose error argument statically implements Go's `error`
  interface, including concrete error types.
- Direct `zap.Any("user", payload)` sinks, including user claims and objects.
  The exception uses the constant key and actual function target, not the
  payload's variable name or log message.
- Direct `zap.Any("claims", payload)` sinks and direct Zap field constructors
  with a constant key whose value is the qualified AuthCrunch `user.Claims`
  type or a read within it. This includes the profile warning's
  `zap.String("jti", parsedUser.Claims.ID)`, nested fields, map/slice elements,
  slicing, type assertions, parentheses, and pointer operations. Match the
  actual claims type, not unrelated fields/types named `Claims`. Mixed
  expressions and arbitrary function transformations remain analyzed.

All require actual Zap function and Logger method targets, including direct
`Logger.With` fields, at every recognized level. All logging uses of a shared
sink must qualify. Keep each exception on the individual sink: other fields in
the same call and the same value logged elsewhere retain their existing
analysis. Passwords merely labeled `realm` or `error`, aggregate realm values,
and objects that do not implement `error` under the error key are not exceptions.
Dynamic keys, wrappers, sugared key/value calls, `WithOptions`, and unrelated
loggers are not exceptions. An Any value with static type `any` does not qualify
as an error. Do not change the upstream flow model or treat realm-bearing
objects, errors, error-message text, user payloads, or claims as globally clean.

The replacement query also excludes `go/clear-text-logging` sinks whose
repository-relative path is exactly `pkg/acl/rule.go`, regardless of logger
or level. Keep this equality check on the sink's location; prefix/suffix
matching or extraction exclusions would expand the accepted scope. Other
rules still inspect this file, and flows from it to sinks elsewhere remain
reportable.

`WeakSensitiveDataHashingWithEnrollmentFingerprint.ql` preserves both upstream
weak-hash flow configurations and excepts one exact sink: SHA-256 over
`append(canonical, hash...)` inside `Store.CreateEnrollment` in
`plugins/identity-stores/sqlite/store.go`. `hash` has already passed the store's
default-cost bcrypt validation; the result is durable enrollment idempotency and
conflict evidence, never a password authenticator. Match the owning file,
method, SHA-256 target, append shape, arguments and ellipsis. Do not sanitize
bcrypt output globally or except another SHA-256 call in the same file or
method. A refactor that changes this shape must make the scanner fixture fail or
restore the alert until the new boundary is reviewed.

The [threat-hunting owner](../../threat-hunting/references/debug-logging.md)
defines the accepted diagnostic behavior and its limits. Keep that policy there
and preserve the explicit rule/file boundary. Do not expand the ACL exception
to directories, other queries or global severity levels. Check query resolution
after upstream pack updates; an upstream path change should fail the fixture,
not silently broaden the filter. Keep `queries/codeql-pack.lock.yml` under
version control.

## GitHub activation

GitHub default setup does not consume this repository's custom query pack.
Before activating the checked-in workflow, switch the repository from default
to advanced CodeQL setup in Settings → Advanced Security → CodeQL analysis
(the security settings label can vary). GitHub's
[advanced setup instructions](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configuring-advanced-setup-for-code-scanning)
describe the switch from default setup.
Use the checked-in workflow rather than replacing it with an autogenerated
one. Land the workflow/configuration together, then run CodeQL on `main` and
verify all four language jobs and uploaded analysis results.

The equivalent REST default-setup change is `state: not-configured`; it requires
repository code-scanning administration access. Do not disable the existing
scan before the replacement is ready to run. A 403 while reading alerts or
default setup is a permissions blocker, not evidence that the alert is a false
positive or the exception is active. Never claim a repository-only edit
dismissed a hosted alert.

Inspect existing alerts after the first successful advanced scan. An alert can
have instances from multiple analysis configurations; changing configurations
may leave historical instances needing separate review. Dismiss only verified
debug diagnostics, qualifying realm-name/error/user/claims fields, or exact ACL
rule/file matches, with a rationale identifying this policy. Do not bulk-dismiss every
alert with the clear-text logging title: other non-debug fields outside the
exempt ACL file remain in scope for review.

The enrollment fingerprint is handled by the checked-in replacement query, not
by a hosted dismissal or inline suppression. After the replacement reaches the
analyzed branch, verify that its prior alert closes while direct password
SHA-256 and near-miss enrollment expressions remain reportable. Do not broaden
the sink predicate to silence a changed implementation without revalidating the
idempotency and credential-storage boundaries.

GitHub documents [custom query configuration](https://docs.github.com/en/code-security/reference/code-scanning/workflow-configuration-options)
and [query suite filtering](https://docs.github.com/en/code-security/tutorials/customize-code-scanning/create-query-suites).
Do not rely on `// codeql[...]`, `// lgtm[...]` or `// #nosec` comments to silence
GitHub alerts; the actual query selection and resulting SARIF are the contract.

## Local scans and regression evidence

Install a compatible CodeQL CLI and provide it on PATH or through `CODEQL`.
The local helper installs the locked custom-query dependencies and downloads
the standard Go query pack. It derives the source root from its own checkout,
not GOPATH or the caller's current directory. Pack downloads can require network
access. No global Go tools or module manifests are changed.

```sh
bash assets/scripts/run_codeql_scan.sh
CODEQL=/absolute/path/to/codeql bash assets/scripts/run_codeql_scan.sh
CODEQL=/absolute/path/to/codeql make test-codeql
```

The scan writes a fresh database, `results.sarif` and `results.csv` under a
unique `.coverage/codeql/scan.*` directory. `CODEQL_OUTPUT_DIR` selects a
different output directory; an existing database is not overwritten. Retain
failed evidence and use a fresh output directory for retries. The helper uses
the same `--codescanning-config` as the GitHub Go analysis.

`make test-codeql` runs `.github/codeql/test_scan.py` against a temporary Go
module with the library's Zap and bcrypt dependency versions. It exercises the
real helper, CodeQL extraction, configured default/replacement queries and
SARIF, then compares the complete upstream default suite on the same database,
including its rule IDs.
It verifies structured claims, headers, token-like values and sugared debug
calls disappear, and all logging levels in `pkg/acl/rule.go` are excepted.
Realm, typed-error, user-payload, and claims fixtures exercise ordinary levels and
attached fields and retain a sensitive neighbor in the same log call. Negative
cases reject label-only, aggregate-realm, expression, dynamic-key, wrapper,
sugared, opaque-error, and unrelated-logger overmatching. Error cases cover Any,
Error, and NamedError constructors with concrete and interface error types.
User cases include maps and objects, and a single call containing accepted
realm, error and user fields alongside a reportable password field.
Claims cases cover the actual profile JTI expression, the qualified claims
type, nested struct/map/slice reads, pointer forms and claim maps. Lookalike
types, mislabeled credentials, mixed expressions, dynamic keys, other loggers
and neighboring credentials must stay reportable. The isolated fixture module
uses the AuthCrunch module path with minimal fixture-owned claims models so
type matching is exercised without importing the application; the full local
scan verifies the production type and alert location.
It preserves ordinary levels, attached fields and unrelated loggers elsewhere,
including a neighboring file that receives sensitive data from the exempt
file and a nested path with the same suffix. It separately selects
the extended-suite log-injection query alongside the replacement and verifies
that Debug, realm/error/user/claims diagnostics, and the exempt ACL file remain
sinks for that rule; it does not enable the extended suite in the production configuration.
The same fixture mirrors the exact SQLite enrollment fingerprint and requires
the upstream weak-hash query to report it before filtering. It retains a changed
argument in the same method, the same expression in another method and direct
SHA-256 password hashing. The configured scan must remove only the exact
fingerprint while preserving those near misses.
The fixture and scan evidence stay in `.coverage/codeql/exception-e2e-*`.

The CodeQL workflow runs this regression after the primary analysis has
finished and before uploading its SARIF. `make ci-check` retains its existing
tool requirements; `test-codeql` is a separate required check for changes to
these exceptions. A missing CLI is
an explicit failure, not a skipped/passing test. Run `make test-automation` for
changes to the shell/Make automation and validate affected skills as usual.
