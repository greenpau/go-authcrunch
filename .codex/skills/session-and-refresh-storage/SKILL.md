---
name: session-and-refresh-storage
description: Maintain the local SQLite refresh-storage plugin, its public parser, atomic rotation and replacement, replay history, durability and lifecycle, and refresh-engine consumer tests. Excludes automatic portal backend selection and storage for OIDC or OAuth sessions.
---

# Session and Refresh Storage

## Ownership and composition

The reference backend is
[`plugins/session-and-refresh-storage/sqlite`](../../../plugins/session-and-refresh-storage/sqlite).
It implements `tokenrefresh.Store`, `ReplacementStore`, and `SessionValidator`.
Pass the result of `sqlite.New(ctx, config)` directly to
`tokenrefresh.NewManager(store, identity, signer, policy, binding)`. Importing the
plugin does not register a portal configuration kind. The portal still owns a
concrete `MemoryStore`; its sessions, OIDC grants, OAuth sessions, and persistent
runtime state have independent storage. This backend establishes engine-level
composition for a local host, not a distributed authentication service.

The [refresh engine](../refresh-token-implementation/SKILL.md) owns issuance,
rotation, and publication ordering. The
[identity contract](../refresh-token-identity/SKILL.md) owns authenticated evidence
and transactional current-identity checks. The embedding host must preserve its
identity backend epoch and signing keys across restarts and coordinate identity
changes with signing and store commit. SQLite persistence alone cannot supply
those guarantees or immediately invalidate already issued stateless access JWTs.

## Configuration

`sqlite.Config` has `Path`, `MaxSessions`, `MaxRotations`, and `Timeout`, with
matching `path`, `max_sessions`, `max_rotations`, and `timeout` serialization keys.
`Config.Validate` validates and normalizes without filesystem access. `New`
snapshots the input; it neither retains nor modifies caller configuration.

Import the public `sqlite/parser` package and call
`NewSQLiteRefreshStorageConfigFromDirectives([]string)`. It accepts the complete
body, one directive per encoded argument line:

```text
path /private/authcrunch/refresh.db
max sessions 10000
max rotations 1024
timeout 1s
```

Encode paths containing spaces with `cfgutil.EncodeArgs`. Every setting is a
singleton; only `path` is required. Unknown settings, duplicates, malformed
arity, nonpositive explicit limits, control characters, and invalid UTF-8 fail.
Limits default to 10,000 live families and 1,024 rotations per family; each is
bounded to 1–100,000. Timeout defaults to one second and is bounded to 1ms–30s.
It limits context-aware work and connection-pool/lock waits. Filesystem calls,
driver connection setup, and an in-progress commit may outlast that budget;
credentials are withheld if cancellation is observed after commit. Direct typed
configs use
zero limits for defaults; explicit parser zero values are errors. Paths must be
absolute local filenames, not SQLite URIs or in-memory database selectors.

## Filesystem, durability, and lifecycle

Use a dedicated database on a local POSIX filesystem with working SQLite locks
and durable sync. The parent must already exist and be private (normally 0700);
files must be regular with mode 0600. Database, direct parent, and existing
journal/WAL/shared-memory sidecar symlinks are rejected. The host must trust the
parent and its ancestors. Do not use a network filesystem, live file replacement,
symlink switching, hard-link aliases, or multiple machines to share this database.
All clients must use the same canonical filename. Within one process, use the
same SQLite driver: independent SQLite implementations cannot coordinate POSIX
descriptor closes. Alternate names can break journal coordination. Alias
detection is not supplied for trusted parent ancestors or hard links. Windows is
unsupported because this implementation's permission checks cannot establish
its private-file contract there.

Keep the plugin and production builds free of cgo. Use the pure-Go SQLite driver;
do not introduce C imports or a cgo SQLite binding. Verify unit and public-consumer
tests with `CGO_ENABLED=0`; the race detector's separate toolchain requirement
does not establish or permit a production cgo dependency. The repository's Make
and release builds already force `CGO_ENABLED=0`.

SQLite uses rollback-journal DELETE mode,
foreign keys, synchronous EXTRA, fullfsync where supported, and secure deletion.
These settings depend on the OS/filesystem honoring its persistence guarantees.
Records are plaintext private authentication evidence. They contain immutable
identity/version evidence, grant metadata, full bindings, and credential digests;
never raw refresh credentials, access JWTs, or signing keys. Private permissions
are not encryption or guaranteed forensic erasure. Protect backups as private
identity data. Do not restore stale live snapshots that revive spent credentials
or revoked families; require fresh authentication after recovery that loses
acknowledged history.

Creation closes and syncs a private temporary file before atomically linking it
to the canonical name, without overwriting a concurrent constructor's database.
The temporary name is removed and the directory synced. Interrupted startup can
leave private temporary files; remove them only with the database offline.
Never open/read/close the database with raw file APIs while SQLite connections
are active: a separate POSIX close can release their process-wide locks. Use
SQLite's backup API for online backups, or drain and close all connections before
copying files. Preserve any recovery journal together with its database.

The database has a private application identity and versioned schema. Reopen
requires exact supported definitions and identical capacity/rotation settings
across clients. Unsupported schemas, altered constraints/indexes/triggers,
SQLite errors, unsafe files, and incompatible limits fail construction with no
runtime. Only genuine SQLite internal objects are exempt from schema checks;
similarly named foreign objects must be rejected at initialization and reopen.
Construction does not scan every record or perform a full integrity check;
malformed records fail closed when accessed. No automatic schema migration is
supplied. A failed first construction
can leave an empty private file. Existing active handles survive a rejected
configuration reload. Runtime checks reject missing or replaced database files.

The host owns `Close`: drain requests, close every old handle, then rebuild
managers with newly opened handles. Close is idempotent and preserves committed
state. Compatible independent handles and local processes share one database;
there is no package-global store registry or background worker. Expired families
are reclaimed during admission. Capacity counts live families. SQLite file
allocation need not shrink when records are removed.

A serialized family is limited to 64 KiB. Session IDs are limited to 256 bytes;
other proof and binding strings to 4 KiB each. Each methods, challenges, audience,
or scopes list has at most 128 entries, and methods must be nonempty. Replacement
accepts at most 128 previous digests. These bounds apply in addition to the
configured capacity and rotation limits; excess input is rejected before commit.

## Atomicity and errors

Every operation uses an immediate write transaction; lock acquisition alone is
retried, with a context-aware bound. Decisions are made from current persisted
state. Creation and rotation check staged access deadlines immediately before
and after commit; rotation also retains and rechecks the original idle deadline.
Caller modifications to a lookup snapshot cannot change stored identity, binding,
or absolute lifetime. Returned snapshots are independent values.

A matching spent credential revokes its whole family, including all descendants,
even after restart. Unknown credentials and any wrong binding cannot revoke it.
Retain all spent digests while descendants are live. Reaching the rotation limit
revokes the family rather than dropping its history. Admission, duplicate
replacements, collision checks, capacity, retirement, and creation are one
transaction. Failed replacement preserves every live family, including at full
capacity. Only fresh authenticated issuance can use old credentials as
replacement targets. Logout accepts current or spent credentials and is
idempotent for unknown credentials. Session-ID liveness is not authentication.

`tokenrefresh.ErrInvalid` denotes invalid, expired, or replayed authority.
Ordinary unavailable/canceled operations roll back without spending a current
credential. Raw SQL errors and paths are not returned. A commit attempt whose
outcome or post-commit deadline/health cannot be confirmed returns the distinct
`sqlite.ErrCommitUncertain` and must never publish staged credentials. It may
already have spent the token: do not blindly retry; require fresh authentication.
An actual database commit failure or failed post-commit file-health check disables
the handle: reconcile storage health, close that handle, and reopen. Cancellation rejected by
`database/sql` before it calls the driver is rollback-safe and returns the context
error. Cancellation or grant expiry after a successful commit withholds only that
request's credentials; it must not disable storage for unrelated families. Do not
translate an uncertain outcome into the engine's retry-safe `ErrUnavailable`.

## Acceptance and verification

Keep unit cases in `store_test.go` for schema/config rejection, snapshots and
large identity versions, independent-handle races, wrong bindings, oldest-spent
replay, replacement rollback at capacity, expiry before commit, rotation bounds,
lock cancellation, concurrent file preparation, unsafe/replaced files, and
real failed SQLite commits. Preserve regressions for cancellation before and
during commit, post-commit expiry, and the continued usability of unrelated
families. Use the driver's commit hook to cancel inside an actual SQLite commit.
Parser unit cases and the executable example belong in `parser/parser_test.go`.
Register public structs in `internal/tag/tag_test.go`.

`consumer_e2e_test.go` composes the public parser, real identity database,
refresh engine, Ed25519 KMS, and gatekeeper over TLS. Preserve successful login,
signature and claim checks, shared capacity, canceled TLS requests, failed
signing/locking, rejected
reloads, reopen/refresh, replay, replacement, logout, identity revocation, and
no credential delivery after a real failed commit. `process_e2e_test.go` uses
independent executable processes to race rotation and checks replay revocation
after reopening. Wait for each child's initialized-store acknowledgement before
starting the next child, then release both for concurrent rotation. Connection
setup can briefly hold read locks and trigger a legitimate busy commit; that
setup overlap must not contaminate the one-winner assertion. It also kills child
processes after acknowledged admission and
rotation, then verifies durable credentials and replay revocation on reopen.
This tests process termination, not hardware power loss or torn disk writes.
`external_module_e2e_test.go` runs these same public-only
consumers in a separate offline module via `tests.RunExternalModule`.

```sh
make test TEST_DIR='./plugins/session-and-refresh-storage/sqlite/... ./internal/tag' COVERAGE_DIR=.coverage/sqlite
make test TEST_DIR='./pkg/authn/token_refresh/...'
CGO_ENABLED=0 COVERAGE_DIR=.coverage/sqlite-no-cgo python3 assets/scripts/test_guard.py run \
  go test -mod=readonly -p 1 -count=1 -run '^(TestSQLite|TestE2ESQLite(AbruptRestart|ProcessStorage|LoginRestartRefreshAndAuthorization)|Example)' ./plugins/session-and-refresh-storage/sqlite/...
make ci-check
```

Filesystem fixtures must explicitly chmod the numbered `t.TempDir()` directory
to 0700: Go's private temporary root does not imply private child permissions.
Use real independent SQLite transactions to simulate lock/commit failures;
replacing a store method with a fake error does not verify database atomicity.
The external-module driver uses the shared race-enabled helper; its public
consumer sources run without cgo through the direct command above.
