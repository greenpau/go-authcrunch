# Private SQLite reference backends

The internal `internal/sqlitedb` helper owns the database mechanics for the
SQLite secrets reference and subsequent category implementations. It is not a
public identity API. External consumers import the plugin packages from the
AuthCrunch module; extracting a plugin into its own module also requires
replacing this internal helper with an owned implementation or public dependency.
The earlier SQLite refresh store owns its own storage implementation.

Use local POSIX files with reliable SQLite locks. The parent must already exist
and have no group/other permissions; database and sidecars must be regular 0600
files. Symlinks at the parent/database boundary, path replacement, missing files,
foreign application IDs, schema drift, and unsupported versions are rejected.
Ancestors and the service account remain trusted. This is plaintext storage;
file permissions do not provide encryption or protection from that account.
Windows and network/distributed filesystems are outside this reference contract.

The driver is pure Go `modernc.org/sqlite`. Each category owns a distinct
application ID, exact version-1 schema, and separate database file. Schema SQL is
compiled code, never user input. The helper currently accepts tables whose
creation order is independent; dependent DDL needs explicit ordering support.
Never share a file across categories or weaken schema checks to allow it.
Rollback journals, synchronous EXTRA, and fullfsync are deliberate. Do not turn
on WAL or change durability pragmas as an incidental performance tweak.

Creation publishes a closed, synced 0600 temporary file with a non-replacing
hard link. Do not open and close a raw descriptor on an active database: POSIX
per-process record locks can be dropped underneath another SQLite connection.

Reads use a consistent read transaction and discard it. Writes acquire an
immediate transaction with bounded BUSY retries before invoking the callback.
Callbacks use bound SQL values, must not reenter the database, and must not
publish results before successful completion. Preserve domain errors while
redacting SQL/paths/values. Never retry COMMIT. A real COMMIT error quarantines
the handle as `ErrCommitUncertain`; drain, reconcile through a fresh handle, and
only then decide whether retry is safe. Cancellation before driver commit rolls
back. Cancellation observed after successful commit withholds results as
uncertain without poisoning the healthy handle.

Hosts own Close and drain request users first. No automatic background workers,
cleanup, migrations, recovery retries, encryption keys, or global registries are
installed. Test durability by reopening; test contention and actual COMMIT
failure using a second real SQLite connection, plus consumer E2E. Keep strict
bounds on category payloads and record counts above this low-level helper.
