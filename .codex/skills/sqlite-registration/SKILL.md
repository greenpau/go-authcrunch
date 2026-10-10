---
name: sqlite-registration
description: Maintain SQLite email-confirmed registration, its public parser, optional portal confirmation hook, hashed pending credentials, recoverable account creation, and registration-to-login E2E tests. Excludes administrative approval and general identity-store account operations.
---

# SQLite Registration

`plugins/registration-workflows/sqlite` composes the SQLite identity store and
message outbox. Its `Workflow` implements `registry.Provider` and the optional
`registry.ConfirmationProvider`. Fresh confirmation creates an enabled account
with only `authp/user`; there is no administrative approval step. Recovery of an
already-created enrollment preserves subsequent account management changes,
including disabled state.

## Configuration and attachment

Use `parser.NewSQLiteRegistrationConfigFromDirectives([]string)`. Required:
`name`, absolute `path`, `identity_store`, `realm`, `email_provider`, and
`public_origin` (a canonical HTTPS origin without path, userinfo, query or
fragment; explicit ports must be 1–65535).
Optional `base_path` defaults to `/auth`; it accepts `/` or slash-separated ASCII
letters/digits/underscore/hyphen segments without a trailing slash, at most 512
bytes. Reject existing portal protocol namespaces (including api, provider and
register) anywhere in the mount; their routing would intercept confirmation links.
Optional `timeout` defaults to 1s and permits 1ms..30s. Each setting takes one
value once.
Realm is 1–64 ASCII letters/digits/underscore/hyphen. Parser validation is pure.

Construct `New(ctx, config, *accounts.Store, *notifications.Outbox)` using the
public SQLite identity-store and messaging packages. The store's name/realm must
match configuration. The constructor creates an internal messaging binding under
email_provider; no host-global lookup occurs. Backend configuration is snapshotted.
The workflow owns only its pending database. Supplied account/outbox lifetimes
remain with the host. Read the shared
[private SQLite contract](../plugin-development/references/sqlite-backends.md).
All three files must be distinct. This plugin uses pure Go and no background job.

Select the identity store and registry names in PortalConfig, inject the store
through PortalParameters.IdentityStores, then call Portal.AddUserRegistry before
serving. Root registry dispatch remains local-only. Embedding adapters must verify
configured registry names and store/realm associations. GetRealmName is immutable;
legacy SetRealmName cannot rebind it. SetMessaging accepts only the existing
outbox pointer under its configured binding. No transport credentials are accepted.

## Enrollment state and recovery

Public registration accepts 3–25 lowercase letters/digits, a bare email address,
and exact UTF-8 passwords of 12–72 bytes. Reject reserved password-import forms
and username `nobody`. Email is canonicalized to lowercase. The portal generates
64–96 character registration IDs and 6–8 character confirmation codes. IDs and
codes are SHA-256 digests in pending storage; passwords use default-cost bcrypt.
GetRegistrationEntry returns username/email/realm and `return_url` for a live
pending entry; never password hashes or confirmation codes.
AsMap excludes paths, origins and credentials. The outbox necessarily contains
the plaintext confirmation code for delivery; protect it separately.

Entries last 45 minutes. The remaining code lifetime bounds account-database lock
waits and enrollment work, even when the operation timeout is longer. Recheck
actual expiry before pending-state finalization and after commit. A deadline
crossed after an account commit withholds success as ErrCommitUncertain; reconcile
the account and pending state rather than treating the outcome as no mutation.
Five wrong confirmations exhaust a durable attempt budget, retained across restart.
Unknown, expired, canceled, locked and spent entries deny. IDs cannot be
overwritten. The 10,000-record lifetime bound includes
terminal entries; no eviction or history-pruning policy is installed. Hosts own
admission controls and any future reviewed retention/migration policy.

ConfirmRegistration takes an immediate pending-database transaction, checks the
code, and calls the account store's idempotent CreateEnrollment with a durable
UUID. The account database commits first; pending state then becomes confirmed
and its credential material is removed. These are two files, not one atomic
transaction. A commit failure can leave an already-created account with a pending
confirmation: reopen and retry the same evidence while still live. Enrollment
fingerprints prevent duplicate/modified accounts, and tombstones prevent revival
if that account was deleted in between. Never replace this with delete-then-create.

Wrong-code counters must commit even though confirmation returns denial; returning
an error from the transaction callback would roll them back. Creation/backend
failure preserves pending evidence. Success is single-use across independent
handles. Concurrent BEGIN attempts can briefly retain read locks, so an actual
COMMIT may fail as busy even without a long-lived reader. Concurrency tests must
assert at most one initial success, allow explicit ErrCommitUncertain, then drain
and reopen before reconciling any zero-success outcome. Verify the same account
UUID, one final confirmation and rejected replay; never retry COMMIT or weaken
uncertainty handling to make a one-winner fixture deterministic. Cancellation or
uncertain commit withholds success. Account commit uncertainty and failures after
a known account commit retain ErrCommitUncertain so hosts reconcile both handles;
an unavailable dependency is never treated as denial-only. Deleting an entry
cancels pending state and clears secrets but preserves its ID history.

## Portal and notification behavior

The optional ConfirmationProvider hook runs before the legacy code comparison,
DeleteRegistrationEntry and AddUser sequence. It accepts exactly one body code,
rejects duplicate/query-only values, passes request cancellation, and returns a
303 to login only after confirmation succeeds. It does not issue a session or
JWT, execute legacy AddUser, or send an admin approval notice. Errors use a generic
page and do not disclose backend details. Legacy providers retain their old flow.
The SQLite provider explicitly rejects direct AddUser.

Notify supports registration_confirmation. It reloads bound pending identity and
checks the supplied code; incoming username/email/realm/URL cannot redirect its
recipient or link. It clones input, uses the configured origin/base path, and
reuses registry's escaped quoted-printable HTML renderer through the outbox.
Notification failure causes the portal to cancel pending enrollment. There is no
resend API, domain-MX lookup, invitation code, terms requirement or admin workflow.
Successful email confirmation proves mailbox access; it is not an MFA factor.

## Acceptance

```
make test TEST_DIR='./plugins/registration-workflows/sqlite/... ./pkg/registry ./internal/tag'
make test TEST_DIR=./pkg/authn TEST='TestE2ERegistrationConfirmationCapability'
```

Units cover attempt budgets, expiry during a real account-database writer lock,
binding, capacity, concurrent confirmations, credential redaction and backend
failure. A real second SQLite reader forces the
pending commit to fail after the account commit; reopening must preserve the same
account UUID and must not resurrect a deleted account. The portable consumer E2E
uses real TLS forms at a nested mount, a forced pending COMMIT failure followed
by fresh-handle recovery preserving account identity, invalid reload rejection,
expiry during account-database contention, a hostile Host, outbox link/code
extraction, workflow/portal restart, invalid/duplicate/query-only codes, replay,
native login and independent JWT verification. Run its isolated external-module
driver. Core TLS coverage
checks the legacy path and that a failed capability cannot fall through.
Also run public units/parser/consumer with CGO_ENABLED=0, excluding the
external-module driver which intentionally runs Go's race detector.

## Bound post-registration navigation

The portal captures a validated `return_url` in the immutable pending entry.
The workflow stores this optional metadata (at most 16384 bytes, valid text),
without treating it as identity or credentials. Confirmation and cancellation
clear this metadata along with the pending secrets. Portal trust rules are applied
at capture and again when successful confirmation releases it. A confirmation
query or shared cookie cannot replace it. The capability path reads metadata
before consuming the record, withholds navigation on failure/uncertainty, and
returns a login URL with an explicit destination (empty means portal). The local
registry cache snapshots maps on insertion and retrieval and refuses overwriting
an existing ID;
its successful legacy confirmation page carries the same navigation.

Pending storage is version 2, adding `return_url TEXT NOT NULL DEFAULT ''`.
`internal/sqlitedb.OpenMigrated` checks the exact version-1 schema, upgrades and
checks the exact final schema in one immediate transaction. Existing entries
retain all evidence and receive an empty destination; unknown versions, schema
drift and failed migrations do not proceed. Drain old runtimes before upgrading;
older binaries cannot reopen version 2. The public consumer E2E starts with a
version-1 database, registers through TLS, restarts, reconciles an uncertain
confirmation, then submits the rendered login form and checks its final URL.
