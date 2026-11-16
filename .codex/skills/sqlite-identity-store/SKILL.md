---
name: sqlite-identity-store
description: Maintain the pure-Go SQLite password identity store, reusable parser, immutable account evidence, idempotent enrollment, portal injection, identity-bound profile reads/password changes, management projections, and login E2E tests. Excludes local JSON database internals and unsupported credential collections.
---

# SQLite Identity Store

`plugins/identity-stores/sqlite` implements `ids.IdentityStore` and the optional
`WithRefreshIdentity` transaction capability, `ids.IdentityRequestStore`, and
`identity.StoreCapabilityProvider`. It reports kind `sqlite`, never
`local`. Inject an open store into `authn.PortalParameters.IdentityStores` and
select its name in `PortalConfig.IdentityStores`. Root hosts describe it through
`ids.NewExternalIdentityStoreConfig(name, "sqlite", realm, normalizedConfig)`,
append that descriptor to `Config.ExternalIdentityStores`, and provide the open
handle in `ServerOptions.IdentityStores[name]` to `NewServerWithOptions`. This
preserves ordinary root assembly; built-in factories remain local/LDAP-only.
The host owns the handle on success and on constructor failure, and closes it
only after every sharing portal/root drains.

Descriptors contain name, actual kind, realm and a SHA-256 configuration digest;
they contain no backend path, credentials or runtime handle. Normalize backend
configuration through its parser/Validate before deriving the descriptor. Native
JSON retains the descriptor but requires fresh runtime bindings after decoding.
Root validation includes external names in default portal selection, disabled
selection filtering and name/realm collision checks. Missing/extra bindings,
misidentified or unconfigured handles, duplicate names and built-in kind
impersonation fail before root resources are acquired.

The descriptor digest participates in persistent root compatibility. Root
construction never attaches persistent state to an injected store or overrides
its fresh proof epoch. Reopening SQLite invalidates restored refresh evidence;
previously issued JWTs keep their configured lifetime. Changed backend identity
or normalized configuration retires persisted authority through the root binding.
Legacy local registry wiring, provider attachments and downstream OIDC local
identity adapters do not accept this backend; profile credentials still require
their independent capability. A password login integration does not grant those
surfaces.

## Configuration and provisioning

Import the public parser and call
`NewSQLiteIdentityStoreConfigFromDirectives([]string)`. The grammar requires
`name`, `realm`, and absolute `path`; optional `timeout` defaults to 1s and accepts
1ms through 30s. Each setting takes one value and occurs once. Parsing has no
filesystem side effects; `New(ctx, config)` snapshots settings and opens a
configured store without creating a default user. GetConfig returns identifiers
only. Read [private SQLite backends](../plugin-development/references/sqlite-backends.md)
for file/durability/error contracts. Database files are private plaintext with
bcrypt hashes; production uses pure Go. Do not share files across categories.

`Create(ctx, *Account, password)` provisions trusted username/email/name/roles.
Usernames and email are canonicalized to lowercase. Usernames use 3–64 ASCII
letters/digits/underscore/dot/hyphen, starting with a letter or digit; `nobody` is
reserved for unidentified login attempts. Email must be a bare address. Roles
are 1–32 bounded identifiers. Passwords are exact UTF-8 plaintext, 12–72 bytes,
nonblank, hashed with bcrypt default cost. No password import grammar is exposed
on login, and no password is stored in Account or ordinary metadata.
The complete roles array must encode to at most 8 KiB using the stored JSON
encoding, including escaping. Validate this shared reader/writer bound before
creation, enrollment, replacement and additive updates; per-role byte limits
alone are insufficient. Additions validate the merged collection. An oversized
result fails without changing roles or credential generation, while bounded
role names containing JSON escapes remain supported.

Use [sqlite-registration](../sqlite-registration/SKILL.md) to change the email
confirmation workflow that composes this store with the SQLite outbox.

`HashPassword` and `CreateEnrollment(ctx, UUID, account, hash)` support trusted
registration composition. Enrollment accepts only validated default-cost bcrypt
hashes. Identical enrollment input returns the existing account without mutation;
conflicting input fails. Durable enrollment fingerprints survive account deletion,
so retries cannot resurrect a deleted account. The lifetime enrollment bound is
10,000 per database, including tombstones; do not prune them casually. A new
username after deletion receives a new account UUID and enrollment ID.

Trusted management supports generated-password AddUser/ResetUserPassword,
SetPassword, exact username/email DeleteUser/DisableUser/EnableUser, full role
replacement and atomic additive roles, metadata and detached account listing. Generated passwords appear
only in the explicit creation/reset result; protect those responses. Unsupported
stored challenge rules, MFA, API keys, public keys, connections and recovery fail
explicitly. Additive roles merge within one immediate transaction; an identical
retry preserves the credential version. All changed grants advance it. Account creation never overwrites an
existing username or email. No automatic self-service/admin route is installed.

## Authentication and issuance

Request supports IdentifyUser, Authenticate and trusted AddUser. Request context
comes from `requests.Request.Upstream.Request` when supplied; otherwise the
operation timeout bounds SQLite work. Bcrypt itself is bounded CPU work and
cannot be interrupted mid-comparison. Missing/disabled users follow the password
checkpoint with a reserved placeholder and one fixed-cost dummy comparison.
Never authenticate from a dummy match. Failed requests clear authentication and
response evidence; wrong-realm requests fail.

Successful password verification produces server-only immutable user ID,
credential version, per-instance epoch, time and `pwd` evidence. Each New creates
a new epoch, invalidating outstanding proofs from an earlier runtime. Fresh
lookups observe cross-instance mutations. Password, role and enabled-state
changes advance the credential version; deletion/recreation cannot preserve it.
Reload checks current health; it installs no cached account snapshot.

WithRefreshIdentity acquires an immediate SQLite transaction and keeps it through
fresh identity checks, challenge evaluation and signing. A callback must not
reenter the store or publish results before success. This serializes mutation
with issuance; failure/uncertain commit must withhold the token. Already issued
access JWTs retain their configured lifetime.
The transaction must retain its revocation lock until the callback returns,
including after cancellation or expiry of the account operation budget. Keep
callback work bounded and respect context errors; an early asynchronous rollback
must not let another connection revoke credentials during independent Documents
work. The database unit regressions and `TestE2ESQLiteDocumentsExpiredCallbackLock`
prove contention, rollback recovery, separate-write reconciliation and subsequent
revocation with real SQLite connections and TLS requests.
Queued identity operations must also observe quarantine before invoking their
callbacks, even if their initial availability check preceded the fault. The
shared helper owns this admission check. `TestE2ESQLiteDocumentsQueuedQuarantine`
forces an account COMMIT failure with a real reader, then verifies that a pending
Documents DELETE cannot mutate its independent database. Drain and reconcile
with a fresh handle and fresh login evidence after an uncertain account commit.

Direct HTTP Basic login applies transaction/policy checks to any selected
identity store whose kind matches the request method, including SQLite. Do not
restore a local/LDAP-only guard. Sandbox HTML/JSON issuance already selects the
capability independently of the kind name. The password-only factor inventory
is authoritative; portal rules requiring extra factors must deny issuance.
Refresh-engine identity composition is available through the capability, but
downstream OIDC adapters retain their separate support restrictions.

## Profile and administrative projection

`RequestWithIdentity` supports only `GetUser` and `ChangePassword`. It checks
immutable UUID, nonzero credential version, current instance epoch, exact
canonical username/email and any supplied realm inside one immediate transaction.
It invokes any server-owned `Request.ValidateIdentity` callback under that
transaction to reject sessions replaced while awaiting the lock. The callback
must not reenter storage. It never delegates to trusted provisioning. Reads return detached `identity.User`
values without password hashes or invented timestamps. Password changes verify
the exact old plaintext, reject reserved import prefixes, preserve significant
whitespace and atomically advance the version. Publish results only after commit;
closed/busy storage and uncertain commits must not look like successful writes.
Malformed or non-default-cost persisted bcrypt verifiers return `ErrUnavailable`
for profile password changes, matching login's storage-fault classification.
Do not blame the caller's old password or attempt an untrusted bcrypt cost.
Comparison-time decode failures also indicate storage faults; only bcrypt's
password-mismatch sentinel reports an incorrect old password.
Failure preserves the stored verifier and generation and publishes no success.
Transaction/lock-budget expiration preserves `context.DeadlineExceeded`, and
caller cancellation preserves `context.Canceled`. The HTTP adapter classifies
these as storage unavailability. A timeout before COMMIT rolls back without
poisoning the handle or advancing the generation; an uncertain COMMIT remains
the stronger reconciliation signal, including when joined with a context error.

The portal's current support is information, diagnostics, partial dashboard,
password changes and all Documents operations. MFA, API/public keys, stored login
rules, connections and OP remain unavailable. Read the
[capability and error contract](../authentication-portal-profile/references/store-capabilities.md)
when integrating clients. Capability metadata is informational, never authority.

Administrative `FetchUserData` returns `kind: sqlite`, canonical ID/username,
structured `email_address`, optional alias `name`, role objects,
`credential_version`, disabled state, capabilities and `credential_counts.password: 1`.
It does not return credential arrays/verifiers, invented dates or unsupported
zero counts. List metadata uses scalar email/name and string roles. Empty lists
are arrays. Only empty or `all` query is supported; other query values fail
explicitly. The complete list has a 10,000-account bound, advertised in metadata;
never truncate it silently. Reload checks health without replacing the proof epoch.

No schema change is needed for this support: existing accounts, immutable UUIDs,
enrollment tombstones and Documents binding survive an upgrade or rollback.
Rollback removes new HTTP capabilities, so coordinate clients and server versions.
Back up account and Documents files consistently; do not reseed or rename a backend
as an upgrade procedure.

## Acceptance

`profile_test.go` additionally checks stale/foreign proofs, concurrent additive
roles, durable password changes and real SQLite COMMIT failure. TLS journeys in
`pkg/authn/profile_sqlite_e2e_test.go` and `documents_sqlite_e2e_test.go` exercise
the public API, browser crypto, restart, source collision and revocation.
`TestIdentityRoleEncodingBound` covers escaped role expansion in every writer,
cumulative additions, unchanged proof after rejection and valid bounded grants.
The admin TLS journey verifies its failure envelope and retained profile access.
`TestIdentityProfileInvalidStoredPassword` and
`TestE2ESQLiteProfileInvalidStoredPassword` inject malformed and high-cost
synthetic verifiers, including invalid salt encoding with a valid cost header,
assert storage failure without mutation, then restore the
fixture and verify real password login still works. These are isolated storage
faults, not tests against operator accounts.

Unit tests cover canonical accounts, detached metadata, rejected input, enrollment
idempotency, deleted-account replay, instance epochs, credential/role/disable
revocation, fresh reopening, and a real second connection blocked while issuance
holds its transaction. The portable consumer fixture uses the public parser,
serialized config, a real TLS portal, browser sandbox, native login client, direct Basic login,
independent JWT verification, policy rejection, backend failure and restart.
Its mutation-after-verification fixture proves direct issuance rechecks current
identity. Run it both in this module and the isolated external-module driver.
Root consumer tests additionally exercise descriptor JSON restoration, native
TLS login and refresh, current-role invalidation, stateful stop/start with fresh
backend epochs, borrowed-handle ownership, failed construction and OIDC denial.
`TestE2ESQLiteAdminLifecycle` qualifies every advertised administrative mutation
through the TLS API: generated-password login, duplicate creation and wrong-selector
failures, full role replacement, idempotent additions, health reload, disable/enable,
password reset and deletion/recreation. Require positive login with returned credentials,
rejection of obsolete passwords/proofs, and unchanged vault ownership after credential
changes. Recreated usernames must receive a new UUID and cannot inherit the previous
vault. A successful HTTP status alone does not establish a management outcome;
inspect the status envelope and persisted state. The OpenAPI native journeys also
validate these responses against the authored schemas.

Management projection changes also require the SQLite registration unit and
public consumer suites, plus Caddy's registration journey when validating the
companion host. Those consumers inspect `email_address` and role records during
enrollment/recovery; JWT claims still contain string roles. Keep typed management
assertions and independent token assertions aligned without conflating them.

```
make test TEST_DIR='./plugins/identity-stores/sqlite/... ./pkg/ids ./internal/tag'
make test TEST_DIR='.' TEST='ExternalIdentity|ExternalSQLite'
make test TEST_DIR='./pkg/authn' TEST='TestE2EAuthenticationChallengeDirectTransaction|TestDirect|TestTokenIssuer'
```

Also run the public plugin units/consumer E2E with CGO_ENABLED=0, excluding the
external-module driver which intentionally uses the race detector. For changes
to shared portal issuance, run the existing authentication/challenge suites.
