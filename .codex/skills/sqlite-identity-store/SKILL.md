---
name: sqlite-identity-store
description: Maintain the pure-Go SQLite password identity store, reusable parser, immutable account evidence, idempotent enrollment, portal injection, and login E2E tests. Excludes local JSON database internals and MFA/profile feature implementation.
---

# SQLite Identity Store

`plugins/identity-stores/sqlite` implements `ids.IdentityStore` and the optional
`WithRefreshIdentity` transaction capability. It reports kind `sqlite`, never
`local`. Inject an open store into `authn.PortalParameters.IdentityStores` and
select its name in `PortalConfig.IdentityStores`. Root configuration factories
remain local/LDAP-only; embedding hosts own selection and Close.

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
replacement, metadata and detached account listing. Generated passwords appear
only in the explicit creation/reset result; protect those responses. Unsupported
additive roles, stored challenge rules, MFA, API keys, recovery and profile
credential operations fail explicitly. Account creation never overwrites an
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

Direct HTTP Basic login applies transaction/policy checks to any selected
identity store whose kind matches the request method, including SQLite. Do not
restore a local/LDAP-only guard. Sandbox HTML/JSON issuance already selects the
capability independently of the kind name. The password-only factor inventory
is authoritative; portal rules requiring extra factors must deny issuance.
Refresh-engine identity composition is available through the capability, but
profile and downstream OIDC adapters retain their separate support restrictions.

## Acceptance

Unit tests cover canonical accounts, detached metadata, rejected input, enrollment
idempotency, deleted-account replay, instance epochs, credential/role/disable
revocation, fresh reopening, and a real second connection blocked while issuance
holds its transaction. The portable consumer fixture uses the public parser,
serialized config, a real TLS portal, browser sandbox, native login client, direct Basic login,
independent JWT verification, policy rejection, backend failure and restart.
Its mutation-after-verification fixture proves direct issuance rechecks current
identity. Run it both in this module and the isolated external-module driver.

```
make test TEST_DIR='./plugins/identity-stores/sqlite/... ./internal/tag'
make test TEST_DIR='./pkg/authn' TEST='TestE2EAuthenticationChallengeDirectTransaction|TestDirect|TestTokenIssuer'
```

Also run the public plugin units/consumer E2E with CGO_ENABLED=0, excluding the
external-module driver which intentionally uses the race detector. For changes
to shared portal issuance, run the existing authentication/challenge suites.
