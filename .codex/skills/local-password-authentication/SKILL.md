---
name: local-password-authentication
description: Maintain local bcrypt and Argon2id password generation, prefixed imports, reusable hashing configuration/parser, duplicate detection, changes, resets, credential revocation, and authentication work equalization.
---

# Local Password Authentication

## Ownership

`pkg/identity/database.go` owns `Database.AuthenticateUser` and identity lookup.
`pkg/identity/password_verifier.go` owns `passwordVerifier`,
`newPasswordVerifier`, `activePasswordCost`, and `activeArgon2Password`. Keep enumeration defenses at
this shared database boundary so HTML, JSON, and other authentication callers
receive the same protection.

The local adapter delegates through `pkg/ids/local/store.go` and
`pkg/ids/local/authenticator.go`. HTML password challenges reach it from
`pkg/authn/handle_http_sandbox.go`; JSON challenges use
`pkg/authn/handle_json_login.go`.

`pkg/identity/password.go` owns password creation/import and `Password.Match`.
`password_argon2.go` owns bounded Argon2id PHC decoding, generation and matching.
Read [password hashing contracts](references/password-hashing.md) for formats,
public configuration/parser APIs, CLI options, resource limits and migration.
The default remains bcrypt; `argon2:` explicitly imports Argon2id v19.
`User.VerifyPassword` in `pkg/identity/user.go` still serves credential-change
checks. Substituting that per-user method for the database's store-wide verifier
would remove work equalization. Client protocol and refresh-evidence lifecycle
changes belong to their separate owning skills.

## Password Management

Keep encoded imports at trusted provisioning boundaries. Public registration and
`Database.RequestWithIdentity` password changes reject
`identity.IsPasswordHashImport` inputs before mutation; see the
[password hashing contracts](references/password-hashing.md). Do not apply this
restriction to login candidates or trusted configuration imports.

`pkg/identity/user.go` owns AddPassword, ResetPassword, ChangePassword, and
UpdatePassword. Their shared replacement helper installs a validated active
record and disables retained older records. Keep these mutation semantics
separate from the authentication verifier's raw-plaintext comparison schedule.

- Validate replacement input through NewPassword before mutating credentials.
  Creation/import trims surrounding whitespace; duplicate comparison uses that
  same normalized input. Validation must still reject invalid imports and
  overlength bcrypt plaintext even if a comparison could match an existing hash.
  Argon2 supports longer plaintext subject to the database password policy.
  Valid imports are checked as hashes, not measured against plaintext length
  policy; import cannot prove the original plaintext satisfies that policy.
  Plaintext policy checks use the same trimmed value that creation hashes;
  surrounding whitespace cannot satisfy a minimum password length.
- For plaintext duplicates, compare against the first active record with
  Password.Match. For bcrypt and Argon2 imports, compare the algorithm and parsed encoded hash directly;
  never verify the serialized import string as though it were plaintext.
- A matching first record is reusable only while enabled and unexpired.
  AddPassword retains its hash, timestamps, and existing history when reusable.
  It must still disable other enabled password records. A duplicate is a
  complete no-op only when there are no such records left to revoke.
- Do not return early from UpdatePassword merely because VerifyPassword
  accepts the candidate: another active credential may need revocation.
- ResetPassword always installs a fresh active record, even when the plaintext
  or imported hash is unchanged. Validate before disabling the old credential;
  a failed reset must leave credentials usable and state unchanged.
- Plaintext replacements of a first Argon2 record retain Argon2 with current
  generation defaults. Explicit imports may switch either way. New users and
  existing bcrypt users keep their default algorithm; login does not rehash.
- ChangePassword still verifies the old password before replacing credentials.
  Database mutation wrappers must continue advancing CredentialVersion and
  persisting it even when the active hash is reused. Hash deduplication does
  not preserve refresh eligibility.

An encoded-hash equality check is useful for repeated imports; independent
salted hashes cannot establish plaintext equality. Cover both forms instead
of substituting one comparison for the other. Preserve existing password
history limits when installing replacements.

`pkg/identity/user_password_test.go` covers duplicate-state preservation,
active/disabled/expired records, plaintext/imported replacements, multiple
active passwords, rejected input without mutation, persistence, and refresh
evidence invalidation. Use TestUserAddPasswordIdempotent, TestUserPasswordMutation
(the SameSecret, DifferentSecret, and InvalidInput cases), and
TestDatabasePasswordMutationPersistence for focused checks.

## Verification Invariants

For a nonempty password candidate, `AuthenticateUser` builds and executes the
verifier before returning for a missing or disabled identity. Hold the database transaction through schedule construction and verification;
file-backed verification also holds the canonical file lock through the fresh
snapshot and all password hashing. Follow
[local database transactions](../local-identity-database/SKILL.md). Preserve
failure evidence clearing, success evidence issuance, existing error contracts,
and the separate non-password/WebAuthn path.

The current schedule is derived from enabled users' active passwords:

- Ignore nil, disabled, and expired password records. Read each usable cost
  from `bcrypt.Cost` on the stored hash; `Password.Cost` metadata does not
  control bcrypt verification.
- Argon2 profiles come from fully validated PHC strings and include memory,
  iterations, parallelism, salt length and output length. Never use `Cost` for
  Argon2 work or derive from a malformed/unbounded PHC string. Unsupported
  algorithms fail closed; an omitted algorithm retains legacy bcrypt meaning.
- For each encoded bcrypt cost or Argon2 profile, take the largest active-password count
  belonging to any one account. Do not sum counts across accounts: adding more
  users with the same password profile must not add hashing work.
- Every target executes that ordered schedule. Use its actual active hashes
  where available and server-controlled dummy comparisons for remaining slots.
  Argon2 dummy slots derive with synthetic salts of the scheduled length.
  If no usable profiles exist in the store, perform one `bcrypt.DefaultCost`
  comparison.
- Never authenticate from a dummy match. Continue the complete schedule even
  after a real password matches.
- A stored hash can pass cost parsing but have a malformed salt. If its
  comparison fails before hashing, perform replacement dummy work for that
  slot. Invalid records must fail closed without creating a cheap target path.

For example, accounts with one cost-10 and one cost-14 password require one
comparison at each cost on every attempt. If one account has two active
cost-10 passwords, every attempt requires two cost-10 comparisons. Other
accounts with a single cost-10 password do not increase that count.

The dummy uses a fixed synthetic salt/checksum with the scheduled cost encoded
in its bcrypt representation. It is never a real identity credential, even if
its plaintext is known. Preserve a structurally valid representation that
executes bcrypt at every supported scheduled cost.

## Candidate Handling and Regression Rationale

Compare the submitted candidate as plaintext. Do not use `NewPassword`,
`NewPasswordWithOptions`, or the import parser to simulate authentication work.
Their creation semantics can trim whitespace, recognize `bcrypt:`/`argon2:` imports, or
reject overlength input before hashing. In the current dependency,
`GenerateFromPassword` rejects more than 72 bytes before hashing, whereas
`CompareHashAndPassword` still performs the comparison. Recheck these behaviors
when changing the bcrypt dependency.

The former missing-user `NewPassword` call also defaulted to cost 10, leaving
cost-14 accounts distinguishable even for ordinary wrong passwords. A dummy
hash at one arbitrary cost does not fix mixed-cost databases. The invariant is
comparable expensive work for every identity, not merely the presence of a
dummy-hash call or identical error text.

Do not special-case or ban `bcrypt:` or `argon2:` plaintext as the mitigation: a legitimate
stored hash can represent a password containing that prefix. If input limits
change, apply the intended validation consistently before identity-dependent
work and preserve the chosen password semantics across affected transports.

## Current State and Operational Cost

The schedule is rebuilt from the current transaction snapshot for each request.
Password replacement, import, reload, account enable/disable, and password
expiration/disable must be reflected immediately. Introducing a cache requires
covering these transitions and supported changes through the exported user
model without weakening the existing locking boundary.

A homogeneous database with one active password per user performs one expensive
comparison per attempt. Mixed algorithms, costs or multiple active passwords add padding
work for cheaper accounts. Construction also scans the user/password records;
it does not hash once per user. Argon2 profiles execute sequentially, so mixed
profiles add CPU and allocation work without retaining every memory arena. Assess this real latency and CPU
tradeoff when changing the algorithm. Local authentication already serializes
through the authenticator mutex, so contention can add queueing noise.

Equal password hashing work is not a claim of perfectly constant wall-clock time or a
complete defense against unrelated account-discovery signals.

## Validation

`pkg/identity/password_verifier_test.go` owns the focused regressions:

| Test | Contract |
| --- | --- |
| `TestPasswordVerifierWorkSchedule` | Equal comparison costs/counts across identities, mixed costs, multiple passwords, metadata mismatch, and successful matches without early return |
| `TestPasswordVerifierRejectsDummyMatch` | Instrumented and real matching dummy credentials never authenticate |
| `TestPasswordVerifierRealBcrypt` | Actual verification of correct passwords and plaintext prefixes, whitespace, and overlength candidates |
| `TestPasswordVerifierMalformedSalt` | Replacement work after a stored salt fails parsing |
| `TestPasswordVerifierCurrentRecords` | Work schedule follows current costs and account/password state |
| `TestDatabasePasswordVerification` | Database dispatch, username/email/case lookup, errors, and authentication evidence |

Argon2 coverage lives in `password_argon2_test.go`,
`password_argon2_verifier_test.go`, and `password_hash_config_test.go`.
`pkg/identity/password/parser` adds external parser units, an executable example
and a file-backed consumer E2E. `TestE2EArgon2PortalPasswords` covers configured
imports through shared-store provisioning, TLS HTML/JSON/Basic login, mixed
bcrypt/Argon2 stores, runtime restart,
password replacement and refresh revocation. Invalid PHC imports also fail
provisioning without persisting a user. The CLI executable E2E generates
and installs a hash, then authenticates with it.

`TestE2EPasswordConfigurationRejectsInvalidImport` also covers malformed bcrypt
headers. `password_input_test.go` and the identity request tests cover reserved
prefix recognition and unchanged credentials/revision/files after rejected
self-service imports. Registration checks live in
`pkg/authn/validators/user_input.go` before caching and
`pkg/registry/local_user_registry.go` before persistence; retain both boundaries.
`local_user_registry_password_e2e_test.go` covers provider persistence and reload,
and `profile_password_input_e2e_test.go` covers TLS rejection, old/new password
login and refresh eligibility. Trusted configuration import tests must keep passing.

Use the private per-verifier comparison/derivation boundaries for deterministic assertions
about completed work. Keep actual bcrypt success/failure tests alongside it;
malformed-input errors before hashing are not completed comparisons. Avoid
exact-millisecond unit assertions and global mutable comparison hooks.

For focused diagnostics and the repository report lifecycle:

```sh
go test -mod=readonly -race -count=1 ./pkg/identity -run 'Test(PasswordVerifier|DatabasePasswordVerification|DatabaseAuthentication|NewPassword)'
make test TEST_DIR='./pkg/identity/... ./pkg/ids/local ./pkg/authn ./pkg/authclient ./cmd/authdbctl'
```

When validating observable timing, use a real local portal and synthetic
accounts. For HTML login, POST username/realm to `/auth/login`, retain the
returned sandbox cookie, then POST `secret` to the redirected sandbox's
`password-auth` route. Missing cookies cause an earlier 401 and cannot measure
password verification. Use fresh sandboxes: the HTML failure limit belongs to
the checkpoint, and a new sandbox resets that counter.

Measure ordinary wrong passwords at different stored costs and include
`bcrypt:10:not-a-hash`, whitespace-only input, and a 73-byte candidate. Check
email/case lookup, successful login, status codes, and generic failure content.
JSON challenge validation trims whitespace; do not assume HTML and JSON accept
identical candidates. Disabled accounts are mapped to the placeholder identity
during identification, so a fast baseline response never proved that no record
existed at all.

Warm both paths, alternate or randomize their order, and keep CPU-heavy tests
separate from timing samples. Record distributions and fixture costs instead
of a universal timing threshold. Compare both homogeneous and mixed-cost
stores to expose regressions and the padding cost.

## Portal Password Attempt Admission

`pkg/authn/password_attempt_limiter.go` admits at most five failed/in-flight
password attempts per source before a five-minute block. Public IPv4 addresses
share a /24; private IPv4 and IPv6 use individual addresses. State is bounded and
owned/closed by each portal runtime. Every browser, JSON, direct Basic and
AuthProxy password path reserves an attempt before verification and completes it
exactly once. Preserve concurrent admission and delayed-success denial tests.
This is process-local, not a distributed rate-limit guarantee. Address metadata
comes from the embedding server's established proxy trust boundary.

Both local and remote Basic parsers must require a separator and nonempty
username/password after Base64 decoding. Keep unit and TLS Server regressions
for malformed input so a remote-authenticator path cannot bypass local guards.
