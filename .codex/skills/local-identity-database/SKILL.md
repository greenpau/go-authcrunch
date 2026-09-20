---
name: local-identity-database
description: Maintain local identity database transactions, file locking and atomic persistence, cross-instance credential revocation, authenticated self-service operations, and TOTP replay/lockout state.
---

# Local Identity Database

`pkg/identity/database.go`, `database_atomic_write.go`, `database_file_lock*.go`,
`identity_request.go`, and `refresh.go` own persistence and security transactions.
`pkg/ids/local` holds the authenticator lock across database replacement and
adapts the optional `ids.IdentityRequestStore` interface. Password hashing belongs
to `local-password-authentication`; portal login proof belongs to
`refresh-token-identity`.

File-backed security decisions use a freshly decoded, normalized and indexed
snapshot under the canonical sidecar lock. Hold that lock through password/API-key
verification and through current-identity issuance callbacks. A locked read
followed by unlocked verification/signing permits revocation to race success.
Preserve lock order: local authenticator, live database, canonical file lock;
callbacks must not reenter that database or another alias of the same file.

Generic commits compare the persisted Revision with the writer's snapshot.
On a stale revision, adopt current state, invalidate the old backend epoch and
return a conflict; never overwrite a newer password, role, disabled flag or
credential version. Callers must re-evaluate against current state before retry.
Do not automatically retry a mutation already authorized with stale evidence.
Fresh self-service transactions may commit an isolated current snapshot once.

Normalize legacy policy/password defaults and rebuild all username/ID/email/
API-key indexes when loading transaction snapshots. Adopt the complete committed
snapshot; copying only Revision or a TOTP counter can make stale credentials
appear current. Preserve the live mutex, path and runtime ownership. Response
objects returned to consumers must not alias newly adopted live records.

`RequestWithIdentity` permits only explicitly listed self-profile operations.
Require canonical username/email, immutable user ID, credential version and
backend epoch, enabled account and unlocked state inside the transaction.
Execute on an isolated in-memory target; persist only a successful mutation,
and publish detached live state. The unbound generic Request remains a trusted
programmatic/admin API, not a browser authorization mechanism.

Password, MFA, role, account status, challenge policy and explicit revocation
changes advance CredentialVersion. Deletion/recreation changes immutable ID;
reload changes the backend epoch unless [runtime-state](../runtime-state/SKILL.md)
restores it for the exact committed database digest. Propagate the state record
to self-service and MFA transaction targets; update its digest under the file lock
after the database write. A copied database must not alter the source record.
When attaching runtime persistence, adopt the identity file read under its lock
before associating that digest with the backend epoch. Construction may have
loaded an older snapshot before another instance committed a mutation.
Role removal must invalidate cached profile
and renewable authority even if the access JWT retains its ordinary lifetime.

Successful `LookupAPIKey` captures server-only `AuthenticationEvidence` with
method `api_key` and the exact `APIKeyID`; failed lookups clear old evidence.
Direct issuance preserves that proof across `IdentifyUser`, which only captures
an identification snapshot. `WithRefreshIdentity` checks that this exact key is
still present, enabled and unexpired while holding the issuance transaction.
Key deletion does not revoke unrelated password/MFA evidence. Never replace
the verified key proof with a newer identification version, or repeat bcrypt
outside the transaction as a substitute for protecting issuance. The `api_key`
marker is internal proof, not a password/MFA AMR claim or renewable session.

TOTP acceptance persists a monotonic `LastTOTPCounter` before success. Replay
and earlier counters fail, including across processes, restart and symlink
aliases. Failure increments, resets and expired-lockout clearing are fresh
read/mutate/write transactions; stale login evidence cannot affect a replacement
or revoked identity. Never treat an ignored conflict as a counted failure.
MFA callers must provide original server-held evidence, including failure paths.

Atomic persistence writes a temporary file, syncs it, replaces the destination
and syncs its directory where supported. Preserve existing mode bits; new private
files use 0600. `Copy` writes an isolated source snapshot without advancing the
live source revision or merging destination TOTP state. Hardlink aliases and
network filesystems without reliable advisory locks are outside this contract.

Run identity/local tests plus real TLS `identity_alias_e2e_test.go`: two realms
sharing a file, revoked passwords/API keys, pending TOTP/WebAuthn, refresh
revocation, shared lockout, role removal, conflicting writes and backup continuity.
Use deterministic synchronization for verification/issuance races. Compile-only
Windows/illumos checks are not runtime filesystem-lock evidence.

`api_key_evidence_test.go` covers proof capture, failed-lookup clearing, exact
key ID, disablement/expiry/deletion, and unrelated password-proof continuity.
The portal's `authentication_challenges_transaction_e2e_test.go` checks those
issuance boundaries through real TLS direct-login consumers; see
[authentication challenge policies](../authentication-portal-challenges/SKILL.md)
for current policy, inventory, and direct issuance rules.
