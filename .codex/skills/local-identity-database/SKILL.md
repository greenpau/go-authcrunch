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
reload changes the backend epoch. Role removal must invalidate cached profile
and renewable authority even if the access JWT retains its ordinary lifetime.

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
