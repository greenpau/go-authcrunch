---
name: refresh-token-identity
description: Maintain refresh-token login evidence, MFA completion, sandbox redemption, immutable local identity, credential-version invalidation, and transactional current-identity checks in AuthCrunch.
---

# Refresh Token Identity

## Ownership and Evidence

`pkg/authn/login_proof.go`, `sandbox_user.go`, `handle_http_sandbox.go`, and
`handle_json_login.go` carry login evidence into the shared issuer.
`pkg/authn/cache/sandbox.go` owns `Acquire`, `SandboxLease`, and single-use
`Redeem`. Serialize a sandbox request through its lease; successful checkpoint
checks alone do not prevent two requests from minting two refresh families.

Capture immutable user ID, credential version, and backend reload epoch when
identification/authentication begins. Record actual successful authentication
time and method on the server and retain them through MFA. JSON input and
transformed claims cannot supply or upgrade this evidence. Keep
`requests.AuthenticationEvidence` and the private fields on `user.User` out of
JSON/XML/YAML; preserve the relevant fields when cloning a user.

Every required checkpoint must pass before redemption and issuance. MFA
enrollment mutates credentials and is not proof of authentication with the new
factor: require a new completed login. A reset or policy change between password
verification and MFA must invalidate the pending evidence. Password, API key,
TOTP, WebAuthn, SSH, and GPG paths must record only methods actually verified.
Do not infer authentication strength from display/profile attributes.

## Local Identity Contract

`pkg/identity/refresh.go` owns `RefreshIdentity`, `WithRefreshIdentity`, and
credential-version invalidation. `pkg/ids/local/refresh.go` is the adapter and
exposes `RevokeUserSessions(ctx, immutableUserID)`. The persisted
`identity.User.CredentialVersion` defaults to zero for legacy files; new security
mutations advance it without rewriting every existing account in bulk.

In `pkg/identity/database.go`, password change/reset/update, MFA add/delete,
account disable/enable, and challenge-rule changes must invalidate captured
versions. Explicit session revocation uses the same boundary. Deletion denies
lookup; recreating a username must not reuse its immutable ID. Database reload
changes `LoadedAt` evidence so restoring an older file cannot restore refresh
eligibility.

Read current account state and re-evaluate required challenges on every
issuance. Role changes use fresh attributes rather than invalidating solely
because roles changed; new challenge requirements must already be satisfied
by verified evidence. A subject rename requires fresh login.

`WithRefreshIdentity` holds the local database lock through transformations,
signing, and the store commit. Security mutation therefore cannot interleave
between checking the credential version and returning credentials. Preserve
lock order and avoid re-entering the database from that callback. Any future
adapter must provide equivalent transactional/version guarantees; a snapshot
read followed by an unguarded commit is insufficient. Temporary lookup errors
must remain distinguishable from definitive denial so an outage does not spend
a valid refresh credential.

## Validation

Run `make test TEST_DIR='./pkg/identity ./pkg/ids/local ./pkg/authn'`.
`pkg/identity/refresh_test.go` covers evidence persistence, security mutation,
serialization exclusion, and mutation/signing serialization.
`pkg/authn/handle_api_refresh_token_test.go` covers real local/KMS issuance,
MFA/reset races, current roles and challenge policy, account lifecycle, and
single-use login. Add regression coverage at the mutation entry point and the
refresh boundary when introducing another security-relevant account operation.
