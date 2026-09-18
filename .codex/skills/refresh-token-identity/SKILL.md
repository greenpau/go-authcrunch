---
name: refresh-token-identity
description: Maintain refresh-token login evidence, MFA completion, sandbox redemption, immutable local identity, credential-version invalidation, and transactional current-identity checks in AuthCrunch.
---

# Refresh Token Identity

## Canonical Identity and Transformed Claims

Keep backend identity independent of output claim transformations.
`createSandboxUser` captures `user.User.LoginUsername` and `LoginEmail` from
the identified backend before transformation, alongside `LoginEvidence`.
These fields are excluded from JSON/XML/YAML and retained by `User.Clone` and
single-use sandbox redemption. HTML and JSON checkpoints use this canonical
identity; neither transformed `sub`/`email` nor a caller-supplied alias may select
another account. JSON continuation compares the newly identified canonical
username with the sandbox, so username, email, and case aliases can refer to
the same record across checkpoints.

`token_issuer.go` revalidates local access-only proofs through
`WithRefreshIdentity`, holding the backend transaction through current claim
transformation, challenge-policy checks, and signing. Compare current username
and email with the canonical sandbox fields, never transformed claims. Security
version changes, reloads, deleted/recreated accounts, or newly required factors
deny issuance. Credential mutation during an outstanding login, including MFA
enrollment, requires a new completed login. Other stores retain their
`IdentifyUser` contract and canonical username/email comparison; this fallback
does not promise transactional credential-version verification.

HTML and JSON access-only login both support email claim transformations.
Access-only token claims are transformed anew
from current attributes and retain the configured access lifetime. Renewable
access keeps its canonical `sub`; OIDC keeps its immutable derived subject and
backend UserInfo attributes. A transformed subject never becomes a backend
lookup key or an OIDC/refresh proof username.

Cached access-only users retain LoginEvidence, canonical LoginUsername/LoginEmail,
and an independent LoginMethods slice. Renewed users reconstruct those fields
from the server-only cloned `tokenrefresh.Result.Principal` and current backend
identity, never transformed access claims. Profile self-service consumes this
metadata through [its bound adapter](../authentication-portal-profile/SKILL.md).

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
account disable/enable, role changes, and challenge-rule changes must invalidate captured
versions. Explicit session revocation uses the same boundary. Deletion denies
lookup; recreating a username must not reuse its immutable ID. Database reload
changes `LoadedAt` evidence so restoring an older file cannot restore refresh
eligibility.

Read current account state and re-evaluate required challenges on every
issuance. Role changes advance CredentialVersion and require a new login; otherwise
cached profile roles could retain credential-management authority. New challenge
requirements must already be satisfied by verified evidence. A subject rename requires fresh login.

Use [local identity database](../local-identity-database/SKILL.md) for durable
locking, cross-instance revisions, snapshot adoption, TOTP and bound profile
operations. File-backed `WithRefreshIdentity` holds the canonical file lock as
well as the local database lock through transformations,
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
`pkg/authn/token_issuer_test.go` covers canonical snapshots, identity/version
denial, current challenge requirements, and the nontransactional store fallback.
`pkg/user/login_identity_test.go` checks independent cloning and serialization
exclusion. `pkg/authn/login_identity_e2e_test.go` uses public APIs, temporary
local stores, a real TLS portal and cookie jar, and independent JWKS signature
verification. Its matrix covers HTML/JSON, username/email aliases, password/TOTP,
refresh/OIDC off and on, excluded realms, renewal, single-use redemption, and
credential revocation between checkpoints. Keep the transformed-subject case
with two distinct accounts and passwords so a claim rewrite cannot change
whose credentials authenticate or whose roles are issued.
