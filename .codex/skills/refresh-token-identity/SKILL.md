---
name: refresh-token-identity
description: Maintain refresh-token login evidence, MFA completion, sandbox redemption, immutable local identity, credential-version invalidation, transactional current-identity checks, and captured upstream provider snapshots in AuthCrunch.
---

# Refresh Token Identity

Read [provider snapshot renewal](references/provider-snapshots.md) when changing
OAuth/OIDC-originated portal families, provider revalidation configuration,
captured claims, or their persistence. That evidence has a separate typed source;
local credential-version and profile authority must never be fabricated for it.

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
enrollment, requires a new completed login. The SQLite identity-store plugin
supplies the same optional transaction
capability with its own immutable IDs, versions and per-instance epochs.
Stores without that capability retain their `IdentifyUser` contract and canonical
username/email comparison; this fallback
does not promise transactional credential-version verification.

HTML and JSON access-only login both support email claim transformations.
Access-only token claims are transformed anew
from current attributes and retain the configured access lifetime. Renewable
access keeps its canonical `sub`; OIDC keeps its immutable derived subject and
backend UserInfo attributes. A transformed subject never becomes a backend
lookup key or an OIDC/refresh proof username.

Cached access-only users retain LoginEvidence, canonical LoginUsername/LoginEmail,
and an independent LoginMethods slice. Renewed local users reconstruct those fields
from the server-only cloned `tokenrefresh.Result.Principal` and current backend
identity, never transformed access claims. Profile self-service consumes this
metadata through [its bound adapter](../authentication-portal-profile/SKILL.md).

When consuming cached login evidence, first validate the presented access JWT,
then use `SessionCache.GetForToken(jti, token)` to require the exact token stored
with that evidence. A browser can reuse its session ID across logins; the ID is
only a lookup key and cannot bind a JWT to a later account's proof. Apply this
to portal/app pages, signed-in login navigation, profile, Documents and account
connections. Internal proof flows may use `Get` only with their independent
token binding, as cross-device approval does with a captured token hash.
Preserve rejection after cache deletion/replacement and successful use of the
current token. TLS tests must switch accounts within one browser, replay the
earlier token and verify that rejected mutations changed neither account.

Cached access-only session issuers add a fresh opaque `nonce` after claim transforms, including
external login and cross-device issuance. Keep the browser's existing `jti`
lookup contract, but distinguish separately issued tokens even for the same
account within one second. HMAC, RSA PKCS#1 and Ed25519 signatures are deterministic;
signature bytes alone cannot supply that distinction. The nonce is not an
upstream OIDC challenge and conveys no identity or factor evidence. Uncached
Basic/API-key proxy tokens do not select private session proof. Renewable
issuance already generates an independent `jti`. Test access-only session uniqueness
with a frozen clock and deterministic signer, and keep real TLS reauthentication
after credential revocation in scope.

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

Challenge selection and AMR belong to
[authentication challenge policies](../authentication-portal-challenges/SKILL.md).
`RefreshIdentity.AuthMethods` carries current registered-factor inventory separately
from completed methods. Access, refresh, and OIDC adapters pass that inventory to
transforms and check the selected replacement sequence plus additive requirements.
`recordLoginEvidence` collects `Checkpoint.Method` for access-only logins too.

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
lookup; recreating a username must not reuse its immutable ID. Volatile database
reload changes `LoadedAt` evidence. With [runtime-state](../runtime-state/SKILL.md),
only the exact last committed file digest can retain that epoch; a replaced or
rolled-back identity file still invalidates old evidence. Keep private proof
serialization separate from public user/config JSON.

Read current account state and re-evaluate required challenges on every
issuance. Role changes advance CredentialVersion and require a new login; otherwise
cached profile roles could retain credential-management authority. New challenge
requirements must already be satisfied by verified evidence. A subject rename requires fresh login.

Use [local-identity-database](../local-identity-database/SKILL.md) to change
transaction locking, cross-instance revisions, snapshot adoption, durable TOTP,
or identity-bound profile operations. File-backed `WithRefreshIdentity` holds the canonical file lock as
well as the local database lock through transformations,
signing, and the store commit. Security mutation therefore cannot interleave
between checking the credential version and returning credentials. Preserve
lock order and avoid re-entering the database from that callback. Any future
adapter must provide equivalent transactional/version guarantees; a snapshot
read followed by an unguarded commit is insufficient. Temporary lookup errors
must remain distinguishable from definitive denial so an outage does not spend
a valid refresh credential.

## Cross-device evidence reuse

[Cross-device browser login](../authentication-portal-cross-device/SKILL.md)
snapshots the completed HTML sandbox proof only after successful normal login.
Local requester redemption reuses `issueSandboxTokens` and `finishOIDCLogin` with the
requester's HTTP context, preserving canonical identity, verified AMR, current
challenge selection and credential-version checks. Each device gets its own
family/session; neither an API key nor a client claim can supply this proof.
An external login completing attached local MFA retains the external transfer
contract: access-only requester credentials, expiry bounded by the approving
login, and no local OIDC session. Dispatch by its separate external proof,
not by the last checkpoint's authenticator or presence of a callback snapshot.

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
