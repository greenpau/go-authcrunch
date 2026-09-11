---
name: refresh-token-implementation
description: Implement or change AuthCrunch portal refresh configuration, opaque token families, atomic rotation, replay revocation, issuance claims, store adapters, and portal lifecycle. Use for portal refresh tokens, not upstream OAuth token renewal.
---

# Refresh Token Implementation

The implementation is opt-in under `authn.Config.RefreshTokens`. Read
[configuration and client contract](references/configuration-and-clients.md)
when exposing settings, integrating clients, or changing public behavior.
Use `refresh-token-identity` for login proof and identity revalidation, and
`refresh-token-transports` for HTTP, cookies, browser coordination, and logout.
These are distinct boundaries; a change may require more than one owner.

## Ownership

- `pkg/authn/refresh_config.go`: serializable config, defaults, canonical HTTPS
  origin/mount validation, cookie naming, durations, and capacity bounds.
- `pkg/authn/portal.go`: configured-realm capability checks, manager creation,
  failed-construction cleanup, and `Portal.Close()`.
- `pkg/authn/token_issuer.go`: shared access/refresh issuance. HTTP and JSON
  sandbox login must call the same issuer; `grantAccess` only delivers signed output.
- `pkg/authn/refresh_runtime.go`: portal adapters, current transformations,
  challenge checks, and KMS signing.
- `pkg/authn/refresh/{token,store,memory,manager}.go`: opaque encoding, store
  contract, bounded in-memory families, and staged issuance/rotation.
- `pkg/kms/crypto_keystore.go`: actual access signing-key lifetime selection.

## Issuance and State

A refresh family originates only from a completed, single-use local login.
An access JWT, user-supplied method list, or refresh token from an OAuth provider
cannot create that evidence. Disabled refresh allocates no store and preserves
existing access-token lifetime behavior. Unsupported or ambiguous configured
realms fail portal construction; never silently claim renewal support.

Raw refresh credentials use `acr1_` plus 32 random bytes in canonical unpadded
base64url. Persist only their SHA-256 digests. Public `sid` and `jti` values
are independently random and do not encode credentials. Session snapshots must
copy owned slices; caller mutation must not change stored grants.

Keep the family binding fixed: portal, exact origin, mount, and transport.
Retain immutable backend/user identity, original authentication evidence,
original audience/scope grant, current and spent digests, revision, and idle and
absolute deadlines. Every renewal has a new `jti`, `iat`, `nbf`, and `exp`;
`sid`, `sub`, `iss`, `auth_time`, and verified `amr` stay bound to the login.
Rebuild roles from current identity and transformations. Audiences and scopes
can shrink but cannot expand, and transformations cannot invent `acr` or
replace the authentication event. Losing all originally granted audiences
requires login. Cap access expiry by both refresh config and the selected
access signing key, ignoring system-only signing keys.

Stage identity revalidation, the next opaque token, and JWT signing before
committing. `Store.Rotate` must atomically recheck current digest, revision,
revocation, idle/absolute deadlines, and staged JWT expiry. Return credentials
only after commit. A signing or transient backend failure leaves the current
credential unspent; a definitive identity denial revokes the family.

A known spent token with the correct binding revokes its entire family,
including the current descendant. Unknown tokens or wrong bindings cannot
revoke another family. Keep spent digests recognizable until absolute expiry.
Strict concurrent reuse can return one success followed by family revocation;
there is no grace period or transparent retry of an ambiguous exchange.

## Lifetime and Extension

The portal currently constructs its own bounded memory store. Capacity fails
closed; exhausted rotation limits require login. Cleanup occurs on creation,
not through an extra refresh goroutine. Restart, portal replacement, and local
identity database reload require fresh authentication. Quiesce requests before
`Portal.Close()`; failed construction must stop owned cache workers as well.

A distributed adapter must satisfy the `Store` atomicity contract across all
instances and coordinate identity changes with issuance. Implementing an
interface alone does not expose configurable distributed storage. Do not promise
restart continuity, upstream refresh, or immediate revocation of stateless
access JWTs without implementing their separate integration boundaries.

## Validation

Use `make test TEST_DIR='./pkg/authn/... ./pkg/identity ./pkg/ids/local ./pkg/kms'`
and `make test-ui` for an affected-flow run; `make test` covers all Go packages
with race detection and reports. The narrow suites are
`pkg/authn/refresh/manager_test.go`, `pkg/authn/refresh_config_test.go`, and
`pkg/authn/handle_api_refresh_token_test.go`. Preserve concurrent reuse,
logout-during-signing, failed-signing retry, replay isolation, expiry during
commit, capacity, realm capability, disabled-feature, and single-use-login cases.
Fuzz token grammar with
`go test ./pkg/authn/refresh -run '^$' -fuzz FuzzRefreshToken -fuzztime 5s`.
