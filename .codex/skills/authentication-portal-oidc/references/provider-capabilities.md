# Claims, authentication context and OIDC refresh

## Typed identity attributes and permissions

`identity.User.Profile` persists optional attributes in the private local user
JSON database. `identity.Profile` contains `given_name`, `family_name`,
`middle_name`, `nickname`, `profile` (Go `ProfileURL`), `picture`, `website`,
`gender`, `birthdate`, `zoneinfo`, `locale`, numeric `updated_at`, `phone_number`,
optional boolean `phone_number_verified`, and `address`. `identity.Address`
contains formatted, street_address, locality, region, postal_code and country.
These are record data, not Caddyfile/user directives. Populate them deliberately
through controlled identity provisioning; no default personal data is invented.
The conformance fixture populates an explicit disposable synthetic record.

The identity transaction passes an independent profile copy. Standard name,
username and email remain sourced from their existing canonical fields. A phone
verification flag is omitted without a number. Missing verification is distinct
from false; only a backend ownership check justifies true. The local portal
continues to return false for email verification. Do not infer either flag from
login, an address being present, or a transform.

`profile`, `email`, `address` and `phone` release their respective attributes at
UserInfo. `openid` alone releases only `sub`. The `claims` request parameter can
request individual claims at `userinfo` or `id_token` even without the associated
scope in the request, but only when that scope is registered for the client.
Each location/name is a separate consent item, bound to the code and tokens.
Prior openid consent cannot silently authorize an individual name. Unknown
claims are ignored. Invalid/duplicate JSON, malformed essential/value/values,
and conflicting value/values are rejected. Essential optional attributes do not
fabricate data or bypass registered permissions. Requested subjects must match;
an unmet essential ID-token ACR request fails with `access_denied`.

## Authentication context

The public provider parser accepts repeatable declarations:

```text
acr urn:example:password pwd
acr urn:example:password-otp pwd otp
```

They populate `Config.AuthenticationContexts` (`[]oidc.AuthenticationContext`).
Values are unique, nonempty identifiers; each mapping requires all its distinct
supported method names. The operator owns the vocabulary's meaning. Advertised
`acr_values_supported` lists these configured values. Selection first honors
requested values that the completed methods satisfy, then falls back to the
first satisfied configured mapping. The client cannot supply authentication
evidence. Hosts must validate `Authentication.Methods` against real completed
server authentication inside `IdentityVerifier.WithIdentity`. Configure only
contexts whose meaning those methods establish; no certification assurance
level is inferred. An essential unmatched ACR is rejected rather than echoed.

## Signed Request Objects

The shared client parser accepts repeated
`request_object_key <kid> <n> <e>` lines. These populate
`ClientConfig.RequestObjectKeys` (`[]oidc.RequestObjectKey`) with public RSA JWK
base64url integers. Keys are 2048–8192 bits, exponent odd and at least 3, at most
eight keys per client, with distinct nonempty IDs. Provision private signing
keys at the client; these fields never contain private keys.

`request_object_signing_alg RS256` pins signed objects and requires keys.
`none` pins the existing unsigned encoding; omitted accepts unsigned objects
and valid RS256 objects with registered keys. Neither setting disables PKCE or
client authentication at the token endpoint. Ordinary authorization requests
without a Request Object remain supported. An object is not login evidence.

Verification binds the signature to that client's keys, requires signed `iss`
and `aud` to identify the client and issuer, checks supplied JWT times, and
preserves client/response-type/effective redirect validation. Header-supplied
keys, remote key URLs, critical extensions, nested/encrypted objects, malformed
or duplicate JSON, and algorithm confusion are rejected. No request_uri fetch
is performed. Provider ID-token keys remain separate from client keys.

## Refresh-token lifecycle

Register `offline_access` explicitly among client scopes. Authorization must
include `prompt=consent`; otherwise offline_access is removed from the grant.
The consent screen always requires a new approval for this request, including
for clients with `skip_consent`. The approved authorization code can then yield
an opaque refresh token. No default/public-client PKCE policy changes.

`grant_type=refresh_token` uses the client's registered token authentication.
Every successful refresh rotates both credentials, invalidates the previous
access token, and retains the spent refresh hash. Replaying a spent credential
revokes the whole family, including concurrent successors. A wrong-client
attempt cannot revoke another client's family. An optional scope can only
narrow the grant, permanently; absent scope retains it. No ID token is emitted
when narrowed scope excludes openid. ID tokens preserve original subject,
audience, nonce, auth_time and verified methods; iat reflects new issuance.

State is SHA-256 indexed and volatile unless persistent runtime state is configured. `refresh lifetime <seconds>` maps to
`Config.RefreshLifetimeSeconds` (default 28800, maximum 86400), bounded by the
original server session's remaining life. It is never extended by refresh.
`max refresh tokens <count>` maps to `Config.MaxRefreshTokens` (default 10000,
maximum 1000000), counting active and spent credentials together. Capacity
returns temporarily_unavailable without evicting replay evidence or consuming
the current credential. Families expire with their code tombstones and hashes.

Explicit token revocation, code replay, browser logout/replacement, account
revocation, password/MFA policy changes, and expiry invalidate use. Closing the
provider rejects work on that instance; persistent grants are not erased by Close. Every issue and UserInfo request revalidates current identity in the same
serialized transaction. The refresh grant can run without a browser cookie;
it remains bounded by server session state. Without persistence, restart/reload
requires fresh authorization. Opt-in [runtime-state](../../runtime-state/SKILL.md)
retains complete families and replay history within unchanged configuration and
identity bindings. Pending browser interactions remain volatile. This is separate
from portal `/api/refresh_token` transport and storage.

## Validation

Run normal `make test`; local E2E remains enabled. Focused reports:

```sh
make test TEST_DIR='./pkg/oidc/... ./internal/tag' COVERAGE_DIR='.coverage/oidc-capabilities'
make test TEST_DIR='./pkg/authn' TEST='^TestE2EOIDC|^TestOIDC' COVERAGE_DIR='.coverage/oidc-portal'
```

`claims_test.go`, `request_keys_test.go`, and `refresh_test.go` cover permission,
JSON, ACR, key/signature, rotation, replay, client, capacity, expiry and scope
boundaries. Parser tests and examples cover new directives and errors.
`TestE2EOIDCClaimsAndRefresh` and `TestE2EOIDCSignedRequestObject` import the public
parser, persist and reload a real identity database, complete password login
and consent over trusted local TLS, and independently verify ID-token signatures
from fetched JWKS. `TestE2EOIDCRefreshRevocation` verifies explicit revocation,
logout, account disablement, password reset, MFA-policy changes and store reload
through the production management API using a separate authenticated administrator.
The optional official harness and exact results live in
[conformance](conformance.md). Consumer Caddy integration is separate work.

Keep administrative revocation requests in a separate client from the user's
browser cookie jar. Mixed admin bearer and user-cookie credentials can select
the wrong identity and invalidate the fixture's intended authorization boundary.
Record actual reports, diagnostics, and Foundation outcomes per run outside the
skill; those artifacts are evidence for that candidate, not permanent guarantees.
