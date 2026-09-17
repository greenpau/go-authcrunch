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

State is process-local and SHA-256 indexed. `refresh lifetime <seconds>` maps to
`Config.RefreshLifetimeSeconds` (default 28800, maximum 86400), bounded by the
original server session's remaining life. It is never extended by refresh.
`max refresh tokens <count>` maps to `Config.MaxRefreshTokens` (default 10000,
maximum 1000000), counting active and spent credentials together. Capacity
returns temporarily_unavailable without evicting replay evidence or consuming
the current credential. Families expire with their code tombstones and hashes.

Explicit token revocation, code replay, browser logout/replacement, account
revocation, password/MFA policy changes, provider close and expiry invalidate
use. Every issue and UserInfo request revalidates current identity in the same
serialized transaction. The refresh grant can run without a browser cookie;
it remains bounded by server session state. Restart/reload requires fresh
authorization. This is separate from portal `/refresh` transport and storage.

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


## Recorded validation and diagnostics

September 17 validation used the repository `go tool tested` lifecycle with race
detection and uncached tests. The full regression report at
`.coverage/oidc-full/index.html` recorded 67 passing packages, 6135 passing tests
and 6 skips. The skips are the explicitly opt-in Foundation test and five
pre-existing `pkg/acl` cases in `TestCustomAccessList`: missing roles, existing
metadata, email outside foo.bar, custom foo=bar, and exp within two hours.
They were not introduced or cleared by this change.

Final changed-code reports are `.coverage/oidc-capabilities-final/index.html`,
`.coverage/oidc-final-regression-2/index.html`, and
`.coverage/oidc-evidence/index.html`. The separate portal protocol regression is
`.coverage/oidc-portal/index.html`. Earlier failed runs remain in distinct
report directories. The first new management-revocation fixture failed because
it sent Alice's browser cookie with an administrator bearer credential; it now
uses the administrator's separate HTTP client, and the real API revocation cases
pass. Authentication/authorization policy was not changed to clear that fixture.

`go vet ./...` and `make linter` passed. `gopls v0.23.0 check -severity=hint`
examined every changed/new Go file, with follow-up checks after edits. No
in-scope diagnostics remain. Existing hints were left unchanged: legacy
`interface{}` declarations in `internal/tag/tag_test.go` and
`pkg/identity/user.go`, and ineffective omitempty on existing time.Time fields
in the latter. Raw diagnostics are retained at
`tmp/oidc-diagnostics-final.log`; these are not claims of a globally hint-free
repository. The OIDC skill passed the skill-creator quick validator.
