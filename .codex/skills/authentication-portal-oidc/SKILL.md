---
name: authentication-portal-oidc
description: Maintain the reusable pkg/oidc OpenID Provider, its public interfaces and methods, and the local-user authentication portal adapter, including client registration, discovery, code/PKCE, consent, ID-token keys, UserInfo, revocation, and conformance tests. Excludes upstream OAuth identity providers and portal refresh-token transport.
---

# Authentication Portal OpenID Provider

## Ownership

`pkg/oidc` owns the reusable provider. `Provider` is an exported concrete type;
`OpenIDProvider` is its public HTTP and browser-lifecycle interface. `NewProvider`
validates and snapshots `Config`, requires an `IdentityVerifier`, and accepts
runtime `Options`. The package has no dependency on the `authn` portal runtime.

- `config.go`: public `Config`, `ClientConfig`, and validation.
- `provisioning.go`: public client constructors, credential generation,
  `Config.AddClient`, and dedicated signing-key generation in PEM or a new file.
- `client_config_parser.go`: `NewClientConfigFromDirectives(nickname, statements)`
  parses an OAuth application block body with the crypto-style `cfg.DecodeArgs`
  encoding. Caddy adapters collect statements using `cfg.EncodeArgs`.
- `identity.go`: public `Authentication`, `Identity`, `IdentityVerifier`, and
  `OpenIDProvider` contracts.
- `options.go`: construction, configurable login URL, cookie names, and excluded
  signing keys; `provider.go`: bounded sessions, consent, and browser lifecycle.
- `keys.go`: dedicated RSA PEM loading, thumbprints, public `JWKS`, signing, hints.
- `http.go`: public `ServeHTTP`, `HandleHTTP`, `ValidateLoginRequest`, and
  `Discovery`, guarded issuer routing, parsing, CORS, and buffered responses.
- `authorization.go`, `request_object.go`, `token.go`: code/PKCE, consent,
  unsigned Request Objects, client authentication, UserInfo, and revocation.

`pkg/authn/oidc_runtime.go` supplies `portalOIDCIdentityVerifier`, local-realm
validation, key/cookie isolation, and sandbox/browser adapters. `configureOIDC`
runs after portal keys and optional refresh configuration. `Portal.Close` closes
the provider; `Portal.GetOIDCProvider` exposes its public interface.
`pkg/authn/oidc_config.go` retains `OIDCProviderConfig` and `OIDCClientConfig` as
aliases; `PortalConfig.OIDCProvider` keeps its `oidc_provider` serialization.

Read [reusing the Go provider](references/reusable-provider.md) when embedding
`pkg/oidc` independently or changing its public API and identity boundary.
Read [configuration and clients](references/configuration-and-clients.md) for
setup and operational constraints. Read [conformance](references/conformance.md)
for the targeted certification profiles, supported features, test evidence,
and the OpenID Foundation test-plan configuration.

Upstream OAuth/OIDC login belongs to `oauth-identity-provider`. Existing portal
JWT JWKS and admin key export belong to `authentication-portal-jwks`. Provider
keys are deliberately independent of those portal credentials.

## Identity and Login Boundaries

The portal adapter permits only explicitly configured, unambiguous local realms.
It uses the existing portal password/MFA sandbox, `recordLoginEvidence`, and atomic
sandbox redemption. `finishOIDCLogin` accepts completed server-side evidence;
portal access JWTs, ID tokens, API keys, JSON claims, and native refresh
credentials cannot substitute for this proof. Native body transport must set
no cookies during login, refresh, or logout, including error responses.

OIDC browser credentials use the portal cookie factory's configurable names:
`AUTHP_OIDC_SESSION_ID` and `AUTHP_OIDC_REQUEST_ID` by default. They honor
`cookie_config.cookie_name_prefix` and explicit name overrides. Credentials are
random, host-only cookies with Secure, HttpOnly, SameSite=Lax, and the issuer
mount as Path (root issuers use `/`). Use distinct names or prefixes for portals
with overlapping mounts on one host. Issuance and deletion use matching paths;
lifetimes remain provider-owned. Duplicate cookies are rejected. Successful interactive
login replaces the previous provider session; external/LDAP portal login clears
it without making that external identity eligible. Logout clears provider
sessions and pending interaction. When a refresh cookie is present, GET logout
only displays confirmation; the protected browser POST clears provider state
after refresh revocation succeeds. Native logout must not touch browser state.

Each session retains immutable local user ID, backend reload epoch, credential
version, original authentication time, actual authentication methods, and
completed challenges. Every authorization, redemption, and UserInfo call uses
`WithRefreshIdentity` to check current account state and current transformed
challenge policy. The public subject is a SHA-256 digest of a JSON array of
backend name, realm, and immutable record ID. Do not derive it from a username,
email, transformed subject, or credential version.

The lock order is provider mutex, then `IdentityVerifier.WithIdentity`, then
the local store/database transaction. Verifiers finish fallible backend work
before invoking their callback and return its result without later fallible work.
No identity callback reenters the provider. Signing and credential publication
commit inside the identity transaction. Network response writes occur after
state locks are released, through `oidcHTTPResponse`.

## Protocol Invariants

Provisioning is explicit: `NewClientConfig` generates missing credentials and
enables S256 PKCE. `Validate`, `Config.AddClient`, and `NewProvider` never generate
credentials. Embedders persist generated registrations and signing keys before
starting the provider, then reuse them on reload. `AddClient` validates and copies
the registration, rejects duplicate IDs, and does not mutate running providers.
`NewClientConfigFromDirectives` is also a provisioning constructor: omitted
credentials are generated. It accepts single-value fields, multi-value
`redirect_uris`/`scopes`, and `cfg.ParseBoolArg` booleans. It rejects duplicate or
unknown directives and never includes raw statements or values in errors.
`GenerateSigningKeyFile` publishes a complete owner-only file with a hard link;
it never overwrites existing paths or follows a destination symlink.

Validate the client and exact registered redirect URI before any redirect.
Never normalize an untrusted redirect into a registered value. Reject duplicate
parameters across query/body, malformed escaping, oversized requests, unsupported
methods, and multiple client authentication mechanisms. Decode HTTP Basic
username and password using OAuth form encoding before comparison. An optional
body `client_id` must match the authenticated Basic identifier; body secrets
cannot accompany Basic.

Authorization supports `code`, `query` and `form_post`; confidential clients use
`client_secret_basic` or `client_secret_post`, public clients use `none` with
mandatory S256 PKCE. Unsigned by-value Request Objects (`alg: none`) encode
untrusted authorization parameters; they never authenticate clients or users.
Object parameters take precedence, except client ID and response type must match
the required outer values. Validate the effective redirect against registration.
Reject duplicate JSON members, nested requests, signed/encrypted objects, and
invalid JWT metadata. Remote request URIs return `request_uri_not_supported`
without network fetches. ID tokens still require RS256. Discovery advertises
only implemented capabilities. `claims` requests are not supported/advertised; optional unrecognized
parameters are ignored. Unknown scopes are omitted from the granted scope.

`prompt=none` never renders interaction. Prior consent covers only scopes
actually approved for that client within the current session. `prompt=consent`
requires a new decision; `prompt=login`, `select_account`, and stale `max_age`
require new checkpoint completion with appropriately recent original authentication
time. Redeeming an older verified sandbox afterward cannot satisfy these freshness
requirements; check authentication age again on continuation. Hints must verify
with dedicated issuer keys
and match the requesting audience; expired hints may identify a session but
never authenticate it. Consent requires a browser-bound random CSRF value and
rejects cross-origin submissions. Template output escapes all client/state data;
form-post auto-submission is protected by a per-response CSP nonce.

Authorization codes expire after 60 seconds. Redemption atomically checks
client, exact redirect URI, PKCE, expiry, and current identity. Keep spent-code
tombstones until the resulting access token expires. A replay revokes that token,
including concurrent replays. All opaque credentials are stored by SHA-256 hash.
Capacity exhaustion fails closed; active state is never evicted to admit a new
request. One pending interactive authorization per browser is supported; a new
interaction supersedes the old one and invalidates its consent form.

Dedicated RSA keys must be 2048–8192 bits and must not overlap portal verification
keys. All ID tokens use RS256 with a public-only JWKS and stable thumbprint `kid`.
ID tokens contain issuer, immutable subject, client audience, numeric times,
verified `amr`, `auth_time`, `at_hash`, and the exact nonce when supplied.
UserInfo returns only the granted standard scopes, with a matching `sub`.
Email verification is not inferred: the portal adapter returns
`email_verified: false`; standalone verifiers may attest verified ownership.
Opaque UserInfo
tokens cannot authorize other portal APIs, and neither ID tokens nor portal
access tokens authorize UserInfo. No OIDC refresh tokens are issued.

## Validation

`pkg/oidc/config_test.go` covers config/parser/client-auth/PKCE contracts.
`provisioning_test.go` covers generated credentials, defaults, copied registration,
duplicate rejection, private-key format, file permissions, and concurrent creation.
`client_config_parser_test.go` covers directive parsing, quoting, arity, boolean
compatibility, error redaction, and stable adaptation with persisted credentials.
`provider_test.go` and `options_test.go` cover keys, hints, identity, expiry,
capacity, construction, public methods, lifecycle, lock release, and parser
fuzzing. `request_object_test.go` covers strict request assembly and fuzzing.
`pkg/oidc/provider_e2e_test.go` imports only the public package and the standard
library, running TLS login, consent, PKCE exchange, independent RSA verification,
UserInfo, fresh login, account disablement, and logout without a portal. It
provisions and persists generated clients/keys, exercises all three client
authentication methods, and repeats login/exchange after restoring the provider.

`pkg/authn/oidc_e2e_test.go` keeps the real portal/local-database password and
MFA E2E flows. `pkg/authn/oidc_runtime_test.go` checks adapter configuration and
browser/native logout. Root `config_test.go` covers server dispatch and the
public provider getter. Keep E2E cases in the default Go suite. Route portal
fixture requests directly to the portal so outer mount filtering cannot mask
incorrect dispatch. Requests outside the issuer mount must not serve keys or
consume codes.

```sh
make test TEST_DIR='./ ./pkg/oidc ./pkg/authn ./internal/tag' TEST='OIDC|Provider|TestTagCompliance|TestStructTagCompliance' COVERAGE_DIR=.coverage/oidc
go test -mod=readonly -race ./pkg/oidc -run '^$' -fuzz '^FuzzOIDCAuthorizationParameters$' -fuzztime=10000x -parallel=2
go test -mod=readonly -race ./pkg/oidc -run '^$' -fuzz '^FuzzOIDCRequestObjects$' -fuzztime=10000x -parallel=2
make ci-check
```

Local tests establish implementation behavior, not OpenID certification. Never
claim conformance-suite success or certification without the actual Foundation
plan results and submission record for this deployment/version.
