---
name: oauth-identity-provider
description: Maintain upstream OAuth identity-provider directive parsers, shared configuration dispatch, OAuth/OIDC discovery, JWKS and static public PEM verification, EdDSA/Ed25519 token validation, key refresh, and real portal OAuth E2E tests. Excludes portal signing-key publication.
---

# OAuth Identity Provider

## Ownership and Entry Points

`pkg/idp/config.go` validates the shared provider parameter allowlist;
`pkg/idp/provider.go` constructs the concrete provider. OAuth behavior lives
under `pkg/idp/oauth`. Exercise this dispatcher as well as concrete helpers:
an OAuth `Config` field is not usable through the shared API until dispatch
accepts it and checks its type.

`pkg/idp/oauth/parser.NewOAuthIdentityProviderConfigFromDirectives` returns
`*oauth.Config`. `pkg/idp/parser.NewOAuthIdentityProviderConfigFromDirectives`
reuses that parser and returns `*idp.IdentityProviderConfig` for the shared
dispatcher or root `Config.AddIdentityProvider`. Both take the provider name
and encoded body statements. Keep grammar in the OAuth parser; the shared
adapter owns only normalized configuration conversion and allowlist validation.
See [directive parsing](references/configuration-directives.md) for the complete
grammar, application examples, parser maintenance, defaults, and validation
boundaries.

`authenticate.go` owns redirects and code exchange; `validator.go` owns token
roles and trust claims; `jwt.go` owns signature verification and bounded retry;
`jwks.go` owns key conversion; `jwks_store.go` owns remote ingestion, static
pins, candidate selection, and refresh. `provider.go` owns setup/discovery.

The provider verifies upstream credentials. The portal subsequently signs a
separate credential using its existing KMS configuration. Keep upstream keys,
algorithms, issuer metadata, and key refresh independent of portal signing
selection, token settings, and portal JWKS publication. ES512 is the existing
autogeneration fallback, not a mandatory portal signing algorithm.

## Ed25519 Verification Contract

`internal/jwtutil` registers the exact `Ed25519` JOSE name and recognizes the
two concrete supported methods. The pinned JWT library provides `EdDSA`.
Both use pure Ed25519 over the original JWS bytes. Preserve exact method names
and never rewrite a signed header, prehash the message, or duplicate registry
initialization. KMS also consumes this helper.
The key representation follows [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html#section-2);
the fully specified JOSE name follows [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html#section-2.2).

New OKP keys require `crv: Ed25519` and canonical unpadded base64url `x` with
exactly 32 bytes. Return a typed `ed25519.PublicKey`, never an HMAC byte secret.
Reject encryption use, incompatible public parameters, private `d`, and other
curves. Ed448 and X25519 are unsupported. Unknown unrelated extensions can be
ignored. For `key_ops`, omission allows verification; an explicit list must
contain `verify`, may also contain `sign`, and cannot contain duplicates or
other operations. Empty, null, and malformed lists are rejected for OKP.
Present empty or null `alg`/`use` values are invalid in remote OKP entries;
Go struct zero values still represent omitted optional fields.

| Ed25519 key restriction | Accepted JWT alg |
| --- | --- |
| JWK alg omitted | EdDSA and Ed25519 |
| JWK alg EdDSA | EdDSA |
| JWK alg Ed25519 | Ed25519 |
| Public PEM | EdDSA and Ed25519 |

JWT header values are case-sensitive. Keep the explicit RS/ES/PS/Ed allowlist,
concrete method checks, and typed verification candidates. HS and none receive
no verification keys. Preserve existing RSA-PSS verification with an
algorithm-unspecified RSA JWK. Explicit PS-labelled RSA JWKs remain outside
the legacy JWK parser's accepted metadata. Do not silently tighten legacy
RSA/EC alg/use/key_ops policy as part of Ed maintenance.
Remote decoding deliberately ignores legacy `key_ops`, including values the
old decoder did not inspect; apply its new typed validation only to OKP.

## Configuration and Static Keys

Discovery uses the existing `metadata_url` and its `jwks_uri`. Advertised
`id_token_signing_alg_values_supported` values neither change the portal signer
nor become an access-token algorithm policy. Unknown advertised capabilities
do not prevent using supported keys.

`jwks_keys` / `Config.JwksKeys` maps explicit key IDs to public PEM paths.
`NewJwksKeyFromPublicKeyPEM` accepts Ed25519 PKIX/SPKI PUBLIC KEY, RSA PKIX
PUBLIC KEY, and RSA PKCS#1 RSA PUBLIC KEY. The RSA-specific exported constructor
retains its RSA-only contract. Private PEM, SSH, and certificate formats are
not added by this feature.

Configuration validation reads static keys; provisioning must also install
them into runtime verification state. Fully explicit authorization/token URLs
and static keys work without metadata or a disable flag. In combined mode,
fetch configured discovery while preserving explicit endpoint overrides.
Static IDs take precedence over remote entries and survive remote replacement.

`key_verification_disabled` retains its existing fetch-control meaning: static
JWT signatures are still verified. Do not prescribe disabled nonce, PKCE, or
TLS verification as a production prerequisite for Ed support.

The shared AuthCrunch configuration accepts the OAuth `issuer` and
`access_token_audience` string fields. An explicit issuer overrides discovered
issuer information. Do not derive issuer from `base_auth_url`. Static-only
users can supply issuer explicitly; absent issuer keeps the existing optional
issuer-check contract. The public parsers accept both settings as single-value
directives. Embedding-server block recognition and parser wiring are separate
consumer work; never edit sibling checkouts to implement or validate them.

## Selection and Refresh

Remote JWK kid may be omitted. Explicit public constructors still require the
caller-supplied ID. A present JWT kid must be a nonempty string and restricts
candidate lookup to that ID; an unknown kid never falls back to other IDs.
Without kid, select compatible trusted candidates. Retain same-kid alternatives
and use the JWT library's VerificationKeySet for actual signature verification.
Apply each OKP entry's restrictions before deduplicating public material.

Snapshots are immutable after publication. `keyMu` protects snapshot/version
publication; `keyFetchMu` serializes refresh and its rate accounting. Network
work happens outside `keyMu`. A fetch version includes failures so concurrent
waiters reuse the outcome. Never mutate published maps or keys in place.

Limits are 1 MiB per metadata/JWKS response and 64 entries per remote or static
key set. Oversized documents fail rather than being truncated. Individual
invalid/unsupported remote entries do not poison valid siblings. A complete
empty or all-invalid keys array replaces the remote set with no usable entries
and returns an error; malformed documents and transport/HTTP failures preserve
the previous snapshot. Static pins are retained in either case.

Refresh allows four attempts, then a five-minute cooldown from the latest
attempt. Unknown keys and actual signature failures can cause at most one
refresh/retry per token validation. Signature failure supports same-kid
material replacement. Claims failures, unsupported methods, and failures for
an explicit static ID do not trigger refresh. Propagate request context to
request-driven JWKS fetching.

Removed remote keys stop verifying after a successful refresh observes their
removal. There is no periodic refresh or instantaneous revocation promise.
Upstream key removal does not revoke already-issued portal sessions.

Delayed setup publishes metadata before admitting authentication; `setupMu`
protects discovery changes and config reads. `IdentityProvider.Close` cancels and awaits
owned synchronous/delayed discovery, metadata/JWKS HTTP work, retry timers, and
the OAuth state worker. Registration of setup work and shutdown are serialized;
no worker may be added after shutdown begins or publish readiness after Close
returns. Configure calls serialize and reuse successful setup; closed providers
cannot be configured or authenticate again. Embedders drain requests before
disposal. The root `Server.Close` owns shared providers once; individual portals
do not own their lifetime. Direct provider consumers call Close themselves.

## Browser State and Nonce Policy

`state.go` atomically publishes nonce, PKCE verifier and login binding. Bind a
five-minute, single-use callback to the initiating protected browser SessionID
and exact callback URL. Claim it atomically before processing any code or direct
token; delete it on every completion/error path. State is distinct from the
browser cookie, and a supplied state must never create its own browser binding.

Capture nonce policy when login starts. `NonceDisabled` omits nonce from the
authorization URL (including a preconfigured nonce parameter) and skips only the
nonce-claim check for that transaction. An enabled transaction requires its exact
stored nonce. Later config changes cannot weaken an existing transaction; legacy
state entries fail closed to nonce-required behavior. Missing state still fails.
Signature, issuer, audience, browser state, expiry, replay and PKCE validation
remain active when nonce compatibility is disabled.

Keep `nonce_policy_test.go`, `state_binding_test.go`, parser round-trip OAuth TLS
coverage and `oauth_state_e2e_test.go` for both settings, wrong/missing nonce,
wrong browser/callback, replay and malformed signed identity tokens.

## Claims and Protocol Compatibility

An invalid ID token or selected identity access token fails authentication.
An unusable optional JWT access token contributes no claims. Opaque access
tokens retain their existing bearer/UserInfo behavior. Preserve the existing
issuer, audience, azp, time, state, nonce, and PKCE checks and role processing.
Do not turn optional legacy claims into new requirements without an explicit
compatibility decision. Malformed nonce/name values must return errors, not
panic. Several named drivers intentionally use UserInfo-oriented fetchClaims
instead of the common JWT path; preserve that dispatch.

Signed UserInfo/JWE, new grants, private_key_jwt, request objects, and a complete
OIDC at_hash/c_hash conformance upgrade are separate features.

## Validation

Follow the repository testing lifecycle. Focused coverage belongs in
`internal/jwtutil/ed25519_test.go`, OAuth's `ed25519_test.go`,
`jwks_store_test.go`, `provider_lifecycle_test.go`, `shutdown_test.go`, and shared provider config
tests. Keep the existing KMS signing/default/refresh/export tests passing when
changing the shared adapter.

Parser unit tests and executable examples belong in `pkg/idp/oauth/parser`
and `pkg/idp/parser`, in `package parser_test`. Cover complete grammar, exact
token boundaries, duplicate aliases/states, redacted errors, immutable inputs,
driver defaults, static key files, and issuer/audience serialization. Root
`config_oauth_identity_provider_test.go` verifies parsed provider registration
and configuration reload.

`pkg/authn/oauth_ed25519_e2e_test.go` imports the shared public parser and reloads
its serialized output before exercising the public provider dispatcher,
local TLS OIDC endpoints, real state/nonce/PKCE code exchange, a portal with a
temporary local database, and an authorization gatekeeper. The fixture signs
upstream JWTs independently with standard-library crypto and uses unrelated
portal keys. It covers discovery/static/combined sources, opaque UserInfo,
verified access claims, signing compatibility, failures, and rollover. Local
self-signed TLS configuration is fixture-only. Use fresh browser sessions and
subjects where caches could obscure verification; stop listeners and workers.

`pkg/authn/oauth_config_e2e_test.go` uses that fixture to verify explicit and
discovered issuers, exact issuer matching, static-only behavior, explicit issuer
overrides, optional access-token audience/issuer rejection without role leakage,
and the existing `azp` fallback only when access audience is omitted. ID-token
audience remains the client ID. Check both successful protected-resource access
and absence of portal credentials after rejected identity tokens.

```sh
make test TEST_DIR='./internal/jwtutil ./pkg/idp/... ./pkg/kms' COVERAGE_DIR='.coverage/oauth-core'
make test TEST_DIR='./pkg/idp/... ./pkg/authn .' TEST='Test(NewOAuthIdentityProvider|OAuthIdentityProvider|ConfigOAuthIdentityProvider|E2EOAuth)|ExampleNewOAuthIdentityProvider' COVERAGE_DIR='.coverage/oauth-directives'
make test TEST_DIR='./pkg/authn' TEST='^TestE2EOAuth' COVERAGE_DIR='.coverage/oauth-e2e'
go test -mod=readonly -race ./pkg/idp/oauth -run '^$' -fuzz '^FuzzOAuthJwks$' -fuzztime=10000x -parallel=2
make ci-check
```

Keep protocol/JWKS fuzzing bounded and test network refresh/coalescing
separately. Verify both successful login and rejection boundaries through E2E;
configuration-only tests do not establish static-key runtime support.
