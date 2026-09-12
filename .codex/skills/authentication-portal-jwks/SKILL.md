---
name: authentication-portal-jwks
description: Maintain portal public signing-key discovery at .well-known/jwks.json, opt-in admin private-key export, KMS key serialization, asymmetric issuer selection, base-path routing, and JWT verification tests. Excludes upstream OAuth provider JWKS consumption.
---

# Authentication Portal JWKS

## Ownership

`pkg/authn/serve_http.go` routes public discovery to
`pkg/authn/handle_http_jwks.go`. `pkg/kms/jwks.go` owns `CryptoKeyStore.GetJWKS`
and public-key serialization. Keep signing-key selection aligned with
`CryptoKeyStore.SignToken(nil, nil, user)` in `pkg/kms/crypto_keystore.go`.
All current portal access-token issuance paths use this default selection.

`pkg/authn/handle_api_private_keys.go` owns the explicitly enabled admin export
route. `pkg/kms/jwks_private_keys.go` owns `GetJWKSPrivateKeys`. Both public
and private exports use `getJWKSSigningKeys` for identical selection, ordering,
and deduplication; keep private encoding separate from `GetJWKS`.

This is portal-issued JWT discovery. Upstream OAuth key consumption belongs to
[oauth-identity-provider](../oauth-identity-provider/SKILL.md) and
`pkg/idp/oauth/jwks.go`; its `JwksKey` model includes shared secrets and must
not be reused as a public export model. JWTs here use signatures, not
asymmetric payload encryption.

## HTTP Contract

The route is the complete `/.well-known/jwks.json` suffix beneath the portal
mount. Root, `/auth/`, `/xauth/`, and `/tenant/xauth/` mounts expose,
respectively, `/.well-known/jwks.json`, `/auth/.well-known/jwks.json`,
`/xauth/.well-known/jwks.json`, and
`/tenant/xauth/.well-known/jwks.json`. The embedding server determines which
paths reach a portal; the library has no general configured mount prefix.

Match the complete suffix on Go's decoded `r.URL.Path`. Do not accept an extra
trailing slash, filename suffix, or a match only in the query. Route before
API/QR-code dispatch and JSON negotiation, so nested mounts containing those
segments, `format=json`, and JSON request headers work identically.

- GET returns 200 with `application/jwk-set+json` and a nonempty `keys` array
  when the selected issuer is asymmetric.
- HEAD returns the same success headers and Content-Length, without a body.
- Missing signing keys or a symmetric selected issuer return 404, including
  a store with HMAC first and RSA/EC later. Verification-only public keys do
  not enable this endpoint.
- Other methods return 405 with `Allow: GET, HEAD`.
- Invalid asymmetric signing material returns 500 without key material or
  internal error text in the response. Response write errors are propagated.

Discovery does not authorize credentials, allocate sessions, set/delete cookies,
or redirect to login. Responses use `Cache-Control: no-store` and `nosniff`;
configuration reload can change keys or switch an issuer to HMAC. Preserve
these properties when adding caching or middleware.

Both discovery and admin export always return a JSON object with a `keys`
array on success, even when it contains only one entry. Never collapse a
singleton into a key object. Preserve this contract for future key rotation;
consumers must iterate the array and use `kid` when present. Public entries
are JWKs; admin entries pair `public_key` with `private_key` in every format.

## Key Selection and Encoding

The first non-system signing key determines whether discovery is available.
When it is asymmetric, publish the public parts of configured non-system RSA,
ECDSA, and Ed25519 signing keys, in signing order, deduplicating identical JWK entries.
Exclude symmetric keys, verification-only keys, and system keys. Derive public
parameters from the actual private signing operator, so sign-only keys work
and a separately loaded verifier cannot substitute another issuer's key.

`publicJSONWebKey` is an explicit allowlist of public parameters. Never marshal
`CryptoKey`, `CryptoKeyOperator`, private keys, configuration, or shared secrets
into the public JWKS response. The format follows [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html)
and [RFC 7518 section 6](https://www.rfc-editor.org/rfc/rfc7518.html#section-6):

| Signing key | Public JWK parameters |
| --- | --- |
| RSA | `kty: RSA`, `n`, `e`; integers use minimal unsigned big-endian bytes |
| ECDSA P-256 | `kty: EC`, `crv: P-256`, 32-byte `x` and `y` |
| ECDSA P-384 | `kty: EC`, `crv: P-384`, 48-byte `x` and `y` |
| ECDSA P-521 | `kty: EC`, `crv: P-521`, 66-byte `x` and `y` |
| Ed25519 | `kty: OKP`, `crv: Ed25519`, 32-byte `x`; no `y` |

Encode integers/coordinates with unpadded base64url. EC coordinates require
leading zero padding; `big.Int.Bytes()` alone is insufficient. Advertise
`use: sig` and the operator's actual default signing `alg`. Emit `kid` exactly
when signing injects it. The default key ID `0` is omitted in both JWT and
JWK; do not invent a discovery-only ID or change existing JWT headers.

The store is configured before serving requests. `GetJWKS` is read-only and
does not add concurrent key-mutation support to KMS. Do not introduce mutable
request-time caches or serialize the global shared buffer.

## Configuration and Consumer Integration

Without explicit keys, `NewCryptoKeyStoreConfig` defaults to ES512 and
`CryptoKeyStore.AutoGenerate` creates an ECDSA P-521 private/public pair.
`generateKey` reuses it via `shared.Buffer` under the configured tag within
the process. This sharing is not HMAC: the key is asymmetric. It is not
persisted across process restarts or shared automatically between servers.

For persistent signing material, configure the portal with, for example:

```text
crypto key signing-v1 sign-verify from file /etc/authcrunch/signing-key.pem
```

RSA, supported ECDSA, and Ed25519 PKCS#8 private PEM keys work. `sign` also works when portal
verification is configured separately. A literal shared secret, such as
`crypto key sign-verify <shared-secret>`, selects HMAC and yields 404. Merely
loading a public RSA/EC/Ed25519 verifier does not configure an asymmetric issuer.

Configure an application's verifier with the trusted portal JWKS URL and its
expected algorithms, issuer, and audience. Use matching `kid` values when
present; the autogenerated/default-key response has no `kid`. Prefer explicit
distinct IDs for configured keys to avoid ambiguous selection in a multi-key
set. Publication reflects current configuration; it does not retain removed
keys for rollover or coordinate keys across processes. This endpoint does not
add `jku` JWT headers or OpenID discovery metadata.

## Ed25519 Signing and Verification

`pkg/kms/ed25519.go` supports both exact JOSE names `EdDSA` (RFC 8037)
and `Ed25519` (RFC 9864), using pure `crypto/ed25519` over the original JWS
input. No prehash, context, Ed448, or X25519 signing is supported. The pinned
JWT library registers only `EdDSA`; `internal/jwtutil`, shared by KMS and
OAuth, registers a separate `Ed25519` method
whose `Alg()` returns `Ed25519`. Keep algorithm allowlists exact and never
rewrite a JWT header before verifying its signature.

Existing PEM loading accepts Ed25519 PKCS#8 private keys and PKIX public keys
through files, directories, or PEM-valued environment variables:

```text
crypto key sign-verify from file /etc/authcrunch/ed25519-private.pem
crypto key verify from file /etc/authcrunch/ed25519-public.pem
```

These are separate issuer/verifier examples. Imported Ed25519 private keys
sign with `EdDSA` by default. Verification accepts both names with the same
public key. The existing `CryptoKey.SignToken` and `CryptoKeyStore.SignToken`
method argument can explicitly select either name. A PEM has no JOSE-label
preference; reimporting an exported generated key restores its material and
uses the imported `EdDSA` default. There is no new Caddy directive to select
the other label for an imported key.

The existing `crypto default autogenerate algorithm` setting additionally
accepts `EdDSA` and `Ed25519`. Each selects Ed25519 key generation and its
corresponding default signing label. Omitted settings retain ES512 generation;
existing HMAC/RSA/ECDSA selection, per-key defaults, token names/lifetimes,
and first-eligible signing order remain unchanged. Explicit method arguments
do not search later keys for a matching algorithm.

Autogeneration tags still share key material within a process. EdDSA and
Ed25519 configurations may share a tag while retaining their own labels.
Reusing a tag across incompatible key families fails configuration. The
existing tag directive can isolate unrelated issuers. Explicit verification
keys continue to suppress autogeneration just as other explicit keys do.
An Ed25519 private key configured for `verify` contributes only its public
verification operator and cannot become the portal signer or an exported key.

Public JWKS advertises each key's actual default signing label, preserving the
existing key-order and `kid` rules. An explicit Go signing-method override does
not alter discovery metadata, just as for existing RSA methods. Consumers
verifying both labels must configure an appropriate algorithm policy.

`pkg/kms/ed25519_test.go` covers both directions, exact allowlists, the RFC 8037
signature vector, existing key sources, role boundaries, invalid key material,
algorithm confusion, generation sharing, exports, and parser fuzzing.
`pkg/authn/ed25519_e2e_test.go` covers TLS login/refresh compatibility, both
verification labels, denied admin export, and PEM persistence. The JWKS E2E
format suite also covers OKP, mixed RSA/EC/Ed25519 sets, and independent
standard-library signature verification. Run:

```sh
make test TEST_DIR='./pkg/kms ./pkg/authn' TEST='Ed25519|JWKS|TestE2EPortalSigningAndRefreshCompatibility' COVERAGE_DIR=.coverage/ed25519
go test -mod=readonly -race ./pkg/kms -run '^$' -fuzz '^FuzzEd25519TokenParsing$' -fuzztime=10000x -parallel=2
make ci-check
```

## Admin Private-Key Export

`GET <mount>/api/server/private_keys` returns the private signing keys paired
with the published public JWKs. For `/xauth/`, the URL is
`/xauth/api/server/private_keys`. The endpoint is disabled by default. Enable
both API flags in portal configuration:

```json
{
  "api": {
    "admin_enabled": true,
    "admin_fetch_private_keys_enabled": true
  }
}
```

The Go field is `APIConfig.AdminFetchPrivateKeysEnabled`; it never implicitly
enables `AdminEnabled`. Its JSON/XML/YAML tag is
`admin_fetch_private_keys_enabled`. This library configuration does not add
syntax to an embedding server's independent configuration parser.

Keep the route inside `handleAPI`, after normal token authorization. The
export handler checks both flags, requires `authorizedRole` with `role.Admin`
and authenticated request state, and then accepts GET only. Ordinary portal
users and anonymous callers receive 403; invalid, tampered, or expired bearer
tokens receive 401 from the common API authorization path. Disabled export or
no matching asymmetric signer returns 404. Unsupported methods from authorized
admins receive 405 with `Allow: GET`. Read the flags on every request, even
when the admin token is cached.

A successful JSON response has a `keys` array. Each entry contains:

| Field | Content |
| --- | --- |
| `public_key` | The exact public JWK, including the existing `kid` behavior |
| `private_key` | The matching private key in the requested format; defaults to an unencrypted PKCS#8 PEM string |

The `format` and `encoding` query parameters select the private-key
representation. The surrounding response always remains JSON, and
`public_key` always remains a public JWK.

| `format` | Supported keys | `encoding` | `private_key` value |
| --- | --- | --- | --- |
| `pkcs8` (default) | RSA, ECDSA, and Ed25519 | `pem` (default), `der` | PKCS#8 PEM string or standard-base64 DER string |
| `pkcs1` | RSA only | `pem` (default), `der` | RSA PRIVATE KEY PEM string or standard-base64 DER string |
| `sec1` | ECDSA only | `pem` (default), `der` | EC PRIVATE KEY PEM string or standard-base64 DER string |
| `jwk` | RSA, ECDSA, and Ed25519 | `json` (default) | Private JWK object, including its public parameters |

For example, request `?format=pkcs8&encoding=der`, `?format=pkcs1`,
`?format=sec1`, or `?format=jwk`. `format=json` retains the existing JSON API
negotiation convention as an alias for `pkcs8`. An omitted format with
`encoding=der` selects PKCS#8 DER. Selectors are lowercase and case-sensitive.

Malformed query escaping, duplicate selectors, explicitly empty selectors,
unknown values, and incompatible combinations return 400 after configuration
and admin checks. A mixed RSA/EC set cannot be exported as PKCS#1 or SEC1:
reject the entire request instead of silently omitting keys. Keep these option
errors distinct from invalid signing material, which returns a generic 500.
`GetJWKSPrivateKeys(format, encoding)` enforces the same option contract for
KMS callers; empty arguments there select defaults.

Private JWK encoding follows RFC 7518 section 6: RSA includes `d`, `p`, `q`,
`dp`, `dq`, `qi`, and `oth` for additional primes; EC includes a fixed-width
`d` scalar. Ed25519 uses the RFC 8037 32-byte seed for `d`, never Go's
64-byte private key. The public serializer must never use `privateJSONWebKey`.

The selected issuer must be asymmetric, just as for public discovery. Export
includes autogenerated keys and configured signing keys, while excluding
HMAC/shared secrets, system keys, and verification-only keys. Do not accept
file paths or key material from request parameters. Portals using the same
autogeneration tag within a process share the exported signing credential.
Enabling export for one portal grants its admins signing authority for every
portal or verifier that trusts that key. Use distinct autogeneration tags or
configured key pairs when portals belong to separate trust domains.
The export contains credentials capable of issuing tokens; retain the existing
admin boundary and explicit opt-in, `Cache-Control: no-store`, JSON content type,
and `nosniff`.
Never log the private response or include encoder details in error responses.

Validate ECDSA scalar bounds and its correspondence to the public point before
marshaling. Go's x509 encoder assumes a non-nil scalar. Marshal RSA from a
struct copy with separate precomputation state: x509 can modify RSA
precomputation, and export must not mutate a key used by concurrent signers.
Encode the complete response before writing it; an invalid later key must not
produce a partial private-key export. Such failures return a generic 500.

## Validation

Run the focused report lifecycle, then the complete repository gate:

```sh
make test TEST_DIR='./pkg/kms ./pkg/authn' TEST='JWKS|AdminFetchPrivateKeys' COVERAGE_DIR=.coverage/jwks
make test TEST_DIR='./pkg/authn' TEST='^TestE2EPortalJWKS' COVERAGE_DIR=.coverage/jwks-e2e
go test -mod=readonly -race ./pkg/kms -run '^$' -fuzz '^FuzzJWKSAdminTokenParsing$' -fuzztime=20s -parallel=4
make ci-check
```

`pkg/kms/jwks_test.go` verifies public-only output, actual signature verification,
all supported RSA methods and EC curves, leading-zero coordinates, default
generation, mixed stores, duplicates, sign-only keys, and invalid material.
`pkg/authn/handle_http_jwks_test.go` exercises `ServeHTTP`, root/custom/nested
mounts, negotiation precedence, route boundaries, methods/statuses, cookie
independence, concurrent requests, and real password login followed by JWT
verification using only the published key. Preserve tests that verify signatures
independently of KMS's `ProvideKey`; comparing JSON shapes alone is insufficient.

`pkg/kms/jwks_private_keys_test.go` parses every PEM/DER/JWK format and signs
tokens with it for verification against public JWKS, including EC scalar
padding and multiprime RSA parameters. It covers exclusions/invalid material,
incompatible format combinations, and concurrent export/signing without RSA
mutation.
`pkg/authn/handle_api_private_keys_test.go` exercises default-disabled and
two-flag gating, admin/user/anonymous/invalid-token authorization, configuration
changes after cached authorization, route boundaries, log/public-response
non-disclosure for every format, selector parsing, and generic export failures.
It checks both HTTP endpoints with one key, multiple RSA keys, and mixed
RSA/EC keys across mounts, preserving list shape and per-entry pairing.
`pkg/authn/api_config_test.go`
covers flag defaults and JSON/XML/YAML serialization.

`pkg/authn/jwks_e2e_test.go` uses the external `authn_test` package, a real TLS
listener, a temporary local identity database, and `authclient` password login.
Preserve this E2E boundary: requests pass through public production APIs without
injecting authenticated users or accessing a portal's internal key store.
Configure `RawCryptoKeyStoreConfig`, because `PortalConfig.Validate` derives
`CryptoKeyStoreConfig` from those directives. Supply `cookie.NewConfig()` as in
the other real-portal fixtures. Use unique autogeneration tags; P-256/P-384
fixtures use generated PEM files because portal autogeneration supports ES512.

The E2E suite independently verifies login JWTs from fetched public keys and
signs with every exported PEM/DER/JWK representation. It exercises configured
and autogenerated keys, all supported EC curves, single/multiple-key arrays,
root/custom/nested mounts, public HEAD, both opt-in flags, real admin/member
roles, invalid signatures, methods, malformed selectors, HMAC issuers, and
concurrent login/discovery/export. It also saves exported PKCS#8, PKCS#1, and
SEC1 PEM to private temporary files, starts a fresh portal with that key file,
and verifies old and new tokens. The configured-rollover case reverses two RSA
signers across portal instances and verifies both generations of tokens using
the retained key list. It tests configuration replacement, not an automatic
rotation service. Keep these tests in the default suite and extend them when
changing either endpoint or key representation.

`pkg/authn/jwks_security_e2e_test.go` tests unsigned and tampered JWTs,
RSA-to-HMAC algorithm confusion, malformed signed identity claims, encoded
and raw HTTP request targets, credential transports, and absence of CORS/JSONP
disclosure. Preserve normal cookie, header, query, and bearer authorization;
none may turn a member into an admin. Trace `Path`, `RawPath`, and `RequestURI`
at the real handler boundary for adversarial path tests. The fixture's trace
header is test-only; never enable it for queries carrying credentials.

`pkg/kms/crypto_keystore_security_test.go` covers identity-claim type validation
and fuzzes untrusted tokens. Even correctly signed JWTs must reject non-string
`iss`, `mail`, `email`, `sub`, `name`, and `jti` without panicking, including
expired tokens used to construct login hints. Use JWT error identities rather
than matching expiration error text. Keep valid login and expired-token
behavior covered when modifying the shared parser.

Retain concurrent real logins in the E2E suite: they exercise claim preparation
as well as signing. `injectPortalRoles` in `handle_http_login.go` must treat the
validated configuration's reserved-role map as read-only; even writing its
existing value races with other requests. `TestInjectPortalRoles` checks role
normalization under concurrent calls with shared configuration.
