---
name: authentication-portal-jwks
description: Maintain portal public signing-key discovery at .well-known/jwks.json, reusable admin API directive parsing, opt-in admin private-key export, KMS key serialization, asymmetric issuer selection, base-path routing, and JWT verification tests. Excludes upstream OAuth provider JWKS consumption.
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
leading zero padding; `big.Int.Bytes()` alone is insufficient. Use
`ecdsa.PublicKey.Bytes` for validated SEC 1 points and split its fixed-width
coordinates. Consumer tests reconstruct points with
`ecdsa.ParseUncompressedPublicKey` and verify real signatures. Do not replace
point validation with unchecked coordinate construction. Advertise
`use: sig` and the operator's actual default signing `alg`. Emit `kid` exactly
when signing injects it. The default key ID `0` is omitted in both JWT and
JWK; do not invent a discovery-only ID or change existing JWT headers.

The store is configured before serving requests. `GetJWKS` is read-only and
does not add concurrent key-mutation support to KMS. Do not introduce mutable
request-time caches or serialize the global shared buffer.

## Configuration and Consumer Integration

Portal signing configuration still enters through `RawCryptoKeyStoreConfig`
and `kms.NewCryptoKeyStoreConfig`. This is legacy parsing inside `pkg/kms`;
there is no dedicated KMS `parser` package. Treat that as a configuration-parser
conformance gap when changing crypto directives, not as evidence that this
surface already satisfies the shared parser contract. The admin API parser
below is a separate, implemented configuration surface.

Without explicit keys, `NewCryptoKeyStoreConfig` defaults to ES512 and
`CryptoKeyStore.AutoGenerate` creates an ECDSA P-521 private/public pair.
`generateKey` reuses it via `shared.Buffer` under the configured tag within
the process when persistent state is omitted. The key is asymmetric.
With root `Config.State`, [runtime-state](../runtime-state/SKILL.md) persists
generated signing material under its single-owner storage contract. Without
that opt-in or explicit key files, process restarts lose generated keys.
Neither mode supplies automatic sharing across independently running servers.

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

Both exact JOSE names, `EdDSA` and `Ed25519`, use Ed25519 keys. Imported keys
sign with `EdDSA`; generated keys retain their configured label. Public discovery
reports the actual default label, and an explicit signing override does not
rewrite discovery metadata. Read [Ed25519 contracts](references/ed25519.md) when
changing algorithms, PEM sources, autogeneration sharing, or verification.

## Admin Private-Key Export

`GET <mount>/api/server/private_keys` requires both `APIConfig.AdminEnabled`
and `AdminFetchPrivateKeysEnabled`, a valid authenticated admin, and an
asymmetric selected signer. Both flags default to false. Public discovery is
independent of those flags. Export grants signing authority; keep private
material out of public discovery, diagnostics, and generic errors.

The dedicated `pkg/authn/admin_api/parser.NewAdminAPIConfigFromDirectives`
returns `*authn.AdminAPIConfig`; `PortalConfig.ConfigureAdminAPI` installs a
snapshot while preserving profile settings. Read [admin export](references/admin-export.md)
when changing its directive grammar, flag semantics, authorization, format
selectors, response encoding, or key consistency checks.

## Validation

Read [validation scenarios](references/validation.md) when changing discovery,
signing, configuration, or private-key export. Preserve real TLS login followed
by independent signature verification using only public discovery, explicit
admin/member/anonymous boundaries, and successful reimport of exported keys.
Malformed selectors or key material must never produce a partial export.

```sh
make test TEST_DIR='./pkg/kms ./pkg/authn/admin_api/parser ./pkg/authn ./internal/tag' TEST='JWKS|AdminAPI|AdminFetchPrivateKeys|Ed25519|TagCompliance' COVERAGE_DIR=.coverage/jwks
```
