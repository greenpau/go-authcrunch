# Admin API Configuration and Private-Key Export

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

The persisted Go field is `APIConfig.AdminFetchPrivateKeysEnabled`; it never
implicitly enables `AdminEnabled`. Its JSON/XML/YAML tag is
`admin_fetch_private_keys_enabled`. Treat the two flags independently:

| Admin API enabled | Private export opted in | Authorized admin GET |
| --- | --- | --- |
| false | false | 404 |
| true | false | 404 |
| false | true | 404 |
| true | true | 200 when an asymmetric signing key is available |

### Admin API Directive Configuration

`pkg/authn/admin_api/parser.NewAdminAPIConfigFromDirectives` accepts a list of
complete statements encoded with `cfgutil.EncodeArgs` and decodes them with
`cfgutil.DecodeArgs`. Its result is `*authn.AdminAPIConfig`, which contains only
`Enabled` and `FetchPrivateKeysEnabled`. Both default to false; an empty list
does not enable either setting. Extend this parser whenever adding admin API
configuration, keeping `authn.AdminAPIConfig` as its result and
`PortalConfig.ConfigureAdminAPI` as the typed application boundary. The exact
grammar is:

```text
enable admin api
enable admin api private key export
```

Each directive also accepts `disable` in place of `enable`. Retain the existing
`enable admin api` spelling; enabling private-key export is a separate explicit
setting. Encode each keyword as a separate token. Boolean literals, underscore
keys, grouped keywords, extra arguments, unknown directives, duplicate or
conflicting settings, and multiline records are rejected without a partial
configuration or input values in errors. Reject empty tokens before encoding,
because `EncodeArgs` can trim a final empty field.

Embedding adapters collect all admin API statements for one portal before
calling the parser, so duplicates are detected across the whole configuration.
Adapters own tokenization, placeholder expansion, and enclosing block traversal;
pass no braces or unrelated directives. After successful parsing, call
`PortalConfig.ConfigureAdminAPI(admin)`. It snapshots the admin settings into
the portal's existing `APIConfig`, initializes it when absent, preserves
`ProfileEnabled`, and retains the flat JSON/XML/YAML fields shown above. Nil
input is rejected without mutation; a zero-value `AdminAPIConfig` clears both
admin flags. Configure before serving requests. Do not replace the combined
profile/admin config with an admin-only model or store competing admin settings.

Keep the parser in its public package and the typed configuration/application
method in `pkg/authn`, without a runtime-to-parser import. Consumer handler
wiring remains separate work under the
[repository scope](../../coding-directives/SKILL.md#repository-scope); do not
change sibling directories or claim to validate their directive handlers.
Public JWKS discovery needs no directive and remains independent of both flags.

### Export Authorization and Representation

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
marshaling. `PrivateKey.Bytes` validates scalar and point separately; reconstruct
with `ecdsa.ParseRawPrivateKey` and compare the derived public key before export.
Do not assume that encoding validates their pairing. Retain nil-coordinate and
nil-scalar guards for manually constructed legacy keys: the standard encoders
assume those fields are initialized. A defensive nil-scalar read and malformed
legacy-key test construction deliberately retain deprecated raw fields.
Safe parsers cannot construct those negative fixtures. Multiprime RSA `oth`
export retains Go's compatibility CRT values and independent precomputation
checks; do not remove a supported format merely to silence a diagnostic. Marshal RSA from a
struct copy with separate precomputation state: x509 can modify RSA
precomputation, and export must not mutate a key used by concurrent signers.
Encode the complete response before writing it; an invalid later key must not
produce a partial private-key export. Such failures return a generic 500.
