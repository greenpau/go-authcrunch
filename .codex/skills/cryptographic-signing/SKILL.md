---
name: cryptographic-signing
description: Maintain the local RSA-PSS PS256 signing plugin, its public parser, refresh-engine composition, public JWKS, and strict core verification. Excludes portal or OIDC signer selection and remote KMS backends.
---

# Cryptographic Signing

## Ownership and integration

The working reference is
[`plugins/cryptographic-signing/rsapss`](../../../plugins/cryptographic-signing/rsapss).
It signs approved access claims with a local RSA private key. It implements
`tokenrefresh.Signer` and is supplied to
[`tokenrefresh.NewManager`](../../../pkg/authn/token_refresh/manager.go).
The embedding host owns authentication, identity revalidation, session storage,
HTTP transport, and publication of verification keys. A successful signature
alone does not authorize issuance or commit a session.

This is an ordinary Go package in the root module. It has no registration side
effects, workers, remote services, key generation, or nested module. Core
production code must not import it. It is not a selectable backend in root JSON,
`authdb`, `authn.NewPortal`, or downstream OIDC. Those concrete signing paths
remain separate; do not imply that importing the plugin replaces them.

[`pkg/kms/rsa_pss.go`](../../../pkg/kms/rsa_pss.go) supplies the core verification
integration. Existing RSA public-key configuration can verify PS256 tokens from
this plugin. Core RSA issuance still uses its existing RS256/384/512 methods and
defaults. This change does not enable PS384 or PS512, change core JWKS discovery,
or create a generic signer factory.

## Public configuration and parser

`rsapss.Config` has `key_file`, `key_id`, `algorithm`, `issuer`, `audience`, and
`max_lifetime` fields. `Validate` normalizes defaults and validates without file
I/O. `rsapss.New(*Config)` validates its own copy and loads the key before
publishing a signer. A failed constructor returns no runtime object.

The dedicated public constructor is
`parser.NewRSAPSSSigningConfigFromDirectives([]string) (*rsapss.Config, error)`.
Its input is a complete encoded block body, with no header or braces:

```text
key file /run/keys/access.pem
key id access-v1
algorithm PS256
issuer https://login.example.test/auth
audience api
max lifetime 5m
```

Each setting occurs at most once. `algorithm` defaults to `PS256`, the only
accepted algorithm. `max lifetime` defaults to `15m` and accepts whole seconds
from `1s` through `24h`. All other settings are required. Use
`cfgutil.EncodeArgs` for values such as filenames containing spaces. Unknown,
duplicate, malformed, invalid-UTF-8, or empty directives fail without echoing
values. Parsing does not expand environment variables or read files.

Key IDs contain 1–128 ASCII letters, digits, dots, underscores, or hyphens.
File path, issuer, and audience limits are 4096, 2048, and 1024 UTF-8 bytes;
reject control characters and surrounding whitespace. Issuer and audience are
exact opaque bindings, not URL normalization or discovery inputs.

For a host, import `plugins/cryptographic-signing/rsapss` and its `parser`, parse
the directives, call `rsapss.New(config)`, and pass the returned signer as the
third argument to `tokenrefresh.NewManager`. The host's engine binding determines
`iss = Origin + strings.TrimSuffix(BasePath, "/")`; this must exactly match the
plugin issuer. The engine access lifetime must fit the configured maximum.
See the executable parser example and the portable
[consumer journey](../../../plugins/cryptographic-signing/rsapss/consumer_e2e_test.go)
for complete construction and transaction wiring.

## Signing and key contract

Accept a single unencrypted PKCS#8 `PRIVATE KEY` or PKCS#1 `RSA PRIVATE KEY` PEM
block containing a validated, two-prime RSA key of 2048–8192 bits. Bound the file
to 16 KiB; reject symlinks, nonregular files, PEM headers, extra blocks, leading
non-whitespace data, and trailing non-whitespace data. Never return parser
contents, private bytes, or filenames in key errors. Operators own filesystem
permissions and atomic replacement; the loader does not enforce a file mode or
provide an HSM/non-exportable-key boundary.

PS256 uses SHA-256 over the complete JWS signing input, MGF1-SHA-256, and an
exactly 32-byte salt as defined by
[RFC 7518 section 3.5](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5).
Use standard crypto implementations, never a custom PSS primitive. Header
`alg=PS256`, configured `kid`, and `typ=authcrunch-access+jwt` are trusted
configuration. The explicit type distinguishes this profile; it does not claim
RFC 9068 conformance or make an unrelated verifier enforce token purpose.

Require the configured issuer, a nonempty subject, and the sole configured
audience (a string or singleton array). Require positive integral `iat`, `nbf`,
and `exp` within signed 64-bit range, with `iat <= nbf <= now < exp` and
`exp - iat <= max_lifetime`. Subject is at most 1024 UTF-8 bytes, without control
characters or surrounding whitespace. Recheck expiry and cancellation after
signing. Context cancellation cannot interrupt the local RSA primitive, but no
token is returned after observed cancellation, deadline, or expiry.

Sign exactly the approved JSON claim snapshot, without changing roles,
audiences, deadlines, or authentication evidence. Accept nil, bool, UTF-8 string,
finite native numeric values, valid `json.Number`, `[]string`, `[]any`, and
`map[string]any`; typed nil containers encode as null. Reject custom marshalers,
other Go shapes, cycles, non-finite values, and invalid UTF-8. Preserve precise
`json.Number` values. Bounds are 128 top-level claims, 4096 value nodes, 16
container levels including the root map, 4096 bytes per string/key, 128 bytes per
numeric literal, and 64 KiB aggregate text and serialized claims. Validate the
serialized snapshot so policy checks apply to exactly the signed representation.
Callers must not mutate claims during `Sign`.

## Lifecycle, publication, and verification

A signer owns an immutable key/config snapshot, closes its input file during
construction, and is safe for concurrent signing and JWKS calls. There is no
`Close` operation or hidden refresh timer. Replacing the file does not alter the
active signer. Build a new signer with a new key ID and consumer to rotate;
failed construction must leave active instances usable.

`PublicJWKS() ([]byte, error)` returns independent public-only JSON bytes with
`kty=RSA`, `alg=PS256`, `use=sig`, `kid`, `n`, and `e`. No private parameters are
exported. The host publishes this data on its own route and retains old public
keys until their access tokens expire. Merely removing an old key from a file
does not invalidate existing verifier instances or cached identities; construct
replacement verifiers and account for their caches when retiring trust.

Core RSA verification accepts PS256 with 2048–8192-bit public keys and pins
SHA-256 and the exact salt size per token. Do not modify golang-jwt's global
`SigningMethodPS256` options: its default verifier accepts other salt lengths.
Reject other PSS algorithms, altered signatures, algorithm relabeling, and HMAC
confusion. Existing RS verification and signing behavior must remain intact.
RSA key configuration historically permits its RSA method family; a `kid` is a
selection label, not a separate trust boundary. Hosts must enforce issuer,
audience, purpose, and authorization independently where their consumer requires
those checks; core key verification alone does not establish them.

The refresh manager stages signing before atomic Create/Rotate. Signing errors,
cancellation, or rejected commits publish no credentials and must not spend the
previous refresh credential. Completed rotations retain normal replay revocation.
The host's identity callback must hold the identity transaction through signing
and commit, reject stale proof and unmet challenge policy, and never infer a
completed login from arbitrary client claims.

## Acceptance and validation

Run:

```sh
make test TEST_DIR='./plugins/cryptographic-signing/rsapss/... ./pkg/kms ./internal/tag' COVERAGE_DIR='.coverage/ps256'
make ci-check
```

[Plugin unit tests](../../../plugins/cryptographic-signing/rsapss/signer_test.go)
cover config, PEM failures, claim preservation and bounds, independent public
verification, ownership, concurrency, cancellation, and failed reload.
Verify signatures produced from both supported PEM formats. Symlink rejection
fixtures must point to an otherwise valid private key so malformed contents
cannot conceal a loader regression.
[Core tests](../../../pkg/kms/rsa_pss_test.go) exercise strict PSS salt handling,
key/method rejection, global-method isolation, and existing RSA verification.
The external parser tests include its executable constructor example.

`TestE2EPS256LoginRefreshAndAuthorization` uses actual TLS, a temporary identity
database, real password authentication, refresh manager/store, and gatekeeper.
It verifies tokens independently from fetched public JWKS, rotates signer/key
versions across PKCS#8 and PKCS#1 files, rejects tampering, retries after
signing/commit/cancellation failures, checks replay revocation, and denies
identity-revoked proof. Rejecting a symlink or malformed replacement key must
leave the active signer able to refresh and authorize; verify the resulting
signature independently. The HTTP cancellation assertion must identify context
cancellation, not accept an unrelated client failure.
`TestE2EPS256ExternalModule` copies this portable journey and helpers into a
temporary module with a local checkout replacement and networking disabled for
module resolution. Keep both in the default suite; do not substitute a compile
check or live service for this public consumer evidence.
