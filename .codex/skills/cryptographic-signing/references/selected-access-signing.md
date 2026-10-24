# Selected portal access signing

Use this contract when integrating a caller-owned signer with the real root or
portal, or when selecting strict PS256 access verification on a policy. The
standalone plugin contract remains in the [signing owner](../SKILL.md).
Downstream OIDC ID-token keys and direct OAuth sessions retain their own owners.

## Declaration, construction and ownership

Declare `Config.ExternalAccessSigners` as `[]*kms.ExternalAccessSignerConfig`.
Each descriptor has `Name`, `Kind`, `ConfigDigest` and `Policy`.
`NewExternalAccessSignerConfig(name, kind, policy, normalizedBackend)` hashes the
validated normalized backend, excluding the declaration name. Supply exactly
those names in `ServerOptions.AccessSigners map[string]kms.AccessSigner`.
Unused declarations are still validated; missing, extra, duplicate, nil and
mismatched runtime bindings fail before root resource acquisition.

`AccessSigner` exposes `Metadata() (AccessSignerMetadata, error)`,
`PublicJWKS() ([]byte, error)` and `Sign(context.Context, map[string]any)`.
Metadata attests the initialized immutable kind, configuration digest and policy.
The root contains panics only in metadata/discovery accessors and sanitizes their
errors. Construction and signing are not hidden behind blanket recovery.
The host owns handles, including optional closers, on success and failure.
Drain root calls before closing borrowed handles. A root or portal never closes
an injected signer and never replaces it with an automatic KMS issuer.

Set `PortalConfig.AccessSigner` and its complete `AccessTokenProfile` together.
Standalone `NewPortal` receives the same pair through
`PortalParameters.AccessSigner *kms.AccessSignerBinding`. `Prepare` returns a
detached binding with private captured metadata, public keys and the original
runtime. Its later `Prepare` and `Sign` calls use that immutable snapshot;
replacing exported input fields does not replace the captured runtime. Caller
mutation of the signer itself remains unsupported.

The profile and descriptor must agree on issuer, sole audience and maximum
lifetime, and the profile must contain the current key ID. Selected portals use
explicit public verification files. Reject ordinary sign/sign-verify keys, and
also reject private PEM material loaded under `verify`: that loader can retain
signing capability. System keys retain their separate use. Never install the
external private signer in KMS, generated-key storage or admin private export.

## Complete profile parser and trust

`kms/parser.NewAccessTokenProfileConfigFromDirectives([]string)` accepts one
complete encoded body:

```text
issuer https://login.example.test/auth
audience api
key ids current retiring
max lifetime 300
```

All four settings occur exactly once. Key IDs are 1–16 unique ASCII identifiers
using letters, digits, dot, underscore and hyphen; validation copies and sorts
them. Lifetime is an integer from 1 through 86400 seconds. Encode each statement
with `cfgutil.EncodeArgs`; parsing does not resolve placeholders, open key files
or discover remote keys. Reject malformed arity, duplicates, unknown settings,
invalid UTF-8, and raw CR/LF/NUL rather than ignoring a second record.

The issuer is an exact HTTPS URL with lowercase authority and an optional clean,
unescaped path without trailing slash. Root uses the bare origin. Credentials,
query, fragment, opaque URLs and silently normalized spellings are rejected.
Issuer paths are trust data and do not inherit reserved portal endpoint words.
Audience is one exact nonempty string. The lower-level signing plugin may retain
its opaque-issuer API; selected root metadata must satisfy this stricter profile.

Assign a profile to `PolicyConfig.AccessTokenProfile`, or directly to
`CryptoKeyStoreConfig.AccessTokenProfile`. Explicit verification keys are
required; automatic generation and direct OAuth/profile combinations fail.
Resolve every profile key ID to exactly one usable RSA verifier of 2048–8192
bits, with odd modulus and a valid odd exponent. Extra configured verifiers do
not become fallback authority. Existing token cookie/header/query aliases still
control discovery of incoming credentials.

`CryptoKeyStore.VerifyAccessToken(ctx, raw)` verifies bounded canonical compact
JWS before converting claims to a User. It requires exactly `alg=PS256`,
`typ=authcrunch-access+jwt`, and a trusted `kid`, with SHA-256 and a 32-byte PSS
salt. Reject extra header selectors, duplicate JSON members at any depth,
noncanonical base64url, malformed claim types and untrusted keys. This does not
change the JWT library's global algorithms or legacy RSA verification.

Reserved `iat`, `nbf`, `exp` are positive integral int64 values with
`iat <= nbf <= now < exp` and a bounded lifetime, without clock leeway. Require
configured issuer, nonempty subject and exactly the configured audience. The
shared bounded JSON codec retains precise `json.Number` values and rejects
custom marshalers and unbounded objects. Profile `CacheUser` verifies the raw
JWT again and compares the canonical claims before admitting it. Setting a
credential TokenSource cannot insert under a raw JWT key; credential-result
cache keys use a separate computed namespace that bearer lookup never accepts.
Plain-payload authenticators retain their separately configured authority.

## Issuance, lifetimes and transport

Ordinary login, completed local sandbox, Basic/API-key, connected identity,
cross-device transfer and refresh all use the selected signing boundary.
Evaluate current identity and policy first, while existing identity transactions
remain held. Policy still sees its established request-derived issuer. Require
an explicitly approved singleton audience; signing never supplies a missing
one. Initial family capture and every renewal check current audience before the
refresh manager's original-grant intersection.

Before User conversion can truncate numbers, reject malformed reserved times,
future `iat`/`nbf`, expiry and inconsistent grants. Preserve integral producer
`iat`, normalize historical generated `nbf` to `iat`, then set the selected
issuer. Retain a shorter approved `exp`, parent proof expiry and family deadline.
Renewal retains the manager's ownership of staged temporal claims. A renewable
signer's issuer must exactly equal refresh origin plus its mount, omitting the
root trailing slash; mismatch is a pure configuration error.

The selected access lifetime is the positive crypto-default lifetime or the
usual 900-second default, capped by signer/profile maximum. Negative explicit
values fail. Verifier-only key lifetimes do not choose issuing lifetime. Refresh
further caps the manager policy by its access limit; result expiry and actual
JWT expiry must agree before commit.

Snapshot the canonical `User.AsMap`, pass a detached copy to the plugin, then
verify its returned JWT and compare every approved claim exactly. Added, removed,
mutated, rounded or otherwise mismatched claims fail. Only a successful exact
match assigns Token/TokenName. Preserve private login evidence, canonical
identity, completed methods and frontend links. Errors and cancellation publish
no staged credential; failed refresh signing leaves the prior credential usable.
Selected signing failures log correlation and sanitized errors, never arbitrary
provider claim maps. Session/store completion still owns final publication and
rollback after signing.

Nonrenewable cookies preserve session-cookie omission and shorter configured
lifetimes; cap longer positive lifetimes at the signed expiry and reject an
expired staged credential. Existing renewable delivery uses result expiry for
Max-Age/Expires. Logical direct/nonrenewable token names remain the crypto name
or `access_token`; renewable User reconstruction keeps its existing effective
cookie name. JSON `access_token_name` and actual cookies always use the resolved
cookie factory. Do not force those distinct labels to match.

## Public keys and persistence

Selected public portal JWKS is the immutable, deterministic public snapshot of
exactly the profile's current and explicitly retained keys. It advertises PS256
and required IDs, excludes unrelated/system/private material, and preserves the
existing GET/HEAD, no-store, nosniff and mount routing behavior. Retain old public
keys deliberately until their tokens expire; removing a key requires replacement
verifiers and their caches. Legacy KMS discovery remains unchanged.

Root persistence includes canonical public trust fingerprints from already
loaded portal and policy-only verifiers and the current signing key's role.
No file is reopened while computing the epoch. Changing key material at the same
filename retires old sessions; changing only PEM encoding does not. Returning to
old trust cannot revive authority from an earlier observed epoch. Roots without
profiles keep their existing fingerprint representation. Descriptor digests
alone cannot identify mutable key-file contents.

## Acceptance

The focused tests are `TestAccessClaims*`, `TestAccessTokenProfile*`,
`TestAccessSigner*`, `TestAccessProfileCacheAdmission`,
`TestSelectedAccessSigning*`, `TestServerExternalAccessSignerOwnership`,
`TestServerAccessSignerPureSelectionValidation`, and
`TestServerLegacyAccessPersistenceBindingUnchanged`. Preserve the public parser
example. `TestE2EServerSelectedAccessSigning` performs real TLS/password login,
independent fetched-JWKS verification, gatekeeper access, native rotation/replay
and protected browser delivery. `TestE2EServerSelectedAccessPersistenceTrust`
replaces the root and changes a policy-only verifier at an unchanged filename,
with an equivalent-encoding positive control and restoration-negative control.
Run these with existing plugin, KMS, refresh, direct-authentication, cross-device,
OAuth and tag regressions, then the required API and quality gates. Recorded
results belong in validation artifacts, not in this contract.
