---
name: authentication-portal-oidc
description: Maintain the reusable pkg/oidc OpenID Provider, its public API and portal adapter, including client registration, discovery, code/PKCE, consent and browser-page rendering, ID-token keys, scoped and individual claims, authentication context, Request Objects, rotating OIDC refresh tokens, revocation, and conformance tests. Use for OIDC renderer integration, form-post continuation, browser errors, and their response policies. Excludes upstream OAuth providers and portal refresh-token transport.
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
- `application.go`: serializable `OAuthApplicationConfig`, associating an exact
  nickname with a validated client; `NewOAuthApplicationConfig` snapshots it
  without generating credentials. Root `Config.OAuthApplications` owns named
  registrations, with copying add/lookup methods in `config_oauth_applications.go`.
- `pkg/oidc/parser`: public
  `NewOIDCClientConfigFromDirectives(nickname, statements)` parses an OAuth
  application block body with `cfgutil.DecodeArgs` and returns `*oidc.ClientConfig`.
  This separate package owns the parser and its external-package unit tests;
  it delegates provisioning to `oidc.NewClientConfig`.
  `NewOAuthApplicationConfigFromDirectives(header, statements, persisted)`
  recognizes the encoded `oauth application <nickname>` header and reuses the
  same client field decoder for adaptation without credential generation.
  `NewOIDCProviderConfigFromDirectives(statements, applications)` parses provider
  settings, resolves selected application nicknames through a caller-owned
  `map[string]*oidc.ClientConfig`, and returns `*oidc.Config` for `NewProvider`
  or `PortalConfig.OIDCProvider`. Embedding adapters collect statements using
  `cfgutil.EncodeArgs` and import the parser directly.
  Keep the client, application, and provider entry points in `client.go`,
  `application.go`, and `provider.go` within this one parser package. Extend
  the matching entry point when exposing additional settings on its config;
  reuse the client decoder when adapting named applications.
- Root `Config.ConfigureOIDCProvider(portal, statements)` supplies registered
  applications to the provider parser, then calls
  `PortalConfig.ConfigureOIDCProvider` to attach a validated snapshot. A second
  definition fails; prior portal validation is invalidated so OIDC defaults run.
- `identity.go`: public `Authentication`, `Identity`, `IdentityVerifier`, and
  `OpenIDProvider` contracts.
- `options.go`: construction, runtime `RenderPage` callback, configurable login
  URL, cookie names, and excluded signing keys; `provider.go`: bounded sessions,
  consent, and browser lifecycle.
- `keys.go`: dedicated RSA PEM loading, thumbprints, public `JWKS`, signing, hints.
- `http.go`: public `ServeHTTP`, `HandleHTTP`, `ValidateLoginRequest`, and
  `Discovery`, guarded issuer routing, parsing, CORS, and buffered responses.
- `pages.go`, `page.template`: browser page snapshots, standalone rendering,
  content negotiation and CSP. The portal uses its `oidc` UI template alias;
  read [browser pages and themes](references/browser-pages.md) when changing
  consent, form-post continuation, browser errors or rendering integration.
- `authorization.go`, `request_object.go`, `token.go`: code/PKCE, consent,
  unsigned/RS256 Request Objects, client authentication, UserInfo, and revocation.
  `claims.go` owns claims permissions and ACR mapping; `refresh.go` owns OIDC
  refresh families; `request_keys.go` validates client verification keys.

`pkg/authn/oidc_runtime.go` supplies `portalOIDCIdentityVerifier`, local-realm
validation, key/cookie isolation, and sandbox/browser adapters. It binds
`pkg/authn/oidc_ui.go` to the existing portal UI factory for browser rendering;
the reusable provider does not import that factory. `configureOIDC`
runs after portal keys and optional refresh configuration. `Portal.Close` closes
the provider; `Portal.GetOIDCProvider` exposes its public interface.
`pkg/authn/oidc_config.go` retains `OIDCProviderConfig` and `OIDCClientConfig` as
aliases; `PortalConfig.OIDCProvider` keeps its `oidc_provider` serialization.

Root `Server.Close()` owns portals and shared providers in reverse construction order, including constructor-error
unwind; individual portals do not close shared upstream identity providers.
Standalone consumers drain requests and close their own provider/portal.
See the [embedding lifecycle](../coding-directives/references/embedding-integration.md).

Read [reusing the Go provider](references/reusable-provider.md) when embedding
`pkg/oidc` independently or changing its public API and identity boundary.
Read [configuration and clients](references/configuration-and-clients.md) for
setup and operational constraints. Read [conformance](references/conformance.md)
for the targeted certification profiles, supported features, test evidence,
and the OpenID Foundation test-plan configuration.
Conformance browser captures must match the module's evidence request. Keep
login captures in the two reauthentication overrides; a generic pending
placeholder can instead request an error page. See the conformance reference
for the Request Object callback-precedence case and the capture regression test.
Read [named application integration](references/reusable-provider.md#named-application-registration-and-reloads)
for directive adapter ordering, registration persistence, and secret rotation.

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
`finishOIDCLogin` takes the canonical sandbox `LoginUsername`, not the
transformed access-token subject. Follow
[canonical identity and transformed claims](../refresh-token-identity/SKILL.md#canonical-identity-and-transformed-claims)
when changing shared login; OIDC UserInfo still returns current backend
attributes and its subject remains bound to the immutable local record.

OIDC browser credentials use the portal cookie factory's configurable names:
`AUTHP_OIDC_SESSION_ID` and `AUTHP_OIDC_REQUEST_ID` by default. They honor
`cookie_config.cookie_name_prefix` and explicit name overrides. Use the
[shared cookie parser and prefix API](../authentication-portal-cookies/SKILL.md)
for directive configuration and post-initialization prefix changes. Credentials are
random, host-only cookies with Secure, HttpOnly, SameSite=Lax, and the issuer
mount as Path (root issuers use `/`). Use distinct names or prefixes for portals
with overlapping mounts on one host. Issuance and deletion use matching paths;
lifetimes remain provider-owned. The common cookie factory rejects collisions
with the effective token refresh cookie as well as the other portal cookie roles.
Duplicate cookies are rejected. Successful interactive
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
`parser.NewOIDCClientConfigFromDirectives` is also a provisioning entry point:
omitted credentials are generated. It accepts repeatable `redirect_uri <uri>`
statements, single-value scalar fields, a single multi-value `scopes` statement,
and `cfgutil.ParseBoolArg` booleans. Each callback statement has exactly one URI
and appends in declaration order. The `redirect_uris` directive is rejected,
including mixed singular/plural input; the native JSON/XML/YAML collection keeps
that plural name. One callback per statement makes individual registrations
easier to review, add, and remove without rewriting a packed list. This grammar
is owned by the shared parser so embedders do not implement competing list
semantics. Duplicate callback values and duplicate nonrepeatable settings still
fail. Errors never include raw statements or values.
For repeated configuration adaptation, use
`NewOAuthApplicationConfigFromDirectives`: credentials must be explicit or
restored from a valid registration with the same nickname. Only credentials are
inherited; current directives define redirect/scopes/consent/PKCE and other policy.
A different client ID cannot inherit the previous secret, and public clients
never inherit secrets. No fallback generation occurs when persisted state is
missing or invalid. Provision once, persist privately, and build a fresh Config
on reload. The host owns durable storage and must persist successful credential
changes before activation; the library performs no automatic credential IO.
Root `Config.AddOAuthApplication` rejects duplicate nicknames even if identical;
lookup returns independent copies. Root validation checks every declared
registration, including unselected ones, without provisioning. Configuration
mutation methods are for assembly before construction, not runtime updates.
Provider settings use readable keywords (`signing key files`, `session lifetime`,
`max pending requests`) and standalone `enabled`/`disabled`; keep that grammar
separate from individual application fields. Collect all application registrations
before provider parsing, regardless of block order. Provider parsing selects only
explicit `applications` references, copies them with `Config.AddClient`, and then
calls `Config.Validate`. Never generate missing credentials, implicitly register
the whole application map, mutate its entries, or defer unresolved references to
runtime. Unknown/nil references, repeated nicknames, and duplicate client IDs fail
even for disabled configurations. Keep reference labels out of errors, and preserve
key-file order for signing/rotation. Parsing performs no key-file IO; construction
owns key loading and portal-specific realm/mount checks.

`GenerateSigningKeyFile` publishes a complete owner-only file with a hard link;
it never overwrites existing paths or follows a destination symlink.

Validate the client and registered redirect URI before any redirect. Public
HTTP literal-loopback clients may vary only the port, as described below.
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
Reject duplicate JSON members, nested requests, unregistered signatures, encrypted
objects, and invalid JWT metadata. RS256 verifies only registered client RSA keys;
remote or embedded header keys are rejected. Pin `request_object_signing_alg RS256`
to prohibit unsigned Request Objects for a registration. Remote request URIs return `request_uri_not_supported`
without network fetches. ID tokens still require RS256. Discovery advertises
only implemented capabilities. `claims` supports `userinfo` and `id_token` locations
within registered scope permissions. Requested disclosure is bound to consent,
code, and access token. Unknown extensions/scopes are ignored. Use
[claims, authentication context, and refresh](references/provider-capabilities.md)
for typed attributes, parser directives, security invariants, and validation.

`prompt=none` never renders interaction. Prior consent covers only scopes and individual claim locations
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
client, exact actually authorized redirect URI, PKCE, expiry, and current identity. Keep spent-code
tombstones until the resulting token family expires. A replay revokes the family,
including concurrent replays. All opaque credentials are stored by SHA-256 hash.
Capacity exhaustion fails closed; active state is never evicted to admit a new
request. One pending interactive authorization per browser is supported; a new
interaction supersedes the old one and invalidates its consent form.

Dedicated RSA keys must be 2048–8192 bits and must not overlap portal verification
keys. All ID tokens use RS256 with a public-only JWKS and stable thumbprint `kid`.
ID tokens contain issuer, immutable subject, client audience, numeric times,
verified `amr`, `auth_time`, `at_hash`, and the exact nonce when supplied.
UserInfo returns granted scopes and consented individual claims, with a matching `sub`.
`identity.Profile` supplies explicit optional profile, address, and phone data;
missing attributes are never fabricated. ACR mappings require completed methods;
an unmet essential ACR or requested subject fails authorization.
Email verification is not inferred: the portal adapter returns
`email_verified: false`; standalone verifiers may attest verified ownership.
Opaque UserInfo
tokens cannot authorize other portal APIs, and neither ID tokens nor portal
access tokens authorize UserInfo. `offline_access` requires explicit `prompt=consent`
and a fresh approval even for `skip_consent` clients. OIDC refresh credentials
rotate; reuse revokes the family. They remain bound to the original client,
identity, session, consent and absolute expiry. The ordinary portal refresh
protocol remains independent.

## Validation

For renderer, template, CSS, browser policy, or consent-presentation changes,
use the [browser-page validation matrix](references/browser-pages.md#validation).
It covers both standalone and portal rendering, filesystem overrides, native
browser form submissions, and JavaScript-disabled continuation.

`pkg/oidc/config_test.go` covers config, client authentication, and PKCE contracts.
`provisioning_test.go` covers generated credentials, defaults, copied registration,
duplicate rejection, private-key format, file permissions, and concurrent creation.
`parser/client_test.go` and `parser/example_test.go` cover the separate public
parser, quoting, arity, boolean compatibility, error redaction, concurrent reuse,
and stable adaptation with persisted credentials. `parser/redirect_test.go`
checks repeated single-URI statements through both public constructors, rejects
plural/mixed forms and malformed later statements, and preserves exact callback
order and serialized arrays. Reloads replace the callback list without mutating
persisted registrations or inheriting removed callbacks.
`application_test.go` covers named registration snapshots and JSON/XML/YAML
roundtrips. `parser/application_test.go` and `parser/application_example_test.go`
cover header recognition, shared field parsing, restored/explicit credentials,
rotation, authentication-method changes, malformed inputs, and concurrent reloads.
Root `config_oauth_applications_test.go` and its executable example cover the
registry, serialization, ordered assembly, independent portal bindings, validation,
and duplicate rejection. `pkg/authn/oidc_config_test.go` checks provider attachment.
`parser/provider_test.go` and `parser/provider_example_test.go` cover provider
settings, registration resolution and copying, disabled state, limits, malformed
arguments, error redaction, concurrent reuse, and serialized roundtrips.
`provider_test.go` and `options_test.go` cover keys, hints, identity, expiry,
capacity, construction, public methods, lifecycle, lock release, and parser
fuzzing. `request_object_test.go` covers strict request assembly and fuzzing.
`pkg/oidc/provider_e2e_test.go` imports the public provider and parser packages
and the standard library, running TLS login, consent, PKCE exchange, independent
RSA verification, UserInfo, fresh login, account disablement, and logout without a portal. It
provisions and persists generated clients/keys, exercises all three client
authentication methods, and repeats login/exchange after restoring the provider.

The standalone E2E fixture imports the provider parser directly; the shared
portal fixture uses root named registration and provider integration.
`pkg/authn/oidc_application_e2e_test.go` imports the application parser directly
and exercises all three client authentication methods through root configuration,
real TLS local-user login, PKCE exchange, independently verified ID tokens, and
UserInfo. It persists credentials and dedicated keys in temporary files, repeats
adaptation after reopening storage, rejects old secrets after explicit rotation,
reloads the rotated secret, and rejects unselected applications. It exchanges
through both separately declared callbacks after each reload and rejects an
unregistered callback variation before redirecting, including equivalent host,
port, and path/query encodings. It checks the response destination and query
values, binds each code to its authorized callback, and tests unselected clients
with their own registered callback on every reload. Runtime sessions
and grants remain process-local even when client credentials survive reloads.
`pkg/authn/oidc_config_parser_e2e_test.go` checks discovery, selected clients,
session/token lifetimes, all capacity limits, and disabled routing through
a real TLS portal. Root `server_oidc_config_test.go` checks parsed configuration
through server dispatch, including realm, key-file, and reserved-mount failures.
`pkg/authn/oidc_e2e_test.go` keeps the real portal/local-database password and
MFA E2E flows. `pkg/authn/oidc_runtime_test.go` checks adapter configuration and
browser/native logout. Root `config_test.go` covers server dispatch and the
public provider getter. Keep E2E cases in the default Go suite. Route portal
fixture requests directly to the portal so outer mount filtering cannot mask
incorrect dispatch. Requests outside the issuer mount must not serve keys or
consume codes.

```sh
make test TEST_DIR='./ ./pkg/oidc ./pkg/authn ./internal/tag' TEST='OIDC|Provider|TestTagCompliance|TestStructTagCompliance' COVERAGE_DIR=.coverage/oidc
make test TEST_DIR='./pkg/oidc/parser' COVERAGE_DIR=.coverage/oidc-parser
go test -mod=readonly -race ./pkg/oidc -run '^$' -fuzz '^FuzzOIDCAuthorizationParameters$' -fuzztime=10000x -parallel=2
go test -mod=readonly -race ./pkg/oidc -run '^$' -fuzz '^FuzzOIDCRequestObjects$' -fuzztime=10000x -parallel=2
make ci-check
```

Local tests establish implementation behavior, not OpenID certification. Never
claim conformance-suite success or certification without the actual Foundation
plan results and submission record for this deployment/version.

For release qualification, record the Foundation suite revision, selected OP
profile, configuration, and per-test results for the actual standalone host or
portal adapter under test. Local TLS tests and parser fuzzing do not substitute
for that plan.

A public registration (`token_endpoint_auth_method none`, mandatory S256 PKCE)
with an HTTP callback at literal `127.0.0.1` or `[::1]` declares the supported
native-loopback subset. `redirect.go` implements the port exception from
[RFC 8252 sections 7.3 and 8.4](https://www.rfc-editor.org/rfc/rfc8252#section-7.3).
At authorization, only port bytes may differ; every other raw URI byte remains
exact, including scheme case, encoded paths, query order/encoding, and empty
query markers. An omitted port is allowed; an explicit TCP port must be decimal
1–65535. Reject empty/zero/out-of-range/nonnumeric ports, userinfo, fragments,
look-alike hosts, nonliteral localhost, IPv6 zones/mapped addresses, and private
schemes. HTTPS and confidential-client registrations retain exact matching.
The grant stores the actual authorized URI, and token redemption must match it
exactly, including the selected port. Never apply the exception at redemption.
CORS origins remain registered origins; this does not grant arbitrary loopback
ports browser CORS access. Native apps redeem directly without browser Origin.
Private-use mobile schemes remain unsupported; do not claim full native-app
best-practice support or Foundation certification from this subset.

Preserve typed/parser serialization of the original registration, the public
parser loopback example, rejection matrices, GET/POST/Request Object/form-post
coverage, and `FuzzOIDCLoopbackRedirect`. Standalone and portal E2E fixtures run
real IPv4 and IPv6 callback listeners on ephemeral ports, perform PKCE exchanges,
and independently verify ID-token signatures and UserInfo. They require both
loopback stacks; report a listener failure as a validation blocker.
