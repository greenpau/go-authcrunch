# Embedding Integration Boundaries

The in-repository standalone host is `cmd/authdb`, using `pkg/httpserver.Serve`.
Its [owning skill](../../authdb/SKILL.md) describes the JSON envelope, HTTP parser,
TLS listener, mounts, and shutdown contract.

Use these entry points when preparing configuration for an embedding server.
The host owns block traversal, tokenization, placeholder expansion, and private
credential storage. Encode each statement with `cfgutil.EncodeArgs`; reject
empty tokens before encoding. Library parser availability does not establish
that a downstream configuration language already recognizes a directive.

| Surface | Public parser | Apply to production configuration |
| --- | --- | --- |
| Standalone HTTP listener body | `pkg/httpserver/parser.NewHTTPServerConfigFromDirectives(statements)` | `httpserver.Serve` with the root security configuration |
| `oauth application <nickname>` | `pkg/oidc/parser.NewOAuthApplicationConfigFromDirectives(header, statements, persisted)` | `Config.AddOAuthApplication` |
| OIDC provider body | `pkg/oidc/parser.NewOIDCProviderConfigFromDirectives(statements, applications)` | `PortalConfig.ConfigureOIDCProvider`; root `Config.ConfigureOIDCProvider` resolves registered applications through this parser |
| `token refresh` body | `pkg/authn/token_refresh/parser.NewTokenRefreshConfigFromDirectives(statements)` | `PortalConfig.RefreshTokens` |
| Admin API statements | `pkg/authn/admin_api/parser.NewAdminAPIConfigFromDirectives(statements)` | `PortalConfig.ConfigureAdminAPI` preserves profile API configuration |
| Complete `cookie ...` statements | `pkg/authn/cookie/parser.NewCookieConfigFromDirectives(statements)` | `PortalConfig.ConfigureCookies` |
| Upstream OAuth provider body | `pkg/idp/parser.NewOAuthIdentityProviderConfigFromDirectives(name, statements)` | `Config.IdentityProviders`; this adapter delegates grammar to `pkg/idp/oauth/parser` |
| Native login client body | `pkg/authclient/parser.NewAuthenticationClientConfigFromDirectives(statements)` | `authclient.NewClient` with explicit refresh body transport |

Read the feature's owning skill for its exact grammar, defaults, and exclusions.
Keep downstream handlers thin; do not copy field allowlists or parse the same
settings independently. Do not route upstream OAuth settings into `pkg/oidc`.

Build a fresh configuration graph. Collect named applications before resolving
provider bodies, regardless of textual order. Provision omitted client IDs,
secrets, and provider signing keys through the explicit `oidc` provisioning
APIs, and persist the result before adaptation. Ordinary application adaptation
and `Config.Validate` do not generate credentials. Restore registrations by
nickname; a missing credential store must not silently rotate client identity.

Configure cookies through their parser or `SetCookieNamePrefix` before runtime
construction. Assigning `CookieNamePrefix` after `cookie.NewConfig` leaves
initialized names intact. An enabled token-refresh cookie-name override takes
precedence over the shared refresh role. Keep access, opaque refresh, OIDC
session, and pending-request cookies distinct.

One OIDC provider belongs to one portal. Its explicit realm list selects local
identity stores allowed to participate; enabling a store on the portal alone
does not grant OIDC participation. When refresh and OIDC coexist, they require
the same canonical HTTPS origin and mount. Provider signing keys must remain
separate from ordinary access-token verification keys.

Persisted configuration is not session persistence. The portal allocates its
own in-memory refresh store; OIDC sessions, pending requests, codes, and access
grants are also process-local. Reloads invalidate that runtime state even when
client credentials and signing keys survive. A standalone refresh `Store`
implementation does not by itself expose distributed storage through a portal.

Resource ownership follows construction. `NewServer` records components as soon
as construction succeeds and unwinds errors in reverse order, including the
component whose configuration failed. `Server.Close() error` is public,
idempotent, and concurrent-safe; it waits for the same disposal and joins
cleanup errors. Optional component `Close()`/`Close() error` methods preserve
existing dispatcher interfaces. Shared providers are closed once, after portals.
Registries receive independent runtime copies through
`LocalUserRegistryProvider.NewRuntime`; configuration never owns their caches.

The host supplies a fresh configuration graph per runtime and must not mutate it
while serving. It owns listeners, replacement publication, and request draining:
remove a runtime from routing and drain its requests before Close. Root lookup
returns `ErrServerClosed` after disposal starts; retained portal and gatekeeper
pointers reject new HTTP work after Close. Portal BasicAuth and OAuth provider
authentication also fail closed. Shutdown is not an HTTP server drain operation.
Coordinate shared identity-file writers during replacement; lifecycle ownership
does not add multi-process database transactions or a live configuration editor.

`Portal.Close` stops and awaits its session, sandbox, and token-validator caches,
and closes refresh/OIDC state. `Gatekeeper.Close` owns its validator, not shared
authenticators. `oauth.IdentityProvider.Close` cancels and awaits owned delayed
or synchronous discovery, metadata/JWKS requests, retries, and state maintenance.
A closed provider cannot restart or publish readiness afterward. Cache Run/Stop
APIs that already support restarting retain it, while disposed runtimes do not.
Persistent identity data, registrations, and signing-key files are not deleted.

Validate the composition in this module: external-package tests should import
the public parsers, serialize/reload configuration, build `NewServer`, and use a
real TLS portal. Exercise combinations as well as each feature separately:
selected/unselected realms, configured claims, browser/native login consumers,
cookie overrides, credential rotation, and runtime replacement.

The external root fixtures `server_composition_e2e_test.go` and
`server_oauth_composition_e2e_test.go` exercise this handoff through actual TLS
listeners. They cover persisted application identity and secret rotation, both
local realms, effective cookie names, native body credentials, separate signing
purposes, private export opt-in, browser refresh/logout, and volatile state loss
on root replacement.
The upstream fixture checks explicit issuer and access-token audience after
shared parser adaptation and JSON restoration. An invalid identity token fails
login; an unusable supplemental access token contributes no claims, preserving
the upstream adapter's compatibility contract.

Run the root composition tests through the tested lifecycle:

```sh
make test TEST_DIR=. TEST='TestE2EServer.*Composition' COVERAGE_DIR=.coverage/server-composition
make ci-check
```

These fixtures validate this library's public API; they do not
implement or certify a downstream configuration handler. The host must retain
private registrations and keys, mount HTTP endpoints, select browser/native
transport intentionally, and coordinate publication/draining during reload.

When the host disables authorization redirects, handle an error returned by
`Gatekeeper.Authenticate` with an appropriate HTTP denial. Do not fall through
to the protected handler or leave an unwritten response as an implicit 200.
The composed fixture maps these authentication errors to 401 and verifies that
OIDC ID tokens and opaque access tokens cannot authorize portal resources.
