---
name: authentication-portal-cookies
description: Maintain portal cookie configuration, reusable cookie directive parsing, common prefixes and explicit names, domain attributes, factory issuance/deletion, and cookie interoperability with OIDC, refresh, OAuth, and gatekeepers.
---

# Authentication Portal Cookies

## Ownership and Configuration

`pkg/authn/cookie.Config` and `Factory` own shared cookie names and attributes.
`configuration.go` owns validation, cloning, the complete role list, and prefix
changes. `cookie_config.go` owns the public suffix constants and defaults.
OIDC and opaque refresh transports retain their own security and lifetime rules.
The SAML browser-binding cookie retains its fixed cross-site callback security
and five-minute lifetime independently of common attributes.

`pkg/authn/cookie/parser.NewCookieConfigFromDirectives(statements []string)`
accepts complete `cookie ...` statements encoded with `cfgutil.EncodeArgs`,
decodes them with `cfgutil.DecodeArgs`, and returns a validated `*cookie.Config`.
Empty input returns ordinary defaults. Use
`(*authn.PortalConfig).ConfigureCookies(config)` before runtime construction to
install an independent snapshot. It replaces the complete cookie configuration,
preserves unrelated portal settings, and leaves the portal unchanged on error.
See [directive grammar and application](references/directives.md).

## Names and Prefixes

Generated names use `AUTHP_<SUFFIX>` unless configuration specifies another
prefix. `Default...CookieName` constants are suffixes, not complete names.
Use `cookie.NewConfig()` or the effective factory fields when selecting a
default; never issue or select bare `SESSION_ID` or `ID_TOKEN` as defaults.

`NewConfig` eagerly initializes every role. Assigning `CookieNamePrefix` directly
is suitable only before default application on a fresh config literal. Use
`Config.SetCookieNamePrefix` after initialization to update all omitted or
previously defaulted names, including both OIDC names, without losing other
overrides. Empty typed prefixes reset to `AUTHP`; empty directive values fail.
An explicit name equal to the old default is indistinguishable from a generated
name, so typed callers apply that override after changing the prefix. The parser
applies the prefix before explicit names regardless of statement order.

When adding a role, update the complete name list, parser mapping, factory,
collision checks, and corresponding unit/E2E assertions. Include the effective
refresh name after its feature override in cross-role collision checks.
Do not introduce feature-specific hashed names or mandatory `__Host-` or
`__Secure-` prefixes. Such names are explicit compatibility configurations;
required attributes remain enforced independently of naming.

`Config.Validate` applies defaults, validates names/collisions, paths/domains,
and reserved-prefix compatibility, and normalizes SameSite. Invalid common configuration fails before feature
runtime creation. Domain-level `strip domain enabled` keeps domain selection
but emits host-only attributes; issuance and deletion must use matching scope.

## Issuance and Deletion

Deletion helpers derive scope and security attributes from their matching issuance
helpers, then set a past `Expires` and `Max-Age=0` (`http.Cookie.MaxAge = -1`).
Keep name, host-only/Domain, Path, Secure, HttpOnly, and SameSite consistent.
Deletion strings now use Go's standard cookie serialization; consumers should
parse attributes instead of depending on attribute order or trailing semicolons.

Return-cookie consumption in `grantAccess` and `handleHTTPPortalScreen` uses
`GetDeleteRefererCookie` once for each consumed cookie, including ignored or
malformed return destinations. Do not construct an additional deletion by
mutating `r.Cookie`: request cookies carry names and values, without their
original scope or security attributes. The factory owns the host-only portal
mount scope and preserves the configured security policy. Keep trusted redirects,
ignored destinations, cookie removal, and unrelated-cookie preservation covered
through the real login and authenticated portal routes.

Reserved prefixes remain optional and are matched case-insensitively.
`__Secure-` requires Secure; `__Host-` also requires no Domain and explicit
`Path=/`. Validate configured scopes through `Config.Validate`; portal mounts
through `Factory.ValidatePortalPath`; and provider-owned names through
`Factory.ValidateIdentityTokenCookieName`. `Portal.ServeHTTP` validates the
inferred portal mount before issuing ordinary portal cookies. A conflicting dynamic mount fails
with HTTP 500 and no cookies, without silently widening paths or domains.
The portal checks enabled upstream identity-cookie names during construction
without changing the provider. See [reserved-prefix compatibility and logout](references/reserved-prefixes.md).

`GetRefreshTokenCookie` and `GetDeleteRefreshTokenCookie` describe the retired
`api/refresh_token` scope. They return an empty string for `__Host-` names;
callers must omit empty headers. The active refresh runtime issues and deletes
its cookie separately at its configured mount, including `/`. Do not emit an
impossible legacy `__Host-` cookie or suppress active root-cookie deletion.

## Consumer Boundaries

OIDC uses the factory's `OIDCSessionIDCookieName` and `OIDCRequestIDCookieName`.
Refresh uses `RefreshTokenCookieName`, with a nonempty feature `CookieName`
override applied before factory creation. These credentials remain Secure,
HttpOnly, host-only, and mount-scoped with their feature-owned lifetimes.

SAML uses `SAMLSessionIDCookieName`, defaulting to
`AUTHP_SAML_SESSION_ID`. `cookie saml session id name <name>` changes the name;
the common prefix also covers this role. Issuance remains host-only, `Path=/`,
`Secure`, `HttpOnly`, `SameSite=None`, and `Max-Age=300` even when ordinary
cookies configure Domain, path, insecure mode, SameSite, or lifetime. Rotate
the value at every SP initiation, require exactly one callback cookie, and
delete it with the same attributes after successful assertion validation.
Reject duplicate callback cookies so a sibling Domain cookie cannot win by
header ordering. An optional `__Host-` configured name adds browser-enforced
Domain protection; do not require that prefix for compatibility.

Ordinary JWT gatekeepers default to `AUTHP_SESSION_ID` and accept `AUTHP_ACCESS_TOKEN` along
with the existing `access_token` and `jwt_access_token` token-source aliases.
Set `PolicyConfig.SessionIDCookieName` and `AccessTokenCookieNames` to match a
portal using overrides. Header/query aliases are not emitted cookie names.
The aggregate `authcrunch.NewServer` discovers portal access-cookie names when
a JWT policy leaves `AccessTokenCookieNames` empty. Supply an explicit list, including
an explicit default name when appropriate, to prevent cross-portal discovery.
The cookie parser itself does not rewrite policies or other portals.

Policies using [authorization-policy-oauth](../authorization-policy-oauth/SKILL.md)
use separate policy-owned opaque session/login cookies and are excluded from
portal access-cookie discovery. Their cookie overrides belong to
`OAuthAuthorizationConfig`, not `cookie.Config`; portal and upstream identity
cookies cannot authenticate those policies. Do not reuse portal cookie names
for direct-policy overrides on the same host.

Upstream OAuth identity cookies default to `AUTHP_ID_TOKEN`. A configured
`oauth.Config.IdentityTokenCookieName` governs issuance, Whoami, and external
logout. A provider can be shared by portals; its configured name is independent
of an individual portal's prefix.

Embedding adapters collect all cookie statements and call the public parser,
or use `SetCookieNamePrefix` with the typed API. Their own directive handlers
must be integrated separately in their owning repositories. Never change or
run validation in sibling checkouts to finish this library's integration.

## Validation

Keep parser unit tests and executable examples external. Cover all roles,
post-constructor prefix changes, explicit old-default overrides in both orders,
alias duplicates, token boundaries, invalid settings, redacted errors, clone
independence, serialization, and atomic application failures.

Consumer coverage includes the real TLS OIDC consent/logout journey in
`pkg/authn/oidc_e2e_test.go`, refresh cookie-jar rotation/logout in
`pkg/authn/token_refresh_config_parser_e2e_test.go`, upstream identity-cookie
Whoami/logout in `pkg/authn/oauth_cookie_e2e_test.go`, and portal-factory cookies
accepted by a gatekeeper in `pkg/authz/cookie_names_test.go`.
`pkg/authn/cookie/factory_e2e_test.go` verifies configured domain stripping,
path boundaries, sharing between subdomains, and matching deletion with a TLS
listener and a public-suffix-aware cookie jar.
`pkg/authn/referer_cookie_cleanup_e2e_test.go` verifies successful login and
authenticated portal consumption of trusted, untrusted, and malformed return
cookies, including a nested custom-prefix mount and root `__Host-` cookies in
Chrome. Keep exactly one matching deletion and preserve unrelated cookies.
`pkg/authn/cookie_browser_e2e_test.go` and its dependency-free CDP driver run
headless Chrome with a temporary profile and a TLS test-certificate SPKI allowlist,
following the [browser engine policy](../testing-and-ci/SKILL.md#browser-engine).
They prove old deletion headers fail in a browser, then verify real local login,
sandbox cleanup, gatekeeper access, path isolation, logout, and subsequent denial
with default, custom, secure-prefixed, and host-prefixed names. Go's cookie jar
alone does not enforce reserved prefixes and cannot establish that regression.
`pkg/authn/saml_state_e2e_test.go` and
`pkg/authn/ui/testdata/saml_browser_e2e.cjs` configure a non-default SAML name
through the public parser, reload its serialized configuration, and prove the
signed cross-site POST journey plus isolated-browser rejection in Chrome.

```sh
make test TEST_DIR='./pkg/authn/cookie/... ./pkg/authn ./pkg/authz ./pkg/idp/oauth/parser' TEST='Cookie|TestFactory|TestPortalConfigureCookies|TestE2EOIDCProviderBrowserConsent|TestE2EOAuth|TestE2ETokenRefreshCookieLifecycle|ExampleNewCookie' COVERAGE_DIR='.coverage/cookie-directives'
make ci-check
```
