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

`Config.Validate` applies defaults, validates names/collisions and paths/domains,
and normalizes SameSite. Invalid common configuration fails before feature
runtime creation. Domain-level `strip domain enabled` keeps domain selection
but emits host-only attributes; issuance and deletion must use matching scope.

## Consumer Boundaries

OIDC uses the factory's `OIDCSessionIDCookieName` and `OIDCRequestIDCookieName`.
Refresh uses `RefreshTokenCookieName`, with a nonempty feature `CookieName`
override applied before factory creation. These credentials remain Secure,
HttpOnly, host-only, and mount-scoped with their feature-owned lifetimes.

Gatekeepers default to `AUTHP_SESSION_ID` and accept `AUTHP_ACCESS_TOKEN` along
with the existing `access_token` and `jwt_access_token` token-source aliases.
Set `PolicyConfig.SessionIDCookieName` and `AccessTokenCookieNames` to match a
portal using overrides. Header/query aliases are not emitted cookie names.

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

```sh
make test TEST_DIR='./pkg/authn/cookie/... ./pkg/authn ./pkg/authz ./pkg/idp/oauth/parser' TEST='Cookie|TestFactory|TestPortalConfigureCookies|TestE2EOIDCProviderBrowserConsent|TestE2EOAuth|TestE2ETokenRefreshCookieLifecycle|ExampleNewCookie' COVERAGE_DIR='.coverage/cookie-directives'
make ci-check
```
