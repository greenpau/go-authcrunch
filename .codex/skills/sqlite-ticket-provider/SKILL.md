---
name: sqlite-ticket-provider
description: Maintain the pure-Go SQLite single-use ticket identity provider, public parser, trusted issuance API, HTTP login capability, cookie and realm binding, portal signing, and TLS consumer tests. Excludes OAuth/SAML protocols and anonymous ticket issuance services.
---

# SQLite Ticket Identity Provider

`plugins/identity-providers/sqlite` supplies kind `sqlite-ticket`, driver `ticket`.
A trusted application authenticates its user and calls Issue; a browser redeems
the issued ticket through a bound portal request. There is no anonymous issuance
endpoint or issuer server in the plugin.

## Configuration and composition

Use `parser.NewSQLiteTicketProviderConfigFromDirectives([]string)`. Required:
`name`, `realm`, absolute `path`, `public_origin`, and `issuer_url`. Each accepts
one value once. Realm uses 1–64 ASCII letters/digits/underscore/hyphen. Origin is
canonical HTTPS with no path, credentials, query or fragment. Issuer URL is HTTPS
with a nonempty path of ASCII letters/digits/underscore/hyphen segments, no query,
fragment or userinfo, and must differ from the portal callback. No discovery or
network request runs during parsing or construction.

Optional `base_path` defaults `/auth`; `/` and unreserved nested paths work.
Segments use ASCII letters/digits/underscore/hyphen, with no trailing slash or
existing portal protocol namespace. Optional `timeout` defaults 1s (1ms..30s).
Optional `cookie_name` defaults `AUTHP_PROVIDER_SESSION_ID`. It is independently
configured, not generated from a hash or a portal's common prefix. An explicit
`__Secure-` prefix is allowed. `__Host-` cannot use the callback subpath and fails.
The parser covers all fields and returns no partial result or sensitive echoes.

`New(ctx, config)` snapshots configuration and opens a private local POSIX file.
Read the [shared SQLite contract](../plugin-development/references/sqlite-backends.md)
for pure-Go storage, permissions, schema ownership, uncertainty and Close. Inject
through `authn.PortalParameters.IdentityProviders` and select the instance in
PortalConfig.IdentityProviders. Root config/standalone authdb dispatch remains
OAuth/SAML-only. Hosts own provision/reload/Close; Portal.Close does not close a
shared provider. Configure/Configured check current storage health.

## Trusted issuance and browser flow

1. HTTPS GET `<base_path>/provider/<realm>` creates a five-minute pending request
   and independent browser secret, both 256-bit random values. Storage contains
   SHA-256 digests. A host-only, Secure, HttpOnly, SameSite=Lax cookie uses the
   exact callback path and a five-minute lifetime.
2. The portal redirects to the pinned issuer URL with `request` and `callback`.
   The issuer must authenticate its user, then call
   `Issue(ctx, requestID, *idp.LoginIdentity)`. It must not trust browser-supplied
   subject/roles or expose this API anonymously. Identity contains subject,
   email, optional name and 1–32 roles; validation bounds every string. No raw
   credential, reserved JWT field or MFA evidence can be supplied through it.
3. Issue returns one 256-bit ticket, stores its digest and a detached identity,
   and refuses repeated issuance. Ticket lifetime is at most two minutes and
   never exceeds its request deadline. Use CallbackURL() as the redirect target;
   do not follow an arbitrary callback supplied by the issuer's HTTP caller.
4. Return the browser to CallbackURL with exactly one `state` and `ticket` query
   parameter. Exact HTTPS host/path, canonical token encoding, one binding
   cookie, request/issuer/realm/configuration binding and both deadlines must
   pass before an immediate transaction consumes the ticket.
5. Only successful commit releases the authenticated identity. Replays cannot
   authenticate, including concurrent callbacks through separate handles. A
   signing/policy failure afterward does not restore the consumed ticket; start
   a new login. Successful consumption deletes the binding cookie with matching
   scope and attributes.

Name, realm, origin, base path, issuer URL and cookie name form the configuration
binding. Compatible reopening preserves pending requests/tickets; changed binding
cannot consume them. Only expiry is pruned on admission; capacity is 1,024 live
requests across the file. Full admission fails without evicting valid work. A new
begin replaces that browser's cookie; older pending requests expire naturally.
There is no sliding grace, background cleanup or automatic retry after uncertain
commit. Never publish an uncertain redirect, ticket or identity. Drain/reopen a
quarantined handle and reconcile; a fresh login is the normal recovery path.

## Portal capability and security boundaries

`idp.HTTPLoginProvider` adds Login(ctx, *http.Request) and GetLoginCookieName.
HTTPLoginResult contains exactly one pinned redirect or validated LoginIdentity,
plus optional cookie state. Runtime results are excluded from serialization.
The portal clears retained request authentication state, checks malformed results,
rejects unsafe redirects/cookies, and withholds credentials on any error. Cookie
names are checked case-insensitively against all portal roles and upstream identity-cookie names
at construction; emitted names must match the declared binding. Secure protocol
attributes are independent of common cookie settings. Add new shared cookie
roles to the factory's central collision inventory.

The `/provider/<realm>` route and login icon are independent of backend kind.
Existing earlier namespaces retain ownership; a provider realm named logout,
portal, register or cross-device remains a provider realm. JSON negotiation
cannot bypass protocol query validation. The route emits no-store and no-referrer
headers, and never logs ticket-bearing redirects. Hosting access logs must redact
callback query credentials; application-issued redirect logs need the same care.

The normal portal applies transforms, current challenge requirements and signing.
Origin is pinned back to the selected realm after transforms. AMR is server-owned
`federated`, never `pwd`, TOTP or WebAuthn. Ticket identity cannot satisfy a local
factor requirement. Provider/store realm collisions and duplicate provider realms
fail at portal construction. The core owns JWT/session issuance; the plugin does
not sign tokens or reuse a supplied access token.

Portal logout clears ordinary portal credentials; this provider has no upstream
logout, identity token, refresh token or account introspection API. Pending tickets
remain valid until consumed/expired; logout is not ticket revocation. Cross-device
transfer and downstream OIDC/refresh identity adapters are separate capabilities
and are not supplied by this reference. Issued access tokens retain their normal
lifetime; upstream account revocation is outside this simple ticket contract.

## Acceptance

```
make test TEST_DIR='./plugins/identity-providers/sqlite/... ./pkg/idp ./pkg/authn/cookie/... ./internal/tag'
make test TEST_DIR=./pkg/authn TEST='TestProviderLogin|TestExtractBasePath|TestCrossDeviceMount|TestExternalLoginSeparatesReturnURL'
```

Units cover single issuance/consumption across independent handles, wrong browser,
issuer and destination, duplicates, expiry, capacity, cancellation, detached
identity, typed/parser validation and actual commit failure withholding identity.
The public-only TLS consumer runs a locally authenticated issuer application,
real portal, separate cookie jars, config roundtrip/restart, wrong credentials,
Host and query negotiation, restored-cookie replay, logout, transforms/MFA denial and
independently verified JWTs. Run the external-module driver as well. Core tests
exercise malformed optional capability output, cookie collisions, namespace
precedence and unchanged OAuth/SAML redirects. Run public units/parser/consumer
with CGO_ENABLED=0, excluding the external driver which enables the race detector.
