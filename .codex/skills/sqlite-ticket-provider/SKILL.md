---
name: sqlite-ticket-provider
description: Maintain the pure-Go SQLite single-use ticket identity provider, public parser, trusted issuance API, HTTP login capability, cookie and realm binding, portal signing, and TLS consumer tests. Excludes OAuth/SAML protocols and anonymous ticket issuance services.
---

# SQLite Ticket Identity Provider

Read [external account attachments](../local-identity-database/references/external-accounts.md)
when changing local provisioning, connection UI, immutable external keys, or
attachment binding in this consumer.

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
fragment or userinfo, and must differ from the portal callback. Explicit ports
on either URL must be 1–65535; a trailing empty port is invalid. No discovery or
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
through `authn.PortalParameters.IdentityProviders` or the root's runtime options,
and select the instance in `PortalConfig.IdentityProviders`. The built-in factory
and standalone authdb declarations remain OAuth/SAML-only. Hosts own
provision/reload/Close; Portal.Close does not close a shared provider.
Configure/Configured check current ticket storage health, not attachment setup.

For root composition, derive `idp.NewExternalIdentityProviderConfig(name, kind,
driver, realm, normalizedBackendConfig)` after the backend parser/Validate. Put
that descriptor in `Config.ExternalIdentityProviders` and the exact ready handle
in `ServerOptions.IdentityProviders`. Descriptors contain a lowercase SHA-256
digest, not runtime handles or private backend fields; they participate in root
state binding. The backend's parser owns operator grammar. The derived descriptor
does not add a second parser or register arbitrary kinds with the built-in factory.
Root pure preflight rejects unknown selections, duplicate names and selected
store/provider name or realm collisions. Omitted portal store/provider lists
include external providers; explicit selections remain unchanged. Disabled
provider filtering retains its existing behavior.

Runtime bindings must match exactly by name, realm, kind and driver and pass
Configured. Missing, extra, nil, typed-nil or unavailable bindings fail before
root state acquisition. Optional attachment consumers must return a nonnil binding;
an explicit StoreName must already be bound. These checks inspect existing wiring
without allocating an unnamed private attachment or testing broader account-store
health. Only plugin metadata/readiness calls contain panics.
The root keeps the original dynamic provider and its optional capabilities; it
never calls Configure/Close or installs attachment/persistent state in borrowed
providers. The host must complete any attachment wiring before construction.
`PortalParameters.IdentityAttachmentsBound` is runtime-only and means the caller
has completed attachment wiring for every supplied store/provider. The root sets
it after binding its owned backends; standalone portals retain automatic binding
when the flag is omitted. Drain all consumers before replacing a shared handle.

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
The login page links this provider without the tab's `redirect_url`, which the
first request would reject; a ticket login returns through the portal's shared
redirect cookie, as described under
[per-flow login destinations](../threat-hunting/references/redirects.md#per-flow-login-destinations).

The normal portal applies transforms, current challenge requirements and signing.
Origin is pinned back to the selected realm after transforms. AMR is server-owned
`federated`, never `pwd`, TOTP or WebAuthn. Ticket identity cannot by itself satisfy a local factor requirement. An explicit
attachment with an enabled local realm can run actual local checkpoints. Provider/store realm collisions and duplicate provider realms
fail at portal construction. The core owns JWT/session issuance; the plugin does
not sign tokens or reuse a supplied access token.

Portal logout clears ordinary portal credentials; this provider has no upstream
logout, identity token, refresh token or account introspection API. Pending tickets
remain valid until consumed/expired; logout is not ticket revocation. Provider
snapshot refresh still requires OAuth, and downstream local OP completion rejects
external proof. Neither authority follows from a ticket's local identity ID.
The generic connected-login path can perform cross-device transfer when enabled;
it rechecks the attachment and transfers access-only evidence bounded by the
approving login's expiry. It creates no ticket refresh family. Issued access
tokens retain their normal lifetime; upstream account revocation is outside this
simple ticket contract.

## Implicit identity lifetime

The provider always owns an `attachment.Attachment`, even when `attach` is omitted.
After committed ticket consumption it resolves the pinned issuer and verified
subject against that attachment and returns current external identity evidence.
Preserve `attachment.Consumer` when adapting the provider: the portal must recheck
that same attachment, rather than create another private fallback. The signed
`id` is a local immutable identifier distinct from upstream `sub`; `origin`,
timestamps, nonce and `amr` remain server-owned. The implicit identity has no
password, local roles or local MFA proof.

Without an explicit attachment, the private memory identity database lives for
one provider instance. Shared portals and reconstructed roots borrowing that same
instance retain the same ID. A new compatible provider restores pending tickets
from SQLite but creates new implicit IDs, and old external proof fails its live
identity recheck. Equal configuration digests do not preserve memory identities.
Explicit persistent attachment is required for durable local identity continuity;
root session serialization and ordinary stateless JWT expiry are separate matters.

## Acceptance

```
make test TEST_DIR='./plugins/identity-providers/sqlite/... ./pkg/idp ./pkg/authn/cookie/... ./internal/tag'
make test TEST_DIR=./pkg/authn TEST='TestProviderLogin|TestExtractBasePath|TestCrossDeviceMount|TestExternalLoginSeparatesReturnURL'
make test TEST_DIR='. ./pkg/idp ./internal/tag' TEST='ExternalIdentityProvider|E2EServerExternalSQLiteTicket|StructTag'
```

Units cover single issuance/consumption across independent handles, wrong browser,
issuer and destination, duplicates, expiry, capacity, cancellation, detached
identity, typed/parser validation and actual commit failure withholding identity.
The public-only TLS consumer runs a locally authenticated issuer application,
real portal, separate cookie jars, config roundtrip/restart, wrong credentials,
Host and query negotiation, invalid-port reload rejection without spending a
pending ticket, restored-cookie replay, logout, transforms/MFA denial and
independently verified JWTs. Run the external-module driver as well. Core tests
exercise malformed optional capability output, cookie collisions, namespace
precedence and unchanged OAuth/SAML redirects.
`TestE2ESQLiteTicketPortalLoginPageDestination` starts the login from a login page
that carries a destination and lands on it. Run public units/parser/consumer
with CGO_ENABLED=0, excluding the external driver which enables the race detector.

The public root TLS consumer covers root and nested mounts, authenticated trusted
issuance through a separate SQLite handle, exact borrowed ownership, shared
attachment IDs across portals, native configuration restoration, pending-ticket
restart, new-instance ID loss, old-proof rejection, independently verified JWTs
and local-factor policy denial after consumption.
