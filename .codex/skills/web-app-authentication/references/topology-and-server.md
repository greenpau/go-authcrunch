# Topology and server integration

## Select by the public browser origin

| Deployment | Integration decision |
| --- | --- |
| App, APIs and portal share scheme/host/port | Same-origin HttpOnly portal cookies are available; implement renewal in the app. |
| Several app mounts share one origin and portal | Share one portal coordinator namespace across apps and native portal tabs. Scope app permissions independently. |
| App and portal are different subdomains or ports | They are different origins. A shared cookie Domain does not satisfy the refresh Origin check. Unify the public origin through a trusted host arrangement or choose OIDC. |
| A server owns the app session and provider tokens | Use the BFF's renewal/session contract; the browser must not also rotate its server-held credentials. |
| React is an OIDC public client | Register `token_endpoint_auth_method: none`, no secret, exact HTTPS redirect URIs and required S256 PKCE. Follow the OIDC client contract, not portal-cookie examples. |
| Login is handled by a gatekeeper's OAuth feature | Inspect its opaque session implementation and policy; do not infer portal refresh support. |

For OIDC, current portal-adapter authentication is local-realm only. Upstream
OAuth login into a portal does not automatically become downstream OIDC evidence.
Public browser token exchange permits registered origins, while portal refresh
has its own exact-origin cookie contract. Provider access tokens are opaque and
ID-token signing keys are separate from portal JWT keys. API/resource-server
acceptance must be explicit; possession of an OIDC token does not configure the
app's gatekeeper. See the [provider client contract](../../authentication-portal-oidc/references/configuration-and-clients.md)
and [OIDC refresh semantics](../../authentication-portal-oidc/references/provider-capabilities.md#refresh-token-lifecycle).

OIDC `offline_access` requires registration and explicit `prompt=consent`; every
such request requires approval. It is not a mechanism for bypassing user consent.
Use a maintained relying-party implementation compatible with the app's pinned
dependencies for state, nonce, S256, discovery, signature/issuer/audience/expiry
validation, callback correlation and token rotation. A confidential client secret
belongs only on the server. Do not invent an AuthCrunch React/OIDC package.

## BFF renewal and restart ownership

The BFF is the sole owner of provider tokens and rotation. React asks its own
server for verified app-session metadata; it never receives those tokens or uses
the portal's localStorage journal. Define the BFF's browser CSRF/Origin checks,
cookie settings, session API and logout acknowledgement as app-owned contracts.

Serialize refresh and token-dependent operations for each server session. Current
AuthCrunch OIDC rotation replaces both access and refresh tokens, so a concurrent
UserInfo request cannot safely assume a captured old access token remains usable.
For multiple workers, require a shared transactional ownership/fencing design;
an in-process promise or a lease that expires during the exchange is insufficient.

Persist the consumer's app-cookie mapping, protected provider credentials, account
binding, deadlines, credential version and pending/revoked state separately from
AuthCrunch's root runtime state. Record pending rotation durably before dispatch
and commit replacement credentials before publishing success. A crash or lost
response between remote rotation and that commit can require fresh authentication;
database rollback cannot unspend a remote credential. Do not retry an uncertain
exchange after restart. Preserve both authorities and their keys to support
ordinary completed-session restart continuity. The [runtime-state contract](../../runtime-state/references/configuration-and-operations.md)
defines AuthCrunch's storage ownership and restoration limits.

OIDC does not use the portal refresh idle-timeout field or its response deadline
metadata. Derive expiry from the actual OIDC grant/verified evidence, define any
additional BFF inactivity/absolute policy explicitly, and never invent a
`refresh_expires_in` field. Revoke the provider family and confirm app-session
logout according to the selected scope; clearing an app cookie does not establish
provider-wide sign-out. Follow the existing OIDC owner for supported endpoints.

## Mount and cookie contract

A portal mount is trusted runtime configuration, never inferred from the current
SPA pathname. `/`, `/auth` and a validated nested mount require correct URL joining.
For examples in this skill, `portalBase` is the canonical mount and `base` is
`portalBase === '/' ? '' : portalBase`. Do not silently normalize an invalid
configured path into a valid-looking mount. See the [mount rules](../../coding-directives/references/portal-routing.md).

The enabled refresh cookie is host-only, Secure, HttpOnly, SameSite=Lax and scoped
to the portal mount. The access cookie must cover the actual application/API
paths that need it; its Domain/Path settings are separate. Default names are
configurable, not a browser API for JavaScript to read. Distinct portals with
overlapping paths need noncolliding names. A `__Host-` name requires Path `/` and
no Domain; it is not valid for every nested refresh mount. The [cookie contract](../../authentication-portal-cookies/SKILL.md)
owns names, parser and effective attributes.

A development origin must exercise these HTTPS cookie rules. Prefer a trusted
local TLS endpoint with the same public-origin arrangement as production. An HTTP
Vite page or a different development port calling the portal directly does not
prove the production flow. Keep signing keys, provider secrets and native refresh
credentials out of client bundles and browser storage.

## Host responsibilities

AuthCrunch is a Go library. Its dedicated parsers do not register host-specific
configuration syntax by themselves. A host adapter mounts the portal and applies
parsed configuration. The standalone [authdb example](../../../../cmd/authdb/config.json)
is an executable server configuration starting point, not a ready-made app gateway.
See the [embedding boundaries](../../coding-directives/references/embedding-integration.md)
for runtime construction and shutdown ownership.

For an embedded/gateway deployment:

- Route portal endpoints and explicit APIs before the SPA fallback. A missing
  script, unknown API or auth error must not become a `200` index page.
- Keep public login/recovery/bootstrap resources reachable. Prefer a public SPA
  shell with protected data APIs if the app must recover access without top-level
  navigation. A gateway that rejects the document before React loads cannot be
  repaired by a React hook; provide a reachable recovery entry or host integration.
- Verify credentials at the trusted server boundary on every protected operation.
  Validate configured signature/algorithm, issuer, audience and token time bounds
  as applicable. Use verified in-process context or an authenticated private
  upstream arrangement; never trust browser-supplied identity headers.
- Return `401` for missing/invalid credentials and `403` for valid identity lacking
  access. Enforce record and operation permissions server-side. Protect reads,
  mutations, exports and downloads consistently; a route guard is presentation.
- Mark personalized session/auth responses `Cache-Control: no-store`; exclude
  them from shared caches and service-worker offline caches. Preserve separate
  `Set-Cookie` headers, configured public scheme/host and portal mount through the
  trusted proxy. Do not broaden accepted Origin or forwarded-header trust.
- Make the portal's authenticated probe accessible to intended app users. Portal
  ACLs and app ACLs are different: an ordinary rejected `whoami` can delete an
  access cookie. Correct admission/configuration rather than looping on login.

Never copy a particular consumer's routes, tenant IDs, role strings, CSRF headers
or Caddy configuration into this generic library contract. Resolve them from the
consuming app and the host adapter's implemented capabilities.
