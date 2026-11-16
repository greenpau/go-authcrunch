# Refresh configuration and operational limits

## Enable issuance, not just a longer access token

The portal's `authn.PortalConfig.RefreshTokens` accepts
`*authn.TokenRefreshConfig`. This portal JSON fragment illustrates local-realm
refresh; substitute the configured realm, public origin and validated mount:

```json
{
  "refresh_tokens": {
    "enabled": true,
    "realms": ["local"],
    "public_origin": "https://app.example.com",
    "base_path": "/auth",
    "access_lifetime_seconds": 300,
    "idle_timeout_seconds": 1800,
    "absolute_timeout_seconds": 28800,
    "body_transport_enabled": false
  }
}
```

The three durations are current defaults, not a universal product policy. Enabled
refresh also caps access lifetime by the configured signing lifetime. A longer
ordinary crypto/JWT lifetime does not override the refresh access cap. Omitting
refresh leaves the existing access-only flow; existing access JWTs cannot be
exchanged to create a new refresh family. Verify a new login actually receives the
proper cookies and family evidence after configuration changes.

The reusable parser is
`github.com/greenpau/go-authcrunch/pkg/authn/token_refresh/parser.NewTokenRefreshConfigFromDirectives`.
It accepts encoded statement lines produced by `cfgutil.EncodeArgs`, without an
outer block/header, and returns the typed config for `PortalConfig.RefreshTokens`.
The [configuration owner](../../refresh-token-implementation/references/configuration-and-clients.md)
contains grammar, defaults, validation, provider selection and storage settings.
Host registration and full server wiring belong to the embedding adapter.

## Capability and lifetime decisions

| Question | Current portal-refresh contract |
| --- | --- |
| Which login can renew? | Explicitly selected supported local identity stores, or OAuth/OIDC upstream providers with explicit snapshot selection. Check the actual store capability. |
| Which login is access-only? | LDAP, SAML, Basic authentication and API-key login do not mint portal refresh credentials. |
| Does upstream snapshot renewal contact the IdP? | No. It retains verified login claims and reapplies current portal policy; upstream disablement, roles and logout are not observed until fresh login. |
| What extends idle life? | A successful refresh; ordinary API requests and session polling do not. |
| What extends absolute life? | Nothing within the family. Fresh authentication is required. |
| Does revoking refresh invalidate issued JWTs immediately? | Not by itself. Already issued stateless access tokens remain valid until expiry unless authorization performs an additional revocation check. |
| Are failed rotations retryable? | Not after an ambiguous dispatch; strict replay protection may revoke the family. HTTP `503` alone does not establish that the credential was unspent. |

Proactive refresh itself extends idle life. Decide whether a hidden/open tab is
allowed to keep a session active, or whether the app should renew only for recent
user activity/foreground work. Document that choice separately from server idle
policy. If other native portal tabs continue renewing, an app-only activity timer
cannot enforce a global inactivity policy. Do not weaken configured idle or
absolute limits merely to eliminate a sign-in prompt.

Use the [identity contract](../../refresh-token-identity/SKILL.md) when assessing
local account changes, factors, provider snapshots and canonical identities.
Shorter access lifetime bounds stale stateless claims; it does not substitute for
application authorization or upstream revocation support.

## Persistence and restart

An omitted refresh store uses memory. Restart continuity depends on more than
persisting refresh rows: signing keys, replay history, identity proof epochs,
root-state bindings and matching runtime configuration must survive compatibly.
Root `Config.State` supports matching local-file identity and refresh snapshots.
Managed stores have additional assembly constraints. The SQLite identity plugin
creates a new proof epoch on reopening, so restored refresh evidence does not
become valid merely because its rows persisted.

Do not promise multi-process failover from a persistent store example. Audit the
actual ownership, transactional rotation, identity revalidation and restart model.
See [runtime state](../../runtime-state/references/configuration-and-operations.md),
[managed refresh storage](../../refresh-token-implementation/references/managed-storage.md),
and [SQLite identity limits](../../sqlite-identity-store/SKILL.md).

## Investigate repeated sign-in prompts

Collect bounded, redacted evidence for the exact transition: actual verified
access expiry, refresh/absolute deadlines when available, login method, portal
origin/mount, route guard decision, probe status, refresh status and whether the
journal was already pending/blocked. Inspect cookie attributes in a disposable
browser without copying credential values into logs. Do not log cookies,
Authorization headers, CSRF values, provider codes, raw response bodies or private
claims. Do not export browser storage/auth state as a normal report artifact.

Trace the flow in order: fresh login issuance; reachable app bootstrap; verified
portal and app session; renewal scheduled before access expiry; cross-tab lock;
protected refresh; fresh app credentials; route remaining mounted. A missing
scheduler, refresh-disabled realm, wrong cookie Path, rejected portal probe,
HTML API response, hidden-tab throttling and unsafe duplicate refreshes have
different fixes. Confirm the actual failure instead of increasing every timeout.
