# Authentication portal token refresh

Portal refresh is opt-in. It retains JWT access tokens and adds a separate,
opaque credential for renewing a completed local authentication. It does not
renew an upstream OAuth provider's tokens.

## Enable through library configuration

Add `refresh_tokens` to the authentication portal configuration:

```json
{
  "refresh_tokens": {
    "enabled": true,
    "realms": ["local"],
    "public_origin": "https://auth.example.com",
    "base_path": "/auth",
    "access_lifetime_seconds": 300,
    "idle_timeout_seconds": 1800,
    "absolute_timeout_seconds": 28800,
    "body_transport_enabled": false,
    "max_sessions": 10000,
    "max_rotations": 1024
  }
}
```

The example shows defaults except for the required realm, origin, and mount.
Omitting `cookie_name` inherits `cookie_config.refresh_token_cookie_name` from
the portal cookie factory, defaulting to `AUTHP_REFRESH_TOKEN`. Setting
`cookie_config.cookie_name_prefix` to `TENANT` gives `TENANT_REFRESH_TOKEN`
unless an explicit cookie name is supplied. A token refresh `cookie_name`
override takes precedence over that shared setting when the feature is enabled.
It is applied before factory construction and collision checks. Disabled refresh
does not apply the override. `authn.TokenRefreshConfig.Validate` leaves an omitted
name empty so independently parsed configuration can inherit its portal's names.
Durations are integer seconds. The maximum absolute timeout is 30 days.
The access lifetime is also capped by the existing access signing key's token
lifetime. Refresh cookies have an independent idle deadline and never inherit
the ordinary access cookie lifetime or Domain setting.

The origin must be an exact HTTPS origin without a path, query, or fragment.
The mount must be a canonical absolute path (`/` is supported). Use a unique
cookie name or prefix for portals with overlapping mounts on the same host.
Names do not require browser security prefixes or hashes. All refresh cookies
remain host-only and scoped to the portal mount, with Secure, HttpOnly, and
SameSite=Lax. Explicit `__Host-` names are supported only at the root mount.

Only explicitly listed realms participate. The local identity store implements
the required capability. Configuring an unsupported realm fails construction.
LDAP, OAuth, SAML, basic-auth, and API key login remain access-only; no refresh credential
is minted from an existing access JWT. An absent or disabled block retains
existing access-token lifetimes and allocates no refresh store.

## Encoded directives for embedding applications

Import `github.com/greenpau/go-authcrunch/pkg/authn/token_refresh/parser`, usually
as `refreshparser`, and call
`refreshparser.NewTokenRefreshConfigFromDirectives(statements []string)`. It returns
`(*authn.TokenRefreshConfig, error)` for direct assignment to `PortalConfig.RefreshTokens`.
Pass individual directive lines encoded with `cfgutil.EncodeArgs`; omit the block
header and braces. Encode each keyword as its own argument, for example
`[]string{"public", "origin", "https://auth.example.com"}`. Quoted values retain
spaces. The constructor enables token refresh, calls the existing
`TokenRefreshConfig.Validate`, and returns a normalized config or an error with no
partial result. Assign its result to `PortalConfig.RefreshTokens`.

The following illustrates the intended block syntax for an embedding parser.
The constructor accepts encoded statements from its body; it does not parse the
outer block or register a Caddyfile directive:

```text
token refresh {
    realms local
    public origin https://auth.example.com
    base path /auth
    access lifetime 300
    idle timeout 1800
    absolute timeout 28800
    body transport disabled
    max sessions 10000
    max rotations 1024
}
```

Only `realms`, `public origin`, and `base path` are required for enabled
configurations. `realms` accepts multiple values on one line; the other value
settings each accept one value. Optional `cookie name CUSTOM_REFRESH_TOKEN`
overrides the portal factory's refresh-cookie name. Numeric settings are decimal
integers; durations are seconds, and zero
selects the existing default. The JSON/XML/YAML configuration keys retain their
existing snake_case names.

State is expressed through keywords: `enabled` or `disabled` as a standalone
line selects token refresh, and `body transport enabled` or
`body transport disabled` selects native body transport. Token refresh defaults
to enabled when the block is present; native body transport defaults to disabled.
Each setting may appear once, so repeated or conflicting states are errors.
Boolean literals such as true/false, on/off, and 1/0 are not directive syntax.
Underscore directive keys are rejected.

Unknown directives, duplicates, empty values, malformed quoting, embedded
newlines, noninteger numeric values, and integer overflow fail parsing. An empty
statement list is invalid. Leave `PortalConfig.RefreshTokens` nil when token
refresh is absent; a `disabled` directive explicitly disables it. Disabled
configs still check directive grammar and retain the validator's existing
semantic opt-out.

The embedding application owns block-header validation, duplicate block
detection, and rejection of additional block arguments or nested blocks. Reject
empty argument values before encoding: `cfgutil.EncodeArgs` trims trailing
whitespace and can discard a final empty field. Resolve environment variables
and secrets before encoding statements and calling the constructor; the library
does not expand placeholders. The portal mount and HTTPS origin must match the
actual HTTP route; validation does not create routes or configure TLS.

This repository supplies the library constructor and runtime. Consumer adapters,
block parsing, wiring, and tests will be updated separately.
Never modify sibling directories to provide that integration or to repair
consumer compatibility; all changes for this work remain in `go-authcrunch`.

## Authentication and issuance

Browser form login and JSON sandbox login share the same issuer. The sandbox
owner serializes requests, checks that every checkpoint passed, and atomically
redeems the completed login once. Signing happens once; delivery handles cookies,
caching, JSON, and redirects.

A local login records the immutable user ID and credential version before
checkpoints begin. Successful authentication records its actual time and method.
Those values survive subsequent MFA without being refreshed. Issuance checks
that the same identity and security version are still current. A password reset
between password verification and MFA therefore requires another login.

Enrollment changes security state. If MFA is enrolled during a login, complete a
new authentication with that factor before obtaining a refresh family. Enrollment
alone is not counted as proof of possession for renewal.

On every issuance, the local store supplies current account attributes and
challenge requirements. Transformations run once on these fresh attributes.
Newly required challenges, disabled/deleted accounts, changed credentials, and
explicit revocation deny renewal. Backend outages leave the credential unspent.
The local adapter holds its identity lock through signing and store commit, so
security changes cannot slip between revalidation and issuance. This serializes
local-store operations during signing; slow external signers would need an
adapter with equivalent transactional version checks.

Claims preserve `sid`, `sub`, `iss`, `auth_time`, and actual `amr`. Each issuance
has a new `jti`, `iat`, `nbf`, and `exp`. Refresh cannot expand the original
audiences or scopes. Roles are rebuilt from current identity and transformation
policy. Transformations cannot replace the authentication event or invent `acr`.
The original subject is pinned; an account rename requires another login.
The issuer is the configured public origin plus mount, independent of the login
route. Issuer-specific authorization rules should use that value.

## Browser requests

Use the portal's origin for both endpoints:

```javascript
await fetch('/auth/api/refresh_token', {
  method: 'POST',
  credentials: 'same-origin',
  headers: {
    'Content-Type': 'application/json',
    'X-Authcrunch-Refresh': '1'
  },
  body: '{}'
});
```

Browsers supply `Origin` automatically. The endpoint requires an exact configured
Origin, the custom header, JSON, and compatible Fetch Metadata. It rejects
query parameters, duplicate refresh cookies, mixed cookie/body credentials,
unknown or duplicate JSON fields, trailing JSON, and bodies over 1 KiB.
The embedding server must strip or normalize forwarded host/protocol metadata,
as it must for other portal routes. TLS and the effective host are checked
against the configured origin.

A successful response contains only metadata:

```json
{
  "authenticated": true,
  "session_id": "public-session-identifier",
  "access_expires_at": 1789140300,
  "refresh_expires_at": 1789141800,
  "session_expires_at": 1789168800
}
```

Expiry values are Unix seconds. Both credentials arrive in Secure, HttpOnly
cookies. Refresh uses a host-only SameSite=Lax cookie; the access cookie retains
its configured domain/path and receives the bounded access expiry. Responses
use `Cache-Control: no-store`.

The embedded portal page loads `assets/js/refresh.js`, which exposes
`window.AuthCrunchSession.refresh()` and `.logout()`. It uses a same-page promise
and a shared Web Lock across tabs, with only session/expiry metadata in browser
storage. Refresh and logout use the same lock. Other pages/apps must deliberately
integrate this client or equivalent coordination; the endpoint cannot refresh
arbitrary protected applications automatically. Custom portal templates should
include the same conditional script/data attributes as the built-in template.

An expired access token on the portal or login page can use a top-level
continuation page to renew the session. The sign-in link uses `fresh=1` to start
a new login after renewal fails. Browsers without Web Locks or usable local storage fail
closed and require login. Cross-origin apps need a top-level portal continuation
or a backend-for-frontend integration; this endpoint does not relax Origin
checks or return credentials in redirect URLs.

## Native clients

Native body transport must be enabled explicitly. Start JSON login with
`Accept: application/json`, `Content-Type: application/json`, and
`"refresh_transport": "body"`. Include the same transport selection on every
sandbox challenge request. Cookie transport is the default. The selected
transport cannot change during authentication or refresh.

Completed native login returns the existing `access_token`, `access_token_name`,
`refresh_token`, and `refresh_token_name` fields plus expiry/session metadata.
Native login does not set cookies. Native clients must not send browser Origin,
Fetch Metadata, or Cookie headers.

```http
POST /auth/api/refresh_token
Content-Type: application/json

{"refresh_token":"acr1_<opaque credential>"}
```

Replace the refresh credential after each successful response. Body transport
returns both new credentials in JSON. Cookie credentials cannot be redeemed as
body credentials, and body credentials cannot be redeemed as cookie credentials.

## Rotation, replay, and failures

A refresh credential contains a version prefix and 32 random bytes. The store
retains SHA-256 digests, not raw refresh tokens. Each family has a stable session
ID, fixed portal/origin/mount/transport binding, identity evidence, original grant,
current and spent digests, revision, idle expiry, and absolute expiry.

The manager stages the new JWT and opaque token before atomic rotation. Commit
rechecks the current digest, revision, revocation, and deadlines, including the
staged JWT's expiry. Failed signing does not consume the old credential.

A known spent credential revokes its entire family, including the current
descendant. Unknown tokens and incorrect bindings cannot revoke another family.
This follows the reuse-detection approach in
[RFC 9700 section 4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2).
Two concurrent requests can produce one successful response and one replay that
revokes that successful response's family. Coordinate clients accordingly.

Never automatically retry an ambiguous network failure. The server may have
committed rotation even if the response was lost. The browser client records a
pending exchange before sending and requires login after an uncertain result,
including after a tab reload. There is no grace period accepting spent tokens.

Status codes: `200` success; `400` malformed/ambiguous request; `401`
reauthentication required; `403` origin/transport violation; `404` disabled or
wrong mount; `405` wrong method; `415` unsupported content type; `503` signing,
storage, or other temporary service failure. No credentials are returned before
commit. The endpoint runs before ordinary access authorization; other APIs
continue enforcing access-token expiration and permissions.

## Logout and security changes

`POST /auth/api/logout` uses the same transport and browser protections as
refresh. It works without a valid access JWT. It revokes the family before
clearing new and legacy cookies. Completing another browser login also revokes
the previous refresh family, including when changing to an access-only realm.
Revocation-store failure returns `503` and does
not claim successful logout. Browser GET logout displays a confirmation page
when a refresh cookie is present; its button performs the protected POST before
following a trusted logout destination. Provider logout remains separate.

Local password changes/resets, MFA add/delete, account disable/enable, challenge
rule changes, and `local.IdentityStore.RevokeUserSessions(ctx, immutableUserID)`
invalidate affected refresh evidence. User deletion prevents lookup, and a
recreated username has a different immutable identity. Version zero is the safe
legacy baseline; the first security mutation persists `credential_version: 1`.
Existing database files do not require a bulk rewrite. Database reload also
invalidates evidence, including restoration of an older file.

Revoking refresh **does not immediately revoke an already-issued stateless JWT**.
Its short expiry bounds remaining access. Immediate access revocation would
require a separate authorization-time session/version check.

## Storage and lifecycle

The portal owns a bounded in-memory store. Restart, portal replacement, or
identity-store reload requires reauthentication. Call `Portal.Close()` after
quiescing requests when disposing of a portal; it stops cache workers and clears
its refresh state. Failed portal construction also cleans up workers.

`max sessions` bounds live families. Logout, replay, definitive identity denial,
and rotation exhaustion retire an entire family and free its slot. Admission
also reclaims idle- and absolutely expired families. Every spent digest remains
recognizable while a descendant is live; once the whole family is terminal,
its digests can be removed together. An old credential then stays invalid without
an unbounded tombstone history. Storage retains at most `max sessions` families
and `max sessions * (max rotations + 1)` digests. No cleanup worker is created.

A freshly authenticated browser can atomically replace its presented family at
full capacity, after successful signing. Failed admission/signing preserves all
live families. Separate native or browser clients still fail closed when all
slots are live; having an access JWT alone cannot free a slot. Security-version
changes are observed during refresh, so an unpresented invalidated family's slot
can remain occupied until expiry. Size capacity for concurrent independent
sessions, and set idle/absolute limits deliberately.

Reusable consumers can use `Manager.IssueReplacing` with an optional
`ReplacementStore` adapter. The unchanged `Store` interface supports ordinary
issuance/rotation. Replacement requires the optional atomic method when a valid
old credential is supplied; unsupported adapters return `ErrUnavailable`.
Never recreate old session snapshots or reuse old IDs/credential material.
The portal constructs `MemoryStore`, which implements both interfaces.

This is a single-process implementation. The `tokenrefresh.Store` contract describes
atomic creation, lookup, rotation, and revocation for future adapters, but the
portal currently constructs its own memory store. Shared/distributed storage,
external-provider refresh capabilities, and persistent reload continuity need
separate integration and transaction tests.

## Validation

```sh
make test
make test-ui
go test ./pkg/authn/token_refresh -run '^$' -fuzz FuzzRefreshToken -fuzztime 5s
```

Tests cover real local/KMS issuance through browser and native login, MFA and
password-reset races, single-use sandbox redemption, current roles/challenges,
expired-access refresh with unchanged API authorization, replay isolation,
concurrent rotation, logout during signing, deadlines, capacity, strict HTTP
parsing, origin/transport checks, cookies, disposal, security-version persistence,
and browser coordination. Deterministic Node tests complement the real Chrome
TLS two-tab bootstrap E2E described in `refresh-token-transports`. Hardware-backed
WebAuthn remains separate validation.
`pkg/authn/token_refresh/parser/parser_test.go` has external-package grammar,
defaults, validation, JSON round-trip, concurrent reuse, and executable example
tests. Preserve explicit empty quoted fields in grammar tests; passing them
through `EncodeArgs` can turn them into missing fields instead.
`pkg/authn/token_refresh_config_parser_e2e_test.go` verifies directive-configured root
and nested mounts, browser cookie policy, native transport opt-in, signed token
lifetimes, session/rotation capacity, and disabled behavior over local TLS.
`TestE2EPortalSigningAndRefreshCompatibility` in `pkg/authn`
constructs its refresh config through the public parser and verifies real local
login, signed credentials, rotation, and replay rejection over local TLS. Its
external test package exercises the library's supported consumer entry point
without requiring a sibling-repository adapter or test changes.
