# Configuration and client integration

The authentication portal can act as a downstream OpenID Provider for users of
its local identity stores. For standalone Go applications, see
[reusing the provider package](reusable-provider.md). Configure `oidc_provider` on a portal; upstream
OAuth/OIDC identity providers are a separate feature.

For Go-based provisioning, use the public
[client and signing-key helpers](reusable-provider.md#provisioning-clients-and-signing-keys).
They generate credentials, apply client defaults, and build the same serializable
configuration shown below. Persist generated values before serving the provider;
configuration validation and reload do not generate or rotate credentials.

For named `oauth application <nickname>` blocks, use
[application registration and reload integration](reusable-provider.md#named-application-registration-and-reloads).
The public application adapter reuses the existing client field parser and
requires explicit or persisted credentials. Root `Config.OAuthApplications`
stores named registrations; `Config.ConfigureOIDCProvider` resolves their
provider references before attaching a validated portal configuration.

For encoded provider settings, use
[`NewOIDCProviderConfigFromDirectives`](reusable-provider.md#provider-settings-directives).
It resolves registered application nicknames before final provider validation and
returns a config assignable to `PortalConfig.OIDCProvider`. This is independent of
parsing or provisioning the individual application blocks.

## Example

This is a complete root `authcrunch.Config` shape. Provision the local database
and provide an independently generated RSA private key and high-entropy client
secret before loading it. The embedding HTTP server mounts this portal at
`https://auth.example.com/auth` and supplies normalized request metadata.

```json
{
  "identity_stores": [
    {
      "name": "localdb",
      "kind": "local",
      "params": {
        "realm": "local",
        "path": "/var/lib/authcrunch/users.json"
      }
    }
  ],
  "authentication_portals": [
    {
      "name": "myportal",
      "identity_stores": ["localdb"],
      "oidc_provider": {
        "enabled": true,
        "issuer": "https://auth.example.com/auth",
        "realms": ["local"],
        "signing_key_files": ["/etc/authcrunch/oidc-signing.pem"],
        "clients": [
          {
            "client_id": "myapp",
            "client_name": "My application",
            "client_secret": "REPLACE_WITH_A_UNIQUE_HIGH_ENTROPY_SECRET",
            "token_endpoint_auth_method": "client_secret_basic",
            "redirect_uris": ["https://app.example.com/oidc/callback"],
            "scopes": ["openid", "profile", "email"],
            "require_pkce": true
          }
        ]
      }
    }
  ]
}
```

`PortalConfig` supplies default cookies and a disabled admin/profile API when
OIDC is enabled and those fields are omitted. Enabling OIDC does not enable an
admin API. This repository implements Go and JSON/XML/YAML configuration;
`caddy-security` owns its separate Caddyfile grammar, which is not extended by
this change. Embedders pass requests through `Portal.ServeHTTP` as usual.

Generate a dedicated persistent key, for example:

```sh
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out oidc-signing.pem
```

Use unencrypted PKCS#8 `PRIVATE KEY` or PKCS#1 `RSA PRIVATE KEY` PEM. Do not use
this key for the portal's ordinary access JWTs. Store private keys and client
secrets using the embedding application's credential-management facilities.
Secrets must contain 32–1024 bytes; use at least 32 random bytes of entropy.

## Endpoints and clients

For this issuer:

| Purpose | URL |
| --- | --- |
| Discovery | `https://auth.example.com/auth/.well-known/openid-configuration` |
| Authorization | `https://auth.example.com/auth/oidc/authorize` |
| Token exchange | `https://auth.example.com/auth/oidc/token` |
| UserInfo | `https://auth.example.com/auth/oidc/userinfo` |
| Public OIDC signing keys | `https://auth.example.com/auth/oidc/jwks` |
| Token revocation | `https://auth.example.com/auth/oidc/revoke` |

Configure the relying party with the exact issuer, registered client ID,
secret/authentication method, exact callback URI, and `openid` scope. Prefer
S256 PKCE for every client. Confidential clients can explicitly omit PKCE for
compatibility; public clients cannot. A public registration sets
`token_endpoint_auth_method` to `none`, omits `client_secret`, and always
requires S256. Public native clients may register an HTTP callback on literal
`127.0.0.1` or `[::1]`, for example `http://127.0.0.1/callback`. They bind an
ephemeral local listener and supply its actual port in the authorization URI.
Only the port may vary; the remaining URI bytes, including encoded path, query,
and case, must match exactly. Explicit ports must be decimal 1–65535; an omitted
port denotes the HTTP default. Retain the actual authorization URI and send that
exact value at token exchange. The registered placeholder port cannot redeem a
code issued for another port. Custom URI schemes remain unsupported.

All other callbacks require HTTPS and match registered strings exactly,
including port. Multiple distinct redirect URIs may be registered. No wildcards
or prefix matching is performed. Browser public clients may call the token
endpoint from their registered origins; the native callback port exception does
not expand CORS origins. Native apps redeem directly without a browser Origin.
Bearer-only UserInfo and public discovery support CORS without credentialed
cookies.

Validate the effective callback before creating pending authorization state,
then repeat client lookup and URI validation in `authorizationResponse` before
either a query redirect or a `form_post` action is emitted. Missing clients,
unregistered callbacks, and malformed URIs fail locally without a redirect.
Both success and error responses use this same final boundary; retain the
exact registered URI and the narrow native-loopback port exception above.

Clients obtain an opaque access token and signed ID token using the authorization
code. Verify the ID token's signature, issuer, audience, expiration, and nonce
with discovery/JWKS. Send the opaque access token in `Authorization: Bearer ...`
to UserInfo. POST form-body `access_token` is also supported; query-string tokens
are rejected. Never send an ID token or ordinary portal access token to UserInfo.

Authorization requests can use query parameters, form POST, or a by-value
Request Object (`request`, compact JWT with `alg: none` or registered RS256). The outer
request must still include `client_id`, `response_type`, and an `openid` scope.
Object values take precedence; any object client ID or response type must match
the outer request. The effective callback must match registration. These objects
only encode authorization parameters and convey no authenticated identity.
RS256 requires the client's registered public verification keys. Encrypted objects
and remote `request_uri` are not supported. See
[provider capabilities](provider-capabilities.md) for registration directives.

## Claims and consent

`sub` is immutable within the configured backend/realm and survives password
changes and database reloads. Renaming the configured backend or realm changes
its namespace. Deleting and recreating a user creates a new subject even if the
username/email are reused.

| Scope | UserInfo claims |
| --- | --- |
| `openid` | `sub` |
| `profile` | Available standard profile attributes from `identity.Profile`, name and username |
| `email` | `email`, `email_verified: false`, plus `sub` |
| `address` | Structured `address` from the current record |
| `phone` | `phone_number` and its explicit verification flag, when present |
| `offline_access` | Rotating refresh token after explicit consent; no additional UserInfo claims |

Unconfigured/unknown scopes are omitted from the granted `scope` response.
Roles and internal credential evidence are not exported. Claims come from the
current local record; transformations still enforce denial and challenge policy.
The provider does not assert that a local email address has been verified.

Consent is required by default and records the scopes and individual claim locations approved for each client
within that login session. Set `skip_consent: true` only when the administrator
intends to preapprove that client for its registered scopes. A client requesting
`prompt=consent` still receives the consent screen. `prompt=none` returns
`login_required` or `consent_required` when interaction would be necessary.

OIDC cookies follow the portal's `cookie_config` naming convention:

| Setting | Default name |
| --- | --- |
| `oidc_session_id_cookie_name` | `AUTHP_OIDC_SESSION_ID` |
| `oidc_request_id_cookie_name` | `AUTHP_OIDC_REQUEST_ID` |

Set `cookie_name_prefix` to change the `AUTHP` prefix for names left unset, or
set the two names explicitly. For example, `"cookie_config":
{"cookie_name_prefix": "PORTAL"}` selects `PORTAL_OIDC_SESSION_ID` and
`PORTAL_OIDC_REQUEST_ID`. Names must be valid cookie names and must not collide
with other portal cookies. Portals with overlapping paths on one host need
distinct prefixes or explicit names.

The reusable cookie parser accepts `cookie prefix PORTAL`,
`cookie oidc session id name LOGIN_SESSION`, and
`cookie oidc request id name LOGIN_REQUEST`. Apply its typed result with
`PortalConfig.ConfigureCookies`. For a config already initialized by
`cookie.NewConfig`, use `SetCookieNamePrefix` instead of assigning the prefix
field. See [cookie grammar and application](../../authentication-portal-cookies/references/directives.md)
for explicit-name precedence, all cookie roles, and consumer integration.

Both cookies are host-only, Secure, HttpOnly, SameSite=Lax, and scoped to the
issuer mount (`/` for a root issuer). Their lifetime follows provider session
and interaction expiry. These attributes are independent of access-cookie
domain, path, lifetime, SameSite, and insecure settings. Creation and deletion
use the same configured names and paths. They are separate from portal access
and refresh cookies. The provider uses
actual password/MFA completion; existing bearer credentials cannot manufacture a
new OIDC browser login. Native portal body transport sets no cookies during
login, refresh, or logout.

## Lifetimes, reloads, and deployment

| Setting | Default | Valid range |
| --- | --- | --- |
| `session_lifetime_seconds` | 28800 | 1–86400 |
| `token_lifetime_seconds` | 300 | 1–3600 |
| `refresh_lifetime_seconds` | 28800 | 1–86400; also bounded by original session |
| `max_refresh_tokens` | 10000 | 1–1000000 active plus spent refresh credentials |
| `max_sessions` | 10000 | 1–1000000 |
| `max_pending_requests` | 1024 | 1–100000 |
| `max_grants` | 10000 | 1–1000000 |

Authorization codes live for 60 seconds; interactive requests for 600 seconds.
ID/access token expiry is bounded by the browser session's remaining lifetime.
`auth_time` is the original verified login time, never a refresh/issuance time.

Provider state is bounded and process-local. Restarting/closing the portal
invalidates browser sessions, pending requests, codes, consent records, and
opaque tokens. Deploy one active provider process for an issuer; active/active
replicas and distributed grant persistence are not implemented. Browser affinity
alone does not route a relying party's backchannel token exchange to the same
process. Ordinary portal refresh sessions remain independent.

Account disablement, password reset, deletion, changed credential/challenge
policy, and local database reload invalidate OIDC credentials. UserInfo checks
current identity on every request. Portal logout revokes the provider browser
session and its dependent opaque tokens. With a portal refresh cookie, GET logout
displays confirmation and the protected POST performs revocation. Already issued
ID tokens remain signed
statements until expiration; clients manage their own application sessions.
There is no advertised RP-initiated logout. OIDC refresh tokens are described in
[provider capabilities](provider-capabilities.md); portal refresh is separate.

The issuer must be a canonical HTTPS URL without a trailing slash, query, or
fragment. The path is the portal mount. Mounts containing reserved portal routes
(such as `/api/`, `/portal`, or `/sandbox/`) are rejected. When portal refresh is
also enabled, its public origin and mount must agree with the issuer. The
embedding server owns host/forwarded-header normalization and TLS policy.

To rotate keys, put the new private key first in `signing_key_files` and retain
old keys later until all relying parties can retire old ID tokens. Thumbprint
key IDs follow the key material, independent of file order. Reload revokes
volatile sessions; published old keys let clients verify previously issued
ID tokens. The separate legacy `/.well-known/jwks.json` endpoint continues to
publish ordinary portal signing keys.
