# Direct OAuth authorization configuration

## Library construction

```go
import (
    "github.com/greenpau/go-authcrunch"
    "github.com/greenpau/go-authcrunch/pkg/acl"
    "github.com/greenpau/go-authcrunch/pkg/authz"
    oauthparser "github.com/greenpau/go-authcrunch/pkg/authz/oauth/parser"
    idpparser "github.com/greenpau/go-authcrunch/pkg/idp/parser"
    cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
    "go.uber.org/zap"
)

func newLinkedInAuthorization(clientID, clientSecret string, logger *zap.Logger) (*authcrunch.Server, error) {
    provider, err := idpparser.NewOAuthIdentityProviderConfigFromDirectives("linkedin", []string{
        cfgutil.EncodeArgs([]string{"realm", "linkedin"}),
        cfgutil.EncodeArgs([]string{"driver", "linkedin"}),
        cfgutil.EncodeArgs([]string{"client_id", clientID}),
        cfgutil.EncodeArgs([]string{"client_secret", clientSecret}),
    })
    if err != nil { return nil, err }
    policy := &authz.PolicyConfig{
        Name: "linkedin_policy",
        AccessListRules: []*acl.RuleConfiguration{
            {Conditions: []string{"match roles authp/user"}, Action: "allow stop"},
        },
    }
    oauthConfig, err := oauthparser.NewOAuthAuthorizationConfigFromDirectives(policy.Name, []string{
        cfgutil.EncodeArgs([]string{"use", "oauth", "identity", "provider", "linkedin"}),
        cfgutil.EncodeArgs([]string{"oauth", "public", "origin", "https://app.example.com"}),
    })
    if err != nil { return nil, err }
    if err := policy.ConfigureOAuth(oauthConfig); err != nil { return nil, err }
    cfg := authcrunch.NewConfig()
    cfg.IdentityProviders = append(cfg.IdentityProviders, provider)
    if err := cfg.AddAuthorizationPolicy(policy); err != nil { return nil, err }
    return authcrunch.NewServer(cfg, logger)
}
```

Resolve environment/host-specific placeholders before encoding each statement;
never log credentials or complete config snapshots. Executable parser examples and
full TLS consumers live in the parser tests and root E2E fixture. Provider credentials
remain ordinary upstream provider configuration. There is no authentication
portal, local database, signing-key configuration, or portal route to provision.
The shared ACL validator currently derives an internal default key store; the
direct policy neither accepts JWTs nor signs application credentials with it.

## Complete statement grammar

Encode one complete statement at a time with `cfgutil.EncodeArgs`; reject empty
tokens before encoding. Pass the whole feature's statement list together, so
repeated settings cannot bypass duplicate checks. No block braces are accepted.

| Statement | Default / constraint |
| --- | --- |
| `use oauth identity provider NAME` | Required once; one named configured OAuth provider |
| `oauth public origin https://HOST[:PORT]` | Optional; no userinfo, path, query or fragment; trailing `/` normalized away |
| `oauth base path /PATH` | `/_authcrunch/oauth2/POLICY`; canonical, unescaped, non-root path |
| `oauth session cookie name NAME` | `AUTHZ_POLICY_SESSION` |
| `oauth login cookie name NAME` | `AUTHZ_POLICY_LOGIN`; distinct from session name |
| `oauth session lifetime SECONDS` | 900; integer 1–86400 |
| `oauth maximum sessions COUNT` | 10000; integer 1–65536 |
| `oauth maximum pending logins COUNT` | 1024; integer 1–65536, including in-flight exchanges |

Policy names in this mode contain 1–128 ASCII letters, digits, `_` or `-`.
Empty parser input returns nil; `ConfigureOAuth(nil)` disables direct login.
Typed zero lifetimes/capacities select defaults; explicit directive zero fails.
All settings round-trip through the policy's `oauth` JSON object.
`ConfigureOAuth` snapshots the input and leaves prior config intact on failure.

ACLs, bypass rules, method/path and source validation, custom identity headers,
`UserIdentityField`, and token stripping remain policy settings. A session-only
policy cannot mix raw or meaningful typed JWT crypto settings, `ValidateBearerHeader`,
`AllowedTokenSources`, auth proxies,
`SessionIDCookieName`, or `AccessTokenCookieNames`; use its OAuth cookie settings.
The ordinary `/auth` redirect URL, JavaScript redirect selection and redirect-query
format do not select an OAuth login or return destination. `AuthRedirectDisabled`
returns 401 when no valid session exists. Valid sessions continue to authorize.

## HTTP and embedding contract

Get the gatekeeper with `Server.GetGatekeeperByName`. Create a fresh
`requests.AuthorizationRequest`, call `Gatekeeper.Authenticate`, and invoke the
protected handler only when `Response.Authorized` or `Response.Bypassed` is true.
A nil error alone never authorizes. OAuth redirects, protocol denials, callback
completion, logout, and shutdown write a complete HTTP response with both flags
false. Ordinary gatekeeper modes may return an error requiring a host denial;
never turn an unwritten error into an implicit 200 or fall through to upstream.

The host must route these paths through the **same policy and runtime**:

- `OAuthAuthorizationConfig.CallbackPath()`: `BASE/authorization-code-callback`,
  GET only, registered exactly with the upstream provider.
- `OAuthAuthorizationConfig.LogoutPath()`: `BASE/logout`, POST with one exact
  same-origin `Origin` header; returns 204 on revocation.
- The protected application resources that initiate and use the login.

The whole `BASE` namespace is reserved. Callback errors cannot fall through to
an application even when bypass rules match. Mounting `authorize` only on
`/private/*` requires an additional route for the callback/logout namespace;
configure a base path under the protected mount or mount that namespace explicitly.
Do not rewrite away the configured base path before calling the gatekeeper.

Missing sessions on GET/HEAD initiate a 302 to the provider. Successful callbacks
return 303 to the saved local URI. Other unauthenticated methods return 401,
without replaying request bodies. Denied identities/resources return 403.
Malformed callbacks return 400; unsupported endpoint methods return 405;
capacity exhaustion returns 503; provider initiation failures return 502.
Handled authentication responses use `Cache-Control: no-store`; protocol/redirect
responses also use `Referrer-Policy: no-referrer`. Session-authenticated protected
responses retain the application's caching policy, like existing authorization.

When public origin is omitted, the incoming request must have TLS and the host
must limit routing to legitimate Host values. Origin is HTTPS plus `Request.Host`;
forwarded headers and absolute request-target URLs cannot override it. Behind TLS
termination, configure the public HTTPS origin and preserve that Host through the
trusted proxy. A host mismatch fails even with a valid cookie. Cookies remain
Secure on the external browser connection. Root-scoped host-only cookies are
necessary for callbacks and applications under different paths; per-policy names
and server-side policy/origin binding prevent cross-policy admission.

This is colocated authorization middleware. It does not reinterpret
`X-Forwarded-Uri` as an independent forward-auth target or expose a remote
verification service. The embedding server owns trusted client-IP metadata.

## Identity and operational limits

Provider roles/groups are retained and verified users receive `authp/user`.
Allowing this role alone allows every account accepted by the provider; restrict
ACLs by roles, email or other supported fields to limit access. Direct policies do
not execute portal transforms, local MFA, profile UI, portal refresh, or downstream
OIDC provider flows. Provider-level authentication/MFA still happens upstream. Existing named-driver
compatibility behavior is preserved: the LinkedIn driver authenticates through
its bearer-authenticated UserInfo endpoint and currently disables nonce and PKCE
in its provider defaults. The generic OIDC driver uses signed identity tokens,
nonce and PKCE by default. The direct-policy browser/state/origin binding applies
to both; this feature does not silently change upstream driver contracts.

`ValidateAccessListPathClaim` requires an effective `user.User` path grant. The
generic provider's identity mapper does not forward arbitrary `acl`/`paths` claims,
and direct policies have no portal transform to add them; enabling that option
therefore denies those identities. Configure resource restrictions with policy ACL
rules and `ValidateMethodPath` instead. Source-address binding is checked against
the embedding server's trusted request metadata on every session request.

Each browser/policy has one active login; starting another supersedes the old one.
Replacement, expiry cleanup, logout and closure also release its provider state.
Custom direct-provider implementations must support
`CancelLogin(state string, sessionIDHash [32]byte, callback string) bool`, with the
SHA-256 hash of the initiating `Upstream.SessionID` and exact callback ownership.
The shared `idp.IdentityProvider` interface remains unchanged.
A session has a fixed lifetime. Expiry starts a fresh upstream login, which may
reuse the provider's own SSO session. Logout revokes this local session, including
an exchange currently in progress, but does not log the user out of the provider.
Already-issued sessions are not instantly revoked by upstream account/key changes;
choose the configured lifetime accordingly.

With root `state` omitted, state is in memory, bounded by the configured limits. Reload/restart invalidates
sessions and pending callbacks. Multiple processes require sticky routing for the
whole login and session lifetime; there is no distributed-store API in this mode.
Keep the runtime alive for all assigned requests, drain it before `Close`, and
let the root server close shared providers once. Standalone gatekeeper consumers
own and close their providers after draining and closing all consumers.

Root [runtime state](../../runtime-state/references/configuration-and-operations.md)
optionally preserves completed sessions and logout across restart without a
portal. Pending logins still restart. One storage directory has one live owner;
this feature does not add active/active session sharing.
