# Agent handoff: OAuth authorization policies in caddy-security

Implement [caddy-security issue #460](https://github.com/greenpau/caddy-security/issues/460)
using the direct OAuth support now provided by go-authcrunch. Work in
`caddy-security` under its own repository instructions. This task's AuthCrunch
change did not modify, build, or test that checkout. Its parser and middleware
sources were read to make this handoff concrete.

## Required result

The following target syntax must adapt, provision, and serve a real login without
an `authentication portal` or `authenticate` route. This is syntax to implement
and test, not a claim that the existing Caddy adapter already supports it.

```caddyfile
{
    security {
        oauth identity provider linkedin {
            realm linkedin
            driver linkedin
            client_id {env.LINKEDIN_APP_CLIENT_ID}
            client_secret {env.LINKEDIN_APP_CLIENT_SECRET}
        }
        authorization policy linkedin_oauth_policy {
            use oauth identity provider linkedin
            allow roles authp/admin authp/user
        }
    }
}

app.example.com {
    route {
        authorize with linkedin_oauth_policy
        reverse_proxy 127.0.0.1:5001
    }
}
```

Register exactly
`https://app.example.com/_authcrunch/oauth2/linkedin_oauth_policy/authorization-code-callback`
with the provider. A policy allowing `authp/user` allows every account authenticated
by that provider. AuthCrunch creates that baseline role but never creates
`authp/admin`. Include a narrower role/email ACL example in user guidance.

## Library APIs and adaptation

Update the dependency to the AuthCrunch revision containing this feature using
the consumer repository's normal workflow; do not publish a library release as
part of this integration unless explicitly requested.

Use:

```go
import oauthparser "github.com/greenpau/go-authcrunch/pkg/authz/oauth/parser"

parsed, err := oauthparser.NewOAuthAuthorizationConfigFromDirectives(policy.Name, statements)
// Check err, then:
err = policy.ConfigureOAuth(parsed)
```

The output is `*authz.OAuthAuthorizationConfig` stored in `PolicyConfig.OAuth`.
The statements are complete directives encoded once with `cfgutil.EncodeArgs`.
Collect every feature statement across the policy body before calling the parser.
Do not reimplement validation, defaults, provider resolution, callback handling,
cookie issuance, or code exchange in the consumer.

In `caddyfile_authz.go`, add policy-body handling for `use` and `oauth` and collect
those statements. Preserve existing ACL/crypto/misc/injection grammar. Apply the
parsed config before `cfg.AddAuthorizationPolicy`. The exact supported forms are:

```text
use oauth identity provider NAME
oauth public origin https://app.example.com
oauth base path /app/oauth
oauth session cookie name app_session
oauth login cookie name app_login
oauth session lifetime 900
oauth maximum sessions 10000
oauth maximum pending logins 1024
```

Reject empty tokens before encoding; preserve quoted value boundaries. Reject
nested blocks if this adapter accepts only the statement grammar. Do not call
the parser separately per line, which loses duplicate detection. Preserve the
consumer's placeholder and runtime-secret conventions. If any feature directive
retains runtime references, keep the complete statement list through Caddy JSON
and reparse after replacement, as its other feature adapters already do.

The named upstream provider still uses the existing
`pkg/idp/parser.NewOAuthIdentityProviderConfigFromDirectives` adapter and existing
provider secret handling. Reference resolution happens in root `Config.Validate`
and `NewServer`, so textual declaration order must not require a provider to be
constructed while parsing a policy. Do not create a hidden portal or synthesize
an identity database/signing key. The root `NewServer` already constructs the
provider and calls `NewGatekeeperWithIdentityProviders`.

Adaptation/JSON tests must cover omitted direct OAuth, every field, duplicate and
unknown settings, malformed values, missing/disabled/wrong-kind providers,
callback/cookie collisions, and persistence through adaptation and provisioning.
Do not add unrelated configuration migrations.

## Critical middleware integration

Inspect `plugin_authz.go` carefully. In the reviewed checkout,
`parseAuthzCaddyfile` returns `caddyauth.Authentication` with an `authorizer`
authentication provider. Its `AuthzMiddleware.Authenticate` returns
`(emptyUser, false, nil)` for a handled gatekeeper response.

Caddy v2.11.4's `caddyauth.Authentication.ServeHTTP` treats a false result from all
providers as a new 401 error, even when the provider already wrote a redirect,
callback completion, or logout. The direct OAuth flow needs **three outcomes**:

1. Authorized/bypassed: set the existing identity placeholders as appropriate and
   invoke the next handler once.
2. Handled by AuthCrunch: preserve its status, body, Location and every Set-Cookie
   header; stop the middleware chain and return without another authentication
   error or error-route response.
3. An unhandled library error: return an appropriate Caddy denial; never leave an
   implicit 200 or call the protected handler.

Implement a proper handler boundary for `authorize` (or an equivalent wrapper
that preserves this contract), while retaining any explicitly supported
`http.authentication.providers.authorizer` compatibility. A nil library error is
not success; check `AuthorizationRequest.Response.Authorized` and `.Bypassed`.
OAuth consumed responses have both false. Do not make callbacks return true just
to satisfy `caddyauth`: that would execute `reverse_proxy` after a login response.
Preserve ordinary JWT policies, metadata normalization, header provenance,
`http.auth.user.*` placeholders, bypass semantics, error handling, and the app's
request admission/draining ownership. Avoid double acquisition or an early release
of the runtime during the request.

Add focused middleware tests that drive the actual Caddy handler chain and
`handle_errors` behavior. Assert the upstream is never called on callback,
redirect, denial, logout, or shutdown; count calls rather than inferring this
from the browser's final status. Check exact responses, including multiple
Set-Cookie values and absence of appended error pages.

## Routing and deployment

Both `CallbackPath()` and `LogoutPath()` belong to the same policy/runtime as its
protected resource. The default whole-site route above covers them. For a
path-restricted application, explicitly mount the OAuth namespace or configure
`oauth base path` within a routed mount. Do not strip its prefix before passing
the request to AuthCrunch. Keep the callback independent of application routes
and preserve exact path/query bytes. The base namespace is reserved ahead of
bypass rules; unsupported descendants fail locally.

Default origin inference uses an actual TLS request and trusted `Request.Host`.
The application must not allow arbitrary hostnames to select callbacks. Explicit
`oauth public origin` pins an external HTTPS origin and permits trusted TLS
termination upstream, with the same external Host preserved. X-Forwarded-Host and
X-Forwarded-Proto never select the library's callback origin. Keep Caddy's existing
trusted client-IP normalization. Do not turn this feature into a service that
blindly trusts X-Forwarded-Uri or arbitrary forward-auth target headers.

Sessions are host-only Secure/HttpOnly/Lax cookies, policy-local and origin-bound.
Only the configured OAuth session cookie authenticates this policy; portal JWTs,
upstream tokens, bearer/query copies of opaque sessions and Basic/API auth do not.
Explicit ordinary JWT key/source/proxy/portal-cookie settings conflict with this
mode, including typed key settings and `ValidateBearerHeader`. Existing JWT-only
policies retain those features. The shared ACL validator derives an internal
default key store; the adapter needs no operator-provided signing key.

Use policy ACLs plus `ValidateMethodPath` for resource restrictions. Generic
OAuth's identity mapper does not forward arbitrary `acl`/`paths` claims, and no
portal transform supplies them here; enabling `ValidateAccessListPathClaim`
without an effective path grant denies access.

Upstream named-driver compatibility remains unchanged: LinkedIn's existing
UserInfo flow disables nonce/PKCE in that driver; generic OIDC keeps both enabled
by default. Do not disable them in the generic TLS test fixture or advertise a
new LinkedIn protocol-security guarantee based only on that generic fixture.
The library also includes a synthetic named LinkedIn TLS journey in
`pkg/idp/oauth/provider_direct_authorization_e2e_test.go`, with its hard-coded
UserInfo host tunneled to a local fixture in an isolated subprocess. This verifies
the driver path and rejection of malformed responses; it does not test the live
LinkedIn service.

No profile UI, local MFA, portal transforms, portal refresh, or downstream OpenID
Provider is instantiated. Session lifetime is absolute; expiry performs another
provider round trip. Same-origin POST `BASE/logout` revokes local session and
pending/in-flight login; it does not perform provider logout. There is one active
login per browser/policy. Sessions/pending transactions are process-local and lost
on reload/restart; use sticky routing for multiple instances. Reuse the app's
existing drain-before-`Server.Close` reload workflow.
Canceled/replaced/expired pending transactions release provider state through
the built-in provider's `CancelLogin` capability. A custom provider wrapper must
preserve that method as well as `idp.IdentityProvider`; direct gatekeeper
construction rejects providers without cancellation support.

## Consumer E2E acceptance matrix

Use synthetic local TLS provider and protected upstream servers, and the actual
built Caddy binary. No live LinkedIn credentials or network service is required.
Port the protocol shape of AuthCrunch's
`server_oauth_authorization_e2e_test.go`, keeping Caddy's own harness conventions.
The fixture validates state/nonce/S256/redirect/client binding and signs assertions
independently. Add a real Chrome cookie journey if required by consumer skills.

Exercise the minimal configuration, explicit-origin/custom-path variants, and
Caddy JSON restoration. Require:

- Unauthenticated GET → provider → callback → original escaped path/query →
  one authorized upstream request, with verified identity headers/placeholders.
- Baseline role with an upstream identity having no roles; narrow ACL denial;
  method/path and source checks reapplied on later requests; no spoofed headers
  on bypass; configured session-cookie stripping observed upstream.
- Wrong/missing nonce, bad signature/issuer/audience/expiry, malformed identity,
  missing subject and provider error: no session and no upstream request.
- Missing/duplicate/malformed state/code, direct-token callback, wrong browser,
  wrong origin, encoded callback, sequential and concurrent replay: fail closed;
  a rejected transplant must leave the legitimate transaction usable.
- Hostile return URI and forwarded-host/proto headers: no foreign redirect.
- Cookie flags, name overrides, two policies sharing one provider, and distinct
  origins: no cross-policy/session admission; no upstream token cookie.
- GET/HEAD initiation versus non-safe-method 401, callbacks before bypass,
  callback/logout method checks, and logout Origin rejection.
- Absolute expiry, pending/session capacity and expired capacity reuse; logout
  cancels a blocked exchange; logout cookie replay fails. Repeated login
  replacement must reuse provider capacity and closing one policy must leave
  another policy's transactions intact.
- Reload/shutdown: old sessions and pending callbacks stop working, retained old
  handlers reject, new login works, and shared provider workers are disposed once.
- Existing portal/JWT, API-key, Basic-auth and remote-authenticator regressions.

Run the consumer's required unit/E2E/diagnostic/CI workflows in that repository.
Update its narrow skills and example configuration. Report the dependency revision,
commands, results and any residual integration limitation. The AuthCrunch tests
prove library behavior, not the consumer adapter or Caddy response handling.
