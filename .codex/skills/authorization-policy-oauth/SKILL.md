---
name: authorization-policy-oauth
description: Maintain authorization-policy OAuth login without an authentication portal, including provider selection, directive parsing, gatekeeper callbacks, opaque sessions, ACL checks, logout, lifecycle, TLS E2E tests, and Caddy integration guidance. Upstream protocol and JWT verification remain with oauth-identity-provider.
---

# Authorization Policy OAuth

## Ownership and public API

`pkg/authz/oauth_config.go` owns `OAuthAuthorizationConfig`, its defaults and
validation, and `PolicyConfig.ConfigureOAuth`. The serialized field is
`PolicyConfig.OAuth` (`oauth`). `pkg/authz/oauth/parser` exposes
`NewOAuthAuthorizationConfigFromDirectives(policyName, statements)` for complete
encoded statements. Empty input disables the feature; nonempty input requires
exactly one `use oauth identity provider NAME`. Apply the returned snapshot with
`ConfigureOAuth`; other policy settings and ACL rules remain independent.

`pkg/authz/oauth.go` owns HTTP orchestration and bounded process-local state.
`authz.NewGatekeeperWithIdentityProviders(config, providers, logger)` selects a
configured shared OAuth provider. `NewGatekeeper` remains compatible for ordinary
JWT policies and rejects OAuth configuration without a provider. The root
`NewServer` passes its shared providers; no portal or identity store is needed.
Direct providers must also expose `CancelLogin(string, [32]byte, string) bool`;
the built-in OAuth provider implements it without changing `idp.IdentityProvider`.
Root validation rejects missing, disabled, wrong-kind and ambiguous references,
overlapping OAuth endpoint namespaces, and cookie collisions between policies.

Read [configuration and operation](references/configuration.md) for exact grammar,
transport semantics, deployment constraints, and examples. Read the
[Caddy agent handoff](references/caddy-security-handoff.md) when integrating this
library into `caddy-security`; parser availability alone does not enable Caddyfile
syntax. Do not modify or run tooling in sibling repositories during work here.

## Authentication and authorization boundaries

The selected provider owns authorization-code exchange, state, nonce, PKCE,
issuer, audience, signature verification, and provider-specific identity lookup.
Use [oauth-identity-provider](../oauth-identity-provider/SKILL.md) for those
mechanisms; do not implement another OAuth client inside the gatekeeper.
Direct policies accept code/query callbacks only. JavaScript/implicit response
configurations fail construction. Existing provider compatibility settings and named-driver defaults are preserved;
notably LinkedIn uses its UserInfo path and disables nonce/PKCE in that driver.
Do not prescribe these disabled controls for generic OIDC; its default flow keeps
signature, issuer/audience, nonce and PKCE verification.

The gatekeeper separately binds provider state, origin, return URI and initiating
method to a random 256-bit login cookie. The pending entry lasts five minutes.
Claim it atomically before exchange, retaining the claimed record until completion
so it counts toward capacity and logout/replacement/Close can cancel issuance.
Wrong-browser/state/origin requests cannot consume a legitimate transaction.
Duplicate, expired, malformed, direct-token and replayed callbacks fail closed.
Application query parameters are not protocol inputs; only validated, explicitly
enabled login hints and additional scopes are forwarded at initiation.

Reserve callback/logout namespaces before bypass rules and ordinary credential
checks. Exact canonical endpoint paths are required; encoded/cleaned aliases
must not bypass validation. Save the local return URI server-side and reject
ambiguous or cross-origin targets. Do not use return cookies or `redirect_url`
as authority. Reauthorize the original method/path before issuing a session and
on every session request through `TokenValidator.AuthorizeUser`. That API only
evaluates trusted identity; it is not an authentication API for caller claims.
Call `TokenValidator.Configure` before using it; incomplete setup and nil requests
return errors.
It preserves all method/path interpretations, source-address and path-claim
checks without caching an authorization decision.

Verified users receive the baseline `authp/user` role, plus provider roles/groups.
A policy allowing that baseline authorizes every successfully authenticated user
of its provider; use narrower ACLs when access is restricted. No admin role is
created. Malformed identities or missing subjects never produce sessions.

## Sessions and lifecycle

Session and login cookies are distinct, host-only, root-path, Secure, HttpOnly,
SameSite=Lax cookies. Conventional names derive from the policy; overrides may
use `__Host-`/`__Secure-`. They belong to the policy, not the portal cookie factory.
Cookie duplicates and malformed credentials fail closed. Stored keys are SHA-256
hashes of random credentials. Sessions are bound to both policy and origin.
No upstream token is issued to the browser or accepted as an application token.

An OAuth policy authenticates only its own session cookie. It cannot configure
ordinary JWT keys, token-source lists, auth proxies, or portal cookie names.
Reject meaningful typed key-store settings and `ValidateBearerHeader` too; allow
the shared validator's derived default key-store config through validation/reload.
Existing JWT-only policies retain their behavior. Header provenance and configured
`StripTokenEnabled` remain gatekeeper responsibilities. Sessions use independent
user clones per request, without entering the JWT credential cache.

Sessions have an absolute lifetime, no sliding renewal or refresh token. Capacity
is bounded and expired entries are reclaimed on admission. A fresh login rotates
the binding; only the newest login per browser/policy can finish. A same-origin
POST to the logout route revokes session and pending/in-flight login, then deletes
both cookies with matching attributes. No upstream single logout is implied.

Cancel provider state when replacing, expiring or discarding a local transaction,
including failed redirect admission, logout and Close. Pass its state, SHA-256
browser binding and exact callback URL to `CancelLogin` outside the policy mutex.
Removing only the local record lets repeated replacements exhaust the shared
provider even when the policy's pending count stays at one. Provider cancellation
does not replace the local final admission check after an in-flight exchange.

`Gatekeeper.Close` clears owned OAuth state and closes its validator, never the
shared provider. Root `Server.Close` owns provider disposal. Hosts must drain
requests before disposal. Reload/restart loses sessions and pending transactions;
multiple instances need sticky routing for this in-memory mode.

## Validation

Keep parser unit tests in external `package parser_test` with the executable
constructor example. Typed config, provider selection, cookie/origin, malformed
callback, expiry and lifecycle unit coverage live in `pkg/authz/oauth*_test.go`.
The public identity-authorization method is covered by the existing validator
path matrix. Root reference validation lives in `config_oauth_authorization_test.go`.
Register public config structs and the conventional `oauth` spelling with tag
compliance tests.

`server_oauth_authorization_e2e_test.go` is an external-package consumer using both
public parsers, JSON restoration, `NewServer`, local TLS IdP/application listeners,
independently signed Ed25519 assertions, real nonce/PKCE exchange, cookie jars,
and downstream observations. It has no portal, local store or live credentials.
Keep successful access, target ACL denial, claim/header integrity, cookie stripping,
provider trust failures, origin/browser/policy isolation, callback replay and
concurrency, capacity, expiry, logout cancellation, and runtime replacement covered.
`server_oauth_authorization_policy_e2e_test.go` checks source binding and denied
identities without effective path claims. Generic provider mapping does not
forward arbitrary `acl`/`paths`; use policy ACLs with `ValidateMethodPath` there.

`pkg/idp/oauth/provider_direct_authorization_e2e_test.go` verifies provider capacity
reclamation and shared-policy isolation through TLS gatekeepers. Its isolated
subprocess also exercises the named LinkedIn flow using a local CONNECT tunnel to
synthetic TLS UserInfo, without a production transport hook or live credentials.

```sh
make test TEST_DIR='./pkg/authz/... . ./internal/tag' COVERAGE_DIR='.coverage/oauth-authorization'
make ci-check
```

Follow `testing-and-ci` for diagnostics and reports. A passing library fixture
is not evidence that Caddy's authentication wrapper preserves handled responses.
