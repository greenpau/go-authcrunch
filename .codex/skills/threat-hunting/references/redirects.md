# Redirect trust boundaries

Start with the actual browser destination. A request-derived string appearing
in `Location` does not by itself establish an open redirect: it may be an
encoded query value on a configured destination. Trace the URL's scheme and
authority separately from its path, query, and fragment. Verify both valid
configured redirects and adversarial inputs through the public HTTP workflow.

## Portal login and external providers

`Portal.injectRedirectURL` handles the user's post-login destination. It checks
`TrustedLoginRedirectURIConfigs` before issuing the referer cookie. That cookie
is client input again when read: `grantAccess` and `handleHTTPPortalScreen`
revalidate it. `redirects.Match` must match the path and domain within the same
configuration entry; two different entries cannot jointly authorize a URL.

The redirect to an upstream OAuth or SAML provider has a different owner.
`handleHTTPExternalLogin` consumes the provider's successful redirect response;
OAuth constructs it from the configured authorization endpoint, while SAML
constructs it from the configured single-sign-on endpoint. A post-login
allowlist is not an allowlist for those provider destinations. Trace every
provider response branch before claiming that a value written earlier into a
shared response field reaches the redirect unchanged.

In the external-provider flow, keep `Set-Cookie` serialization separate from
the provider's URL response field. Cookie attributes are not a redirect
destination, and reusing a field for both hides which component owns the final
value. Verify accepted return-cookie behavior,
provider authorization destinations, callback completion, and rejected return
destinations together in a TLS login journey.
`recordRedirectURL` sets the cookie without assigning the provider destination;
the external handler clears stale response state and rejects a provider's 302
when it supplies no destination. The legacy `injectRedirectURL` wrapper retains
the cookie/presence behavior of other portal handlers.

## OpenID Provider callbacks

`pkg/oidc/authorization.go` applies Request Object precedence, then validates
the effective `redirect_uri` against the selected immutable client registration
before constructing `oidcAuthorization`. Check this ordering for success,
protocol errors, prompt-none responses, and both query and form-post modes.
An invalid client or redirect must produce a local error, without redirecting
or posting an error to the supplied destination.

`ClientConfig.allowsRedirectURI` requires exact registered bytes. The only port
exception is a public client with PKCE and an HTTP literal loopback callback,
as implemented in `pkg/oidc/redirect.go`. Host, path, raw query, escaping, and
address family remain bound. Do not replace this with host-only matching,
prefix matching, or general URL normalization. The actual requested callback,
including the selected loopback port, remains bound to authorization-code
redemption.

Registered external callbacks are intentional. Requiring portal same-origin
callbacks would break relying parties. OIDC's exact-match rule is defined in
[Core authentication requests](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest),
with the native loopback port exception in
[RFC 8252 section 7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3).

## Gatekeeper redirects

For `ForbiddenURL`, `{uri}` and `{http.request.uri}` expand to a local
origin-form request URI; `{url}` intentionally expands to the current absolute
URL. Preserve path escaping, query semantics, and the distinction between
these placeholders. The embedding server owns trusted request-host and
forwarded-header policy. An arbitrary unprotected Host or forwarded header is
not evidence of a slash-check bypass in the local URI helper.

Validate placeholder composition as well as the substituted value. A safe
`/evil.example/path` becomes a cross-origin `//evil.example/path` in `/{uri}`.
`getForbiddenRedirectLocation` rejects templates where local URI substitution
can change the scheme, authority, or userinfo. It compares two distinct local
marker expansions before checking the actual destination; a single marker can
be selected by the attacker and is insufficient. Validation accounts for
browser backslashes, edge spaces, and multiple leading slashes without rewriting
safe output bytes. Ambiguous scheme-only or opaque templates fail closed with
403 and no `Location`. Keep `{uri}`, fixed-host path templates, query templates,
and intentional `{url}` behavior covered by successful consumer cases.

The authorization redirect handlers send the user to configured `AuthURL`.
Their return URL, login hint, and additional scopes are encoded query values.
Classify absolute-form targets by parsing `RequestURI` with
`url.ParseRequestURI`, not by testing `r.URL.IsAbs()`. HTTP/3 servers such as
quic-go populate `URL.Scheme` and `URL.Host` from pseudo-headers while retaining
an origin-form `RequestURI`. Copying that path as the return URL loses the
application origin and sends a successful login back to the portal.
For origin-form requests, including `//host/path`, use
`addr.GetCurrentURLWithSuffix` to retain the serving origin and the existing
forwarded-header contract. Preserve raw path escaping, duplicate/empty query
values, ports, and dot segments. An actual absolute-form target remains raw
return data; do not concatenate it onto another origin. This classification
must be independent of HTTP version and applies to both redirect renderers.
Inspect the generated JavaScript as well as `Location` when testing both modes.
For leading slash/backslash findings, evaluate the emitted URL using browser
semantics; Go's `url.Parse` is not a browser URL parser. Include absolute request
targets, `//`, `/\\`, percent-encoded separators, and dot segments. Avoid
cleaning paths merely to satisfy a query when it changes intended resource
identity.

## Regression ownership

Gatekeeper placeholder unit cases belong in `pkg/authz/authenticate_test.go`;
configured-login redirect cases belong in `pkg/authz/handlers/redirect_test.go`.
`TestRedirectRequestTargetForms` covers both renderers with HTTP/1, HTTP/2,
and HTTP/3 request representations, raw target preservation, and forwarded
origins. Root `server_redirect_e2e_test.go` exercises real HTTP/1.1, HTTP/2,
and HTTP/3 transports through `authcrunch.NewServer`, a temporary local identity
database, separate application/portal origins, cookie-jar login, and final
gatekeeper authorization. Assert the negotiated protocol and original resource
after login; assigning `ProtoMajor` in a handler is not HTTP/3 transport coverage.
The pinned quic-go dependency is imported only by tests. Keep this journey in
the default suite with bounded requests and cleanup of QUIC workers and sockets.

`pkg/authz/redirect_e2e_test.go` exercises the public Gatekeeper over TLS and
the browser destination behavior. Retain a failing pre-fix reproduction for
unsafe placeholder composition, plus safe fixed-host and local forms.

External-provider field isolation belongs in
`pkg/authn/external_login_redirect_test.go`. Its complete TLS OAuth consumer
journey is `TestE2EExternalLoginReturnURLIsSeparateFromProviderRedirect` in
`pkg/authn/oauth_state_e2e_test.go`, using the shared OAuth fixture. Verify both
the initial provider redirect and the final accepted/rejected return destination.

OIDC callback matching and exact code binding are covered by
`pkg/oidc/redirect_test.go`; real consumers live in
`pkg/oidc/provider_e2e_test.go` and `pkg/oidc/loopback_e2e_test.go`. The existing
loopback fuzzer checks host/path/query invariants independently of the matcher.
Run the corresponding unit and E2E cases through the repository test lifecycle;
scanner output alone does not establish these contracts.

For authorization login return URLs, run:

```sh
make test TEST_DIR='./pkg/authz/... .' TEST='TestRedirect|TestLocationHeaderRedirect|TestJavascriptRedirect|TestE2EAuthorizationRedirect|TestE2EServerAuthorizationLoginRedirectProtocols' COVERAGE_DIR=.coverage/authorization-redirects
```

## Scanner evidence

Read the complete SARIF source-to-sink path and the selected query version.
CodeQL may widen a nested response object into another field or miss a
registration predicate and provider overwrite. Confirm the real assignments,
checks, and branch conditions instead of interpreting taint as proof of an
exploitable authority change.

Keep regression tests even when a finding is a false positive. Record the
classification separately from any maintainability or defense-in-depth change.
Do not rename a function solely to trigger a sanitizer-name heuristic or
exclude a redirect rule to clear a sound runtime path. A local scan and a
source-backed finding report do not dismiss a hosted GitHub alert; report any
remaining alert and its exact rationale.
