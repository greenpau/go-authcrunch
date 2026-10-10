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
It rejects every URL whose decoded path holds a `.` or `..` segment, splitting on
slash and backslash. Browsers remove dot segments, literal or percent-encoded,
before they request a URL, so a path restriction matched against Go's parsed
path would not hold for the path the browser requests. Rejecting them, rather
than cleaning the emitted URL, keeps encoded separators, query bytes and
resource identity unchanged. The matcher compares `URL.Host` literally: `prefix`,
`suffix` and `partial` domain modes are string operations, so suffix
`example.com` also matches `notexample.com`. Prefer `exact` domains, or anchored
label-aware regular expressions, where an exact authority is the intended policy.

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

### Per-flow login destinations

The referer cookie is one value per browser, so concurrent tabs overwrite it. Each
login flow therefore also carries its own destination, separately from the cookie.
`Portal.trustedLoginRedirectURL` holds the trust rules for every login
destination, per flow or in the cookie (`recordRedirectURL`, `grantAccess`,
`handleHTTPPortalScreen`): `TrustedLoginRedirectURIConfigs`, an absolute `http`
or `https` URL with a host, a `redirects.Match`, and `login_hint` stripped. A
browser reads the first path segment of a URL without a host as its host, so
such a URL is never trusted. Destinations are bounded to 16384 bytes before and
again after removing `login_hint` and re-encoding. Values above 2048 bytes must
never be serialized into redirect cookies; they travel with their transaction.
The first `redirect_url` value chooses the destination. An explicitly empty,
untrusted, oversized or subsequently distrusted choice means the portal; it must
never fall back to another tab's cookie. Keep the explicit `redirect_url=` marker
on local continuations, including the final portal redirect, to protect the GET
following a 303 from intervening cookie writes. Legacy clients without any flow
context can still use the cookie within the common hard bound.

Preserve the presence of malformed first values too. Go's `URL.Query` silently
drops invalid escapes and unescaped semicolons, allowing a later value to win.
`loginDestinationQuery` selects the first decoded parameter name from the raw
query and treats an invalid value as an explicit empty choice. Cookie capture,
password binding, signed-in redirects and refresh continuation use that same
selection. Unit tests and the server TLS boundary journey cover malformed first
values, later trusted values, encoded parameter names and competing cookies.

Capture points include password sandbox `LoginReturnURL` and
`LoginReturnURLBound`, OAuth state, SAML request/RelayState bindings, pending
registration `return_url`, and the cross-device requester's pending transfer.
Registration releases its stored destination only after successful confirmation;
SQLite persists it across restart. Cross-device approval contributes identity,
never requester navigation. Callback URLs, poll queries and another tab's cookie
cannot replace these bindings. Every successful OAuth/SAML or cross-device
transaction sets `requests.Response.ReturnURLBound`, including an empty choice.
`grantAccess` revalidates the destination and consumes any legacy cookie with one
deletion, but never uses it for a bound flow or a rejected nonempty flow value.

The renderer receives runtime `ui.Args.LoginNavigation` and adds navigation to
ordinary forms and portal links in both built-in and filesystem themes. It uses
an HTML tokenizer, preserves script text, encodes query values, and limits edits
to known portal routes and configured OAuth/SAML initiation endpoints. It fills
core login, refresh and cross-device script attributes. Provider-owned HTTP
login routes retain their empty-query protocol and are not rewritten. Custom
JavaScript which invents new navigation must preserve this context explicitly;
render-time adaptation cannot inspect future DOM mutations. Do not treat a
return URL or the rendering context as authentication evidence.

GET forms need leading hidden destination/freshness controls because submission
replaces the action query. Analyze the form owner and every submitter's effective
action/method before adding shared controls: a foreign or protocol override must
not receive a portal destination, and a GET override on a POST form still needs
controls. Keep empty actions unchanged so they keep submitting to the document
URL rather than its base. Mixed-target forms need explicit theme handling.
Map plans to actual parsed elements/source positions: matching opening-tag text
can inject fields at an ignored nested form and leak them through its foreign
outer form. Table parsing and malformed closing tags can associate submitters
with forms outside their DOM ancestry; do not trust ancestry alone or inject
fields where ownership is ambiguous. See the
[HTML form owner rules](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#association-of-controls-and-forms).
When adding bound fields, remove conflicting reserved `name`/`dirname` attributes
from that form's existing controls, including those before the form via `form=`.
Do not disable a submit button or alter ordinary field values to resolve this.
Classify core scripts using their first `src`, including duplicate attributes.
HTML enumerated attributes need ASCII-only keyword matching. Unicode case folding
can classify a browser's invalid/default GET as POST, or an invalid/default
submit button as reset; either breaks this submission analysis. Retain unit and
real-browser regressions for `poſt` and `reſet`, plus valid mixed-case ASCII.
Resolve links against the first active HTML base,
ignoring inert template bases, and never attach destinations to navigation made
foreign by a base URL. Fragment-only links keep their original behavior.

Never
reuse `Response.RedirectURL` for it: identity providers own that field. A
signed-in login page, or a signed-in portal page, with a trusted destination and
without `fresh=1` answers 303 to it (`returnToLoginDestination`) without writing
the cookie, so two signed-in tabs whose responses interleave cannot exchange
destinations. It requires the portal session (`hasPortalSession`), as the portal
page it would otherwise pass through does; without one, the portal clears stale
access evidence and keeps the explicit destination on the login continuation. With refresh tokens or OIDC every login POST starts a new login
whose sandbox carries the destination. A GET with only a refresh cookie renders
the session continue page with the destination as `data-next` and on its
`fresh=1` sign-in link. These paths delete the shared cookie only when it holds
the same destination (`consumeOwnRedirectCookie`), so nothing stale lingers and
another tab's value survives. A `fresh=1` GET always renders the login page, and
its form, back navigation and start-over link keep `fresh=1`.

The basic login page passes its destination to `login.js`. While visible, the
script asks the mounted identity endpoint with `probe=login`,
`Accept: application/json` and
`redirect: "manual"`. A 200 replaces the tab with its own destination, or the
portal. A 401 means signed out. A token that is valid but rejected by the portal
ACL, or that has no stored portal session, answers 403 and is not deleted
(`isLoginElsewhereProbe`), because gatekeepers may still accept it and the
portal pages would otherwise delete it; the script then stops asking. Invalid or
expired tokens are still deleted, and every other request keeps the existing
deletion. A `fresh=1` login renders without the probe: another tab's session is
not evidence of it.

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

`getRequestURI` guards both `//` and `/\` at its output boundary, keeping
either browser authority prefix behind a local dot segment. `URL.RequestURI`
normally escapes literal path backslashes as `%5C`; retain the explicit check
on the completed URI as well. Preserve valid `RawPath` and raw query bytes,
and do not use path cleaning or decode encoded separators to clear an alert.

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
Treat `X-Forwarded-Prefix` as an origin-relative path only: it must begin with
`/` and must not contain a query, fragment, backslash, control bytes, or invalid
request-URI encoding. A value such as `@attacker.example` appended directly to
`https://trusted.example` becomes userinfo and changes the effective authority.
Helpers that cannot return an error discard a malformed prefix; fallible URL
builders reject it before composition.
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
`TestE2EAuthorizationRedirectRawRequestSeparators` writes literal slash and
backslash targets over TLS for both local placeholders; `http.Client` would
escape backslashes before transmission and miss that input boundary.
`TestE2EAuthorizationRedirectBrowserOrigin` follows redirects emitted by the
production `{uri}` gatekeeper in Chrome before checking ambiguous template
rejection. Keep the initial test navigation separate from the gatekeeper's
actual redirect under test.

Dot-segment rejection is unit-tested in `pkg/redirects/redirect_match_test.go`.
Per-flow destination boundaries (length before and after re-encoding, scheme,
host, dot segments, trust, first value, cookie precedence, consumption and shared
rules, signed-in GET and POST with and without a portal session, signed-in and
signed-out portal, refresh continuation, probe session and the login page's
form, links, fresh state and probe) are unit-tested in `pkg/authn/login_return_url_test.go`
and `pkg/authn/ui/login_destination_test.go`; `make test-ui` covers `login.js` and
the `refresh.js` continuation.
Root `TestE2EServerAuthorizationLoginRedirectPerTab` sends three tabs of one
cookie jar through the gate over HTTP/1.1, HTTP/2 and HTTP/3: one goes back from
the password step, one logs in, one reloads and one resubmits, and each lands on
its own encoded destination.
`TestE2EServerAuthorizationLoginRedirectBoundaries` carries destinations above
the cookie-size bound with their flow, and lands untrusted or larger-than-16-KiB
values on the portal without falling back to a competing cookie.
`TestE2EServerAuthorizationLoginRedirectFreshBack` goes back from a fresh login's
password step and lands on its destination.
`TestE2EExternalLoginReturnsEachTabToItsOwnPage` completes two OAuth callbacks in
reverse order, one carrying another `redirect_url`.
`TestLoginPageProviderLinksCarryDestinationOnlyWhereAccepted` and the SQLite
`TestE2ESQLiteTicketPortalLoginPageDestination` keep HTTP login provider links bare
and land a ticket login on the login page's destination through the cookie.
`TestE2ELoginElsewhereProbeKeepsTokenThePortalDoesNotAdmit` keeps a gatekeeper-only
OAuth token through repeated probes and still deletes a forged one.
`TestE2ELoginElsewhereSendsWaitingTabsHomeBrowser` drives the probe in headless
Chrome, including background and `fresh=1` tabs that must not leave.

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

For per-flow login destinations, run:

```sh
make test TEST_DIR='./pkg/authn/... ./pkg/idp/oauth ./pkg/redirects ./plugins/identity-providers/sqlite .' TEST='MatchRejectsDotSegments|LoginReturnURL|LoginPageLocation|LoginElsewhereProbe|HTTPPortalSigned|RefererCookieCleanup|^TestE2ELoginRedirect|LoginContinuation|LoginRedirectFreshBack|LoginPageProviderLinks|SQLiteTicketPortalLoginPageDestination|LoginFlowDestination|LoginSignedInReturnsToOwnDestination|LoginRefreshContinues|LoginScreenFlowDestination|BasicLoginCarriesFlowDestination|ExternalLogin|StateBindingReturnURL|ReturnsBoundDestination|LoginRedirectPerTab|LoginRedirectBoundaries|SAMLCallbackIgnoresDestination|LoginElsewhere' COVERAGE_DIR=.coverage/login-destinations
make test TEST_DIR='./pkg/authn/... ./pkg/idp/saml ./pkg/registry ./internal/sqlitedb ./plugins/registration-workflows/sqlite/...' TEST='LegacyTheme|LoginDestination|Registration|Migration|SAML|StateManager|CrossDevice' COVERAGE_DIR=.coverage/login-destinations-extended
make test-ui
```

For authorization login return URLs, run:

```sh
make test TEST_DIR='./pkg/authz/... .' TEST='TestRedirect|TestLocationHeaderRedirect|TestJavascriptRedirect|TestE2EAuthorizationRedirect|TestE2EServerAuthorizationLoginRedirectProtocols' COVERAGE_DIR=.coverage/authorization-redirects
```

## Login return regression boundaries

`pkg/authn/login_redirect_e2e_test.go` defines consumer regressions for login
return destinations using real TLS and local password authentication.
`TestE2ELoginRedirectSignedInTabs` completes both signed-in GET responses before
following either redirect with a shared cookie jar. It checks both follow orders
and a single-tab control without sleeps. Completing each tab's entire redirect
chain serially does not exercise shared-cookie destination replacement.

`TestE2ELoginRedirectPathBoundaryBrowser` uses headless Chrome and
`pkg/authn/ui/testdata/login_redirect_browser_e2e.cjs` to follow actual redirects.
An exact host and restricted path prefix must reject destinations whose literal,
encoded, or mixed dot segments resolve outside that prefix. Preserve successful
plain and escaped-path/query controls. Exercise both signed-in GET and
POST destinations; Go's parsed path alone is not an independent oracle for
the browser's final path.

Both pass: the shared matcher rejects dot segments, and a signed-in tab returns to
its own destination without the shared cookie. Keep them in the default suite;
do not skip them or change their expectations to an unsafe behavior.

```sh
make test TEST_DIR='./pkg/authn' TEST='^TestE2ELoginRedirect' COVERAGE_DIR=.coverage/login-redirect-regressions
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
