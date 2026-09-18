---
name: refresh-token-transports
description: Change AuthCrunch refresh/logout HTTP routes, secure cookies, native JSON credential transport, browser Web Locks, continuation pages, fresh login, or cross-tab session coordination.
---

# Refresh Token Transports

## HTTP Ownership

`pkg/authn/handle_api_refresh_token.go` owns refresh and logout parsing,
transport checks, response delivery, cookie creation/deletion, and revocation of
an earlier browser family. `respond_api.go` dispatches these reserved routes
before ordinary access authorization so expired access tokens can renew or log
out. Preserve authorization and access-expiry checks on all other APIs.

Routes are POST `<mount>/api/refresh_token`, `<mount>/api/refresh_session`, and
`<mount>/api/logout`. The session endpoint is browser-only and returns only the
current family ID without rotating its credential; it uses the same origin,
header, JSON, mount, and cookie checks. It does not establish fresh identity
authorization. Known spent credentials retain normal lookup replay revocation;
never use this endpoint to recover an uncertain exchange.

The embedded profile client also uses a top-level GET navigation to
`<mount>/api/refresh_token` after a 401. Canonical, query-free requests with
`Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document` redirect to
`<mount>/login?fresh=1`, including when refresh is disabled. With refresh enabled,
the configured origin and mount must match. This compatibility path never
rotates credentials; ordinary API GETs retain their method/availability errors.

Refresh exchanges require the exact configured HTTPS origin, effective host, and
canonical mount.
Browser requests require matching Origin, `X-Authcrunch-Refresh: 1`, JSON,
and compatible Fetch Metadata. Reject query parameters, unknown/duplicate JSON
fields, trailing data, bodies over 1 KiB, duplicate refresh cookies, and mixed
cookie/body credentials. Embedding servers still own forwarded-host/protocol
normalization; never broaden trust merely to make a proxy setup pass.

Cookie transport returns session/expiry metadata only. Cookie names come from
the portal factory's `RefreshTokenCookieName`, defaulting to `AUTHP_REFRESH_TOKEN`.
Use the [shared cookie owner](../authentication-portal-cookies/SKILL.md) for
`cookie prefix`, `cookie refresh token name`, and the reusable cookie parser.
Honor the common prefix and explicit name settings. An enabled token refresh
`cookie name` directive overrides the shared refresh-cookie setting before
factory construction. Read that effective name for request extraction, browser
session detection, issuance, native response metadata, revocation, and deletion.
Never derive an independent name from the origin/mount or require a browser
security prefix. Explicit `__Host-` names still require root scope.

Refresh cookies are Secure, HttpOnly, host-only, SameSite=Lax, and mount-scoped.
Access cookies retain configured domain/path with bounded access
expiry. Refresh cookie lifetime is independent of access cookie configuration.
Responses use `Cache-Control: no-store`.

Native body transport requires explicit config and `refresh_transport: body`
at initial JSON login and every sandbox checkpoint. Pin that choice through
issuance and rotation. Reject browser Origin, Fetch Metadata, and Cookie
headers for native requests; return credentials in JSON and set no cookies.
Never accept a cookie-family token through body transport or vice versa.

API key JSON `/login` is a separate access-only path owned by
`authentication-client`. It does not enter sandbox refresh issuance, sets no
cookies, and rejects `refresh_transport: body`, even in a refresh-enabled realm.
Do not treat possession of an API key as completed password/MFA login evidence.

Use the status contract: 400 malformed/ambiguous request, 401 login required,
403 origin/transport violation, 404 disabled/wrong mount, 405 wrong method,
415 wrong content type, and 503 transient signing/storage/backend failure.
No response delivers credentials before the store commits.

## Browser Lifecycle

`pkg/authn/ui/core/js/refresh.js` exposes `AuthCrunchSession.refresh()` and
`.logout()`. Preserve the same-page promise and shared cross-tab Web Lock for
both operations. Browser storage holds only session/expiry metadata and an
in-flight marker, never access or refresh secrets. Another tab may reuse a
completed result; it must not rotate the same credential concurrently.

Persist the pending marker before dispatch. A lost response can mean the server
already rotated, so do not automatically retry an ambiguous result, including
after navigation or reload. Browsers without Web Locks or usable local storage
fail closed to login. Never introduce a spent-token grace window to hide client
coordination defects.

Bootstrap reads and writes session metadata under the shared Web Lock. Treat
HTML `data-session`/`data-expires` values as stale hints, never authority to
replace storage. The client confirms the current signed access cookie through
`GET <mount>/whoami?probe=true`. A different confirmed SID identifies a new
login and can replace an older SID's pending/blocked marker; the same SID
cannot clear uncertainty, including when a lost response updated its access
cookie. Failed access confirmation cannot look up an uncertain refresh token.
If access expired before initial portal use and there is no uncertainty, the
protected session endpoint obtains a family ID before the first rotation.

Each JavaScript rotation sends `X-Authcrunch-Refresh-Session` with the SID saved
in its pending marker. `Manager.RefreshForSession` checks that precondition
before identity verification/signing/rotation, so a concurrent login that changes
cookies cannot redirect an old pending request to a new valid family. Unknown
or different expected IDs fail without consuming a valid current credential.
The existing `Manager.Refresh` and requests omitting the header retain their
contract; embedding browser coordinators must opt into the precondition too.
Serve the matching JavaScript and HTTP surface together; embedding adapters
must forward the metadata route and precondition header. Do not assume older
handlers implement the precondition merely because they accept extra headers.
An empty/duplicate header, or use on native/logout/lookup requests, is malformed.
Known spent-token lookup retains ordinary replay-revocation semantics.

Storage events clear timers for pending/blocked state and reconfirm a different
healthy SID under the lock. A previously rejected tab can reconfirm access on an
explicit refresh/focus even before the storage event is delivered. Those access
probes do not rotate or look up uncertain refresh credentials. Preserve the
same-page flight promise and the response SID check. Use the current signed
access deadline when confirming metadata, and reject nonnumeric expiry state
before scheduling or rotating. Logout retains its SID in
the blocked marker and remains available after bootstrap refuses rotation.
Malformed or pre-release uncertain records without a SID fail closed; never
relabel them using a document's ID or assume they refer to a new login.

`handle_http_session.go` and `ui/page_templates/basic/session.template` own
continuation/confirmation UI; `handle_http_portal.go`, `handle_http_login.go`,
and the portal template load the client conditionally. Expired portal access
can renew through top-level continuation; `fresh=1` starts a new login without
looping back to renewal. Fresh login also works on access-only portals and
deletes the old access cookie so the next form submission can start a sandbox.
Retain refresh cookies until login completion can revoke the previous family.
Preserve CSP and trusted destination checks. External
apps must explicitly integrate this flow; a same-origin portal client does not
automatically renew arbitrary cross-origin applications.

GET logout shows confirmation when refresh state exists. The protected POST
revokes the family before clearing cookies and following a trusted destination.
A revocation failure returns 503 without claiming success. A completed new
browser login revokes the previous family even when the new realm is
access-only. Clear legacy refresh cookies at `<mount>/api/refresh_token` without
deleting the active credential at `<mount>`: the two cookies can share the same
factory name. Keep explicit security-prefix compatibility without making those
prefixes defaults. Provider logout retains its separate protocol behavior.

Account replacement coverage must include JSON password/MFA login with browser
cookies and Origin, including transitions to realms outside the refresh list.
The shared issuer stages signing and atomically replaces presented cookie
families through `Manager.IssueReplacing`, including at full capacity. Use the
implementation owner's terminal-retention and optional-adapter contract.
`handleIssueTokens` also retires prior refresh authority on access-only
completion, then completes OIDC login and delivers browser credentials. Revocation
failure returns 503 without claiming success or changing authentication cookies.
These components do not share one transaction. JSON completion revokes its new,
undelivered refresh family when a later step fails, with bounded cleanup that
survives request cancellation. Cleanup failure returns unavailable. Require a
fresh login; never restore a previously replaced family. Keep OIDC-capacity
recovery, canceled-request cleanup, and cleanup-outage regressions in
`token_refresh_completion_test.go` and real TLS coverage in
`token_refresh_completion_e2e_test.go`.
When an existing refresh cookie identifies a browser switching to an access-only
realm, update its access cookie as well as returning the existing access-only
JSON result. Use the factory's effective names and delete both active and legacy
refresh paths. HTML and JSON login validate the refresh origin when a refresh
cookie is present even if the new realm is unselected.

Check the previous credential at the real refresh endpoint after successful
replacement; checking only the new access token or response headers misses
retained authority. Keep API-key and explicit native body authentication outside
browser replacement. A cookie-free access-only JSON login retains its existing
response contract and does not acquire an access cookie through replacement.

## Validation

Run `make test TEST_DIR='./pkg/authn/... ./pkg/apiauth'` and `make test-ui`.
The Go route suite is `pkg/authn/handle_api_refresh_token_test.go`; cookie and
embedded inventory tests live in `pkg/authn/cookie` and `pkg/authn/ui`.
`pkg/authn/ui/testdata/token_refresh_client_test.cjs` simulates DOM, storage, fetch,
and Web Locks. Keep concurrent refresh/logout, stored-pending failure,
continuation, fresh-login recovery before/after storage events, different IDs,
delayed initialization, and lost/malformed responses. Assert all metadata writes
occur under the lock. This simulation is distinct from the real browser suite.
Update UI asset inventories when adding embedded files.

`token_refresh_session_test.go` and `token_refresh/session_test.go` cover lookup and
precondition boundaries. `TestE2ERefreshSessionPrecondition` uses a real TLS
portal with default/custom cookie names and checks that an older SID cannot
consume another account's current credential.

`TestE2ERefreshBrowserBootstrap` runs in the default Go suite and requires Node
24 and headless Chrome, following the
[browser engine policy](../testing-and-ci/SKILL.md#browser-engine). Do not use
Firefox. Set `AUTHCRUNCH_TEST_BROWSER` to the Chrome executable if it is
not on PATH or at the standard macOS Chrome location. Missing engines fail
rather than substituting the VM simulation. The Go fixture owns the browser
process and a temporary profile, trusts only its test certificate's SPKI, and
uses mock/basic key storage without changing OS trust or browser profiles.
The launcher waits up to 45 seconds for `DevToolsActivePort` within the existing
90-second E2E deadline and detects process exit while waiting. Failed startup
stops and reaps the process before reporting its output, so diagnostics cannot
race with subprocess writes. `TestE2ERefreshBrowserStartup` exercises delayed
partial readiness, early exits, deadline cleanup, and missing executables with
local process fixtures; the bootstrap test retains the real Chrome journey.
Its standard-library Node CDP driver is `ui/testdata/token_refresh_browser_e2e.cjs`.
Two real tabs use actual cookies, storage events, and Web Locks while the server
holds previously rendered HTML and truncates an already committed refresh
response. Assert the old HTML preserves the new family's pending state, sends
no repeated rotation, and recovers both tabs after a real new login; then verify
logout blocks further refresh. The fixture also checks Whoami authorization.
This proves local Chrome behavior, not every browser or production proxy.

```sh
make test-ui
make test TEST_DIR='./pkg/authn' TEST='TestE2ERefreshBrowserBootstrap|TestE2ERefreshSessionPrecondition' COVERAGE_DIR='.coverage/refresh-browser'
```

`TestE2ETokenRefreshCookieLifecycle` in
`pkg/authn/token_refresh_config_parser_e2e_test.go` uses a real TLS client and
cookie jar with both public configuration parsers to check prefix/name overrides,
legacy-path cleanup, rotation, logout, and revocation. Keep ordinary fixtures on
the common portal cookie convention.
`login_replacement_e2e_test.go` covers actual TLS browser replacement across
accounts and realms, same-account MFA login, default/custom names, old-path
cleanup, OIDC replacement, foreign-Origin denial, and native/API-key isolation.
`login_replacement_test.go` injects a revocation outage and checks both selected
and access-only completion, including preservation of the prior OIDC session.
