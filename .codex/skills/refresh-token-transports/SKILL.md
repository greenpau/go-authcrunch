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

Routes are POST `<mount>/api/refresh_token` and `<mount>/api/logout`.
Require the exact configured HTTPS origin, effective host, and canonical mount.
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

`handle_http_session.go` and `ui/page_templates/basic/session.template` own
continuation/confirmation UI; `handle_http_portal.go`, `handle_http_login.go`,
and the portal template load the client conditionally. Expired portal access
can renew through top-level continuation; `fresh=1` starts a new login without
looping back to renewal. Preserve CSP and trusted destination checks. External
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

## Validation

Run `make test TEST_DIR='./pkg/authn/... ./pkg/apiauth'` and `make test-ui`.
The Go route suite is `pkg/authn/handle_api_refresh_token_test.go`; cookie and
embedded inventory tests live in `pkg/authn/cookie` and `pkg/authn/ui`.
`pkg/authn/ui/testdata/refresh_client_test.cjs` simulates DOM, storage, fetch,
and Web Locks. Keep concurrent refresh/logout, stored-pending failure,
continuation, and fresh-login cases. This simulation does not prove real proxy,
secure-cookie, browser, or hardware WebAuthn behavior; name those limits when
reporting validation. Update UI asset inventories when adding embedded files.
`TestE2ETokenRefreshCookieLifecycle` in
`pkg/authn/token_refresh_config_parser_e2e_test.go` uses a real TLS client and
cookie jar with both public configuration parsers to check prefix/name overrides,
legacy-path cleanup, rotation, logout, and revocation. Keep ordinary fixtures on
the common portal cookie convention.
