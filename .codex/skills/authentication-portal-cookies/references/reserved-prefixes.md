# Reserved Prefixes and Cookie Deletion

## Browser Contract

A deletion is another `Set-Cookie` response. Browsers validate its prefix and
attributes before replacing the stored cookie and applying expiry. A past
`Expires` alone cannot make an otherwise invalid header delete a cookie.
[RFC6265bis storage rules](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-5.7)
match `__Secure-` and `__Host-` case-insensitively. Cookie names themselves remain
case-sensitive and must match exactly for lookup/deletion.

For example, this header is rejected for a reserved name because it lacks Secure:

```http
Set-Cookie: __Host-ACCESS=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT
```

The factory now emits a browser-compatible deletion:

```http
Set-Cookie: __Host-ACCESS=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly; Secure
```

Deletion retains issuance's effective name, Domain/host-only status, Path, Secure,
HttpOnly, and SameSite. Both expiry mechanisms expire it: a positive Max-Age
inherited from issuance would otherwise take precedence over the past Expires.
Attributes use standard `http.Cookie` serialization. Code consuming raw headers
must not depend on their former attribute order or trailing semicolon.

## Supported Roles

All roles keep ordinary `AUTHP_<SUFFIX>` defaults. Prefixes are optional
compatibility choices; they do not enable features or relax their security rules.

| Role | Issued scope | `__Host-` compatibility |
| --- | --- | --- |
| Access token | Configured host/domain and Path, default `/` | Only root Path with no emitted Domain |
| Session ID | Configured host/domain, always `/` | Only no emitted Domain |
| Referer | Portal mount | Root-mounted portal only |
| Sandbox ID | Portal mount | Root-mounted portal only |
| Identity token | Portal mount plus `/whoami`, provider-owned name | Incompatible with the whoami subpath |
| Active refresh token | Configured refresh mount, host-only | Root refresh mount only |
| Legacy refresh token | Portal mount plus `/api/refresh_token` | Incompatible; legacy helpers return an empty string |
| OIDC session ID | Issuer mount, host-only | Root issuer only |
| OIDC request ID | Issuer mount, host-only | Root issuer only |

`__Secure-` works with non-root paths and Domain cookies when Secure is enabled.
Ordinary portal `insecure enabled` behavior stays supported for ordinary names.
The common factory retains its existing per-domain security selection: either
a secure global setting or a secure selected-domain setting retains Secure.
Refresh and OIDC runtimes independently require Secure and HttpOnly.

`Config.Validate` and the directive parser reject statically incompatible
combinations, including a host-prefixed access cookie with a non-root global or
domain path, an emitted/guessed Domain, or insecure common cookies. Domain
stripping permits host-only cookies without changing which domain policy wins.
Validation covers the global fallback as well as every domain configuration.

The ordinary portal's mount is inferred from each HTTP request. The factory's
`ValidatePortalPath` checks referer/sandbox scope; `Portal.ServeHTTP` calls it
before issuing ordinary portal cookies. An incompatible mount yields HTTP 500
without Set-Cookie.
Keep `extractBasePath` aligned with dispatch, including `/api/` before endpoint
suffixes such as `/logout`, and root-level QR, favicon, beacon, and app routes.
Treating a route segment as the mount can reject valid root requests with
host-prefixed cookies; `extract_base_path_test.go` and the browser/refresh E2E
fixtures cover this boundary.
A root mount emits explicit `Path=/` for referer/sandbox cookies. Fixed OIDC and
refresh mounts retain their own construction-time checks.

Enabled upstream provider identity-cookie names are checked for valid HTTP cookie
syntax and compatible prefix attributes when constructing the portal. They use
`/whoami` even for a root-mounted portal; do not widen them
to `/` to accommodate a prefix. Two portals sharing a provider keep that
provider's explicitly configured name, independently of either portal prefix.

## Conventional Naming and Coordination

An explicit cookie name is complete. For example:

```text
cookie prefix PORTAL
cookie session id name AUTHP_SESSION_ID
cookie access token name AUTHP_LOGIN_ACCESS
```

The two explicit roles use exactly those names. All other defaulted roles use
`PORTAL_...`. `LOGIN_ACCESS` would also be valid, but no implicit `AUTHP_` prefix
would be added to an explicit value. Statement order does not change precedence.

A single parser statement `cookie prefix PORTAL`, or a typed call to
`config.SetCookieNamePrefix("PORTAL")`, covers every defaulted role:

| Role | Result |
| --- | --- |
| Session ID | `PORTAL_SESSION_ID` |
| Referer | `PORTAL_REDIRECT_URL` |
| Sandbox ID | `PORTAL_SANDBOX_ID` |
| Identity-token fallback | `PORTAL_ID_TOKEN` |
| Access token | `PORTAL_ACCESS_TOKEN` |
| Refresh token | `PORTAL_REFRESH_TOKEN` |
| OIDC session ID | `PORTAL_OIDC_SESSION_ID` |
| OIDC request ID | `PORTAL_OIDC_REQUEST_ID` |

Embedding Caddy adapters can translate `set cookie name prefix PORTAL` to the
shared parser's `cookie prefix PORTAL`; adapter integration is owned separately.
Provider-owned upstream identity names are not rewritten by either form.

For the explicit access/session example, coordinate the gatekeeper with
`PolicyConfig.SessionIDCookieName = "AUTHP_SESSION_ID"` and
`AccessTokenCookieNames = []string{"AUTHP_LOGIN_ACCESS"}`. Choose allowed token
sources separately; naming a cookie must not enable header, query, Basic, or API
key credentials. A matching session ID is not authentication evidence.
The common cookie parser does not coordinate other portals or policies. The
aggregate `authcrunch.NewServer` retains its historical behavior of discovering
portal access-cookie names when a policy's `AccessTokenCookieNames` is empty.
Supply an explicit list to prevent that cross-portal discovery; use an explicit
`AUTHP_ACCESS_TOKEN` list when only the default portal name is intended. Session
names still need their own matching policy setting. This deletion change does
not alter server-level discovery or token-source defaults.

## Validation and Limits

The Chrome fixture verifies real local password login, sandbox-cookie removal,
a cookie-only gatekeeper, path boundaries, a deliberately broken deletion control,
production logout, and denial afterward. It covers default/custom names and both
reserved prefixes, including mixed-case prefix spelling. Tests isolate browser
profiles and trust only the test certificate's SPKI; no global browser trust is
changed. OAuth identity-cookie and active-refresh lifecycle fixtures separately
verify their production issuance/deletion paths. Public-suffix-aware Go jars
verify host/domain and path boundaries; they do not replace Chrome's prefix checks.

Logging out removes browser credentials. It does not retroactively revoke a
copied stateless access JWT; that token follows its existing verification and
expiry policy. Opaque refresh and OIDC session revocation retain their existing
runtime behavior. Cookie removal does not end a session at an external upstream
identity provider unless its logout integration performs that operation.

Gatekeeper rejection-time cookie cleanup is a separate best-effort path. Incoming
Cookie headers contain names and values, not their original Domain or Path. This
change does not add portal scope information to authorization policies; use the
portal logout endpoint for authoritative deletion.
