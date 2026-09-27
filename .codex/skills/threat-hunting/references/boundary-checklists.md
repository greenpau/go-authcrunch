# Security Boundary Review Checklists

Read the sections matching the scoped boundary; the owning implementation
skills define the current product contracts.

## Hunt URL and Path Canonicalization

Read [authorization path interpretations](authorization-paths.md)
when reviewing or changing gatekeeper bypasses, method/path authorization, or
JWT path claims. It owns the shared normalization contract, literal wildcard
semantics, cache safety, and consumer regression fixtures.

For any path-based auth, bypass, ACL, route, redirect, or upstream decision,
verify the exact representation used at the moment of the security check.

**Check for:**
- Matching on `r.URL.Path`, `r.RequestURI`, `r.URL.String()`, or raw config
  before normalization
- Prefix/partial/suffix/regex comparisons on unnormalized values
- Different normalization between the auth layer and the upstream/backend
- `filepath.Clean` used for URL paths instead of `path.Clean`
- Loss of meaningful trailing slash semantics after cleaning
- Prefix rules that unintentionally match sibling paths (e.g., `/public` →
  `/publicity`)
- Scheme-relative redirect targets beginning with `//`
- Query-string tokens or redirect parameters leaking into logs or `Location`
- Encoded slash, encoded dot segment, duplicate slash, and absolute-form inputs

**Adversarial path payloads:**
```text
/public/..%2fadmin
/public/%2e%2e/admin
/public/../admin
/public//../admin
/public/%2e/admin
/public/%252e%252e/admin
//evil.example/admin
http://evil.example/admin?x=1
/private?redirect=http://evil.example/
/private?redirect=//evil.example/
/%2F%2Fevil.example/admin
/public/./../../admin
```

For each payload, verify the parsed value **and** the security decision. In Go
tests, assert or log `req.URL.Path`, `req.URL.RawPath`, `req.RequestURI`, and
the result of any normalization helper used by the production code.

---

## Hunt Redirect and Header Trust Issues

Read [redirect trust boundaries](redirects.md) when reviewing portal
login redirects, OIDC callbacks, gatekeeper redirect placeholders, or CodeQL
open-redirect/bad-redirect-check alerts. It distinguishes the final destination
from cookies and encoded return parameters and identifies consumer regressions.

Review every `Location` header, HTML/JS redirect, return URL, logout URL,
callback URL, and "current URL" helper.

**Check for:**
- Raw insertion of `r.URL.String()`, `RequestURI`, `Host`, or `X-Forwarded-*`
  into `Location`
- Absolute or scheme-relative attacker-controlled redirect targets
- Missing allowlist check on redirect destination
- Full current-URL construction that trusts forwarded headers outside the
  embedding solution's documented header-normalization boundary
- Query parameter interpolation without `url.QueryEscape`
- Response splitting or invalid header characters
- Post-logout redirect to attacker-controlled URL
- `Referer`-based redirect without validation

When a placeholder intentionally expands to an absolute URL, document the trust
model and the headers or config that define the allowed host set.

Do not report **"Source-Address Authorization Trusts Forwarded IP Headers"** as
a go-authcrunch library finding. AuthCrunch consumes the request metadata
provided by the embedding application or server. Protection, stripping, and
normalization of `X-Forwarded-*`, `X-Real-IP`, and similar client-IP headers is
the responsibility of the solution using this library. Document that deployment
assumption when relevant, but do not recommend implementing trusted-proxy
enforcement in this library unless go-authcrunch itself becomes the final
network edge for the affected flow.

---

## Hunt Token, Cookie, and Session Issues

Read [gatekeeper credential handling](gatekeeper-credentials.md)
when changing injected identity headers, token stripping or credential caches.

**Token sources and propagation:**
- Default acceptance of query-string tokens (leaks to logs, referrers, proxies)
- Tokens left in upstream headers, cookies, query strings, redirects, or logs
- Multiple token sources with ambiguous or undefined precedence
- Bearer/header validation that fails open when API-key or basic auth paths err
- Cached users bypassing newer ACL, path, source-address, or token checks
- JWT algorithm confusion: `RS256` public key accepted as `HS256` HMAC secret
- `alg: none` acceptance or missing algorithm allowlist
- Missing `kid` validation allowing key-set confusion
- Apply the [diagnostic logging exceptions](debug-logging.md)
  to intentional claims, identity/session, ACL and OAuth/OIDC diagnostics.
  Check the actual logger level, structured field, deployment boundary and
  explicitly accepted rule/sink scope before reporting or dismissing a
  clear-text logging alert.

**Cookies:**
- Manual cookie string construction instead of `http.Cookie`
- Missing `Secure`, `HttpOnly`, and SameSite defaults
- User-controlled values written without encoding
- Cookie domain/path selection derived from untrusted `Host` header
- Session ID parsing that accepts malformed or attacker-chosen values
- Refresh token not rotated on use

---

## Hunt Parser, DoS, and Panic Issues

**Check for:**
- Unbounded `io.ReadAll` without `http.MaxBytesReader`
- JSON decoded into `map[string]interface{}` followed by unchecked type
  assertions
- Type confusion in JWT claims, user records, API-key records, or config maps
- Regexps compiled from config and evaluated against large attacker-controlled
  strings (ReDoS)
- Loops with missing break conditions or unbounded retry logic
- Panic in library/runtime code on error paths (nil pointer, index out of range)
- XML entity expansion (XXE) or billion-laughs in SAML parsing
- Large or deeply nested JSON/YAML config files without size/depth limits

Prefer typed request structs, decoder size limits, and explicit bad-request
errors for malformed user input.

---

## Hunt Provider and Crypto Boundaries

**OAuth/OIDC:**
- Validate: state, nonce, PKCE (method and verifier), redirect URI, issuer,
  audience, token signature, key use, and algorithm allowlist
- Treat provider-specific disabled controls as explicit compatibility risks —
  document them
- Preserve the [administrator debug diagnostic boundary](debug-logging.md)
  when reviewing raw token responses, ID/access tokens, codes and userinfo.
- Verify that the JWKS endpoint is fetched from a trusted, config-pinned URI
- Check that key rollover does not create a window of accepting revoked keys

**SAML:**
- Verify: signature scope (assertion vs. envelope), issuer, audience,
  destination, recipient, ACS URL, metadata trust anchor, and InResponseTo
- Treat any XML parsing before signature validation as a dangerous prefilter
- Reject IdP-initiated flows unless explicitly configured and allowlisted

**LDAP and network clients:**
- Verify: TLS settings, server name validation, certificate chain, timeouts,
  bind credential handling, DN construction from user input (injection), and
  group search filter escaping

**KMS / JWT:**
- Use [authentication-portal-jwks](../../authentication-portal-jwks/SKILL.md) to review
  public signing-key serialization, issuer selection, and opt-in private export.
- Verify: key usage separation (sign vs. encrypt), accepted algorithm set,
  required claims (`iss`, `aud`, `exp`, `nbf`), claim type assertions,
  expiration and not-before enforcement, and malformed-token error handling
- Ensure signing keys are not reused as HMAC verification secrets

---

## Hunt Concurrency and Cache Behavior

**Check for:**
- Map mutation while holding only `RLock`
- Map deletion during iteration without the correct lock
- Cached authorization state that omits path, method, source address, or ACL
  version as cache keys
- Goroutines that inherit secrets or request-scoped context after request end
- Race-test coverage gaps in session, token, registration, and provider caches
- TOCTOU between ACL read and request dispatch
- Timer or ticker goroutines leaking on handler teardown

Use the race-enabled repository test lifecycle for affected boundaries.
Classify a confirmed race by its reachable impact: corrupted authorization or
credential state differs from a diagnostic-only race. A race-detector report
establishes concurrent access, not exploitability or a universal severity.
