---
name: threat-hunting
description: go-authcrunch threat-hunting workflow for security audits, vulnerability triage, and deep review of authentication and authorization boundaries. Use when auditing the package for security issues, validating external vulnerability reports, reviewing authn/authz bypasses, ACL/path matching, redirects, token/cookie/session handling, OAuth/SAML/LDAP/KMS flows, input parsing, concurrency, secret logging, dependency vulnerabilities, or producing security findings and remediation plans.
---

# Threat Hunting

## Operating Posture

Treat every authentication shortcut, authorization shortcut, redirect, token
source, cookie, forwarded header, parser, cache, and cryptographic decision as a
security boundary until proven otherwise.

Skepticism is a verification mode, not a reason to dismiss a report. Translate
claims into falsifiable checks, then test or inspect the exact runtime behavior.

**Core authorization question — answer it for every protected path:**

1. What object is being authorized?
2. What object is later served, proxied, redirected to, or trusted?
3. Are those objects represented by the same normalized value?
4. Which checks execute before token validation, ACL evaluation, or signature
   verification?

Use the repo-local `coding-directives` skill for fixes, `testing-and-ci` for
test selection, and `scripts-and-automation` for repository tooling.

---

## Severity Rubric

| Severity | Criteria |
|----------|----------|
| **Critical** | Unauthenticated authn/authz bypass, token forgery, RCE, secret exfiltration |
| **High** | Authenticated privilege escalation, open redirect to authn bypass, session fixation |
| **Medium** | Unintended token/secret leakage outside explicit admin debug diagnostics, missing cookie security flags, SSRF with limited reach |
| **Low** | Defense-in-depth gap, hardening issue with no direct exploit path |
| **Info** | Coding pattern risk, missing test coverage, informational finding |

---

## Workflow

### 1. Scope the Hunt

Identify the security boundary and all attacker-controlled inputs before
searching code.

**Request inputs:**
- URL fields: `Path`, `RawPath`, `RequestURI`, query, fragment, scheme, host,
  absolute-form targets, HTTP/2 pseudo-headers (`:path`, `:authority`)
- Headers: `Host`, `X-Forwarded-*`, auth and API-key headers, cookies,
  content-type, client-IP headers
- Body fields: JSON maps, form values, SAML/OAuth payloads, metadata,
  profile/admin API inputs
- Protocol upgrade paths: WebSocket `Upgrade`, gRPC framing, chunked encoding

**Stored / external inputs:**
- Config: bypass rules, ACLs, IdP config, identity store records, crypto key
  config, cookie domains, redirect allowlists
- External: LDAP, OAuth/OIDC discovery and JWKS endpoints, SAML IdP metadata,
  email providers, upstream services, filesystem identity stores

**For external vulnerability reports, extract before judging:**
- Entry point and exact package/function names
- Required configuration and deployment assumptions
- Claimed payloads and their expected parsed forms
- The check that should have run but did not
- Downstream sink or side effect
- Severity claim and whether it depends on a separate component

If a report is plausible but deployment-dependent, classify it that way and
still consider a library hardening fix when the package makes an unsafe
normalization, trust, or ordering assumption.

---

### 2. Map the Decision Path

Follow the call chain from input → decision → sink. Do not stop at a grep hit.

**Authorization / gatekeeper paths — map explicitly:**
1. Bypass checks
2. Session parsing
3. Token source extraction
4. Token validation and cache lookup
5. ACL evaluation
6. Header injection and token stripping
7. Redirect or forbidden response construction
8. Upstream handoff behavior

**Authentication / identity paths — map explicitly:**
1. Login, logout, recovery, registration, profile, and admin handlers
2. Cookie issuance, deletion, domain selection, SameSite/Secure flags
3. Identity store lookup, password/API-key verification, MFA checks, lockout
4. OAuth/SAML callback processing and external metadata/token/userinfo fetches

---

### 3. Run Targeted Search Passes

Use `rg` as the starting point. Inspect surrounding code and tests — do not
treat a grep hit as a confirmed finding.

**URL, path, redirect, and matching:**
```bash
rg -n "r\.URL\.(Path|RawPath|String|EscapedPath)|RequestURI|PathUnescape|\
path\.Clean|filepath\.Clean|HasPrefix|Contains|MatchString|Location" pkg

rg -n "X-Forwarded|Host|GetCurrentURL|GetTargetURL|Redirect|ForbiddenURL|\
Set\\(\"Location\"" pkg
```

**Token, cookie, session, and secret exposure:**
```bash
rg -n "access_token|id_token|refresh_token|api[_-]?key|password|secret|\
private|credential|Set-Cookie|SameSite|Secure|HttpOnly" pkg

rg -n "logger\\.|zap\\.|Printf|Errorf|Debug|Info|Warn" \
  pkg/idp pkg/authn pkg/authz pkg/kms pkg/identity
```

**Parsing, body limits, and type assertions:**
```bash
rg -n "io\.ReadAll|ReadAll|MaxBytesReader|map\[string\]interface\{\}|\
\.\(string\)|\.\(\[\]interface\{\}\)|json\.NewDecoder|Unmarshal" pkg
```

**Crypto, TLS, and token verification:**
```bash
rg -n "InsecureSkipVerify|tls\.Config|x509|jwt|ParseWithClaims|SignedString|\
Verify|Sign|alg|nonce|pkce|state|RS256|HS256|ES256|none" pkg
```

**Concurrency and cache mutation:**
```bash
rg -n "RLock|Lock\(|Unlock|map\[|delete\(|go func|sync\." pkg
```

**Dependencies and static analysis:**
```bash
go list ./...
govulncheck ./...
staticcheck ./...
```

Document any tool that requires network access, an updated vulnerability
database, or loopback listeners; record that condition in validation notes.
Treat `govulncheck` findings in the Go standard library as release/toolchain
notes unless this repository is the final binary being shipped. For this
library, do not report stdlib CVEs as library-code findings or recommend
raising the `go` directive solely to clear them. Document the scanning
toolchain, the downstream/final binary build toolchain, and whether consumers
need a patched Go release on their supported Go line.

---

### 4. Hunt URL and Path Canonicalization

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

### 5. Hunt Redirect and Header Trust Issues

Review every `Location` header, HTML/JS redirect, return URL, logout URL,
callback URL, and "current URL" helper.

**Check for:**
- Raw insertion of `r.URL.String()`, `RequestURI`, `Host`, or `X-Forwarded-*`
  into `Location`
- Absolute or scheme-relative attacker-controlled redirect targets
- Missing allowlist check on redirect destination
- Full current-URL construction without validating forwarded headers against
  a trusted proxy list
- Query parameter interpolation without `url.QueryEscape`
- Response splitting or invalid header characters
- Post-logout redirect to attacker-controlled URL
- `Referer`-based redirect without validation

When a placeholder intentionally expands to an absolute URL, document the trust
model and the headers or config that define the allowed host set.

---

### 6. Hunt Token, Cookie, and Session Issues

**Token sources and propagation:**
- Default acceptance of query-string tokens (leaks to logs, referrers, proxies)
- Tokens left in upstream headers, cookies, query strings, redirects, or logs
- Multiple token sources with ambiguous or undefined precedence
- Bearer/header validation that fails open when API-key or basic auth paths err
- Cached users bypassing newer ACL, path, source-address, or token checks
- JWT algorithm confusion: `RS256` public key accepted as `HS256` HMAC secret
- `alg: none` acceptance or missing algorithm allowlist
- Missing `kid` validation allowing key-set confusion
- Treat debug-level OAuth/OIDC token, code, and userinfo logging as intentional
  admin diagnostics in AuthCrunch. Do not report it as a finding unless the
  data is logged outside debug level, exposed to non-admins, enabled in an
  untrusted sink by default, or returned in user-visible responses.

**Cookies:**
- Manual cookie string construction instead of `http.Cookie`
- Missing `Secure`, `HttpOnly`, and SameSite defaults
- User-controlled values written without encoding
- Cookie domain/path selection derived from untrusted `Host` header
- Session ID parsing that accepts malformed or attacker-chosen values
- Refresh token not rotated on use

---

### 7. Hunt Parser, DoS, and Panic Issues

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

### 8. Hunt Provider and Crypto Boundaries

**OAuth/OIDC:**
- Validate: state, nonce, PKCE (method and verifier), redirect URI, issuer,
  audience, token signature, key use, and algorithm allowlist
- Treat provider-specific disabled controls as explicit compatibility risks —
  document them
- Recognize that portal admins intentionally need debug-level visibility into
  raw token responses, ID tokens, access tokens, codes, and userinfo bodies.
  Report sensitive OAuth/OIDC logging only when it escapes the admin debug
  boundary or contradicts the configured trust model.
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
- Verify: key usage separation (sign vs. encrypt), accepted algorithm set,
  required claims (`iss`, `aud`, `exp`, `nbf`), claim type assertions,
  expiration and not-before enforcement, and malformed-token error handling
- Ensure signing keys are not reused as HMAC verification secrets

---

### 9. Hunt Concurrency and Cache Behavior

**Check for:**
- Map mutation while holding only `RLock`
- Map deletion during iteration without the correct lock
- Cached authorization state that omits path, method, source address, or ACL
  version as cache keys
- Goroutines that inherit secrets or request-scoped context after request end
- Race-test coverage gaps in session, token, registration, and provider caches
- TOCTOU between ACL read and request dispatch
- Timer or ticker goroutines leaking on handler teardown

Run `go test -race ./...` and treat data-race reports as High severity.

---

### 10. Validate Findings

For each suspected issue, reach one of these outcomes before reporting:

| Outcome | Meaning |
|---------|---------|
| **Confirmed** | Reproduction or regression test exists |
| **Deployment-dependent** | Plausible; preconditions documented |
| **Hardening** | No direct exploit path; concrete risk reduction identified |
| **Release/toolchain note** | Standard-library or final-binary exposure driven by build toolchain |
| **False positive** | Source-backed reasoning provided |
| **Unknown** | Exact missing evidence listed |

When `govulncheck` reports reachable standard-library vulnerabilities, classify
them as **release/toolchain notes** for go-authcrunch unless the finding is
caused by repository code that can be fixed independently of the final build
toolchain. Avoid treating the local scan's Go version as this module's minimum
supported Go version.

For every confirmed or deployment-dependent finding:
- Add a focused regression test **before or with** the fix
- Cover both a safe input that must still pass and an adversarial input that
  must fail closed
- For path and redirect issues, test encoded forms and absolute / scheme-relative
  variants explicitly

A normalization fix with no accompanying test is incomplete.

---

### 11. Report Clearly

Lead with findings, not an audit narrative. For each issue:

```
## [SEVERITY] Title

**Status:** confirmed | deployment-dependent | hardening | release/toolchain note | false positive | unknown
**Files:** pkg/foo/bar.go:L42, pkg/foo/baz.go:L17
**Root cause:** <one sentence>
**Impact:** <what an attacker gains>
**Preconditions:** <config, role, or network position required>
**Reproduction:** <minimal payload or test case>
**Recommended fix:** <specific change, not "add validation">
**Validation performed:** <test run, manual trace, or static analysis result>
**Residual risk / follow-up:** <what remains unverified>
```

For release/toolchain notes, include the local scan toolchain, the module's
declared `go` version, known downstream build constraints, and the patched Go
toolchain line needed by final binary builders.

Save the full report to a repo-relative `tmp/threat-hunt/` directory. Create
the directory when it does not exist. Prefix the report filename with the local
timestamp in `YYYYMMDD_HHMM_` format, for example
`tmp/threat-hunt/20260629_1530_authz-bypass-review.md`. After saving the
report, run `versioned -toc -filepath <report-path>` to add or refresh the
table of contents, for example
`versioned -toc -filepath tmp/threat-hunt/20260629_1530_authz-bypass-review.md`.
Mention the saved report path in the final response.

End each report with a **"Not deeply tested"** section naming surfaces that were
not fully exercised, especially:
- Path canonicalization edge cases
- Redirect validation against all allowlist bypass variants
- Provider cryptography (JWKS rollover, SAML signature scope)
- Concurrent cache mutation under load

---

### 12. Fix Conservatively

When remediating:

- Keep the patch close to the package that owns the boundary
- Normalize config at `Validate()` time; normalize request inputs immediately
  before the security decision
- Compare config and request values in the same canonical representation
- Preserve intentional behavior (e.g., trailing slash semantics)
- Fail closed on malformed or ambiguous security inputs
- Redact secrets in new log lines and test fixtures unless the log line is an
  explicit admin debug diagnostic whose sensitive output is intentional
- Add package-local table-driven regression tests

Do not broaden the patch into unrelated findings unless the same unsafe helper
or trust boundary is directly involved.

---

## Definition of Done

The hunt is complete only when all of the following are true:

- [ ] Security boundary and attacker-controlled inputs are explicitly named
- [ ] Decision order is confirmed from source, not assumed
- [ ] All risky patterns (path matching, redirects, tokens, cookies, parsers,
      crypto, concurrency) were searched or explicitly scoped out with a reason
- [ ] At least one adversarial test or concrete source-backed counterexample
      exists for every primary claim
- [ ] `go test -race ./...` was run, or the exact blocker is documented
- [ ] `govulncheck ./...` and `staticcheck ./...` were run or scoped out
- [ ] Every finding includes impact, preconditions, remediation, validation
      performed, and residual risk
- [ ] The full report is saved under `tmp/threat-hunt/` with a
      `YYYYMMDD_HHMM_` filename prefix
- [ ] `versioned -toc -filepath <report-path>` was run against the saved report
- [ ] A "Not deeply tested" section names unexercised surfaces
