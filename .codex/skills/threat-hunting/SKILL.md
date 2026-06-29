---
name: threat-hunting
description: go-authcrunch threat-hunting workflow for security audits, vulnerability triage, and deep review of authentication and authorization boundaries. Use when auditing the package for security issues, validating external vulnerability reports, reviewing authn/authz bypasses, ACL/path matching, redirects, token/cookie/session handling, OAuth/SAML/LDAP/KMS flows, input parsing, concurrency, secret logging, dependency vulnerabilities, or producing security findings and remediation plans.
---

# Threat Hunting

## Operating Posture

Treat every authentication shortcut, authorization shortcut, redirect, token
source, cookie, forwarded header, parser, cache, and cryptographic decision as a
security boundary until proven otherwise.

Use skepticism as a verification mode, not as a reason to discount a report.
Translate claims into falsifiable checks, then test or inspect the exact
runtime behavior.

When reviewing authorization logic, always answer:

- What object is being authorized?
- What object is later served, proxied, redirected to, or trusted?
- Are those objects represented by the same normalized value?
- Which checks happen before token validation, ACL evaluation, or signature
  verification?

Use the repo-local `coding-directives` skill when implementing fixes, the
`testing-and-ci` skill when choosing or adding tests, and
`scripts-and-automation` when running repository automation or dependency
tooling.

## Workflow

### 1. Scope The Hunt

Start by identifying the security boundary and the attacker-controlled inputs:

- Request URL fields: `Path`, `RawPath`, `RequestURI`, query, fragment, scheme,
  host, and absolute-form request targets.
- Headers: `Host`, `X-Forwarded-*`, auth headers, API-key headers, cookies,
  content type, and client IP headers.
- Body fields: JSON maps, form values, SAML/OAuth payloads, metadata, and
  profile/admin API inputs.
- Stored config: bypass rules, ACLs, identity provider config, identity store
  records, crypto key config, cookie domains, and redirect allowlists.
- External inputs: LDAP, OAuth/OIDC, SAML IdP metadata, email providers,
  upstream services, and filesystem stores.

For external vulnerability reports, extract these facts before judging:

- Entry point and exact package/function names.
- Required configuration and deployment assumptions.
- Claimed payloads and expected parsed forms.
- Check that should have run but did not.
- Downstream sink or side effect.
- Severity claim and whether it depends on another component.

If the report is plausible but deployment-dependent, classify it that way and
still consider a library hardening fix when the package makes an unsafe
normalization, trust, or ordering assumption.

### 2. Map The Decision Path

Follow the call chain from input to decision to sink. Do not stop at a grep hit.

For authz and gatekeeper paths, explicitly map:

- Bypass checks.
- Session parsing.
- Token source extraction.
- Token validation and cache lookup.
- ACL evaluation.
- Header injection and token stripping.
- Redirect or forbidden response construction.
- Upstream handoff behavior.

For authn and identity paths, map:

- Login, logout, recovery, registration, profile, and admin handlers.
- Cookie issuance, deletion, domain selection, and SameSite/Secure behavior.
- Identity store lookup, password/API-key verification, MFA checks, and lockout.
- OAuth/SAML callback processing and external metadata/token/userinfo fetches.

### 3. Run Targeted Search Passes

Use `rg` first. Treat the following searches as starting points, then inspect
the surrounding code and tests.

URL, path, redirect, and matching:

```bash
rg -n "r\.URL\.(Path|RawPath|String|EscapedPath)|RequestURI|PathUnescape|path\.Clean|filepath\.Clean|HasPrefix|Contains|MatchString|Location" pkg
rg -n "X-Forwarded|Host|GetCurrentURL|GetTargetURL|Redirect|ForbiddenURL|Set\\(\"Location\"" pkg
```

Token, cookie, session, and secret exposure:

```bash
rg -n "access_token|id_token|refresh_token|api[_-]?key|password|secret|private|credential|Set-Cookie|SameSite|Secure|HttpOnly" pkg
rg -n "logger\\.|zap\\.|Printf|Errorf|Debug|Info|Warn" pkg/idp pkg/authn pkg/authz pkg/kms pkg/identity
```

Parsing, body limits, and type assertions:

```bash
rg -n "io\\.ReadAll|ReadAll|MaxBytesReader|map\\[string\\]interface\\{|\\.\\(string\\)|\\.\\(\\[\\]interface\\{\\}\\)|json\\.NewDecoder|Unmarshal" pkg
```

Crypto, TLS, and token verification:

```bash
rg -n "InsecureSkipVerify|tls\\.Config|x509|jwt|ParseWithClaims|SignedString|Verify|Sign|alg|nonce|pkce|state" pkg
```

Concurrency and cache mutation:

```bash
rg -n "RLock|Lock\\(|Unlock|map\\[|delete\\(|go func|sync\\." pkg
```

Dependencies and toolchain:

```bash
go list ./...
govulncheck ./...
staticcheck ./...
```

If a tool needs network access, an updated vulnerability database, or loopback
listeners, request the needed permission and record that condition in the
validation notes.

### 4. Hunt URL And Path Canonicalization First

For any path-based auth, bypass, ACL, route, redirect, or upstream decision,
verify the exact representation used for matching.

Check for:

- Matching on raw `r.URL.Path`, `r.RequestURI`, `r.URL.String()`, or raw config.
- Prefix/partial/suffix/regex comparisons before canonicalization.
- Different normalization between the auth layer and the upstream/backend.
- Encoded slash, encoded dot segment, duplicate slash, and absolute-form inputs.
- Scheme-relative redirect targets beginning with `//`.
- Query-string tokens or redirect parameters leaking into logs or `Location`.
- `filepath.Clean` used for URL paths instead of `path.Clean`.
- Loss of meaningful trailing slash semantics after cleaning.
- Prefix rules that unintentionally match sibling paths such as `/publicity`.

Adversarial path payloads to test when relevant:

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
```

For each payload, verify both the parsed value and the security decision. In Go
tests, log or assert `req.URL.Path`, `req.URL.RawPath`, `req.RequestURI`, and the
result of any helper used by the code.

### 5. Hunt Redirect And Header Trust Issues

Review every `Location` header, HTML/JS redirect, return URL, logout URL,
callback URL, and "current URL" helper.

Check for:

- Raw insertion of `r.URL.String()`, `RequestURI`, `Host`, or `X-Forwarded-*`.
- Absolute or scheme-relative attacker-controlled redirect targets.
- Missing redirect allowlist checks.
- Full current URL construction without validating forwarded headers.
- Query parameter interpolation without `url.QueryEscape`.
- Response splitting or invalid header characters.

When a placeholder intentionally expands to an absolute URL, document the trust
model and the headers/config that define the allowed host.

### 6. Hunt Token, Cookie, And Session Issues

Check token sources and propagation:

- Default acceptance of query-string tokens.
- Tokens left in upstream headers, cookies, query strings, redirects, or logs.
- Multiple token sources with ambiguous precedence.
- Bearer/header validation bypass when API-key or basic auth paths fail open.
- Cached users bypassing newer ACL, path, source-address, or token checks.

Check cookies:

- Manual cookie string construction instead of `http.Cookie`.
- Missing `Secure`, `HttpOnly`, and SameSite defaults.
- User-controlled values written without encoding.
- Cookie domain/path selection from untrusted hosts.
- Session ID parsing that accepts malformed or attacker-chosen values.

### 7. Hunt Parser, DoS, And Panic Issues

Review request and config parsers for:

- Unbounded `io.ReadAll`.
- JSON decoded into `map[string]interface{}` followed by unchecked assertions.
- Type confusion in JWT claims, user records, API-key records, and config maps.
- Regexps compiled from config and then run against large attacker strings.
- Loops with missing break conditions or unbounded retries.
- Error paths that panic in library/runtime code.

Prefer typed request structs, `http.MaxBytesReader`, decoder limits where
available, and explicit bad-request errors for malformed user input.

### 8. Hunt Provider And Crypto Boundaries

OAuth/OIDC:

- Verify state, nonce, PKCE, redirect URI, issuer, audience, token signature,
  key use, and algorithm handling.
- Treat provider-specific disabled controls as explicit compatibility risks.
- Avoid logging token responses, ID tokens, access tokens, or userinfo bodies.

SAML:

- Verify signature validation, issuer, audience, destination, recipient,
  ACS URL handling, metadata trust, and IdP-initiated flow assumptions.
- Treat raw XML parsing before signature validation as a sensitive prefilter.

LDAP and network clients:

- Verify TLS settings, server names, certificate validation, timeouts, bind
  credentials, DN construction, and group search filters.

KMS/JWT:

- Verify key usage separation, accepted algorithms, required claims, claim type
  checks, expiration/nbf handling, and malformed-token errors.

### 9. Hunt Concurrency And Cache Behavior

Look for caches and maps touched by authn/authz request paths.

Check for:

- Map mutation under `RLock`.
- Deletes during iteration without the correct lock.
- Cached authorization state missing path, method, source address, or ACL
  dependencies.
- Goroutines that inherit secrets or request-scoped state after the request.
- Race-test coverage for session, token, registration, and provider caches.

### 10. Validate Findings

For each suspected issue, aim for one of these outcomes:

- Confirmed vulnerability with a reproduction or regression test.
- Plausible deployment-dependent issue with clear preconditions.
- Hardening issue with a concrete risk reduction.
- False positive with source-backed reasoning.
- Unknown with the exact missing evidence listed.

Prefer adding a focused regression test before or with the fix. Cover both:

- A safe input that must still work.
- An adversarial input that must fail closed.

For path and redirect fixes, include tests for encoded forms and absolute or
scheme-relative forms. A one-line normalization fix is not enough unless tests
prove the important semantics survive.

### 11. Report Clearly

Lead with findings, not a narrative of the audit. For each issue include:

- Title and severity.
- Status: confirmed, deployment-dependent, hardening, false positive, or
  unknown.
- Affected files and lines.
- Root cause.
- Impact.
- Exploit preconditions.
- Reproduction or reasoning.
- Recommended fix.
- Validation performed.
- Residual risk or follow-up.

For broad audits, include a "Not deeply tested" or "Residual risk" section.
Name important surfaces that were not fully exercised, especially path
canonicalization, redirects, provider cryptography, and concurrent caches.

### 12. Fix Conservatively

When asked to remediate:

- Keep the patch close to the package that owns the boundary.
- Normalize config at validation time when the repository already treats
  `Validate` as a normalization boundary.
- Normalize request inputs immediately before the security decision.
- Compare config and request values in the same canonical representation.
- Preserve established behavior intentionally, such as trailing slash meaning.
- Fail closed on malformed or ambiguous security inputs.
- Redact secrets in new logs and tests.
- Add package-local table-driven regression tests.

Do not broaden the patch into unrelated findings unless the same unsafe helper
or boundary is directly involved.

## Definition Of Done

Do not call a hunt complete until:

- The security boundary and attacker-controlled inputs are named.
- The decision order is understood from source, not assumed.
- Risky string matching, redirect, token, cookie, parser, and crypto patterns
  were searched or explicitly scoped out.
- At least one adversarial test or concrete source-backed counterexample exists
  for the primary claim.
- Focused tests ran, or the exact blocker is documented.
- Findings are written with impact, preconditions, remediation, validation, and
  residual risk.
