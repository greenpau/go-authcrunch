---
name: threat-hunting
description: Audit AuthCrunch security boundaries, triage vulnerability reports and scanner findings, reproduce authentication or authorization failures, and prepare evidence-backed remediation. Covers trust, credentials, redirects, concurrency, diagnostic logging, and dependency exposure.
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

Remediation follows [coding-directives](../coding-directives/SKILL.md),
validation follows [testing-and-ci](../testing-and-ci/SKILL.md), and tool side
effects follow [scripts-and-automation](../scripts-and-automation/SKILL.md).
Use [authorization-policy-oauth](../authorization-policy-oauth/SKILL.md) to audit
direct-policy callbacks, opaque sessions, browser/origin binding, and logout.
Use [local-password-authentication](../local-password-authentication/SKILL.md) to
review enumeration defenses, work schedules, and trusted password imports.
Use [local-identity-database](../local-identity-database/SKILL.md) to audit durable
credential, replay, lockout, and cross-instance transaction boundaries.
Use [authentication-portal-profile](../authentication-portal-profile/SKILL.md) to
review canonical account selection and identity-bound self-service.
Use [authentication-portal-mfa](../authentication-portal-mfa/SKILL.md) to review
factor checkpoints, proof binding, and enrollment.
Use [saml-identity-provider](../saml-identity-provider/SKILL.md) to review signed
assertions, request/browser binding, and authoritative certificate pins.

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
Resolve dependency source paths with `go env GOMODCACHE` and `go env GOROOT`,
then inspect the exact package directory. Do not search a home directory or
sibling checkouts to locate cached tooling or dependencies.

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

Record the scanner version, source/binary mode, build metadata, stripping flags,
and output precision. Govulncheck JSON is a stream of JSON values, not necessarily
one compact object per line; decode the stream and distinguish OSV records from
actual findings. JSON-mode exit zero alone does not mean no findings. Separate
module matches, imported affected packages, and reported call/symbol evidence.

For stripped binaries, the scanner may fall back to module-level precision and
emit wildcard package/symbol entries from an advisory. Those placeholders do not
prove that the affected package or function is linked. Preserve the exact
shipping-artifact assessment and supplement it with source analysis and a
matching build retaining symbols when needed; do not remove findings or change
release stripping solely to produce a green scan. Govulncheck v1.8.0 documents
this fallback in its
[official binary analyzer](https://github.com/golang/vuln/blob/v1.8.0/internal/vulncheck/binary.go).
A retained module can still match an advisory for a package no longer imported.
State that boundary instead of claiming the module itself is advisory-free.

Use [identity-public-keys](../identity-public-keys/SKILL.md) to review user-owned
GPG/SSH import, authenticated profile input, and OpenPGP compatibility. Trace actual
operations before equating dependency maintenance debt with an exploit.

---

For the selected boundary, read [boundary checklists](references/boundary-checklists.md):
path interpretation, redirects and host metadata, credential propagation,
parsers and resource limits, provider/key trust, or concurrency. These checklists
link the narrower contract references; unrelated surfaces may remain out of scope.

---

### 4. Validate Findings

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

When source-address authorization uses forwarded client-IP headers, classify
header protection as an embedding-solution responsibility for library consumers.
For the in-repository `authdb` listener, verify its own stripping of forwarded
headers before making that classification. Treat the expected upstream protection as a
deployment assumption unless the reviewed code bypasses its own authorization
checks independently of `X-Forwarded-*` or `X-Real-IP` trust.

For every confirmed or deployment-dependent finding:
- Add a focused regression test **before or with** the fix
- Cover both a safe input that must still pass and an adversarial input that
  must fail closed
- For path and redirect issues, test encoded forms and absolute / scheme-relative
  variants explicitly

A normalization fix with no accompanying test is incomplete.

---

### 5. Report Clearly

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
report, run `go tool versioned -toc -filepath <report-path>` to add or refresh the
table of contents, for example
`go tool versioned -toc -filepath tmp/threat-hunt/20260629_1530_authz-bypass-review.md`.
Mention the saved report path in the final response.

End each report with a **"Not deeply tested"** section naming surfaces that were
not fully exercised, especially:
- Path canonicalization edge cases
- Redirect validation against all allowlist bypass variants
- Provider cryptography (JWKS rollover, SAML signature scope)
- Concurrent cache mutation under load

---

### 6. Fix Conservatively

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
- [ ] `make test` ran the guarded race-enabled suite, or the exact blocker is documented
- [ ] `govulncheck ./...` and `staticcheck ./...` were run or scoped out
- [ ] Every finding includes impact, preconditions, remediation, validation
      performed, and residual risk
- [ ] The full report is saved under `tmp/threat-hunt/` with a
      `YYYYMMDD_HHMM_` filename prefix
- [ ] `go tool versioned -toc -filepath <report-path>` was run against the saved report
- [ ] A "Not deeply tested" section names unexercised surfaces
