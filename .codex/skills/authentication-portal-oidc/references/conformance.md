# OpenID Provider conformance

The implementation targets **Basic OP**, **Config OP**, and **Form Post OP for
code flow**. It is not an OpenID Certified implementation merely because local
tests pass. Certification requires the Foundation's plan results for an actual
deployment and the Foundation's submission process.

## Scope and requirements

The implementation follows [OpenID Connect Core 1.0 errata set 2](https://openid.net/specs/openid-connect-core-1_0.html),
[Discovery 1.0 errata set 2](https://openid.net/specs/openid-connect-discovery-1_0.html),
[RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html),
[RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html),
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html),
[RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html), and
[RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html) for the supported surface.
Discovery advertises code flow, scoped and individual claims, RS256 Request
Objects, address/phone scopes and rotating OIDC refresh grants. See
[provider capabilities](provider-capabilities.md) for registration, explicit
identity data, authentication context and consent requirements. Implicit/hybrid
flows, Dynamic Client Registration, encrypted Request Objects, remote request
URIs, unsigned/encrypted ID tokens, RP logout profiles and FAPI remain outside
the supported surface.

The initial compatibility review used the official
[conformance suite](https://gitlab.com/openid/conformance-suite) at commit
`e3b5558d6d5e0c17ab578a47b955fd3b405f902b` and its
`OIDCCBasicTestPlan`, `OIDCCConfigTestPlan`, and `OIDCCFormPostBasicTestPlan`.
Review the current plans again before certifying a release.

| Conformance behavior | Local coverage |
| --- | --- |
| Discovery, issuer-relative endpoints, HTTPS/JWKS, GET/HEAD | `TestE2EOIDCProviderBrowserConsent`, `TestE2EOIDCIssuerMount`, `TestE2EOIDCProtocolErrors` |
| Public provider API without an authentication portal | `pkg/oidc/provider_e2e_test.go`: `TestE2EStandaloneProvider` |
| Code response and client authentication | `TestE2EOIDCClientBindingAndPKCE`, `TestOIDCClientAuthentication` |
| RS256, `kid`, issuer/audience/time/nonce/`at_hash` | Independent `crypto/rsa` assertions in `oidc_e2e_test.go` |
| UserInfo GET, POST header/body, scope filtering | `TestE2EOIDCProviderBrowserConsent`, `TestE2EOIDCConsentAndPrompt` |
| Missing nonce, optional/unknown parameters, POST authorization | `TestE2EOIDCOptionalParametersAndFormPost` |
| Login, silent login, consent, fresh authentication, delayed checkpoint redemption | `TestE2EOIDCConsentAndPrompt`, `TestE2EOIDCFreshLoginRejectsEarlierCheckpoint` |
| Unsigned Request Objects, redirect/mode precedence, client binding, hostile claims | `TestOIDCRequestObjects`, `TestE2EOIDCRequestObjects` |
| Unregistered signatures, encrypted objects and remote URI rejection, invalid redirects and prompts | `TestE2EOIDCProtocolErrors`, `TestE2EOIDCRequestObjects` |
| Single-use code, replay revocation, concurrent exchanges | `TestE2EOIDCConcurrentCodeRedemption`, `TestE2EOIDCProviderBrowserConsent` |
| PKCE S256 and downgrade/missing-verifier rejection | `TestOIDCPKCE`, `TestE2EOIDCClientBindingAndPKCE` |
| Escaped form-post responses and CSP | `TestE2EOIDCOptionalParametersAndFormPost` |
| Themed native consent, Allow/Deny, callback origin/referrer policy, automatic and no-JavaScript form-post | `TestE2EOIDCThemedBrowser`; [browser-page validation](browser-pages.md#validation) also covers overrides and rendering failures |
| Expiry, bounded storage, shutdown, separate keys | `TestOIDCLifetimesAndCapacity`, `TestOIDCKeys`, `TestOIDCConfigurationTrustBoundaries` |
| Real local MFA and account invalidation | `TestE2EOIDCRequiresCompletedMFA`, `TestE2EOIDCAccountChanges` |
| Logout, revocation, token-purpose separation, native compatibility | `TestE2EOIDCLogoutAndRevocation`, `TestE2EOIDCTokenPurposeSeparation`, `TestE2EOIDCNativeLoginDoesNotSetBrowserCookies` |

These cases are regression evidence. They are not replacements for the
Foundation's specific interactive tests, TLS checks, or test-plan results.

## Running the Foundation plans

Follow the Foundation's [OP testing instructions](https://openid.net/certification/connect_op_testing/).
For static registration, provision three confidential clients: two distinct
`client_secret_basic` clients and one `client_secret_post` client. Use independent
high-entropy secrets and register this exact URI on each:

```text
https://www.certification.openid.net/test/a/YOUR_UNIQUE_ALIAS/callback
```

Leave `require_pkce` false on these conformance clients to permit the Basic
profile's requests that omit PKCE. The PKCE test itself supplies S256. Use a local
user with a name and email, and preserve the deployment's actual MFA policy.
Clients may use default consent or explicit administrator preapproval; user
interaction must be completed when requested by the plan.

Create these plans under **Test an OpenID Provider**:

- `oidcc-basic-certification-test-plan`
- `oidcc-config-certification-test-plan`
- `oidcc-formpost-basic-certification-test-plan`

For Basic and Form Post, select discovery and static-client variants. Config OP
already fixes those variants; do not supply them a second time. An illustrative
plan configuration uses the suite's field names:

```json
{
  "alias": "YOUR_UNIQUE_ALIAS",
  "description": "AuthCrunch release and deployment identifier",
  "server": {
    "discoveryUrl": "https://auth.example.com/auth/.well-known/openid-configuration"
  },
  "client": {
    "client_id": "conformance-basic",
    "client_secret": "FIRST_REGISTRATION_SECRET",
    "scope": "openid profile email"
  },
  "client2": {
    "client_id": "conformance-second",
    "client_secret": "SECOND_REGISTRATION_SECRET",
    "scope": "openid profile email"
  },
  "client_secret_post": {
    "client_id": "conformance-post",
    "client_secret": "POST_REGISTRATION_SECRET",
    "scope": "openid profile email"
  }
}
```

Use the hosted suite with a reachable HTTPS deployment, or the official local
suite with its documented Java/MongoDB or Docker environment. Do not expose a
local development database or production administrator credentials for testing.
The embedding server, certificate chain, and TLS configuration are part of the
certified deployment and are not provided by this Go library.

Run every applicable module and follow the interactive instructions, including
logged-out/logged-in states, forced reauthentication, max-age waits, and captured
screenshots. Review every warning/skip and resolve every failure/interruption.
Unsupported optional features should be skipped by truthful discovery and the
chosen static registration, never hidden by suppressing failed tests. Retain the
complete result bundle, release commit, actual deployment config with secrets
redacted, and required screenshots, then follow the
[submission process](https://openid.net/certification/).

## Validation boundary of this change

The implementation was exercised by repository unit/TLS E2E tests and the
unmodified Foundation suite v5.2.4 at the commit above, built and run locally with
Java 21, MongoDB 7, and the suite's development mode. A disposable local portal
used three static confidential clients, real password login, and consent. The
suite's HtmlUnit browser automation submitted the real forms and captured page
source for the required visual checks. No production credentials or deployment
were used.

Final local run on 2026-09-12: all **71 modules finished**, with **zero failed
or interrupted modules**. The exact results were:

| Plan | PASSED | WARNING | SKIPPED | REVIEW | FAILED |
| --- | ---: | ---: | ---: | ---: | ---: |
| Basic OP | 25 | 3 | 4 | 3 | 0 |
| Config OP | 0 | 1 | 0 | 0 | 0 |
| Form Post OP (code) | 25 | 3 | 4 | 3 | 0 |

The runner exited nonzero because warnings and skips were not suppressed or
listed in an expected-failures file. That exit is retained with the result bundle;
it is not represented as a completely passing certification run.

The historical September 12/13 warning categories reflected the then-supported surface:

- Profile scope: the earlier local model supplied name and preferred username,
  without every optional OIDC profile claim. Missing data is not fabricated.
- `acr_values`: no authentication-context class vocabulary was advertised or
  asserted. Verified authentication methods remain in `amr`.
- Request Object signing: only unsigned by-value objects were implemented.
  Discovery recommends RS256 support for signed Request Objects; the suite
  reports that missing recommendation as a Config OP warning. Client signing-key
  registration/verification was not implemented. Object signatures still do not
  replace end-user or token-endpoint client authentication.
- Essential individual claims: `claims_parameter_supported` was false; the
  provider released data through approved scopes and ignored this optional
  parameter. A request for an individual name claim without profile scope does
  not override consent.

REVIEW results contain captured login/error-page evidence and need Foundation
review. Skips cover scopes not advertised and optional refresh behavior. Keep these outcomes visible; they are not all PASSED results. The
Config plan validates discovery and public JWK metadata; it does not certify the
embedding server's complete TLS deployment.

For the official command-line runner, the corresponding plan selections are:

```sh
python scripts/run-test-plan.py --no-parallel --export-dir RESULTS \
  'oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]' CONFIG.json \
  oidcc-config-certification-test-plan CONFIG.json \
  'oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]' CONFIG.json
```

Create `RESULTS` first and configure `CONFORMANCE_SERVER` and the runner's
appropriate authentication/development mode as documented by the suite.
Interactive deployments need human browser steps or an appropriate `browser`
configuration; error-page capture is needed for the unregistered redirect test.

Hosted testing, review of every non-PASSED result, and certification submission
remain unperformed steps. Local developer-mode evidence does not establish that
this library or any downstream deployment is OpenID Certified.

## Reproducible repository harness

`server_oidc_conformance_e2e_test.go` contains
`TestE2EServerOIDCFoundationPlans`, an opt-in external root consumer. It provisions
three independent confidential registrations with explicit `require_pkce off`,
a synthetic password user, a separate OIDC signing key, and a real local portal.
Ordinary directive parsing defaults to requiring PKCE; do not accidentally apply
that provisioning default to Basic OP conformance clients. The existing static
registration unit test verifies this profile-specific choice and persistence.
Public/native client policy is unchanged.

The harness launches an unmodified suite and disposable MongoDB on loopback,
puts a local TLS proxy in front of the suite, and drives real password/consent
forms with the official HtmlUnit browser commands. The browser records actual
login and rejection page source for visual-review placeholders. Login capture
is restricted to the `oidcc-prompt-login` and `oidcc-max-age-1` overrides;
ordinary login tasks only submit credentials. A pending placeholder does not
mean it requests a login page: Request Object tests can offer an error-page
placeholder while awaiting a valid callback. Keep rejection captures restricted
to rejection modules, the authorization endpoint, and actual `invalid_request`
page content. The generated browser configuration is covered by
`TestOIDCConformanceBrowserEvidenceRouting`; execute the official plans to verify
the interactions and their resulting signed exports. Those captures
remain REVIEW results; they are not approvals or screenshots from a certified
production deployment. The current harness trusts its local TLS certificate via
a private Java truststore and Python SSL_CERT_FILE, authenticates the runner
with a local suite API token, and removes inherited TLS-bypass and outcome
suppression switches. Java dev mode is local suite authentication setup; the
runner does not use CONFORMANCE_DEV_MODE or DISABLE_SSL_VERIFY. It runs all three plans without expected-failure lists
or validator modifications. Consent commands cover both `/oidc/authorize` and
`/oidc/continue`, since a second client can receive consent directly at authorize. An optional Config-only preflight is explicitly
marked in execution metadata and is never full qualification.

Prepare the suite inside this repository, at the pinned revision
`e3b5558d6d5e0c17ab578a47b955fd3b405f902b` (v5.2.4). Its source checkout must be
unmodified. Build its `target/fapi-test-suite.jar` with Java 21 and Maven using
`mvn -B -Dmaven.test.skip -Dpmd.skip package`, following the suite's own build
instructions. Put generated suite sources in a hidden directory so this
repository's legacy recursive lint command does not traverse them. Do not use
or build a sibling checkout.

Verified local prerequisites were Temurin 21.0.12.1+1, Maven 3.9.16, MongoDB
Community 7.0.43, Python 3.14.6, and runner dependencies httpx 0.28.1 and
pyparsing 3.3.2 in a private virtual environment. Keep module/tool caches and
MongoDB data isolated, and verify official download checksums. Docker is not
required by this harness. No production identities, database, publishing token,
public listener, or certification submission is involved.

With the prerequisites already installed, supply their actual executable paths
and a new result directory whose parent exists inside this repository:

```sh
AUTHCRUNCH_CONFORMANCE_SUITE="$PWD/tmp/oidc-conformance/.suite" \
AUTHCRUNCH_CONFORMANCE_JAVA="$JAVA_HOME/bin/java" \
AUTHCRUNCH_CONFORMANCE_MONGOD="$PWD/tmp/oidc-conformance/.tools/bin/mongod" \
AUTHCRUNCH_CONFORMANCE_PYTHON="$PWD/tmp/oidc-conformance/.venv/bin/python" \
AUTHCRUNCH_CONFORMANCE_RESULTS="$PWD/tmp/oidc-conformance/run-1" \
go test -mod=readonly . -run '^TestE2EServerOIDCFoundationPlans$' -count=1 -timeout=30m -v
```

The directory is created with mode 0700; private configuration and logs use
0600. It contains the deployment, a redacted deployment copy, discovery,
candidate revision/build metadata and a source manifest including untracked
additions, exact runner configuration, process logs,
execution status, the official signed plan export ZIPs, independently verified
per-instance signed exports, captured visual evidence, summary.json and a private
index.html linking the results and evidence. Preserve the entire
bundle privately: registrations, user credentials, grants, and request logs are
sensitive even though they are synthetic. A redacted deployment alone is not
complete test evidence. The runner has its own bounded execution context, and
owned processes are stopped and awaited on fixture completion.

Without the explicit suite environment, the external prerequisite test is
SKIPPED in ordinary CI; the local unit, TLS, browser, and standalone provider
regressions still run. The official runner's nonzero exit remains a failed
opt-in Go run, including warnings or skips that make the runner fail. REVIEW can coexist with
a zero runner exit and must still be reported as REVIEW. Always inspect and retain those outcomes rather than changing
exit handling to make the certification run appear green.

A local rehearsal of the new harness on 2026-09-13 completed all 71 modules:
Basic OP and Form Post OP each had 24 PASSED, 3 WARNING, 4 SKIPPED, and 4 REVIEW;
Config OP had 1 WARNING. There were zero FAILED or INTERRUPTED modules. The
additional REVIEW compared with the September 12 record was the Request Object
redirect case; retain that result as reported by the suite. The same historical warning
categories described above applied to that rehearsal. This is local developer-mode
candidate evidence, not Foundation certification or hosted deployment testing.

For the September 13 rehearsal, the four REVIEW modules in each code-flow plan
were `oidcc-prompt-login`, `oidcc-max-age-1`,
`oidcc-ensure-registered-redirect-uri`, and
`oidcc-ensure-request-object-with-redirect-uri`. The first two request evidence
of reauthentication; the latter two offer redirect-error-page evidence slots.
Filling a slot does not establish that the attached page is appropriate; the
September 17 export audit found this distinction matters for the Request Object
case, as described below. Address, phone, all-scopes, and OIDC refresh-token modules
were SKIPPED because those optional capabilities are not advertised. Portal
token refresh is a separate protocol. The later OIDC refresh implementation
uses its own client-bound rotating families.


## September 17 capability implementation

The first completed runs of the updated library candidate exercised the same
pinned unmodified suite's 71
modules with **63 PASSED, 8 REVIEW, zero WARNING, SKIPPED, FAILED or INTERRUPTED**,
and original runner exit **0**. Basic and Form Post each contribute 31 PASSED
and 4 REVIEW; Config OP contributes 1 PASSED. This is library portal evidence,
not validation of Caddy's binary, routing, TLS deployment, or configuration.
Do not call the eight reviews passes or claim certification.

Those REVIEW modules occurred once in each code-flow plan:

| Module | Reason and remaining work |
| --- | --- |
| `oidcc-prompt-login` | Examine captured evidence of fresh login after prompt=login. |
| `oidcc-max-age-1` | Examine captured reauthentication after authentication age exceeds the limit. |
| `oidcc-ensure-registered-redirect-uri` | Examine the provider's rejection page for an unregistered callback. |
| `oidcc-ensure-request-object-with-redirect-uri` | The initial harness incorrectly attached a login page to an optional error-page slot. This is invalid evidence for that purpose; the valid Request Object callback subsequently succeeded. |

The suite preserves REVIEW after attaching captured page source. The first
three rows require examination of the appropriate login/error pages. The fourth
row required a harness correction and a new run. The module puts a registered
callback inside the Request Object and an invalid callback in the outer request;
it accepts processing the inner callback or displaying a redirect error. It
does not test an unregistered callback inside the Request Object. Provider code
must not spoof interaction or relabel any result.
Any certification submission or publication remains a separate instruction.

Private local runs are under `tmp/oidc-conformance/`. `capabilities-2` completed
63 PASSED/8 REVIEW with runner exit 0. `capabilities-final` reproduced those
module outcomes and runner exit 0, but its subsequent export collector rejected
the suite's padded base64url signature encoding; its Go test failed and that
failure is preserved. The collector now accepts padded and unpadded base64url
and verifies RS256 before interpreting an export. `capabilities-verified` is
the complete evidence/report run after that fix.

`capabilities-1` is retained as an interrupted attempt: the original browser
matcher missed direct authorization-page consent for the second refresh client.
Before terminating the owned runner, all 70 instantiated module exports were
saved: 60 PASSED, 8 REVIEW, and 2 still waiting without a result; one requested
module had no instance. `interruption.json` records these facts, and
`execution.json` preserves runner exit -1 (`signal: terminated`), followed by
Go exit 1. These incomplete outcomes are not merged into the successful run.
The consent matcher was corrected without weakening provider consent checks.

Normal test runs still skip only the external-prerequisite Foundation harness.
Local provider/portal E2E and the evidence collector's deliberately mixed-result
TLS fixture run by default. Keep all private bundles, original runner exits,
source manifests, failed reports and signed exports when comparing candidates.


The verified run preserved 71 independently verified per-instance signatures
and 8 page-source captures, but two captures were inappropriate for their slots
as described above. Signature verification proves export integrity, not that a
capture satisfies the requested visual evidence. Its private entry point is
`tmp/oidc-conformance/capabilities-verified/index.html`; every module is linked
to its original signed export. The three requested plans were fully instantiated.
All owned Java/MongoDB/runner processes were stopped after collection.

### Corrected browser evidence routing

The subsequent `capture-routing-fixed` run restricts login-page capture to the
two reauthentication modules. Both Request Object redirect-precedence cases
now complete their real callbacks and are reported **PASSED by the unmodified
suite**, with no page source attached to their optional error-page placeholders.
No provider redirect validation or suite validator was changed.

All 71 modules finished on September 17 with original runner exit **0** and
Go test exit **0**:

| Plan | PASSED | REVIEW | WARNING | SKIPPED | FAILED | INTERRUPTED |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Basic OP | 32 | 3 | 0 | 0 | 0 | 0 |
| Config OP | 1 | 0 | 0 | 0 | 0 | 0 |
| Form Post OP (code) | 32 | 3 | 0 | 0 | 0 | 0 |

The six remaining REVIEW results are `oidcc-prompt-login`, `oidcc-max-age-1`,
and `oidcc-ensure-registered-redirect-uri`, once per code-flow plan. The signed
exports contain four login-page captures in `ExpectSecondLoginPage` slots and
two `invalid_request` pages in `ExpectRedirectUriErrorPage` slots. All 71
per-instance export signatures were independently verified. These six captures
are page-source HTML, not screenshot images or Foundation review approvals;
retain REVIEW and satisfy the Foundation's visual-evidence instructions before
any separately authorized submission. Nothing was submitted or published.

The private HTML entry point is
`tmp/oidc-conformance/capture-routing-fixed/index.html`. Older bundles and their
original eight-review results remain intact, including the two misplaced
captures. The new outcome totals do not retroactively change those runs.
The race-enabled focused unit/TLS evidence-collector run passed all 12 tests
in `.coverage/oidc-capture-routing`; the complete official-plan E2E run took
125 seconds. The changed Go files passed gopls diagnostics and `go vet .`;
the owning skill passed its validator. All owned suite processes were stopped.

Local suite/tools live under `tmp/oidc-conformance/` (this rehearsal used
`suite`, `tools`, and `venv`). No global package installation is required.
After keeping the private evidence bundles, remove those three prerequisite
directories to reclaim their disk space. MongoDB files in each run directory
are disposable evidence data, not a system database. Removing an entire run
directory also removes its logs, credentials, signed exports and reports.
