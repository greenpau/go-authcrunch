# OpenID Provider conformance

Contents:

- [Scope and requirements](#scope-and-requirements)
- [Running the Foundation plans](#running-the-foundation-plans)
- [Official runner](#official-runner)
- [Reproducible repository harness](#reproducible-repository-harness)
- [Evidence interpretation and recovery](#evidence-interpretation-and-recovery)

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

The repository harness pins the official
[conformance suite](https://gitlab.com/openid/conformance-suite) at commit
`e3b5558d6d5e0c17ab578a47b955fd3b405f902b` and exercises its
`OIDCCBasicTestPlan`, `OIDCCConfigTestPlan`, and `OIDCCFormPostBasicTestPlan`.
Review current certification requirements before qualifying a release; a pinned
local harness is not evidence that an external program's requirements are unchanged.

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

## Official runner

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

Supply Java 21, Maven, MongoDB 7, and Python with the pinned suite's runner
dependencies in a private virtual environment. Record their exact versions for
each qualification run. Keep module/tool caches and MongoDB data isolated, and
verify official download checksums. Docker is not
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
COVERAGE_DIR=.coverage/oidc-conformance python3 assets/scripts/test_guard.py run \
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

## Evidence interpretation and recovery

Keep each run self-contained: suite revision, candidate source manifest,
configuration, original runner and Go exit codes, signed exports, captures, and
per-module outcomes. Do not merge an interrupted run into a later completed one
or describe local developer-mode results as hosted deployment certification.

Verify each export's RS256 signature before interpreting results. The collector
accepts both padded and unpadded base64url signature encodings. A valid signature
proves export integrity; it does not establish that a captured page satisfies the
module's requested visual evidence. Preserve REVIEW as REVIEW until the required
external review is complete; attaching page source is not a screenshot or approval.

The Request Object redirect-precedence module can supply a valid callback inside
the object and an invalid outer callback. Processing the valid inner callback
can succeed without filling an optional redirect-error evidence slot. Never attach
an unrelated login page merely because a placeholder is pending. The prompt-login
and max-age modules require evidence of actual reauthentication; registered-redirect
rejection requires the real error page. Keep browser matching scoped to the module
and page behavior, including consent presented directly at authorization.

On runner interruption or collection failure, preserve completed and waiting
module instances, original exits, and the incomplete result bundle. Correct the
harness boundary without weakening provider checks or modifying suite validators,
then run again into a new directory. Report both test completion and evidence
collection; one can succeed while the other fails.

Keep private evidence bundles when cleaning prerequisite checkouts, tools, or
virtual environments. Deleting a run directory also deletes its signed exports,
logs, and captures. Requalify the actual release/deployment; historical totals
are not a current support or certification claim.
