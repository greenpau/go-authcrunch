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
Discovery intentionally does not advertise implicit/hybrid flows, Dynamic Client
Registration, signed/encrypted request objects, remote request URIs, individual
claims requests, unsigned
or encrypted ID tokens, address/phone scopes, OIDC refresh grants, or RP logout
profiles. FAPI profiles are outside this implementation.

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
| Signed/encrypted object and remote URI rejection, invalid redirects and prompts | `TestE2EOIDCProtocolErrors`, `TestE2EOIDCRequestObjects` |
| Single-use code, replay revocation, concurrent exchanges | `TestE2EOIDCConcurrentCodeRedemption`, `TestE2EOIDCProviderBrowserConsent` |
| PKCE S256 and downgrade/missing-verifier rejection | `TestOIDCPKCE`, `TestE2EOIDCClientBindingAndPKCE` |
| Escaped form-post responses and CSP | `TestE2EOIDCOptionalParametersAndFormPost` |
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

The warning categories have specific scope explanations:

- Profile scope: the local model supplies name and preferred username; it does
  not supply every optional OIDC profile claim. Missing data is not fabricated.
- `acr_values`: no authentication-context class vocabulary is advertised or
  asserted. Verified authentication methods remain in `amr`.
- Request Object signing: only unsigned by-value objects are implemented.
  Discovery recommends RS256 support for signed Request Objects; the suite
  reports that missing recommendation as a Config OP warning. Client signing-key
  registration/verification is not implemented, and objects confer no client
  authentication. Do not claim support for signed Request Objects or JAR.
- Essential individual claims: `claims_parameter_supported` is false; the
  provider releases data through approved scopes and ignores this optional
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
