# OIDC Provider and Portal Validation

For renderer, template, CSS, browser policy, or consent-presentation changes,
use the [browser-page validation matrix](browser-pages.md#validation).
It covers both standalone and portal rendering, filesystem overrides, native
browser form submissions, and JavaScript-disabled continuation.

`pkg/oidc/config_test.go` covers config, client authentication, and PKCE contracts.
`provisioning_test.go` covers generated credentials, defaults, copied registration,
duplicate rejection, private-key format, file permissions, and concurrent creation.
`parser/client_test.go` and `parser/example_test.go` cover the separate public
parser, quoting, arity, boolean compatibility, error redaction, concurrent reuse,
and stable adaptation with persisted credentials. `parser/redirect_test.go`
checks repeated single-URI statements through both public constructors, rejects
plural/mixed forms and malformed later statements, and preserves exact callback
order and serialized arrays. Reloads replace the callback list without mutating
persisted registrations or inheriting removed callbacks.
`application_test.go` covers named registration snapshots and JSON/XML/YAML
roundtrips. `parser/application_test.go` and `parser/application_example_test.go`
cover header recognition, shared field parsing, restored/explicit credentials,
rotation, authentication-method changes, malformed inputs, and concurrent reloads.
Root `config_oauth_applications_test.go` and its executable example cover the
registry, serialization, ordered assembly, independent portal bindings, validation,
and duplicate rejection. `pkg/authn/oidc_config_test.go` checks provider attachment.
`parser/provider_test.go` and `parser/provider_example_test.go` cover provider
settings, registration resolution and copying, disabled state, limits, malformed
arguments, error redaction, concurrent reuse, and serialized roundtrips.
`provider_test.go` and `options_test.go` cover keys, hints, identity, expiry,
capacity, construction, public methods, lifecycle, lock release, and parser
fuzzing. `request_object_test.go` covers strict request assembly and fuzzing.
`pkg/oidc/provider_e2e_test.go` imports the public provider and parser packages
and the standard library, running TLS login, consent, PKCE exchange, independent
RSA verification, UserInfo, fresh login, account disablement, and logout without a portal. It
provisions and persists generated clients/keys, exercises all three client
authentication methods, and repeats login/exchange after restoring the provider.

The standalone E2E fixture imports the provider parser directly; the shared
portal fixture uses root named registration and provider integration.
`pkg/authn/oidc_application_e2e_test.go` imports the application parser directly
and exercises all three client authentication methods through root configuration,
real TLS local-user login, PKCE exchange, independently verified ID tokens, and
UserInfo. It persists credentials and dedicated keys in temporary files, repeats
adaptation after reopening storage, rejects old secrets after explicit rotation,
reloads the rotated secret, and rejects unselected applications. It exchanges
through both separately declared callbacks after each reload and rejects an
unregistered callback variation before redirecting, including equivalent host,
port, and path/query encodings. It checks the response destination and query
values, binds each code to its authorized callback, and tests unselected clients
with their own registered callback on every reload. `pkg/authn/oidc_config_parser_e2e_test.go` checks discovery, selected clients,
session/token lifetimes, all capacity limits, and disabled routing through
a real TLS portal. Root `server_oidc_config_test.go` checks parsed configuration
through server dispatch, including realm, key-file, and reserved-mount failures.
`pkg/authn/oidc_e2e_test.go` keeps the real portal/local-database password and
MFA E2E flows. `pkg/authn/oidc_runtime_test.go` checks adapter configuration and
browser/native logout. Root `config_test.go` covers server dispatch and the
public provider getter. Keep E2E cases in the default Go suite. Route portal
fixture requests directly to the portal so outer mount filtering cannot mask
incorrect dispatch. Requests outside the issuer mount must not serve keys or
consume codes.

```sh
make test TEST_DIR='./ ./pkg/oidc ./pkg/authn ./internal/tag' TEST='OIDC|Provider|TestTagCompliance|TestStructTagCompliance' COVERAGE_DIR=.coverage/oidc
make test TEST_DIR='./pkg/oidc/parser' COVERAGE_DIR=.coverage/oidc-parser
COVERAGE_DIR=.coverage/oidc-authorization-fuzz python3 assets/scripts/test_guard.py run \
  go test -mod=readonly -race ./pkg/oidc -run '^$' -fuzz '^FuzzOIDCAuthorizationParameters$' -fuzztime=10000x -parallel=2
COVERAGE_DIR=.coverage/oidc-request-fuzz python3 assets/scripts/test_guard.py run \
  go test -mod=readonly -race ./pkg/oidc -run '^$' -fuzz '^FuzzOIDCRequestObjects$' -fuzztime=10000x -parallel=2
make ci-check
```

Local tests establish implementation behavior, not OpenID certification. Never
claim conformance-suite success or certification without the actual Foundation
plan results and submission record for this deployment/version.

For release qualification, record the Foundation suite revision, selected OP
profile, configuration, and per-test results for the actual standalone host or
portal adapter under test. Local TLS tests and parser fuzzing do not substitute
for that plan.
