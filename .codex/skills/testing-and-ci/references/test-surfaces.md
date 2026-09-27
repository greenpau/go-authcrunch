# Test Ownership and Consumer Boundaries

Root configuration and server tests exercise composed AuthCrunch configuration
and server construction across credentials, messaging, identity stores,
identity providers, authentication portals, authorization policies, OAuth keys,
and validation phases. Use these when a change affects cross-package wiring.

Use [logging](../../logging/SKILL.md) to validate the directive parser,
immutable Zap filter, and root TLS journeys that verify actual JSON log output
while preserving denial and successful authentication behavior.

Authentication tests live under `pkg/authn`, including HTTP login/logout,
external logout, response handling, cache sandbox behavior, cookie settings,
transformers, icons, and embedded UI pages/static assets. Use `httptest` and
`internal/testutils` helpers for request/response and token-driven behavior.

Standalone server tests live under `pkg/httpserver` and `cmd/authdb`, including
parser-based TLS refresh/OIDC journeys and the actual race-enabled executable.
Use [authdb](../../authdb/SKILL.md) to validate listener lifecycle, routing, configuration,
subprocess cleanup, and targeted validation.

Reusable login-client tests live under `pkg/authclient`, including E2E tests
against a real local TLS portal and identity store in the default test suite;
CLI tests live under `cmd/authdbctl`, including executable E2E against a real
portal and local database plus Python-backed pseudo-terminal tests. Use [authentication-client](../../authentication-client/SKILL.md) to validate
reusable protocol/credential coverage and its 100% gate.
Use [authdbctl](../../authdbctl/SKILL.md) to validate management commands,
terminal fixtures, and executable E2E behavior. The CLI subprocess is separate from the parent coverage profile.

Authorization tests live under `pkg/authz`, including gatekeeper behavior,
authentication requests, redirect handlers, cache behavior, options, and token
validator sources. Path normalization and JWT path-claim changes use the TLS
consumer fixtures in `pkg/authz/path_e2e_test.go`; the
[authorization path owner](../../threat-hunting/references/authorization-paths.md)
defines their adversarial matrix and unit/fuzz coverage.
`pkg/authz/validator` and related tests use `httptest`,
test crypto key stores, test users, ACL helpers, and exact source/match
expectations.
Authorization login return URLs also use the root
`TestE2EServerAuthorizationLoginRedirectProtocols` journey with real HTTP/1.1,
HTTP/2, and quic-go HTTP/3 transports. It requires loopback TCP and UDP sockets;
do not replace HTTP/3 with a modified HTTP/1 request or silently fall back to
another protocol. See the
[redirect owner](../../threat-hunting/references/redirects.md#regression-ownership)
for the full login journey and request-target invariants.

Use [authorization-policy-oauth](../../authorization-policy-oauth/SKILL.md) to
validate direct OAuth policy login, callbacks, sessions, and logout.
Root `server_oauth_authorization_e2e_test.go` exercises both public parsers,
configuration restoration, shared provider dispatch and TLS gatekeeper journeys
without a portal or identity database. Keep callback consumption, ACL checks,
opaque sessions, logout cancellation and lifecycle distinct from portal JWT tests.

Use [runtime-state](../../runtime-state/SKILL.md) to validate durable credentials
and replay history, including root TLS portal-free OAuth and portal/OIDC/refresh
restart journeys and an actual
built `authdb` process killed without cleanup. Verify old credentials and replay
revocations after reopening; graceful Close alone is insufficient crash evidence.

Identity and store tests live under `pkg/identity`, `pkg/ids`,
`pkg/ids/local`, `pkg/ids/ldap`, and `pkg/registry`. They rely on temporary
identity databases, registration/user JSON fixtures, domain restriction cases,
LDAP DN/config parsing, and table-driven success/error cases.
Use [local-password-authentication](../../local-password-authentication/SKILL.md) to validate the password-verifier regression matrix and controlled timing validation.

Use [local-identity-database](../../local-identity-database/SKILL.md) to validate
transactions and the two-realm TLS journeys in `pkg/authn/identity_alias_e2e_test.go`.
Use [authentication-portal-profile](../../authentication-portal-profile/SKILL.md) to
validate transformed-account, revoked-evidence, and cross-origin persistence
checks. Use [authentication-portal-mfa](../../authentication-portal-mfa/SKILL.md) to
validate factor enrollment and replay prevention.

Identity provider and SSO tests live under `pkg/idp`, `pkg/idp/oauth`,
`pkg/idp/saml`, and `pkg/sso`. OAuth tests cover request parsing, state,
provider setup, JWKS, GitHub email lookup, and provider HTTP interactions.
Use [oauth-identity-provider](../../oauth-identity-provider/SKILL.md) to validate upstream
JWT/JWKS, static key provisioning, rotation, and real portal OAuth E2E coverage.
SAML/SSO tests use metadata, certificate, and key fixtures from
`testdata/saml` and `testdata/sso`.

KMS and credential tests live under `pkg/kms` and `pkg/credentials`. They use
RSA, ECDSA, GPG, OAuth, malformed PEM, missing-key, and mixed-key fixtures
under `testdata`. Preserve package-relative paths such as
`../../testdata/rskeys/test_2_pri.pem` when adding cases.
Use [authentication-portal-jwks](../../authentication-portal-jwks/SKILL.md) to validate public signing-key export, admin private-key export authorization, and portal
endpoint tests that independently verify issued JWT signatures.

Embedded UI tests live under `pkg/authn/ui`. `static_test.go` asserts the
static asset count, sorted paths, and content types; `pages_test.go` and
`ui_test.go` exercise built-in templates, page rendering, and filesystem
template parity. Update these tests deliberately when embedded assets or
templates change.

Utilities and policy primitives have focused table-driven tests under
`pkg/acl`, `pkg/apiauth`, `pkg/authchal`, `pkg/messaging`, `pkg/redirects`,
`pkg/tagging`, `pkg/translate`, `pkg/user`, `pkg/util`, and `pkg/waf`. Add new
cases in the nearest package-level test before creating a broader integration
test.
