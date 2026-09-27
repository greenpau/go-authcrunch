# Authentication Challenge Validation

`transformer/parser/custom_fields_test.go` covers directive and typed-config
rejection, the shared value decoders, snapshots, and a public constructor example.
`transformer/custom_fields_test.go` covers literal substitutions, self-references,
existing claim text and nested type collisions. Fuzz both
`FuzzUserTransformerLiteralClaims` and `FuzzUserTransformerCustomFields` when
changing these boundaries. `authentication_challenges_claims_e2e_test.go` checks
parser-configured scalar/list/map claims with TOTP-only HTML/JSON login, profile
previews, renewal and OIDC, plus collision errors without credential issuance.

Unit and executable-example coverage belongs in the public parser packages;
keep typed policy validation and resolver tests with their owning configuration.
`pkg/authn/authentication_challenges_e2e_test.go` consumes both parsers through a
real TLS portal, temporary identity database, actual password/TOTP and signed
WebAuthn assertions, independent JWKS verification, a second TLS application
protected by an AMR gatekeeper, refresh, and OIDC token exchange. It also tests policy failure, additive requirements,
credential revocation, direct Basic policy rejection, API-key separation, and
wrong-factor/key/challenge rejection for JSON WebAuthn. Preserve hardware-only cases with
both TOTP and U2F registered to catch accidental backend-password retention.
TOTP-only cases cover HTML/JSON with refresh and OIDC independently enabled or
disabled, reject password submission, and verify `otp` alone after login and
renewal. `authentication_challenges_direct_e2e_test.go` checks stored policies,
portal replacements, default compatibility, and additive requirements through
both public embedding APIs in a TLS server and the portal's direct routes.
`authentication_challenges_transaction_e2e_test.go` arranges committed policy,
role, password/key revocation, and account lifecycle changes between direct
identification, verification, and issuance. Cover public Basic/API-key APIs,
HTTP Basic, JSON API-key login, and encrypted system Basic/API-key requests, with
unchanged-account controls and independent JWT verification or authenticated
message decryption. Keep deterministic store hooks rather than timing sleeps.
The direct policy matrix also checks encrypted system requests, including
default MFA, explicit preferences, replacements, additive requirements and AMR
forgery. `authentication_challenges_system_e2e_test.go` covers current issuer/
client-address policy and rejected credentials through the real TLS endpoint,
plus bounded malformed/chunked request bodies and a subsequent valid login.
`authentication_challenges_apikey_context_e2e_test.go` checks issuer-dependent
additive, replacement, and deny policies through JSON `/login`, including path
and source-address controls, independently verified allowed tokens, and absence
of browser-session cookies. Its unit companion checks query exclusion, public
proxy issuer compatibility, and cancellation before transactional issuance.
`authentication_challenges_sequence_e2e_test.go` covers WebAuthn first, last,
and between other required factors, including an additive password. JSON must
return an assertion challenge before visiting the next checkpoint.
`authentication_challenges_context_e2e_test.go` covers issuer/address matching
and context changes at OIDC authorization, code exchange, UserInfo, OIDC refresh,
and portal refresh. Keep both successful factor-only issuance and rejection of
inadequate earlier evidence when a later request adds requirements.

`login_identity_e2e_test.go` checks automatic AMR across HTML/JSON, access-only,
refresh, OIDC-only, combined, and excluded-realm logins. Keep tests proving that
transforms cannot forge AMR, and that renewal does not upgrade authentication.
Synthetic WebAuthn signatures establish protocol behavior, not browser/device
certification. Factor verification and enrollment belong to
[portal MFA](../../authentication-portal-mfa/SKILL.md).

```sh
make test TEST_DIR='./pkg/authchal/... ./pkg/authn/transformer/... ./pkg/user ./pkg/acl ./pkg/identity ./pkg/ids/local ./pkg/ids/ldap ./pkg/authn ./internal/tag' COVERAGE_DIR='.coverage/authentication-challenges'
make ci-check
go test ./pkg/authchal/parser -run '^$' -fuzz '^FuzzAuthenticationChallengeDirectives$' -fuzztime=10000x -parallel=2
go test ./pkg/authn/transformer/parser -run '^$' -fuzz '^FuzzUserTransformerAuthenticationChallenges$' -fuzztime=10000x -parallel=2
```

Embedding-server directive wiring belongs to the consumer repository. Publish
these reusable parser APIs and validate them here; do not edit sibling projects.
