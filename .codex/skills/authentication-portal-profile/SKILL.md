---
name: authentication-portal-profile
description: Maintain authenticated local profile APIs, user authentication-flow preferences and UI integration, canonical account selection, atomic identity-bound operations, browser origin checks, and credential-management TLS tests.
---

# Authentication Portal Profile

## Ownership and configuration

`authn.APIConfig.ProfileEnabled` gates profile access. The existing admin API
parser preserves this field but does not configure it; no dedicated profile
enablement parser is present. Keep that legacy configuration gap separate from
the implemented challenge-rule parser used by the flow-selection operations.

## Canonical identity and mutations

`pkg/authn/handle_api_profile.go` dispatches local self-service operations after
JWT authorization and lookup of the server-cached login. `profile_identity.go`
wraps the selected backend with `ids.IdentityRequestStore`; each delegated
operation carries a snapshot of canonical username/email and immutable login
evidence. Never select a profile account from transformed token `sub` or `email`,
or accept identity evidence from the request body.

Require matching backend name/realm, local authentication, canonical account
fields, immutable user ID and backend epoch. Perform the initial bound GetUser
check even for ceremony endpoints that do not otherwise touch the backend.
Every later read or mutation must still use the bound wrapper: an earlier
successful check cannot authorize an unguarded write after revocation.
Unsupported stores and stale/missing identity evidence fail closed.

The local adapter delegates to `Database.RequestWithIdentity`. Follow
[local database transactions](../local-identity-database/SKILL.md) for its fresh
snapshot, operation allowlist, locking, rollback and detached response contract.
The generic trusted `IdentityStore.Request` API remains a separate provisioning
boundary; do not substitute it for authenticated self-service.

Identity-bound password changes accept plaintext and reject reserved hash-import
prefixes before mutation. Keep this check at `Database.RequestWithIdentity` so
every local self-service caller receives it; trusted provisioning still supports
imports. Follow the [password owner](../local-password-authentication/SKILL.md)
for the shared predicate, work-factor trust boundary and regression coverage.

For reading, selecting, or resetting a user's authentication flow, follow the
[profile authentication-flow API contract](references/authentication-flows.md).
It owns the existing `fetch_user_auth_challenges` and
`overwrite_user_auth_challenges` operations, strict parser integration,
registered/effective policy metadata, administrative precedence, and immediate
fresh-login navigation after a successful save. Use it when preparing backend
support for the separately maintained Profile UI.

`api_origin.go` checks Origin and Sec-Fetch-Site before unsafe portal API actions.
Reject foreign, null, empty or duplicate Origin, and cross-site/same-site fetch
metadata; same-site does not mean same-origin. Native clients without browser
headers remain supported. The embedding server owns forwarded-header
normalization. Profile bodies require application/json and remain bounded at
1 MiB; text/plain JSON must not become a browser simple-request mutation path.
Refresh endpoints retain their stricter feature-owned origin/transport checks.

Password, MFA and role mutations that advance the credential generation invalidate the login evidence. A cached access
JWT may still have time remaining, but it cannot authorize another profile
operation after its underlying evidence is revoked. Require a fresh login;
do not silently update cached credential versions after enrollment or deletion.
[Portal MFA](../authentication-portal-mfa/SKILL.md) owns WebAuthn ceremony details.
The embedded profile client's recovery navigation is handled by the
[refresh transport compatibility path](../refresh-token-transports/SKILL.md).
`profile_session_e2e_test.go` covers passkey addition and deletion, same-browser
fresh login, and recovered profile access with refresh disabled/enabled. Its
Chrome driver `ui/testdata/profile_session_browser_e2e.cjs` runs the shipped
profile application using real TLS login cookies and checks the 401-to-login
journey; signed synthetic WebAuthn assertions exercise the factor checkpoints.
The driver waits for the completed login page and the rendered password checkpoint.
Keep its DOM evaluations synchronous; only read-only observations may retry
Chrome document-replacement errors, including `Inspected target navigated or closed`,
within the existing deadline. Never retry form submission or swallow unrelated
protocol failures. `profile_session_client_test.cjs` covers these retry and timeout
boundaries through `make test-ui`; the real Chrome journey remains required.

## Acceptance and validation

Validation belongs in `profile_identity_test.go`, `api_origin_test.go`,
`profile_identity_e2e_test.go`, `identity_alias_e2e_test.go`, and the identity
request tests. `profile_password_input_e2e_test.go` covers reserved import
rejection without credential or refresh revocation, followed by a successful
plaintext change and real TLS login checks. Flow selection adds `profile_auth_challenges_test.go` and
`profile_auth_challenges_e2e_test.go`. Preserve real TLS login, two accounts
with different credentials,
subject/email transformations naming the other account, revoked/deleted/recreated
identities, role removal, refresh renewal, cross-origin cookie submissions,
and persistence checks showing rejected operations changed no credentials.
Run focused tests through `make test` before the full quality gate.

`TestE2ETokenRefreshProviderProfileBoundary` in
`token_refresh_provider_e2e_test.go` checks the profile boundary before and after
provider snapshot renewal. Even with profile enabled and portal profile roles,
provider users lack the canonical local authentication evidence required by the
bound adapter. Renewal cannot confer local credential-management authority.

```sh
make test TEST_DIR='./pkg/identity ./pkg/ids/local ./pkg/authn' TEST='Profile|IdentityRequest|IdentityAlias|RoleChange' COVERAGE_DIR=.coverage/portal-profile
```

A current local identity can read and change its own profile even when token
claims have been transformed. A transformed claim naming another account,
cross-origin submission, or revoked identity cannot change that account's
credentials. A successful generation-changing mutation requires fresh authentication
before another self-service operation. API-key enrollment/deletion currently
retain the generation; see the credential contracts below.

## Credential wire contracts

Read [credential records and diagnostics](references/credential-contracts.md)
when changing API-key/TOTP enrollment, diagnostics, returned verifier records or
credential-generation behavior. Use [openapi-generation](../openapi-generation/SKILL.md)
to update their YAML contracts and native HTTP/schema tests together.
