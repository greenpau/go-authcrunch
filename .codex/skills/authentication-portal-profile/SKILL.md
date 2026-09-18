---
name: authentication-portal-profile
description: Maintain authenticated local profile APIs, canonical account selection, atomic identity-bound operations, browser origin checks, and credential-management TLS tests.
---

# Authentication Portal Profile

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

`api_origin.go` checks Origin and Sec-Fetch-Site before unsafe portal API actions.
Reject foreign, null, empty or duplicate Origin, and cross-site/same-site fetch
metadata; same-site does not mean same-origin. Native clients without browser
headers remain supported. The embedding server owns forwarded-header
normalization. Profile bodies require application/json and remain bounded at
1 MiB; text/plain JSON must not become a browser simple-request mutation path.
Refresh endpoints retain their stricter feature-owned origin/transport checks.

Credential or role mutation invalidates the login evidence. A cached access
JWT may still have time remaining, but it cannot authorize another profile
operation after its underlying evidence is revoked. Require a fresh login;
do not silently update cached credential versions after enrollment or deletion.
For WebAuthn ceremony details use
[portal MFA](../authentication-portal-mfa/SKILL.md).

Validation belongs in `profile_identity_test.go`, `api_origin_test.go`,
`profile_identity_e2e_test.go`, `identity_alias_e2e_test.go`, and the identity
request tests. Preserve real TLS login, two accounts with different credentials,
subject/email transformations naming the other account, revoked/deleted/recreated
identities, role removal, refresh renewal, cross-origin cookie submissions,
and persistence checks showing rejected operations changed no credentials.
Run focused tests through `make test` before the full quality gate.
