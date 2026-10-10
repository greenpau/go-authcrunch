# Provider snapshot renewal

## Selection and meaning

Portal refresh can renew authentication completed through an upstream OAuth/OIDC
provider. It issues an AuthCrunch opaque family and AuthCrunch access JWTs;
it does not renew, retain, or redeem upstream tokens. Select each provider realm
in `TokenRefreshConfig.Realms` and add a `TokenRefreshProviderConfig` to
`ProviderRevalidation` with matching `Realm` and `Mode: "snapshot"`.
The serialized key is `provider_revalidation`. The public parser accepts the
repeatable directive `provider revalidation REALM snapshot`, once per realm.
Modes `userinfo` and `refresh_token` are unavailable. Membership, uniqueness,
and mode are validated before portal construction. Disabled refresh preserves
its existing semantic opt-out.

Every selected realm must resolve to exactly one source across attached stores
and providers. Local stores require the existing refresh capability and no
provider mode. Providers require kind `oauth` and explicit snapshot mode;
their upstream request method remains `oauth2`. SAML and other unsupported sources
fail construction. A selected provider's identity-token cookie must be disabled.
Unselected providers retain their access-only behavior.

Captured upstream roles, groups and other attributes can remain usable after
upstream logout, account disablement, role changes, token expiry or key removal.
Only fresh upstream authentication observes those changes. Choose a conservative
absolute lifetime. Portal logout, replay detection, current portal policy denial,
trust-configuration changes and family deadlines still deny renewal. Idle time
extends only after an actual successful refresh exchange; ordinary application
traffic does not extend it. Access expiry never exceeds the absolute deadline.

## Capture, authority and policy

Capture only after the provider has verified a successful callback and redeemed
its single-use, browser-bound state. An existing JWT, caller-provided JSON,
claims transformation or upstream refresh credential cannot create the proof.
The callback is a GET navigation that may legitimately be cross-site. Require
the configured TLS origin and mount, an absent or exact singleton Origin, and
compatible optional navigation Fetch Metadata after state redemption. Ordinary
refresh POSTs retain their strict same-origin protections.

`tokenrefresh.Principal.Source` is `ProviderSnapshotSource`; pin provider name,
kind, realm, original nonempty subject, actual authentication time and exactly
`["federated"]` methods. `BackendVersion` contains a digest of the normalized
provider configuration and driver; secrets themselves do not enter that field.
Changing the provider's trust configuration invalidates captured evidence even
if name and realm are reused. `UserID` equals the pinned provider subject and
does not select a local account. CredentialVersion and local challenges are empty.

Capture verified claims before transformations into independent canonical JSON
bytes. Preserve custom claims needed by policy, including exact JSON numbers.
Remove protocol credential keys recursively and remove portal-owned proof,
grant, timing and session fields at the root. Limit encoded size to 32 KiB,
depth to 16, nodes to 4096 and subject length to 4096 bytes. Reject invalid UTF-8,
unsupported Go values, nonfinite numbers, malformed or noncanonical JSON,
duplicates and oversized evidence without logging claim contents. This is
bounded server-held evidence; it is never a public serialization or HTTP input.

On renewal, verify source, provider identity, configuration digest and pinned
subject, then reapply current group/role mapping, transformations, challenge
policy and portal roles to a new decoded copy. The engine pins subject, original
authentication time, federated AMR, issuer and SID; each JWT gets fresh timing
and JTI. Captured upstream AMR/ACR cannot satisfy local password, TOTP or WebAuthn
requirements. A definitive policy denial revokes the family. Signing/service
failures leave the current credential usable for a known unsuccessful exchange.

Normalize every recognized role contribution before policy, including root
`realm_access.roles` and `app_metadata.authorization.roles` returned by an
injected provider adapter. Preserve the latter's role list before recursively
removing authorization credentials. Retain bounded raw attributes for policy,
then prevent legacy nested role carriers from adding roles during signing.
An overwrite or removal of `roles` must remain effective in the final JWT.
Generic OAuth already flattens nested signed-token roles; its UserInfo object
stays under `userinfo`. Do not promote arbitrary UserInfo fields into root roles.

Context-dependent policy receives the current portal request's `addr` and `iss`,
never captured upstream metadata or the original login address. Preserve this
same request context through signing and cached-user reconstruction. Transform
time uses the existing portal issuer helper: OAuth callback issuers use the
provider route ending in `/`, while renewal uses the refresh endpoint URL.
The signed JWT issuer remains the fixed family origin/mount. A newly matching
factor rule must deny snapshot renewal; provider evidence cannot satisfy it.

Initial provider callbacks issue cookies only and remove bearer Authorization
delivery. Native upstream token exchange is unavailable. Cross-device provider
requesters remain access-only; the approving browser's actual family is retained
for approval invalidation. Cached initial and renewed users have no local
LoginEvidence, LoginUsername, LoginEmail or LoginMethods. A matching local account
name or email and portal profile roles cannot supply local credential-management
authority.
Snapshot cross-device redemption applies the same role normalization and
current requesting-device factor policy. The access-only requester receives
the approving issuer's verified federated AMR and original authentication time,
without inheriting its SID or a refresh credential. Normal approving-family
rotation keeps an approved transfer live; replay and logout invalidate it.

## Transactions and persistence

Use the existing manager's atomic replacement, rotation, deadlines and replay
contracts. A fresh completed callback can replace presented families at capacity
one. Signing precedes commit. Completion failures discard an undelivered new
family with bounded cleanup independent of request cancellation; previously
replaced families remain revoked. Never return credentials before commit or
restore old authority after a later failure.
The refresh HTTP adapter also discards a committed but undelivered rotation when
cached-user reconstruction fails. Cleanup failure is unavailable (503), even
when the initiating reconstruction error is a definitive policy denial.

Deep-copy ProviderSnapshot bytes on all store, manager and result boundaries.
The persistent MemoryStore's encrypted gob records retain the source, binding,
snapshot and full replay history. Validate restored provider evidence before
publishing state. SQLite's private principal DTO retains the same fields while
omitting them for legacy local records, preserving their canonical encoding.
Older SQLite readers reject records with the new provider fields; this is not a
cross-version rollback guarantee. The storage adapter does not authenticate an
upstream callback; the consumer must supply completed server-held evidence.

## Verification

`pkg/authn/token_refresh_provider_test.go` covers sanitation, identity/source
confusion, current policy, trust changes, callback proof, signing and delivery
cleanup. `token_refresh_provider_e2e_test.go` uses public parsers, a real TLS
OAuth issuer, signed ID tokens, nonce/state/PKCE and a browser cookie jar. Keep
expired-access renewal, no upstream credential leakage, unselected providers,
local/provider replacement, local profile denial, current policy denial,
concurrent replay, idle/absolute expiry, logout and persistent restart coverage.
The issuer can be disabled after login to prove renewal uses captured evidence.
This proves the synthetic issuer protocol, not any named provider's live service.

`TestTokenRefreshProviderRequestPolicy` and
`TestE2ETokenRefreshProviderRequestPolicy` cover issuer/address-dependent factor
requirements. Their request-claims counterparts verify transforms at callback
and renewal while independently checking the fixed signed issuer. The renewal
completion-cleanup tests cover request cancellation, a provider becoming
unavailable after rotation, restored admission at capacity one without any old
credential, and 503 when persistent cleanup fails.
The role-alias unit/TLS cases verify top-level and legacy nested contributions
before policy and the final signed roles after overwrite. Nested-role policy
cases require factors at callback and renewal, with denial revoking the family.
Positive nested-role journeys verify sanitation, detached evidence and restart.
The cross-device unit/TLS cases exercise independent requester credentials,
verified federated proof, current requester policy and approving-family rotation.
Their injected provider adapter maps already verified UserInfo into the root
claim shape; it retains real state/signature/nonce/PKCE and the TLS exchange.

`server_token_refresh_provider_e2e_test.go` exercises root configuration round-trip
and mixed-source composition at a nested mount. Engine cloning and persistence
tests cover source evidence and malformed restore. The SQLite public-consumer
TLS E2E `TestE2ESQLiteProviderSnapshotRestart` checks restart, signature/proof,
signing failure retry and durable replay using server-held captured evidence.
Run these alongside existing local refresh, OAuth, browser coordination and
OpenAPI contract suites, including the storage owner's CGO-disabled checks.
