# Store capabilities and partial profile support

`GET <mount>/api/capabilities` requires a current cached exact-token login and a
portal user/admin role, independently of Profile/Admin/Documents enablement.
It accepts no body or query. The result describes only the caller's backend
kind/name/realm; it contains no filesystem paths, account records or keys.
Transactional stores revalidate immutable evidence and canonical selectors
before returning metadata. Replaced, revoked and old-epoch evidence returns 401.
Omitted API configuration behaves like disabled flags throughout API dispatch;
noncanonical capability aliases and other unavailable routes must return the
ordinary JSON refusal, never panic while inspecting absent flags.

`identity.StoreCapabilityProvider.GetCapabilities()` returns a detached
`StoreCapabilities`: profile read, password change, API keys, public keys, MFA,
authentication flows, connections, Documents and supported admin operation names.
Absent metadata does not imply implemented collections. A host must preserve
optional store interfaces when injecting a backend. These are descriptive flags;
the actual operation must still validate configuration, permission and proof.
Profile availability requires the actual `ids.IdentityRequestStore` interface
and at least one declared Profile operation family. A password-only or
credential-only partial provider need not expose information reads. Forwarding
metadata through a host wrapper is not sufficient. An
omitted provider `AdminOperations` slice serializes as an empty array in both
discovery and dashboard metadata. Preserve absence of the provider itself rather
than fabricating a declaration for legacy stores.
The profile identity wrapper must preserve absence of this optional metadata.
Older stores retain their existing dashboard collection queries without a
fabricated all-false declaration; stores declaring capabilities query only
supported collections. Unknown operation names never inherit MFA or another
capability. Add each new operation to its explicit family and regression coverage.

The response additionally separates `enabled`, `supported`, `allowed` and
`reason` for Profile, Admin, Documents, OIDC, JWKS and private-key export.
Reasons are `available`, `disabled`, `forbidden`, `unsupported_capability` or
`no_eligible_keys`. Disabled configuration takes precedence, followed by
permission and implementation. A disabled feature can still have backend support.
Public discovery is independent of the Admin flag. Export additionally requires
its explicit opt-in, Admin enablement, administrator permission and eligible
legacy asymmetric keys. Selected PS256 access keys never imply private export.
Capability reads consult only public keys. HMAC-only portals advertise no
eligible asymmetric keys; never export a symmetric/system secret to fill a UI.
Unconfigured OIDC stays disabled; SQLite OP integration remains unsupported.

Local JSON retains its existing credential operations. SQLite supports
`fetch_user_info`, `fetch_debug`, `fetch_user_dashboard_data` and
`update_user_password`. Unsupported recognized requests return 501 with
`code: unsupported_capability` after current identity verification. The dashboard
contains metadata and capability flags, omitting unsupported collection counts
and the placeholder connected-account list. Missing counts mean unavailable,
not zero. Missing timestamps/revision are omitted, not invented.

Profile failures preserve the timestamp/status/message envelope and may add a
stable code: `identity_required` (401), `storage_unavailable` (503),
`commit_uncertain` (503), `unsupported_capability` (501), or `operation_failed`.
Backend strings are not a user-facing diagnostic contract. Uncertainty takes
precedence over joined identity-denial or context errors. Backend deadline and
cancellation errors, including expiration while waiting for a SQLite transaction,
map to `storage_unavailable`, not bad password/input. This applies both to the
initial identity read and a mutation admitted before contention begins.
After a successful password
change, the former credential generation cannot authorize profile/Documents
operations: use fresh login, never rewrite cached evidence. Preserve exact
SQLite plaintext bytes; legacy local trimming remains unchanged.

Admin remains a separate access-JWT/role boundary. Supported mutations retain
the existing HTTP-200 `status: success|failure` envelope; clients must inspect it.
Failures add safe `operation_failed`, `storage_unavailable` or `commit_uncertain`
codes instead of exposing backend strings. Read current state after uncertainty
before considering another mutation.
Backend deadline/cancellation errors use `storage_unavailable` while retaining
that HTTP-200 failure envelope. Do not replace typed context errors with a
generic domain error in the storage layer to obtain the HTTP classification.
Declared unsupported operations return 501 before invoking storage. Unknown
realms return 404. The SQLite record projection and complete-list limits belong
to the [SQLite store contract](../../sqlite-identity-store/SKILL.md).

`TestE2EProfileLegacyStoreDashboard` exercises a real injected store without the
metadata extension, a credential mutation, and its resulting dashboard count.
The omitted-config JWKS/capability TLS matrix and `TestAPIWithoutConfiguration`
cover authenticated and anonymous unavailable API paths and encoded aliases as
well as the working endpoint. No-token requests can reach API dispatch even when
they are not authorized to use a feature; absent flags must be safe there too.
`TestE2EProfileDeclaredCapabilities` checks a partial provider's empty operation
array and a host wrapper that retains metadata but erases bound profile operations.
Discovery must agree with the actual Profile API refusal in the latter case.
`TestE2EProfilePasswordOnlyCapabilities` proves password change and fresh login
work when information reads are unavailable; aggregate Profile availability must
not hide that implemented operation.
`TestE2ESQLiteProfileStorageTimeout` holds a real competing SQLite writer before
admission and separately before the password transaction; it also exercises an
admin mutation. Require correct failure codes, unchanged credentials/generation,
continued use of the same valid proof after releasing the lock, and fresh login.

Qualify the full advertised admin lifecycle through the public API, including
login with returned generated passwords and denial of replaced passwords.
Duplicate creation and wrong-email reset must return a failure without a password
or account mutation. Add/replace grants, disable/re-enable and reset must invalidate
old bound Profile/Documents evidence. A no-op additive retry and a successful
SQLite realm health reload preserve it. Delete/recreate must not transfer a vault
by username. The SQLite admin lifecycle journey covers these boundaries; Caddy's
counterpart adds host stop/start persistence.

The separate authored UI must consume capability metadata, safe counts and error
codes before advertising full parity. Do not hand-edit embedded bundles or
fabricate credential arrays to satisfy an old client. Retain fallback behavior
for older servers and validate new bundles through the maintained asset workflow.
