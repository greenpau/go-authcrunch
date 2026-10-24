---
name: runtime-state
description: Maintain host-independent persistent runtime state, its reusable directory parser, encrypted records and generated keys, portal and portal-free OAuth sessions, refresh/OIDC replay history, local identity epochs, restart E2E tests, and embedding lifecycle contracts.
---

# Runtime State

## Configuration and ownership

`authcrunch.Config.State` (`state`) opts the root runtime into persistence with
`*state.Config`. Omission keeps the previous volatile behavior unless a portal
selects a managed refresh store, which requires root state. A present empty
configuration is invalid. The only setting is `Directory` (`directory`), an
absolute non-root path. Validation normalizes it without filesystem writes.

`pkg/state/parser.NewStateConfigFromDirectives(statements)` parses exactly one
encoded `directory PATH` body statement. Hosts own traversal, placeholders and
`cfgutil.EncodeArgs`; the public parser owns grammar and typed validation.
Empty blocks, duplicates, unknown settings and extra arguments fail. Apply the
result to `Config.State` before `NewServer`. There are no Docker, Caddy, HTTP,
environment-variable or global-directory dependencies.

Read [configuration and operations](references/configuration-and-operations.md)
for retained state, restart guarantees, backups and deployment limits. Hosts
adapt their configuration syntax to the public parser and coordinate runtime
ownership. Do not change or run tooling in sibling repositories.

## Storage invariants

`pkg/state/{store,catalog,codec}.go` owns `Store` and `Record`. `state.Open`
creates private 0700 local storage, holds an exclusive advisory `owner.lock`,
and reuses a private 0600 AES-256 key in `master.key`. Record filenames are
SHA-256 hashes of trusted component names. AES-GCM authenticates the envelope
version, binding and payload with the filename as associated data. A separately
authenticated catalog detects missing committed records. Reject corruption,
missing key/catalog, unsafe permissions, symlinks, and concurrent owners.

Use local Unix filesystems with reliable locks, atomic replacement and directory
sync. Windows persistence fails closed: secure ACL and durable directory support
are not implemented. Do not weaken commits to make an unsupported platform pass.
When creating a state directory hierarchy, sync the containing directories too;
syncing records alone does not persist newly created directory entries.

Save a complete private snapshot under the component mutex. Commit an intent
marker, synced temporary record, atomic rename and directory sync; remove/sync
the marker before acknowledging success. An interrupted marked record is retired
on reopen, sacrificing its sessions rather than resurrecting a possible
revocation. Failed disk commits poison the store. No failed write may publish a
credential, redirect, successful logout or subsequent state-backed cached authentication.
Successful mutations are durable before Close; Close only releases resources.

Never accept persistence DTOs from HTTP. `Record.Encode/Decode` uses gob to retain
server-only proof fields whose public JSON/XML/YAML tags remain `-`. The encrypted
envelope is format version 1; evolving DTO/security semantics requires a reviewed
migration or explicit invalidation. Bounded snapshots reject oversized records.
Keep plaintext snapshots, keys and credentials out of errors and logs.

Transactional consumers can call `Record.PrepareEncode` before committing a
candidate and then `Save` the prepared bytes. `state.ErrCapacity` from preparation
leaves the record and store unchanged: reject or undo the candidate without
discarding existing authority. Ordinary `Encode`/`Save` retain fail-closed behavior
for oversized mutations. This is an encoded-payload limit, not a hard bound on
gob's internal staging allocation; retain component input and count limits.
Count and request-size limits do not bound the aggregate snapshot. All session
admissions and rotations must prepare their candidate and undo it on capacity
refusal. Preserve previous sessions, replacement targets, and complete replay
history. A full component must not disable unrelated persistent consumers.
Deletion and terminal revocation must remain possible at the record limit.

## Runtime integration

`server_persistent_state.go` binds sessions to a random configuration epoch stored
under the digest of the normalized security configuration, excluding the storage
path and diagnostic-only `Logging` settings. Logging rule additions, changes,
and removal must preserve valid persisted sessions; `server_logging_e2e_test.go`
exercises that invariant through real TLS restarts. Every other observed configuration transition within that
directory changes the epoch, including removal of a component; returning to an older configuration cannot
restore that component's old authority. Reordering or unrelated configuration
changes can conservatively require login. Stable generated KMS keys use separate
bindings and survive these session invalidations.

Strict access profiles additionally bind public RSA trust captured from every
portal and policy-only verifier, plus the current signer role. Fingerprints use
loaded key snapshots, never a second file read. A key change at an unchanged
filename retires the epoch; equivalent PEM encoding of identical authority does
not. No-profile roots preserve their existing binding representation. See
[selected signing](../cryptographic-signing/references/selected-access-signing.md)
for descriptor and ownership rules.

Root construction opens storage first and owns it last during reverse cleanup.
It injects KMS storage before constructing keys, restores local identity epochs,
then attaches session state before publication. `Server.Close` leaves durable
records intact. Each directory has one live owner: drain and close the old runtime
before opening its replacement. Opening new-before-closing-old must fail, not
fall back to memory. This is not a distributed store or overlapping reload API.
The separate [OAuth login storage contract](../oauth-identity-provider/references/login-storage.md)
can share pending upstream exchanges through a host-injected backend. It does
not change this directory's ownership or share the other runtime components.

| Owner | Persistent integration |
| --- | --- |
| `pkg/kms` | `CryptoKeyStoreConfig.SetStateStore`; generated ES512/EdDSA/Ed25519 material is bound to generation tag and algorithm family; no process-global key sharing in persistent mode |
| `pkg/user` | `MarshalSession` / `UnmarshalSession` retain canonical identity and private login proof, rebuild derived maps, and exclude unfinished authenticator secrets |
| `pkg/authn/cache` | `SessionCache.ConfigurePersistentState` restores only unexpired completed users; Add/Delete commit synchronously |
| `pkg/authn/token_refresh` | Without a named store, `MemoryStore.ConfigurePersistentState` retains complete families, original authentication time/deadlines, current digest and every spent digest |
| `pkg/authn` managed refresh | `Portal.ConfigurePersistentState` records a private namespace and generation, then activates the borrowed view; families and spent digests remain exclusively in the selected backend |
| `pkg/authz` | `Gatekeeper.ConfigurePersistentState` restores completed direct OAuth sessions; origin binding and current ACL evaluation remain mandatory |
| `pkg/identity`, `pkg/ids/local` | `ConfigurePersistentState` retains the backend epoch only for the exact recorded identity-file digest; transactions update that digest under the existing file lock |
| `pkg/oidc` | `Provider.ConfigurePersistentState` retains browser sessions, consent, codes and complete access/refresh families; issuance commits inside the current-identity transaction |
| `pkg/authn` | `Portal.ConfigurePersistentState` attaches its owned components and rejects HTTP/BasicAuth after storage failure |

Standalone consumers own the `state.Store`, choose trusted names and bindings,
configure components before exposing them, and close storage after draining all
consumers. A custom binding must cover issuer, providers, policies, clients,
identity and signing configuration. Directly configured standalone components
must also invalidate removed/reintroduced namespaces; root `NewServer` supplies
that configuration-epoch behavior automatically. For selected managed refresh,
the binding must be a durably changing whole-configuration epoch covering loaded
trust material and every transition, including complete portal/store omission.
A reusable deterministic configuration digest is insufficient. Keep the same state
directory enabled throughout an omitted phase; private generation records cannot
observe a transition while their state is disabled or elsewhere. Read the
[managed refresh contract](../refresh-token-implementation/references/managed-storage.md)
for pending publication, borrowed ownership and partial activation failures.

Root state and a managed refresh database are separate durable resources. Root
construction does not atomically commit across databases: if one generation is
retired before a later activation fails, that retirement remains effective. The
failed root is never published. Closing it does not close borrowed stores or
restore earlier generations, and it does not duplicate managed families into a
`portal-refresh` snapshot.

External identity-store, provider and registration descriptors participate in root
configuration binding through their normalized backend digests. Runtime handles
remain excluded. Hosts regenerate descriptors after configuration resolution;
changing an enrollment destination or policy must not silently retain prior
session authority. Independent pending-enrollment persistence still belongs to
the workflow, with its own origin/mount binding and reconciliation contract.

External identity provider descriptors also enter the normalized root binding.
Their digests describe configuration, not live attachment identity. A ticket
provider can restore pending SQLite tickets after replacement while losing its
implicit memory account IDs; root persistence does not make those IDs durable.
The [ticket provider owner](../sqlite-ticket-provider/SKILL.md) defines this boundary.

Preserve spent credentials until no descendant remains live. Restoring only
current refresh hashes or clearing replay history at restart is a security bug.
Validate restored sessions and grants in detached maps, then publish them together.
A failed restore must leave no partially restored authority, including through
standalone OAuth gatekeeper and OIDC provider APIs.

Refresh gob snapshots retain typed provider source, provider trust digest and
bounded captured claim bytes as well as complete replay history. Restore rejects
unknown sources, mixed local/provider evidence, invalid JSON, unsupported kinds
and oversized snapshots before publishing detached state. Current provider
trust and canonical claim checks still run at renewal. Keep provider configuration
in custom portal bindings; persistence does not turn captured claims into live
upstream revalidation. Provider cached users retain no local password/profile authority. Their separate
server-only `ExternalIdentity` proof binds the attached local ID, epoch and
credential generation. Durable external sessions require a named file-backed
attachment; omitted attachments are provider-lifetime memory databases and lose
their identities on provider recreation. Keep persistent OAuth consumer fixtures
explicitly attached, and retain the real restart test that rejects implicit-memory
sessions. Use [local-identity-database](../local-identity-database/SKILL.md) to
maintain external account provisioning and connection transactions.
`TestPersistentProviderEvidenceRejection` and the provider portal TLS restart
journey cover these boundaries alongside existing local identity epochs.
The portal response guard strips staged headers/cookies when a later composite
login commit fails; preserve this even when the earlier session write succeeded.
Check component health as well as the backing store: a session serialization
failure can poison the cache without a failed disk write. Both HTTP and BasicAuth
must reject that portal state.
OIDC HTTP responses are buffered: a failed commit must discard success headers,
body, redirects and cookies. Hosts composing OIDC logout/login must use
`LogoutWithError` / `ClearSessionWithError` and stop on error. Existing void
methods emit an unavailable response for compatibility.
Recoverable OIDC capacity errors also require composite login cleanup: remove
new portal sessions, revoke undelivered refresh families with a bounded context
independent of request cancellation, and restore pre-credential response headers.
Do not undo earlier completed revocations. Consult the OIDC skill for candidate
rollback and revocation-size invariants.

Injected identity-store descriptors (`Config.ExternalIdentityStores`) participate
in the normalized root fingerprint, including a digest of the backend's resolved
configuration. Their runtime handles remain borrowed and are never configured
with root state. A fresh SQLite handle retains its fresh proof epoch, so restored
refresh sessions cannot renew old identity evidence. Account-file durability does
not imply continuity of authentication proofs. See the
[SQLite identity-store contract](../sqlite-identity-store/SKILL.md) for supported
consumers and root construction/ownership validation.

Local identity files remain the source of current account status and credential
versions. Persist their epoch after an atomic identity write and before granting
authority from current identity. Keep persistence attached to transaction targets,
including self-service mutations; `Database.Copy` must not modify the source's
state record. File mismatch chooses a fresh epoch, never trusts serialized
`loaded_at` as authentication evidence. During attachment, adopt the identity
snapshot read under the file lock before binding its digest to an epoch; the
constructor's earlier in-memory snapshot may already be stale.
Rolling back both the identity file and
its entire matching state backup requires external rollback protection.

## Validation

Keep parser tests external with an executable constructor example. Use the
parser in root TLS consumers and the actual `authdb` executable fixture.

- `pkg/state/*_test.go`: configuration, private authenticated storage, locking,
  corruption/missing files, independent snapshots, interrupted writes, process
  exit without Close, nested directory creation, partial first initialization,
  and failure poisoning.
- `pkg/kms/persistent_state_test.go`: all generated algorithms, old JWT verification
  after reopen, and independent-directory key isolation.
- `pkg/user/session_state_test.go`, `pkg/authn/cache/session_state_test.go`:
  private-proof fidelity, derived authorization fields, expiry/deletion/failure.
- `pkg/authn/token_refresh/persistent_test.go`, `pkg/oidc/persistent_state_test.go`:
  rotation, complete spent history, replay revocation, expiry, commit failure,
  and capacity refusal that preserves existing credentials and unrelated records.
- `pkg/authn/oidc_completion_e2e_test.go`: real browser login rejects recoverable
  OIDC capacity refusal without delivering credentials or leaking session slots;
  healthy retry succeeds at the configured refresh capacity.
- `pkg/authz/oauth_test.go`, `pkg/oidc/persistent_state_test.go`: atomic restoration
  rejection through unit and real TLS consumers.
- `pkg/identity/persistent_state_test.go`: unchanged-file continuity, durable
  security-version revocation, self-service transactions, identity-file rollback,
  and file replacement between database construction and persistence attachment.
- `server_persistent_state_e2e_test.go`: TLS portal-free OAuth, lost pending login,
  ACL checks, logout, config serialization and removal/reintroduction; portal
  session/profile, native refresh, OIDC consent/code/access/refresh and replay;
  interrupted commit recovery, failed final login commits, and failed construction
  releasing exclusive ownership.
- `server_refresh_store_e2e_test.go`: real TLS managed-refresh continuity, replay
  and logout after replacement, whole-component removal with state retained,
  loaded trust changes, partial multi-store activation and actual COMMIT failure.
- `pkg/authn/token_refresh_managed_e2e_test.go`: standalone caller-owned durable
  epochs across removal/reintroduction; root replacement is not an OS restart.
- `cmd/authdb/persistent_state_e2e_test.go`: built executable, real browser login,
  SIGKILL, same-address restart, identical JWKS and surviving old credentials.

```sh
make test TEST_DIR='./pkg/state/... ./pkg/user ./pkg/kms ./pkg/authn ./pkg/authn/cache ./pkg/authn/token_refresh ./pkg/authz ./pkg/identity ./pkg/oidc . ./cmd/authdb ./internal/tag' TEST='State|Store|RecordCodec|ConfigValidation|Persistent|SessionState|Capacity|TagCompliance|TestE2EAuthdb' COVERAGE_DIR='.coverage/runtime-state'
make ci-check
```

The [testing contract](../testing-and-ci/SKILL.md) defines diagnostics and artifact
interpretation. The default
full suite must retain volatile-mode replacement tests alongside persistent-mode
journeys; opt-in storage must not change existing omission semantics.
