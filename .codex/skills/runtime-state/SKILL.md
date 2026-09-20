---
name: runtime-state
description: Maintain host-independent persistent runtime state, its reusable directory parser, encrypted records and generated keys, portal and portal-free OAuth sessions, refresh/OIDC replay history, local identity epochs, restart E2E tests, and embedding lifecycle contracts.
---

# Runtime State

## Configuration and ownership

`authcrunch.Config.State` (`state`) opts the root runtime into persistence with
`*state.Config`. Omission keeps the previous volatile behavior. A present empty
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
under the digest of the complete normalized security configuration, excluding
only the storage path. Every observed configuration transition within that
directory changes the epoch, including removal of a component; returning to an older configuration cannot
restore that component's old authority. Reordering or unrelated configuration
changes can conservatively require login. Stable generated KMS keys use separate
bindings and survive these session invalidations.

Root construction opens storage first and owns it last during reverse cleanup.
It injects KMS storage before constructing keys, restores local identity epochs,
then attaches session state before publication. `Server.Close` leaves durable
records intact. Each directory has one live owner: drain and close the old runtime
before opening its replacement. Opening new-before-closing-old must fail, not
fall back to memory. This is not a distributed store or overlapping reload API.

| Owner | Persistent integration |
| --- | --- |
| `pkg/kms` | `CryptoKeyStoreConfig.SetStateStore`; generated ES512/EdDSA/Ed25519 material is bound to generation tag and algorithm family; no process-global key sharing in persistent mode |
| `pkg/user` | `MarshalSession` / `UnmarshalSession` retain canonical identity and private login proof, rebuild derived maps, and exclude unfinished authenticator secrets |
| `pkg/authn/cache` | `SessionCache.ConfigurePersistentState` restores only unexpired completed users; Add/Delete commit synchronously |
| `pkg/authn/token_refresh` | `MemoryStore.ConfigurePersistentState` retains complete families, original authentication time/deadlines, current digest and every spent digest |
| `pkg/authz` | `Gatekeeper.ConfigurePersistentState` restores completed direct OAuth sessions; origin binding and current ACL evaluation remain mandatory |
| `pkg/identity`, `pkg/ids/local` | `ConfigurePersistentState` retains the backend epoch only for the exact recorded identity-file digest; transactions update that digest under the existing file lock |
| `pkg/oidc` | `Provider.ConfigurePersistentState` retains browser sessions, consent, codes and complete access/refresh families; issuance commits inside the current-identity transaction |
| `pkg/authn` | `Portal.ConfigurePersistentState` attaches its owned components and rejects HTTP/BasicAuth after storage failure |

Standalone consumers own the `state.Store`, choose trusted names and bindings,
configure components before exposing them, and close storage after draining all
consumers. A custom binding must cover issuer, providers, policies, clients,
identity and signing configuration. Directly configured standalone components
must also invalidate removed/reintroduced namespaces; root `NewServer` supplies
that configuration-epoch behavior automatically.

Preserve spent credentials until no descendant remains live. Restoring only
current refresh hashes or clearing replay history at restart is a security bug.
Validate restored sessions and grants in detached maps, then publish them together.
A failed restore must leave no partially restored authority, including through
standalone OAuth gatekeeper and OIDC provider APIs.
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
- `cmd/authdb/persistent_state_e2e_test.go`: built executable, real browser login,
  SIGKILL, same-address restart, identical JWKS and surviving old credentials.

```sh
make test TEST_DIR='./pkg/state/... ./pkg/user ./pkg/kms ./pkg/authn ./pkg/authn/cache ./pkg/authn/token_refresh ./pkg/authz ./pkg/identity ./pkg/oidc . ./cmd/authdb ./internal/tag' TEST='State|Store|RecordCodec|ConfigValidation|Persistent|SessionState|Capacity|TagCompliance|TestE2EAuthdb' COVERAGE_DIR='.coverage/runtime-state'
make ci-check
```

Use `testing-and-ci` for diagnostics and artifact interpretation. The default
full suite must retain volatile-mode replacement tests alongside persistent-mode
journeys; opt-in storage must not change existing omission semantics.
