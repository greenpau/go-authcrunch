# Managed portal refresh storage

Read this contract when selecting a borrowed refresh backend or changing root,
standalone portal, generation and recovery behavior. The
[SQLite owner](../../session-and-refresh-storage/SKILL.md) defines its physical
storage, migration and transaction rules. Ordinary `Store` injection into a
standalone `Manager` remains available without this portal lifecycle.

## Configuration and public boundary

`authn.TokenRefreshConfig.Store` (`store`) selects a named backend. Omission or
an empty typed value keeps the one portal-owned `MemoryStore`; a nonempty value
requires enabled refresh. The public
`pkg/authn/token_refresh/parser.NewTokenRefreshConfigFromDirectives` accepts the
singleton body statement `store NAME`, with one nonempty value. It still parses
all ordinary realm, origin, mount, transport and capacity settings. No host
module registry, block parser or placeholder expansion is supplied by this API.

For each root declaration:

1. Parse and validate the backend's configuration without opening it. For SQLite,
   use `sqlite/parser.NewSQLiteRefreshStorageConfigFromDirectives` or
   `sqlite.Config.Validate`; valid duration spellings normalize before hashing.
2. Derive `tokenrefresh.NewExternalStoreConfig(name, kind, maxSessions,
   maxRotations, normalizedConfig)` and add it to `Config.ExternalRefreshStores`.
   The descriptor contains only name, kind, lowercase SHA-256 config digest and
   file-wide limits. Its digest excludes the declaration name and live handles.
3. Construct the host-owned backend and pass it through
   `ServerOptions.RefreshStores map[string]tokenrefresh.ManagedStore` before
   `NewServerWithOptions`. Select its exact name on each participating portal.
   Selected roots require `Config.State`; portal limits must match the descriptor.

Pure root validation rejects malformed/duplicate declarations, missing selections,
disabled selected refresh and limit mismatches without opening keys or storage.
Every declaration, including an unused one, requires exactly one runtime binding;
extra, nil, unready or mismatched runtime entries fail before root acquisition.
Unused declarations are validated, never automatically selected or activated.
Descriptors participate in the normalized persistent configuration fingerprint.
Resolve host values once before freezing descriptors/factories. A selected name
that resolves to empty must fail in the host rather than silently select memory.

The core interfaces separate lifecycle from ordinary family operations:

- `ManagedStore.Metadata()` returns `StoreMetadata` with kind, normalized config
  digest and both limits; `CheckReady(context.Context)` checks initialized usable
  storage without writing a family or generation probe.
- `ManagedStore.ActivateGeneration(ctx, Generation)` returns one immutable borrowed
  `ActiveStore`. The view implements `ReplacementStore`, `SessionValidator` and
  `Generation()`; every operation checks its captured marker transactionally.
- `ExternalStoreBinding.Prepare(ctx)` captures exact metadata and the runtime in
  private immutable state, with cooperative bounded readiness. Replacing its
  exported inputs after preparation does not replace the captured handle.
  `Activate(ctx, generation)` checks the returned view's exact generation.

Metadata/readiness/generation accessor panics are contained and sanitized.
Operational activation and backend execution are not hidden by blanket recovery.
Bundled nil receivers return invalid metadata/zero generations or errors. Do not
introduce reflection to inspect arbitrary plugin pointers; a third-party plugin
that deliberately supplies plausible nil-receiver metadata violates this contract.

## Standalone publication and ownership

Standalone callers set `PortalParameters.RefreshStore` to the exact selected
`ExternalStoreBinding`. `NewPortal` validates the binding, realm capabilities and
configuration, but returns a pending portal with no fallback store or manager.
Call `ConfigurePersistentState` before exposing it. Until that succeeds, HTTP
and explicit-mount entry points return no-store 503 with no credentials; Basic
and API-key authentication stop before backend work; `GetOIDCProvider` returns
nil. Internal issuance cannot interpret a nil manager as access-only permission.

Persistence setup restores completed sessions and OP state first, obtains the
private namespace/generation, activates the backend view, constructs exactly one
manager and publishes readiness last. A setup failure latches failure; discard
that portal and construct a fresh instance. Root publication occurs only after
all portals and gatekeepers finish their ordinary persistence setup.

Handles and activated views stay caller-owned. Root/portal success, Close and
failed construction never close them or write borrowed families into an owned
memory snapshot. The host removes routes, drains every consumer, closes the root,
then closes each owned backend once. An activated view is not an additional
resource to close. Close retains committed families and complete spent history.
Unselected portals retain their existing memory-store ownership and snapshots.

## Namespace and changing configuration epoch

A private random namespace identifies the retained root state directory. A
separate private random generation is bound to the caller's durable changing
whole-configuration epoch. Both identities use 32 random bytes encoded as
lowercase hexadecimal, never public URL/provider/session values. Load/save initialization is serialized within the exclusively owned state
store. Each record commits durably on its own; initialization is not one
multi-record transaction. Backend activation does not run under that
initialization lock.

Root already obtains its epoch after full config normalization, key loading and
portal/policy construction. It includes selected descriptors and actual loaded
trust, including policy-only verifiers. Equivalent public authority can preserve
the epoch; changing a key at an unchanged filename retires it. Do not move this
fingerprint earlier or reread key files to approximate the loaded snapshot.

Standalone callers must persist an independently changing whole-configuration
epoch covering all observed policy, identity and trust transitions, including
periods when the portal or selected store is completely omitted. A reusable
deterministic config digest is insufficient. Root omission/reintroduction is
observed only while the same `Config.State` directory remains enabled during
the omitted phase. Turning persistence off or using a different directory
cannot record a transition in the dormant directory. Private generation records
do not infer changes the caller never records.

Activating a new generation atomically retires complete old families and spent
history for that namespace, including families belonging to a removed portal.
Other namespaces survive; capacity and ID/digest uniqueness remain file-wide.
Old views cannot create, rotate, look up or revoke through a retired marker.
Restoring an older configuration does not revive the retired generation.

Several store activations are not a cross-database transaction. If a first
retirement succeeds and a later activation fails, root publication fails and the
first retirement remains effective. Never restore old authority to simulate
rollback. The root state lock owns deployment exclusion; generation markers do
not create active/active availability or distributed fencing.

Losing the namespace/state while retaining SQLite can leave old rows occupying
file capacity. Opening a new namespace does not delete another namespace's
families. Use deliberate offline reconciliation or whole-family expiry; do not
promise automatic deletion, revive backups or reset markers during ordinary
restart. SQLite does not persist local identity epochs, signing keys, completed
portal sessions or downstream OP grants by itself.

## Commit uncertainty and recovery

`tokenrefresh.ErrCommitUncertain` means attempted or completed commit cannot safely
publish the staged credentials. The SQLite error is an alias of this sentinel.
Check it before joined denial, cancellation or ordinary outage errors: manager
renewal must not perform an extra denial revocation, and refresh/native/provider,
form and cross-device completion use unavailable responses without credentials.
No new wire field or success shape is introduced.

Cancellation rejected before driver COMMIT is rollback-safe. Actual COMMIT
failure quarantines its handle; a successful COMMIT followed by cancellation or
late expiry can still withhold credentials without poisoning unrelated families.
Do not automatically re-exchange a refresh token or look up its uncertain state.
Reconcile storage, replace unhealthy handles and require independent fresh login.
Bounded cleanup after a returned result may revoke only the newly undelivered
family; already replaced families cannot be resurrected.

Fresh native authentication has no previous browser family to replace. A concrete
rejected-COMMIT rollback can leave the old family occupying a capacity-one store;
fresh login then needs spare capacity or explicit reconciliation/logout/expiry.
It does not prove server-side retirement. Fresh browser login may replace a
presented matching family only after independent authentication. Client pending
and blocked-state rules remain owned by
[refresh transports](../../refresh-token-transports/SKILL.md).

## Acceptance map

These tests define required coverage; a source map is not a test-run result.

| Boundary | Focused tests |
| --- | --- |
| Immutable exact binding, nil/panic handling, no borrowed close, scope and error precedence | `pkg/authn/token_refresh/managed_test.go` |
| Public single-word selection, disabled/duplicate/malformed rejection and native round trip | `pkg/authn/token_refresh/parser/managed_test.go` |
| Pending/failed portal admission, OP/direct guards, one manager, no duplicate snapshot, concurrent identity initialization | `pkg/authn/token_refresh_managed_test.go` |
| Joined uncertainty through provider/cross-device issuance and access-only form/callback replacement, with ordinary-invalid controls | `TestManagedRefreshHTTPUncertaintyPrecedence`, `TestManagedRefreshAccessOnlyReplacementUncertainty`, `TestManagedRefreshCallbackReplacementUncertainty` |
| Real TLS/SQLite standalone continuity and caller-owned epoch through complete omission | `TestE2EManagedRefreshStandaloneCallerEpoch` |
| Pure root selection and runtime readiness before resource acquisition | `server_refresh_store_test.go` |
| Real root TLS, selected signing/policy, same-config replacement, replay/logout, full removal, loaded trust, partial activation and actual form COMMIT failure | `server_refresh_store_e2e_test.go` |
| Transactional migration, exact maximum legacy record, old-reader barrier, immutable generation, global capacity and real driver uncertainty | SQLite `migration_test.go`, `managed_test.go` and `store_test.go` |

Root TLS fixtures replace runtime/SQLite handles and reopen identity state while
retaining one TLS listener; do not describe them as OS-process restarts. Separate
SQLite process and embedding-host executable tests establish their own process
boundaries. Preserve ordinary memory, provider/connected-account, cross-device,
completion cleanup and OP regressions, all-severity diagnostics, tag checks,
CGO-disabled checks and the HTTP contract/quality gates. Use actual independent
SQLite transactions with deferred constraints or commit-hook rejection for COMMIT
tests; ordinary reader/writer contention must fail safely at admission without
quarantining handles. Injected joined errors test classification
only. Preserve every initial failure and guard outcome in validation evidence.
