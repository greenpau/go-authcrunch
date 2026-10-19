# OAuth login transaction storage

## Public configuration and injection

`oauth.Config.LoginStore` is an optional `*oauth.LoginStoreConfig` with `Name`
and `Namespace`. Omission uses a private `MemoryLoginStore`; a present empty
configuration fails. Both identifiers must be nonblank, control-free UTF-8,
without surrounding whitespace, at most 128 bytes. The owning provider parser
accepts exactly one complete directive:

```text
login store shared namespace production
```

Both `pkg/idp/oauth/parser` and the adapting `pkg/idp/parser` preserve this setting.
The serialized provider setting is `login_store: {name: shared, namespace: production}`.
This is a reference to a runtime backend, not backend connection configuration.
Parsing and declarative validation never initialize the backend.

Choose the matching construction boundary:

- `oauth.NewIdentityProviderWithLoginStore(config, logger, store)` for direct
  provider composition; configuration and the non-nil backend must both exist.
- `idp.NewIdentityProviderWithLoginStores(config, logger, stores)` for shared
  dispatch, resolving `config.Params.login_store.name` from the supplied map.
- `authcrunch.NewServerWithOptions(config, logger, authcrunch.ServerOptions{
  OAuthLoginStores: stores})` for root portal and direct-policy composition.

The established constructors remain compatible for omitted storage. They fail
closed for an unresolved named store. Runtime clients are excluded from JSON,
XML and YAML; inject fresh bindings after decoding declarative configuration.
The host owns injected backends, including construction failure and shutdown.
Drain and close all consuming runtimes before closing a backend. Closing one
provider/root must not close a borrowed client or purge another replica's
transactions. Never mutate config/bindings while constructing or serving.

The effective namespace combines the configured deployment namespace with a
SHA-256 digest of normalized provider configuration. Compatible replicas must
use identical provider/trust settings and store reference names. Configuration
changes isolate outstanding logins conservatively. Adapters receive the complete
namespace; do not reconstruct it or share records across namespaces. Treat
backend clients as trusted authentication infrastructure and never pass a typed
nil implementation through an interface.

## Store semantics

`oauth.LoginStore` has `Create`, `Claim`, `Get`, `Complete` and `Cancel` methods,
all accepting `context.Context` and an explicit namespace. `LoginTransaction`
contains the state, nonce/nonce policy, PKCE verifier, exact `LoginBinding`,
return URL, creation/expiry Unix seconds and an initially empty claim ID.
Browser binding is SHA-256 of the protected per-browser SessionID, not the state.
No transaction is accepted from an HTTP client as server evidence.

- Create a complete, bounded transaction before issuing the authorization redirect.
  Never overwrite a live state. The callback lifetime is five minutes.
- Claim must atomically check namespace/state, expiry, exact browser/callback,
  and absence of a claim; install the supplied unpredictable claim ID and return
  the coherent record. Rejected bindings must preserve the legitimate login.
- Get returns an independent unexpired snapshot. Token validation reads the
  captured nonce policy, preserving disabled-nonce compatibility without
  weakening issuer, audience, signature, PKCE or browser checks.
- Complete rechecks expiry and the exact claim and atomically consumes it before
  the provider returns successful identity evidence. Cancellation during an
  exchange must prevent completion. Errors also attempt bounded cleanup.
- Cancel removes only matching pending/claimed evidence. Missing, expired or
  mismatched transactions return false, nil; backend failure remains an error.

Return `ErrLoginInvalid` for invalid/replayed transactions and `ErrLoginCapacity`
for capacity refusal. Backend failures must never return tentative data or
success. The provider redacts those failures to `ErrLoginUnavailable`; the
portal returns HTML 503 with no authenticated response evidence. Invalid
callbacks retain 401. A failed claim that made no mutation may be retried;
an ambiguous or already committed claim requires a fresh login. Never reset
claimed state after a timeout or worker crash. Complete uses an independent
five-second cleanup deadline, including after request cancellation. The legacy
bool cancellation API cannot confirm remote success; new consumers should use
`CancelLoginContext` and handle its error.

Operations require linearizable decisions, not independent Get/Set/Delete calls.
Acknowledged claims, cancellation and consumption must not reappear after
supported failover. A backend with expiring unfenced locks or asynchronous
replication does not automatically satisfy this contract. Agree on backend
clock semantics and synchronize replica/backend clocks. Validation permits a
creation timestamp at most 30 seconds ahead for small clock differences; the
stored expiry deadline has no grace period and the recorded lifetime remains
at most five minutes. Expiry is checked during admission and completion, not
merely by a sweeper. Protect backend transport, stored PKCE evidence and backups.
Do not log raw records or backend errors carrying connection secrets.

## SQLite reference

`plugins/oauth-login-storage/sqlite.New(ctx, *Config)` implements the contract
using independent clients of one private local database. Its parser is
`plugins/oauth-login-storage/sqlite/parser.NewSQLiteOAuthLoginStoreConfigFromDirectives`.
Body statements are `path PATH`, optional `timeout DURATION` (default `1s`,
range `1ms`–`30s`), and `capacity COUNT` (default 10000, range 1–100000).
Use `cfgutil.EncodeArgs`; duplicates, multiline/unknown settings and empty values
fail. All clients of a database must agree on its capacity, shared across namespaces.

The parent directory must already be private. The helper enforces private files,
exact application/schema identity, local locking/sync and transaction commits;
claims survive closing/reopening independent clients. Reads and writes acquire
exclusive SQLite transactions before their callbacks, with bounded admission
retries. This avoids commit-time lock upgrades and read queries failing with BUSY
under competing callbacks. Operations serialize across clients; never replay a
mutation after an uncertain commit. The database contains
plaintext private authentication evidence. Protect the directory and backups.
Persisted records are bounded to 64 KiB. Creation reserves the largest possible
JSON-encoded claim before accepting a pending record, so claiming cannot make
an accepted transaction unreadable. Preserve this invariant when changing fields
or encoding; test both the accepted boundary and rejection before a redirect.
This backend is a local reference: do not put the file on a network filesystem,
replicate file snapshots between nodes, or advertise it as a multi-host service.
Backend timeout covers context-aware database work; filesystem/commit operations
can outlast it. The host closes each client after its consumers drain.

## Support boundary and validation

Sharing these transactions enables portal OAuth initiation on one runtime and
callback on another. It does not share portal session caches, MFA/sandbox state,
refresh families, direct-policy pending/opaque sessions, downstream OIDC,
cross-device/connection transactions or canonical identity databases. Default
external-account attachments are provider-private memory stores; stable local
identities require a separately supported shared authority. Compatible JWT
signing/verification keys are also required. `pkg/state` remains single-owner
restart persistence and must not be unlocked or repurposed for active/active use.

Maintain the store unit contracts in `state_test.go`, nonce tests, parser
round trips, and SQLite independent-client claim/cancellation/reopen coverage.
`server_oauth_login_storage_e2e_test.go` uses two independent roots and SQLite
connections at one TLS origin with real upstream nonce/PKCE code exchange.
It covers both replica directions, small clock differences, browser and namespace/trust isolation,
concurrent duplicate callbacks, ordinary JWT authorization on either replica,
backend failures (including lost acknowledgements) and peer shutdown. The SQLite external-module fixture reruns
that public-only consumer. The direct-policy injection fixture proves backend
selection without claiming that policy-owned state is shared.

```sh
make test TEST_DIR='./pkg/idp/... ./plugins/oauth-login-storage/sqlite/... ./internal/tag .' TEST='OAuth|Oauth|LoginStore|LoginTransaction|SQLiteLogin|TagCompliance|StructTagCompliance' COVERAGE_DIR='.coverage/oauth-login'
make ci-check
```

Update the OAuth HTTP YAML and reviewed source inventory when changing callback
completion, error statuses, configuration or lifecycle. A host integration must
separately test its actual module/parser, two processes and chosen backend.
