# Configuration and Operations

## Enable persistence

Supply this field in the root `authcrunch.Config` JSON:

```json
{
  "state": {
    "directory": "/var/lib/authcrunch/runtime"
  }
}
```

In `authdb`, place it inside the existing `security` object. Any Go host can use
the same typed field, including an application with authorization policies and
no authentication portal or identity store. No container-specific setup is
required. Choose a stable absolute directory outside temporary/release paths.
The runtime creates a missing directory as 0700; an existing directory must
already be private. Storage files are 0600. Retain the service account's access
when moving or upgrading the application.

A text adapter encodes the one statement `directory /var/lib/authcrunch/runtime`
and calls `pkg/state/parser.NewStateConfigFromDirectives`; assign its result to
`Config.State`. Omit `State` to use memory only. Do not treat an empty block or
invalid path as a request for volatile fallback. Parsing and validation perform
no storage I/O. Creation/restoration happens in `NewServer`.

## What survives

| State | Behavior with persistence enabled |
| --- | --- |
| Runtime encryption key | Reuses `master.key`; encrypted records require this exact key |
| Generated access-token signing keys | Reuses generated KMS material by tag and algorithm family; old valid JWT signatures remain verifiable |
| Completed portal users | Restores unexpired browser sessions, canonical login identity, authentication time and verified methods |
| Direct OAuth without a portal | Restores completed opaque sessions without a new upstream exchange; checks the same origin and current ACL on every request |
| Portal refresh | Preserves families, absolute/idle expiry, rotations and spent-token replay detection |
| Downstream OIDC | Preserves browser sessions, consent, unredeemed/spent codes, opaque access grants and complete rotating refresh families |
| Local account security | Preserves the backend proof epoch only for the matching identity database; current account and credential versions are still checked |
| Logout/revocation | Successful direct OAuth, refresh and OIDC revocations remain effective after restart |

Existing user accounts, passwords, factors and API keys stay in their configured
identity databases. Explicit signing/encryption/TLS key files, environment secrets,
upstream OAuth client credentials, and provisioned OIDC application registrations
stay in their existing configuration/files. Keep those resources too. Runtime
state does not replace configuration persistence or generate missing external
credentials. Dedicated OIDC signing keys remain separate from portal access keys.

Pending OAuth exchanges, interactive OIDC authorization/consent pages, password
checkpoints, MFA/WebAuthn challenges, enrollment, pending registration and sandbox
transactions are not restored. Start those incomplete interactions again. Completed authentication
is retained. Upstream provider discovery/JWKS is fetched and validated normally;
this feature does not save upstream access/refresh tokens or add upstream renewal.

Restart never extends a session or token deadline. Offline time counts toward
expiry. Existing stateless access/ID tokens retain their previous expiration and
revocation semantics; durable sessions do not introduce immediate revocation of
all signed JWTs. Relying parties still own their own application sessions.

## Replacement and configuration changes

Use one live runtime per state directory on a local Unix filesystem supporting
advisory locks, atomic rename and directory fsync. Network filesystems and
active/active replicas are not supported. Windows opt-in persistence fails
closed until secure ACL and durable directory replacement support exists.

Stop routing to the old runtime, drain admitted requests, and call `Server.Close`
before constructing a replacement with a fresh configuration graph. Close does
not flush or delete state: successful mutations were already committed. Opening
a replacement while the old owner holds the directory returns an error. The
host owns listener availability during this handover. No transparent overlapping
hot-reload contract is provided.

An unchanged normalized security configuration restores state. A changed
configuration opened against the same directory creates a new session epoch,
conservatively requiring fresh login;
this includes unrelated settings, ordering, clients, policies or provider changes.
The storage path and diagnostic-only logging rules are excluded, so a coherent
directory move or logging-only change can retain sessions. Removing and later reintroducing a component
cannot revive its old sessions. Generated KMS keys persist independently across
configuration changes; explicit key-configuration changes still apply normally.

A directory records only configurations opened against it. Temporarily omitting
persistence or using another directory does not revoke credentials in a dormant
directory. Returning to it can restore its still-valid sessions; retaining old
directories is subject to the same deliberate recovery policy as backups.

On first enabling this feature, existing volatile sessions are not migrated.
Keep configured key files if previously issued JWTs must remain verifiable.
Deleting the entire state directory is a new installation and generates new
keys; do not use that as an ordinary restart or recovery procedure.

## Failure and backups

Corruption, unsafe permissions, missing committed records, a missing master key
or catalog, and competing owners cause errors. There is no volatile fallback.
A failed commit disables further state-dependent decisions in that runtime.
An interrupted commit marker retires its component's ambiguous snapshot on
reopen; this can require new login but cannot resurrect a possibly revoked token.
A response lost after a successful commit remains ambiguous to the client:
refresh retries still follow the existing strict replay rules.

Back up the entire state directory together with configuration, identity databases
and explicit key files while the host is drained/stopped. Restore a coherent set,
preserve permissions, and retain the matching master key. Do not merge individual
snapshots from different points in time or edit internal files. The key is stored
beside the ciphertext: encrypt and restrict complete backups as credentials.
This protects individual records from disclosure/tampering without their key;
it does not protect a stolen complete directory from decryption.

Identity-file-only rollback changes the proof epoch. Restoring an older complete
matching database and state backup can restore old authority; preventing an
operator/storage rollback requires an external monotonic authority. Restore
backups deliberately, with an explicit revocation/relogin plan when needed.

Snapshots are synchronous local files, not a database optimized for very large
session populations. Mutations encode each affected component's live snapshot;
individual record payloads are limited to 64 MiB. Existing component capacities
still apply. Do not increase capacity without measuring write latency and storage
size under the intended load.
