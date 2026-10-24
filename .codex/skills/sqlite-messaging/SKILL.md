---
name: sqlite-messaging
description: Maintain the pure-Go SQLite notification outbox, public parser, runtime messaging-provider injection, worker leases, bounded SMTP delivery, and registration notification E2E tests. Excludes registration enrollment state.
---

# SQLite Messaging

`plugins/messaging/sqlite` implements `messaging.Provider` with kind `sqlite`.
Success from Send means durable local queue acceptance. This plugin does not
send email, run a worker, or guarantee final delivery.

## Provisioning and integration

Use `parser.NewSQLiteMessagingConfigFromDirectives([]string)`: required `name`
and absolute `path`, optional `timeout` (default 1s; 1ms through 30s). Each setting
occurs once with one value. Parsing has no filesystem effects. `New(ctx, config)`
snapshots settings and opens storage. Read the
[SQLite file contract](../plugin-development/references/sqlite-backends.md)
for private local POSIX files, errors, commit uncertainty and caller-owned Close.
The database is plaintext, including notification bodies and confirmation codes.

Bind an open queue using `messaging.Config.AddProvider(name, outbox)`, then call
Validate before publishing. Bindings are runtime-only, survive Validate, and are
excluded from JSON/XML/YAML. Duplicate names and reserved built-in kinds fail.
`messaging.Config.Validate` reparses nonempty raw declarations as the authority;
when raw declarations are absent it preserves and validates typed native email
and file providers instead. Duplicate names across built-in kinds and runtime
injections fail; unsuccessful validation retains the previous published lists.
`Outbox.CheckReady(ctx)` checks the opened queue through a bounded empty read
transaction without consuming messages or altering leases. Configuration-only
Validate remains pure; workflow/root hosts use readiness before publication.
The factory remains email/file-only: hosts must reconstruct injections on reload.
AsMap returns only name/kind. Configured names select logical queues; the file's
capacity is shared across those queues. Drain producers/workers before Close.

Registration's LocalUserRegistryProvider.Notify selects generic providers through
ExtractProvider, retaining the built-in email/file paths. Rendering stays with
registry. Its current body is quoted-printable HTML; a delivery adapter must
preserve that encoding contract or explicitly decode/re-encode it. The outbox
preserves body bytes and supplies no sender or MIME headers. A host worker owns
sender configuration and its independent transport credentials. Never persist
SendInput.Credentials in queue records; non-nil credentials are rejected.

## Queue and worker contract

Subjects are 1–512 bytes, trimmed UTF-8 without controls. Bodies are nonempty
UTF-8 up to 60,000 bytes, without NUL. Recipients are 1–16 bare mail addresses,
each at most 320 bytes. Encoded payloads are at most 65,536 bytes. Admission at
1,000 outstanding records fails without deleting work. Inputs and returned
messages are detached snapshots. SendContext honors caller cancellation and the
configured operation deadline; legacy Send uses the latter with Background.

Claim atomically leases the oldest available message in this queue for one
minute. Message carries ID, subject, body, recipients, creation time and Lease.
The worker must retain the lease privately; serialization intentionally omits it.
`Message.LeaseExpiresAt` is the exact committed lease expiry as Unix seconds;
like Lease, it is runtime-only and excluded from JSON/XML/YAML. A slow claim
may return with less than one minute remaining. Derive the delivery deadline
from this timestamp and leave a bounded acknowledgement reserve.
Only the current unexpired lease can Acknowledge (delete) or Release (retry).
Wrong queue, wrong ID, expired/stale lease, and repeated acknowledgement fail.
Leases survive restart; expiry makes unfinished work available again. Independent
handles serialize claims, so one message has one current owner.
The outbox acquires an exclusive SQLite transaction lock before each operation.
Ordinary readers and competing workers wait at admission under the operation
deadline, before message or lease mutation. This avoids commit-time lock upgrades
quarantining a queue during normal concurrent delivery. Admission timeout leaves
the handle usable; genuine COMMIT failures still require drain/reconciliation.

For SMTP delivery use `EmailProvider.SendContext(ctx, input)` with a deadline
inside the lease. Cancellation closes the actual socket through TCP/TLS dialing,
greeting, commands, DATA and QUIT; it does not abandon a send goroutine. Ordinary
`Send` retains compatibility through a background context and transport defaults.
The existing SMTP/SMTPS configuration and certificate verification remain in
force. Delivery preserves registration's quoted-printable HTML bytes and MIME
headers. Transport credentials belong only to this delivery call. A non-passwordless
transport rejects missing credentials before dialing; it never silently falls
back to anonymous delivery.

Workers send first, then acknowledge within the lease. A crash after delivery
and before acknowledgement can duplicate delivery: use downstream deduplication
where available. There is no lease renewal, retry schedule, dead-letter worker,
or exactly-once delivery claim. Hosts own those policies. ErrEmpty means no
currently available work, not necessarily an empty database. ErrFull requires
worker progress. An uncertain Send may have committed; reconcile before retrying.
A transport error or cancellation after DATA can occur after remote
acceptance; it does not prove that delivery failed. Use independent bounded
acknowledgement cleanup after success. Failed work can remain leased until expiry
to avoid immediate blind resends. FileProvider performs synchronous filesystem
writes and does not provide the SMTP cancellation contract.

## Acceptance

Root hosts can preflight declared provider names without opening an outbox.
`LocalUserRegistryProvider.SetMessaging` only binds a pointer. Bind real queues
before root construction; root validation rebinds registries to the final
messaging config and runtime copies retain that pointer. No unbound provider
proxy is needed. Queue persistence is independent of root authentication state;
notification-only backend changes do not require a new authentication binding.

Run unit/parser and public consumer tests, including the external-module driver:

```
make test TEST_DIR='./plugins/messaging/sqlite/... ./pkg/messaging ./pkg/registry ./internal/tag'
```

The consumer uses parser + serialized config + actual registration templates,
queues confirmation and admin notices, closes the producer, reopens a worker,
checks recipient isolation and HTML escaping, and acknowledges messages. Unit
coverage races two real SQLite handles, expires leases, checks stale workers,
queue isolation, exact committed expiry, lease/expiry serialization exclusion,
capacity, cancellation, malformed input and backend failure. Messaging consumer
E2E restores native typed transport config, sends real SMTP messages with MIME
and recipient checks, cancels stalled greetings/TLS/DATA/QUIT and checks socket
closure, and rejects untrusted SMTP TLS certificates.
Hold an independent SQLite reader to verify send/claim/acknowledge/release time
out before mutation and retain usable handles. Public consumer coverage drains
same-name and distinct-name queues through independent workers, checks every
acknowledgement, and reuses both live handles after draining.
Also run units and public consumer E2E with CGO_ENABLED=0; exclude the external
module driver because its test harness intentionally enables Go's race detector.
