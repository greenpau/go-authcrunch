# Compatible portal-cookie renewal

The existing [transport contract](../../refresh-token-transports/SKILL.md) and
[native client](../../../../pkg/authn/ui/core/js/refresh.js) own the wire protocol
and journal format. This reference specifies how a generated app cooperates with
them. Read the implementation at the deployed version before adopting the format.

## Exact shared namespace and browser requests

Given a validated canonical portal mount, derive:

```ts
const base = portalBase === '/' ? '' : portalBase;
const coordinationKey = 'authcrunch-session:' + base;
```

Use this exact key for both `navigator.locks.request` and the localStorage journal.
Web Locks/storage are already origin-scoped. Do not add an app ID, tenant suffix,
version suffix, full origin or private namespace: native portal tabs would rotate
outside that lock. All same-origin apps using the portal must participate. Use
in-process single-flight as well so local callers share an outcome.

The native-compatible journal contains only:

```ts
type PortalJournal = {
  session_id?: string;
  access_expires_at?: number;  // Unix seconds
  session_expires_at?: number;
  pending?: boolean;
  blocked?: boolean;
};
```

Validate parsed storage as untrusted metadata. It cannot authenticate a user,
grant permissions, or prove cookies exist. Do not store tokens, claims, account
profiles, CSRF secrets or drafts here. Do not overwrite pending/blocked state from
stale HTML or an ordinary timer. Storage corruption/failure or unavailable Web
Locks disables safe custom rotation; do not silently fall back to unsynchronized
requests. Existing verified access may remain usable under app policy, with an
explicit recovery state before it expires.

| Operation | Request |
| --- | --- |
| Verify current access | `GET <base>/whoami?probe=true`, exact `Accept: application/json` |
| Inspect an unambiguous family | `POST <base>/api/refresh_session` |
| Rotate | `POST <base>/api/refresh_token` plus `X-Authcrunch-Refresh-Session: <expected sid>` |
| Revoke/logout | `POST <base>/api/logout` |

All requests use same-origin credentials and `cache: no-store`; reject redirects
in the custom fetch adapter (`redirect: 'error'`). The three POSTs
send `Content-Type: application/json`, `X-Authcrunch-Refresh: 1` and exactly `{}`.
Do not send the session precondition header on inspect/logout. The browser supplies
Origin/Fetch Metadata; JavaScript must not synthesize or loosen them. Use exact
paths without query parameters. Browser success supplies metadata and Set-Cookie,
not access/refresh tokens in JSON. Treat unexpected redirects/HTML as failure,
not as an authenticated result. GET refresh is navigation, not rotation.

## Bootstrap while holding the shared lock

1. Confirm storage and Web Locks work. Read/validate the current journal **after**
   acquiring the lock, then probe current access. Do not rely on stale app state
   captured before a queued lock was granted.
2. On a valid probe, require `authenticated === true`, nonempty `sid`, and finite
   `exp` for renewable sessions. An access-only login follows its separately
   configured policy; never manufacture a refresh family from it.
3. An existing pending/blocked marker can be superseded only by verified current
   access with a **different known family**. A same-family valid JWT, including
   one with a newer expiry, does not prove a prior rotation was safely completed.
   If the marker has no known family, fail closed. Preserve only the compatible
   absolute deadline for the same family; signed access expiry is authoritative.
4. On probe `401`, with no pending/blocked uncertainty, use `refresh_session` to
   discover the nonempty current `session_id` without consuming it. Record that
   family with access expiry zero, then proceed through the rotation algorithm.
   Re-read the journal if the lock is released between operations.
5. On probe `403`, wrong media/shape, or a read outage, do not rotate blindly.
   Distinguish portal admission/configuration failure from an unavailable read.
   Retry safe reads with bounded backoff/user action; never mislabel an outage as
   proven logout. A terminal family lookup denial requires appropriate recovery.
6. After usable access is established, obtain/validate the app session and its
   expected family/account. Only then expose authenticated app state.

`refresh_session` is not a recovery oracle for pending/blocked exchanges. Looking
up a known spent credential can itself trigger replay revocation. A timed-out
inspection has not rotated a credential, but must not be used to clear earlier
rotation uncertainty. Current server evidence, not elapsed time, controls recovery.

## Rotate as a transaction owned by the coordinator

Within one Web Lock and one local flight:

1. Re-read the journal and verified session/deadline. Reconcile a changed family.
   Stop if missing, pending or blocked. If access is fresh enough, return without
   rotating; a competing tab may already have completed the work.
2. If rotation is needed, synchronously persist `{...state, pending: true}` before
   dispatch. If storage write fails, do not dispatch. Bind the POST precondition
   to the same nonempty `session_id` recorded in that marker.
3. Hold the lock until the response body is fully read and validated and the
   resulting journal is persisted. `fetch()` resolving headers is not completion.
   Do not detach rotation under a caller's abort signal or release the lock while
   its network request is still running. A deadline that ends an exchange must
   leave uncertainty; it does not authorize a second request.
4. Accept success only for the expected family and valid metadata including
   access/absolute deadlines, with the success envelope required by the transport.
   Publish a healthy native-compatible journal only after confirmation. Never
   convert an incomplete `200`, JSON failure or storage-commit failure into ready.
5. If dispatch may have occurred but completion is unconfirmed, retain pending or
   blocked state, stop renewal and require intentional recovery. This includes
   connection loss, timeout/abort, malformed success and `503`. Do not automatically
   retry, delete the marker, inspect the refresh credential or infer a rollback.
6. Refresh verified app identity/permissions/CSRF before releasing app operations.
   If the family/account changed while an interactive login raced outside the lock,
   fence old work and reconcile; the session precondition prevents rotating a newly
   installed family on behalf of the old marker.

`400/403/404/405/415` indicate malformed/configuration/transport problems, not a
reason to weaken checks. `401` requires session recovery; a dispatched failure
still does not justify reusing that exchange. Reject unexpected response fields
according to the current transport and never accept a different family as rotation
success. No client-generated grace interval overrides server replay protection.

## Cross-tab events and logout

Listen for changes to the coordination key (and full storage clearing). Treat
those events as invalidation signals. Pause timers/hold protected work on
pending/blocked metadata, and schedule verified reconciliation even in hidden tabs;
otherwise a logged-out background tab may retain writable stale identity.
Do not authorize from a healthy event or equate `pending` with confirmed logout.
For a changed healthy family, re-probe under the shared lock. Same-document writes
do not emit a storage event to their writer, so update its controller directly.

Logout uses the same lock and remains callable when bootstrap/refresh is blocked.
Mark uncertainty before its protected POST, require `logged_out === true`, then
write the native-compatible blocked marker retaining the known old family, stop
timers and invalidate private app state. Preserve the marker across reload so a
stale JWT cannot revive that family. An explicit logout failure retains an
unconfirmed state and permits an explicit logout retry; it never automatically
rotates the uncertain credential. Subsequent fresh login can establish a new
verified family. The server's replay/revocation checks remain authoritative.

The native script exposes `refresh(force = false)` and `logout()` only. It has no
public React subscribe/dispose/ready contract. If the host deliberately embeds it
as the sole local renewal owner, adapt only real available behavior and do not
add a competing controller. A generated custom controller should be tested with
an independent native portal tab, not merely two copies of itself.
