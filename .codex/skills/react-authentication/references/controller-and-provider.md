# Controller and React provider blueprint

## App-owned module contract

Use the app's existing layout; the following split illustrates responsibilities:

| Module | Owns |
| --- | --- |
| Session adapter | Fetch/validate verified app session, map wire fields, derive trusted expiry and account identity; no navigation. |
| Browser coordinator | Shared portal lock/journal, bootstrap, rotation, logout, timers and cross-tab reconciliation; no React imports. |
| Auth controller | Immutable snapshots, one local flight, account/request generations, subscriptions and recovery decisions. Can be combined with the coordinator. |
| React provider/hook | Subscribe to controller, expose explicit state/actions, preserve account subtree through renewal. |
| API transport | Wait for appropriate session readiness; enforce request account/generation, CSRF and bounded retry policy. |
| Route integration | Guard after bootstrap/recovery resolves; validate return destinations and render denied/signed-out/retry states. |

Illustrative TypeScript interface to implement in the app, not a library import:

```ts
type AuthPhase =
  | 'bootstrapping' | 'ready' | 'renewing' | 'unavailable'
  | 'reauthentication-required' | 'signing-out' | 'signed-out';

type AuthSnapshot = {
  phase: AuthPhase;
  session: ApplicationSession | null; // app-owned verified response contract
  accountGeneration: number;         // fences a replaced/invalidated account lifetime
  generation: number;                // rejects obsolete requests/credential errors
  reason?: string;                   // bounded app message code, no raw errors
};

interface AuthController {
  getSnapshot(): AuthSnapshot;
  subscribe(listener: () => void): () => void;
  start(): () => void;
  ensureSession(): Promise<ApplicationSession>;
  retrySessionRead(): Promise<void>;
  logout(): Promise<void>;
}
```

Define `ensureSession` to return only current, usable verified app evidence after
any required renewal; it rejects with a typed state/reason otherwise. The app API
transport owns mutation preflight and generation checks. The illustrative method
names may change; ownership and promises must remain explicit.

## State and presentation

| Event | State and user behavior |
| --- | --- |
| Initial document | Bootstrap without briefly rendering a signed-out guard. |
| Verified access, sufficient lifetime | Ready; render the permitted account subtree. |
| Renewal due or expired access with safe family evidence | Renewing; retain same-account state and route, hold sensitive operations. |
| Session/probe read fails before a rotation is dispatched | Unavailable; offer bounded retry, retain permitted drafts privately, never claim current authorization from stale data. |
| Refresh is ambiguous, family invalid, or policy requires login | Reauthentication required; stop rotation and explain intentional recovery. |
| Valid identity has no resource permission | Render access denied for that resource; do not turn `403` into a login loop. |
| Verified different account | Advance generation, clear old account data, then mount the new account lifetime. |
| Logout requested | Signing out; prevent new account work while awaiting revocation. |
| Logout acknowledged | Signed out; clear private state, stop timers and avoid automatic SSO bounce. |

An unavailable or reauthentication state may retain a same-account draft in
memory for deliberate recovery, according to product policy. It must not expose
that draft to an unverified or different account or persist private form contents
in the renewal journal. Login completion must reverify identity before reuse.

During ordinary same-account renewal, keep the currently permitted UI visible and
preserve input focus; use unobtrusive status and hold protected actions. Hiding the
whole account subtree on every refresh can disrupt typing despite preserving React
state. Hide private content when identity is unconfirmed or policy requires it,
separately from routine renewal presentation.

## React lifetime and cleanup

Create a side-effect-free controller for the configured public origin/portal
mount and keep it stable across route renders. Prefer one application owner and
subscription through the app's existing store mechanism; `useSyncExternalStore`
is suitable when supported by its installed React version. Return cached immutable
snapshots until a real state transition. Supply an explicit server snapshot for
SSR; do not touch `window`, cookies or localStorage during server rendering.

`start`/cleanup must be idempotent or reference-counted. React StrictMode's
start/cleanup/start cycle must not send duplicate rotations, discard a pending
marker, or create two permanent timers. Remove owned listeners/timers and abort
obsolete read-only work on disposal. A dispatched rotating POST has a different
lifetime: continue holding the shared lock through response processing; do not
abort it or erase uncertainty because one component unsubscribed. Tab/process
termination may interrupt it, in which case the durable marker survives reload.

Keep mutation/logout work outside render and effect-cleanup callbacks. Avoid
unhandled promise rejections and commits to unmounted subscribers. Sign-out is an
explicit action, never automatic React teardown behavior. Do not key the account
provider by token ID, expiry, permissions array or serialized session response.
Update credentials/permissions within the stable account provider. A changed
account invalidates the entire old account lifetime before publishing new data.

## Expiry and scheduling

Use verified expiry and fresh server time, not a fixed interval from initial
mount, unverified JWT parsing or HTML data attributes. Convert Unix seconds to
milliseconds once. Derive a deadline from the server's remaining lifetime and a
monotonic clock where available; re-probe after resume/clock discontinuity.
Validate finite values and bound timers so malformed/extreme dates do not overflow
browser timer limits or cause a busy loop.

Choose an app policy for renewal lead time large enough for network latency and
background throttling but smaller than the access lifetime. The native portal
uses 30 seconds; an app may choose a different conservative margin and test it.
If a short access lifetime makes that margin impossible, adjust the effective
margin instead of rotating continuously. Do not rotate just because another
healthy journal update arrived or every API call occurs.

Use one timer plus visibility/focus/online reconciliation, with a bounded wake-up
interval if needed for suspended/long-lived pages. A resume first rechecks current
server evidence under coordination, not blindly forcing another rotation. Decide
whether hidden/inactive tabs renew; honor the selected product policy and the
[server idle/absolute limits](../../web-app-authentication/references/configuration-and-limits.md).
Avoid hidden-tab login navigation when no user action is possible.

Successful rotation must be followed by a fresh app-session read. Publish its
credentials and current permissions atomically, rearm scheduling, and release
waiting operations only after generation/account checks pass. If that read fails,
retain the confirmed rotation outcome and retry the **read** while access remains
usable. Do not force another rotation merely because the app endpoint failed. If
that access later expires during the outage, ordinary coordinated renewal remains
allowed for a healthy confirmed family. A read outage does not make a completed
rotation uncertain or permanently disable its next scheduled renewal.
