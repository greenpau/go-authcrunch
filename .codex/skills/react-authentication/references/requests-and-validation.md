# API transport and acceptance evidence

## One account-aware request path

Route protected app requests through one adapter. Establish session readiness
before sending work and capture its account plus request generation. Distinguish
read-only work from mutations; endpoint method alone may not describe side effects.
Never make every component implement its own refresh-on-401 interceptor.

For a mutation that depends on token-derived CSRF or current cookies:

1. Acquire the coordinator's shared Web Lock; do not nest another acquisition
   from `ensureSession`. Provide internal lock-held operations to avoid deadlock.
2. Reconcile current access and renew if due. Read the app's current verified
   session under the lock, including fresh CSRF credentials. A healthy journal is
   insufficient: another tab can rotate the token without changing account/sid.
3. Verify that the draft/request still belongs to the same account lifetime.
   A same-account credential revision during this preflight may be adopted before
   dispatch; it is not an account switch. Capture the response ticket with the
   fresh credentials after preflight. Reject work crossing an account lifetime
   fence, and send the server-defined account precondition and CSRF value using
   the app's real contract. Never replace the expected draft owner with a new user.
4. Dispatch the mutation and keep the rotation-sensitive part serialized through
   its complete response handling. Avoid unbounded lock holds: define timeouts and
   a specific server/request design for long uploads, downloads and streams.
   Do not release the lock merely because a caller stopped awaiting a still-running
   request. If a deadline actually aborts the fetch, settle its handling as an
   uncertain mutation; cancellation does not prove server rollback.
5. Apply the result only to its matching account/generation. Server-side
   authorization, account comparison and idempotency are still required because
   interactive login, nonparticipating clients and network ambiguity are outside
   the lock's guarantee.

If the app's server uses a stable independent CSRF scheme or request-bound
credentials, narrower locking may be possible; document and test that actual
contract rather than serializing every unrelated read indefinitely. Keep bounded
request/response-body deadlines and handle lock acquisition cancellation before
work starts. An aborted mutation may already have committed; report ambiguity and
use server idempotency/status reconciliation instead of automatic replay.

## Retry and error policy

| Observation | Behavior |
| --- | --- |
| Read `401` for the current generation | Attempt one coordinated recovery, then retry a replay-safe read at most once. Stop if still unauthorized. |
| Old-generation `401` arrives after renewal/account change | Ignore it for global auth state; it must not sign out the new session. |
| Mutation `401` | Replay only if the server guarantees rejection before side effects and the request is safely replayable/account-bound. Otherwise hold/reject with an explicit action. |
| `403` on app resource | Access denied; do not refresh/login in a loop. A known CSRF-specific response needs fresh credentials and its own safe policy. |
| Network failure before any rotation | Recoverable read/availability state with bounded retry; no unconditional logout. |
| Dispatched rotation has uncertain outcome | Retain journal uncertainty; fresh authentication required. No transport retry middleware may retry this POST. |
| Confirmed rotation followed by failed app-session read | Retry the safe read while access is usable; preserve healthy refresh state so normal renewal can proceed when access actually expires. |
| Explicit logout not acknowledged | Show unconfirmed failure and allow explicit retry; do not claim server revocation. |

Do not replay request bodies that have been consumed, stream operations, exports
with side effects or non-idempotent writes by default. Do not turn a successful
HTML login page returned by a redirecting API into a `200` app result. Validate
content type, schema and redirect expectations at the transport boundary.

## Focused unit/integration scenarios

Test observable outcomes with controlled clocks, deferred fetch/body completion,
realistic storage events and account transitions. Include:

- Stable subscription snapshots, StrictMode start/cleanup/start, bounded timers,
  listener removal, Unix-second conversion and skew/resume reconciliation.
- First load after access expiry, refresh-disabled/access-only login, malformed
  session responses, root and nested portal mounts.
- Shared callers waiting for one rotation; pending persisted before dispatch;
  lock held through a delayed body; no abort/retry when one consumer unmounts.
- A native-compatible pending/blocked journal across reload, same-family valid
  JWT refusing recovery, verified different-family login allowing recovery.
- Corrupt/blocked storage, missing Web Locks, storage clearing, failed journal
  commit after a successful response, and invalid/different-family success.
- Read outages preserving drafts, a failed post-refresh session read, old reads
  arriving after account switch, late old `401`, permission changes and new CSRF.
- Explicit/remote logout while a tab is hidden; no automatic sign-in bounce.
- Mutation preflight after another tab's rotation; stale-account write rejected
  by the server, ambiguous mutation outcomes and no unsafe request replay.
- A rotation between initial readiness and mutation preflight for the same account
  adopts fresh credentials without a spurious account error; an account switch
  across the same interval still prevents dispatch.
- A confirmed rotation followed by an app-session outage longer than access life
  permits the next normal renewal of its healthy family, without treating the
  read failure as an uncertain exchange or rotating in a retry loop.

Mocks establish client logic, not real authentication. Avoid assertions that
merely mirror private function names or an exact implementation arrangement.

## Real HTTPS browser acceptance

Use synthetic users and an isolated server/browser profile. Exercise the actual
configured origin, cookie attributes, gateway/session adapter and login method.
Short test lifetimes may accelerate cases, but also run a realistic-lifetime
journey to detect throttling and scheduling errors. Include these outcomes:

| Journey | Required evidence |
| --- | --- |
| Keep a form open past access expiry | One successful renewal as needed, refreshed credentials, same route and same permitted draft; no Sign In click. |
| Reload with expired access and valid refresh | Reachable bootstrap inspects/renews without a login detour. |
| Two app tabs and a native portal tab | One compatible lock/journal, serialized rotations, no replay revocation; a subsequent CSRF-protected write succeeds. |
| Background, suspend and resume | Current session reconciles before protected work; no timer-only assumption. |
| Interrupted rotating response then reload | No second rotation/lookup of uncertain credentials; intentional reauthentication works. |
| Temporary safe-read outage | Recoverable UI, preserved same-account state, eventual read recovery without forced logout. |
| Account switch during delayed read/write | Old results cannot commit into the new account; server rejects an unexpected-account mutation. |
| Logout in app or native portal | Server acknowledgement, cookies cleared as scoped, hidden sibling apps invalidate, reload cannot resurrect the old family. |
| Idle/absolute expiry, account disablement/factor changes | Appropriate required login/denial; no endless retries or unsupported lifetime extension. |
| Portal probe denied, wrong origin/mount, API fallback HTML | Clear bounded failure, no auth bypass or redirect loop. |
| Restart with selected storage/identity backend | Outcome matches that backend's documented proof/state persistence limits. |

Also verify unauthenticated API denial, forbidden roles/records, unsafe return
URLs, trusted-header spoofing and absence of credentials in browser storage,
bundles and logs. For upstream snapshot login, explicitly distinguish snapshot
policy from upstream revocation; do not assert immediate IdP logout propagation.

The current library evidence includes the [native client simulations](../../../../pkg/authn/ui/testdata/token_refresh_client_test.cjs),
[browser interoperability tests](../../../../pkg/authn/token_refresh_browser_e2e_test.go),
[browser-launcher cleanup tests](../../../../pkg/authn/token_refresh_browser_startup_e2e_test.go),
[session lookup tests](../../../../pkg/authn/token_refresh_session_e2e_test.go),
and [parser-to-runtime tests](../../../../pkg/authn/token_refresh_config_parser_e2e_test.go).
These do not substitute for the consuming app's real session/CSRF integration.
The transport owner documents focused Make commands; the app uses its own
inspected manifest/test tooling. Stop owned fixtures and remove synthetic
credentials, browser profiles, traces and auth-state files after validation.
Preserve pre-existing user services and state.
