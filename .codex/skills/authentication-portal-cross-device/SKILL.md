---
name: authentication-portal-cross-device
description: Maintain optional cross-device portal login, its directive parser, QR and polling UI, approving-browser binding, single-use transfers, MFA and provider evidence, logout invalidation, and TLS/browser tests.
---

# Cross-Device Portal Login

## Configuration and ownership

`authn.CrossDeviceLoginConfig.Enabled` is an explicit opt-in. Nil, omitted and
zero configurations disable both routes and login links. Assign the result of
`pkg/authn/cross_device/parser.NewCrossDeviceLoginConfigFromDirectives(statements)`
to `PortalConfig.CrossDeviceLogin` before construction. The parser accepts complete
`enable cross-device login` or `disable cross-device login` statements encoded
with `cfgutil.EncodeArgs`. Empty input disables; duplicate/conflicting settings,
extra tokens, joined keywords and multiline records fail without partial output
or echoed values. Collect all feature statements before parsing. JSON/XML/YAML
use `cross_device_login` with nested `enabled`; serialization preserves the opt-in.

Portal-owned implementation uses the `cross_device_` filename prefix. The
embedded `cross_device` template and `core/js/cross_device.js` serve the flow.
The login template exposes the action inside `user_actions` for local and
provider-only configurations and beside the provider choices for mixed portals.
Filesystem login overrides must add the opt-in action themselves; the built-in
new template remains available unless overridden. The old `/qrcode/login.png`
bookmark still encodes ordinary portal navigation and is a separate feature.

The [cross-device presentation contract](../authentication-portal-themes/references/cross-device.md)
owns step-specific headings, prominent matching codes, copy fallback, action
layout, recovery labels, and optional Chrome screenshot capture. Built-in requester
terminal states hide inactive controls and offer a fresh request; clipboard
feedback remains separate from lifecycle status. Neither presentation changes
nor recovery controls weaken explicit approval or revive a stopped interaction.

## Browser and HTTP contract

All routes are relative to the portal mount; nested and root mounts work. Match
the complete route segment so mounts such as `/cross-device-team/auth` continue
to serve ordinary login and the transfer flow. Existing route namespaces retain
ownership of names such as `/oauth2/cross-device` and `/assets/js/cross-device`,
whether the feature is enabled or disabled. The `/provider/<realm>` namespace
also retains ownership; `/provider/cross-device` is a provider login, while
`/cross-device/provider/...` remains an invalid transfer endpoint. The optional
HTTP login capability does not supply cross-device completion evidence. An unknown child beneath the actual
transfer route must remain a 404, including children resembling other routes.
This is a browser login transfer, not an RFC 8628 device authorization endpoint.

| Route | Method | Result |
| --- | --- | --- |
| `/cross-device` | GET | Requesting page; JavaScript starts an interaction |
| `/cross-device/start` | POST | Independent activation code and requester secret, PNG data URI, verification URI, matching display code, 300-second lifetime and 2-second interval |
| `/cross-device/activate?code=...` | GET | Matching-code warning and form; new approving-browser binding cookie |
| `/cross-device/begin` | POST | Checks activation code and browser CSRF value, binds the interaction, starts a fresh portal login |
| `/cross-device/confirm` | GET / POST | Shows the authenticated account and matching code; explicit approve or deny |
| `/cross-device/poll` | POST | Pending/slow-down status, or one-time cookie issuance and a next destination |
| `/cross-device/cancel` | POST | Cancels an unconsumed interaction |

The fresh login opened when the approving browser binds an interaction renders
without the login page's signed-in-elsewhere probe, so a session another tab
holds or renews cannot carry the approving browser away before it completes the
interactive login. Going back from the password step or starting over keeps that
login fresh.

POSTs require HTTPS, exactly one matching Origin, compatible Fetch Metadata,
and a form body bounded to 4 KiB, including unknown-length/chunked requests.
Require one valid Content-Type header; accept URL-encoded media types with
parameters such as `charset=UTF-8`. Oversized bodies return 413, unsupported media
types return 415, and malformed/ambiguous forms return 400. Duplicate form values,
Content-Type headers and binding cookies fail closed. A method error advertises
all methods supported by that endpoint, including GET and POST for confirmation.
The host must normalize trusted forwarded metadata before
calling the library. The requesting secret travels in form bodies only; the QR
and copyable link contain only the activation code. Browser JavaScript retains
capabilities only in page memory, polls serially every two seconds, and stops on
expiry, cancellation, navigation, denial or ambiguous network failure. Reloading
the requester starts over. Navigation clears the pending capability and hides
the QR/link with a terminal status, so a restored history document cannot display
a stopped request as waiting. Late network or clipboard results must not replace
a terminal status. A lost redeemed response requires a fresh interaction;
there is no retry grace that can mint a second credential family.

Use the original AbortController/event-listener APIs for bounded fetches; the
flow must not require `AbortSignal.any` or `AbortSignal.timeout`. Abort in-flight
work on cancellation/navigation, bound start/poll requests and response-body reads
to ten seconds, and give cleanup cancellation its own five-second budget.
Remove the parent abort listener and clear the deadline on every exit. A late
start result must be cancelled without revealing its QR/link or restarting polling.

Responses disable caching and framing, confine content/form submission to the
same origin, and use `Referrer-Policy: strict-origin`. Do not switch the form
page to `no-referrer`: Chrome then sends `Origin: null`, breaking strict CSRF
checks. Strict-origin omits the activation path and query from referrers.

The shared cookie role is `CrossDeviceSessionIDCookieName`, default
`AUTHP_CROSS_DEVICE_SESSION_ID`. `cookie cross-device session id name <name>` and
`cookie prefix <prefix>` configure it through the shared cookie parser. The
factory always emits Secure, HttpOnly, host-only, mount-scoped, SameSite=None,
300-second cookies; None permits signed cross-site SAML POST callbacks. Its
CSRF protection comes from origin checks, random binding and explicit approval,
not SameSite. Deletion matches issuance. Optional `__Host-` names require root
mounts; no reserved prefix is required.

## Evidence, issuance and lifecycle

A code alone cannot authenticate either device. The approving browser must
complete ordinary HTML password/MFA, OAuth or SAML login after binding, then
explicitly approve the displayed account and matching code. Preexisting JWTs,
API-key/Basic login and JSON login cannot supply completion. Never auto-approve
on a GET or immediately after a provider callback. Matching-code warnings help
users detect unsolicited QR requests; possession of a link is not evidence that
the requesting device belongs to them.

The store snapshots completed sandbox proof or authenticated upstream attributes
before portal transforms. It also binds the proof to the issued session token.
Only local/LDAP proofs go through `issueSandboxTokens`; local identity/version
checks and current challenge policy run again for the requesting address and
issuer. AMR comes from verified checkpoints. Refresh and OIDC, when configured,
create independent browser credentials using the normal issuer/completion APIs.

OAuth/SAML transfer rechecks the configured backend, uses the captured upstream
attributes, reruns transforms for the requesting device, and checks additional
local-factor requirements. Retain the original protocol method (`oauth2` versus
the provider kind `oauth`) so GitHub claim ownership remains correct. Decode
snapshots with JSON-number preservation. Provider transfer expiry cannot exceed
the original portal login; upstream ID/refresh tokens are not copied. Upstream
revocation cannot be detected beyond the provider's existing login/session
contract; this feature does not add introspection.

Each requester receives a fresh session ID and ordinary credential cookies;
poll JSON never includes bearer tokens. If grant, persistence or OIDC completion
fails, remove newly cached credentials, revoke an undelivered refresh family,
and restore response headers before returning failure. No credential-bearing
response precedes successful completion.

Pending records live only in the owning portal, including when runtime-state
persistence is enabled. They expire after five minutes, are pruned on admission,
and disappear on Close/restart. Bounds are 1024 active requests total and eight
per trusted source address; they are fixed runtime limits, not configuration.
A binding cannot select multiple live requests. Approval is bound to the exact
form displayed: when another approving tab changes the binding cookie and account,
an old confirmation must not approve the new request.
Its CSRF token must still match that browser's current binding. Mutex-protected
approval consumption precedes issuance; concurrent polls mint at most one result.
Cancellation/denial before consumption prevents issuance. Cancellation cannot
undo a redemption that already won the race. Portal, external-provider and
browser refresh logout invalidate outstanding transfers by session or family.
Before confirmation and redemption, validate both the cached approving access
session and any associated refresh family. Obtain the family reference from the
committed local issuer result, never an arbitrary `sid` claim. Use the refresh
manager's read-only `ValidateSession`: normal rotation remains live; replay,
replacement, logout without an access cookie, expiry and unavailable storage
fail closed. Never look up a captured old refresh credential, which would itself
trigger replay revocation. This liveness check adds no authentication authority
to a public family ID. A concurrent revocation cannot undo a completed transfer.
Local credential revocation and a stronger current challenge policy also deny
redemption. Sharing one portal across hosts/mounts does not permit cross-scope
capabilities; each interaction fixes its HTTPS origin and mount.

## Validation

Parser unit tests and its executable example cover grammar, defaults, redaction,
independent results and serialized opt-in. Store tests cover scope, snapshots,
capacity, expiry, binding uniqueness, cancellation/logout, shutdown and concurrent
single redemption. Cookie tests cover names, collisions and fixed attributes.

`cross_device_e2e_test.go` uses public parsers, temporary local databases, separate
cookie jars and TLS production handlers. It covers local/MFA, root/nested mounts,
refresh/OIDC coexistence, signed upstream OAuth/SAML, independent credentials,
JWKS/gatekeeper verification, wrong secrets/origins, explicit approval, denial,
cancellation, revocation, current policy, expired login, logout and concurrency.
Keep explicit family lifecycle cases for rotation, replay, account replacement
and logout after the access cookie is removed. Verify access-only custom `sid`
claims remain independent of local refresh state, and provider names equal to
`cross-device` still complete real login with the feature on or off.
Keep a two-account stale-form case with two requesting browsers and one approving
cookie jar: a stale form cannot approve either request, and a valid new form
delivers credentials only to its corresponding requester.
Completion-capacity rejection must deliver no credentials and release the
undelivered refresh family for subsequent logins.
`cross_device_browser_e2e_test.go` runs Chrome with isolated browser contexts and
real forms, QR rendering, responsive layout, scheduled polling, cookie checks,
navigation and history recovery. Disable the newer AbortSignal static helpers in
that browser fixture to exercise compatibility through real fetches and forms;
this is not physical TV/VR certification. Node client tests complement it with
expiry, request/body deadlines, and late-start/poll/clipboard cancellation races.
The browser journey also checks approval/denial and recovery presentation across
phone/tablet/desktop widths, real clipboard success/denial, and keyboard focus.
Set `AUTHCRUNCH_CROSS_DEVICE_SCREENSHOT_DIR` to an ignored review directory to
retain the captures described in the presentation contract.
Keep the legacy filesystem-theme journey: presentation wrappers must remain
optional for the original polling, copying, cancellation, and redemption hooks.

```sh
make test TEST_DIR='./pkg/authn ./pkg/authn/cookie/... ./pkg/authn/cross_device/parser ./pkg/authn/token_refresh' TEST='CrossDevice|ExampleNewCrossDevice|ValidateSession|ExtractBasePathCookieMount|PersistentRefreshReplayAndRevocation' COVERAGE_DIR=.coverage/cross-device
make test-ui
make ci-check
```
