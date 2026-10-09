# Cross-device sign-in presentation

The `cross_device` template and `core/js/cross_device.js` present a requesting
device and an approving browser as separate roles. The
[feature owner](../../authentication-portal-cross-device/SKILL.md) defines the
protocol, browser binding, explicit consent, and cancellation races. Styling
must preserve those decisions and the warnings about unsolicited requests.

## Hierarchy and wording

Use a title for the current step in both the visible heading and document title.
The built-in template derives server-rendered titles from `.Data.view`; the
requester's script updates both titles when its state ends. Replace only a
matching heading suffix in the document title. When a custom theme uses a
different document title, retain it as the prefix of the terminal title.

| View | Heading | Main actions |
| --- | --- | --- |
| Requesting device | Sign in on another device | Copy link; Cancel |
| Before approving-browser login | Sign in to continue | Continue |
| Authenticated confirmation | Approve sign in | Approve; Deny |
| Approval submitted | Sign-in approved | Return to the other device; the page may be closed |
| Denial submitted | Sign-in denied | Explain that the other device has not been signed in |
| Request cancelled | Sign-in cancelled | Start again |
| Client expiry | Sign-in link expired | Start again |
| Poll unavailable or failed | Sign-in unavailable | Start again |
| Start failed | Unable to start sign-in | Start again |
| History-restored ended request | Sign-in request ended | Start again |

Keep Back to sign in as secondary navigation. Start again navigates to a fresh
requesting page; it never resumes a stopped capability. Terminal views hide
the QR/link/code and Cancel, rather than leaving a disabled control with a stale
heading. Successful requester redemption navigates onward without a retry action.
Unavailable responses do not disclose whether denial, revocation, expiry, or a
network failure caused the loss. Do not invent a specific cause from that result.

Show the matching code in a dedicated, centered panel on request, activation,
and confirmation. Use the same label, large monospace type, spacing, and contrast
in all three views. It is a visual comparison, not an input or a code to type.
The approval page must also identify the account and explain that the codes
must match and the user must control the requesting device. Continuing to login
is distinct from approving; explain that a separate decision follows login.

## Layout and interaction

Scope styling to `.cross-device-*` and the cross-device element IDs in
`basic.css`. Use the existing brand tokens and phone/tablet shell. Grid spacing
owns the vertical rhythm; avoid accumulating paragraph margins. Explicitly
preserve `[hidden]` when a wrapper gains grid or flex display.

Center the 256px QR in the content area, preserve its white quiet zone, and let
it shrink only when the available width requires it. Group Copy link and Cancel
in one evenly spaced action row below the code and status. Disable copying until
the link is ready. The activation URL is hidden by
default. Clipboard success has its own live feedback so it cannot replace
waiting/expiry guidance. Keep that empty `role="status"` region exposed to
assistive technology before the first update; do not hide it and reveal it
alongside its message. This follows the preexisting status-container requirement
in [W3C ARIA22](https://www.w3.org/WAI/WCAG22/Techniques/aria/ARIA22.html).
An empty feedback region must not create a blank layout row. Apply the normal
24px spacing when feedback has content and before the manual-copy fallback.
On clipboard denial or absence, reveal a labeled,
readonly wrapping textarea for manual copying. Focus it and select its value
only if keyboard focus has not moved since copying began. A delayed permission
failure must not pull focus away from Cancel or navigation. When focus has
moved, announce the manual-copy option without claiming its value is selected.
The entire activation link stays copyable; never include the requester secret.

Approval actions share equal widths and heights with a visible 12px gap. The
row may wrap when needed while preserving Approve then Deny in DOM/tab order.
Continue spans the available action row. Use the theme's focus outlines and
touch target sizes. Explicit cancellation moves focus to the updated heading.
Background polling moves focus only when its current control is about to be
hidden; otherwise it announces status without stealing focus from surviving
navigation. Make the destination programmatically focusable, including in old
themes whose heading has no `tabindex`. If the custom heading is absent, use
the status element as the focus destination.

For the complete presentation, filesystem overrides should carry the current
script hooks, including the
focusable `cross-device-title`, `cross-device-recovery`, `cross-device-controls`,
`cross-device-copy-status`, and `cross-device-link-fallback` wrappers, as well
as the existing details/status/QR/code/copy/cancel/link IDs. These new wrappers
are optional enhancements to the original client contract: an older theme must
still poll, copy or select its existing visible link, cancel, and complete login.
Without a dedicated copy-status element, reuse the original status element for
copy feedback. Without a recovery wrapper, retain the theme's existing sign-in
navigation. Do not let an absent enhancement interrupt cancellation or approved
navigation. Updating a filesystem copy is required to acquire the full layout
and Start again action, not to keep its original login protocol working.

## Browser evidence

`TestE2ECrossDeviceBrowser` exercises real TLS, fresh password authentication,
separate browser contexts, explicit approval/denial, clipboard permissions,
cancellation/restart, client expiry, and history recovery. Its legacy subtest
loads `ui/testdata/cross_device_legacy.template` through the public filesystem
override, retaining the original DOM and a custom document title. Preserve that
fixture's old hooks; adding the new wrappers would erase the compatibility case.
Both browser journeys reject unhandled script exceptions. The Chrome driver
checks content-area fit, QR centering, prominent matching codes, equal decision
buttons and their gap, document titles, and keyboard focus at 320, 390, 639,
640, 768, and 1280px widths. Require the exact visible action labels/counts for
each view before checking geometry; conditional checks alone can miss a hidden
or absent button. Chrome's accessibility tree must expose the same polite,
atomic clipboard status region before and after copying. Also verify that empty
feedback adds no blank row and populated feedback has the intended spacing.
This checks browser accessibility semantics, not actual speech output from a
screen reader. Delay delivery of a native clipboard permission denial until
after a real Tab keystroke to verify that the user's new focus is preserved;
then retry copying to verify that immediate denial still selects the fallback.
Node client tests cover the same delayed-focus boundary for current and legacy
templates and retain the timing/race coverage
and verify title preservation, optional wrappers, and focus inside versus outside
hidden controls. `TestCrossDeviceTemplate` covers all five server-rendered views,
root/nested mounts, embedded/filesystem parity, escaping of account and form
values, explicit POST decisions, custom CSS ordering, and an initially empty
copy-status region whose ancestors do not hide it from assistive technology.

```sh
AUTHCRUNCH_CROSS_DEVICE_SCREENSHOT_DIR="$PWD/tmp/cross-device-ui-review" make test TEST_DIR='./pkg/authn' TEST='^TestE2ECrossDeviceBrowser$' COVERAGE_DIR=.coverage/cross-device-ui-browser
make test TEST_DIR='./pkg/authn/ui' COVERAGE_DIR=.coverage/cross-device-ui-render
make test-ui
```

Screenshot capture is optional; assertions run without it. The directory contains
phone and desktop captures of the flow, plus small-phone request, clipboard,
manual-copy, and keyboard-focus views. Captures use production-rendered pages
and synthetic fixture accounts. Expiry advances the client clock after admission
and waits for the real poll timer. Inspect the full PNGs as well as geometry:
overflow checks alone cannot establish balanced spacing or readable hierarchy.
Keep review screenshots under ignored `tmp/`, outside tracked assets.

## Localization

Titles, security instructions, actions and dynamic copy/poll/terminal feedback
use the shared catalog and portal language. The external script receives its
selected messages in `data-i18n`, with English fallbacks for older overrides.
Keep code/URL display LTR inside RTL pages and preserve machine decision values.
Follow [internationalization](internationalization.md) for language ownership,
escaping and multilingual browser/screenshot validation.
