# Template Contracts

## Rendering Model

Read the template in `pkg/authn/ui/page_templates/basic` and its current handler
before changing a page. `pkg/authn/ui/ui.go` is authoritative for `Args` and
template functions. A custom file is one complete Go `html/template` document,
parsed separately and executed with `ui.Args`.

Only the built-in Go template functions plus `pathjoin` and `brsplitline` are
available. Separate files do not share `define` blocks. Shared source fragments
must be composed into each final file by tooling owned by the consuming app,
or kept as shared external CSS/JS. Remote template URLs are not supported.

Important common fields:

| Field | Meaning |
| --- | --- |
| `.ActionEndpoint` | Request's portal base path, e.g. `/xauth`; join local route/asset segments onto it |
| `.Language`, `.LanguageCode`, `.Direction` | Normalized portal language and document reading direction |
| `.Translate`, `.Messages` | Plain-text catalog lookup and escaped JSON client message attributes; see [internationalization](internationalization.md) |
| `.PageTitle` | Page heading selected by the handler |
| `.MetaTitle`, `.MetaDescription`, `.MetaAuthor` | Configured site metadata |
| `.LogoURL`, `.LogoDescription` | Configured logo, with the base path already applied to local URLs |
| `.CustomCSSEnabled` | Factory flag used by every current basic template to include custom CSS after all base/view styles |
| `.Message`, `.MessageType` | Top-level status/error values used by some pages |
| `.PrivateLinks` | Configured and user-specific links; keep target/icon conditions |
| `.Data` | Handler-specific values and translations; not a general theme-settings map |

Keep the existing `.Data.i18n_*` bindings for functional labels. Go `range`
changes the current dot; preserve the original root references and per-item
fields when moving blocks. Flags are not uniformly typed: login/UI options
often compare string `"yes"`, while refresh/registration flags may be booleans.
Preserve the type expected by each existing conditional.

Contextual template escaping protects the generated JavaScript source, but it
does not make a decoded JavaScript string safe for a later HTML parser. Render
status and error messages with `textContent` or an equivalent text-node API.
Never concatenate `.Message` or `.Data` values into Materialize's `html` option,
`innerHTML`, or another HTML-producing DOM sink. The sandbox toast passes an
element populated with `textContent` to Materialize and appends its close button
with DOM APIs; preserve that boundary in built-in and filesystem templates.

Use `pathjoin` for path segments only; append a query string after the joined
path. Do not use it to construct an absolute `https://` URL. Keep Go's contextual
HTML/URL/JavaScript escaping and avoid introducing raw HTML helpers for branding.

The shared portal renderer makes every HTML page non-embeddable with both CSP
`frame-ancestors 'none'` and `X-Frame-Options: DENY`, and sends `nosniff` with an
explicit UTF-8 HTML content type. Filesystem themes inherit this response policy;
do not describe iframe embedding as a supported theme integration or weaken the
headers in page-specific handlers. Page-specific CSPs compose with the shared
frame policy as separate response values.

## Pages and Their Functional Content

| Alias | Preserve while changing presentation |
| --- | --- |
| `login` | `.Data.login_options` branches, authenticator loop, username/realm POST, registration/recovery/support visibility, QR controls, per-flow destination on the form, provider links and login script |
| `sandbox` | Every `.Data.view` branch, server-provided sandbox ID, credential forms, MFA setup/challenge controls, cancel/retry/error views |
| `portal` | `.PrivateLinks` loop with target/icon flags, sign-out navigation, conditional refresh script |
| `register` | `register`, `registered`, `ack`, `ackfail`, `acked` views; realm/registration IDs, policy attributes, terms/code conditions, alerts and inline DOM consumers |
| `generic` | `.Data.message`, optional `.Data.go_back_url`, page title; used for more than a single success screen |
| `whoami` | Escaped `.Data.token` JSON display, Highlight.js assets/initialization, portal and logout links |
| `apps_sso` | Numeric `.Data.role_count`, `.Data.roles` entries with `ProviderName`, `AccountID`, and `Name`, generated role links and empty state; this is the AWS SSO role-selection page |
| `apps_mobile_access` | Instructional content and navigation; the current baseline does not itself render a mobile QR image |
| `oidc` | All `.Data.oidc.Kind` branches: consent CSRF/decisions, form-post action/values/nonce/manual Continue, and local error message; see the [owning contract](../../authentication-portal-oidc/references/browser-pages.md#page-and-template-contract) |
| `cross_device` | `.Data.view` request/activate/confirm/approve/deny branches, matching-code warnings, CSRF/decision form fields, and external cross-device client hooks; see the [presentation contract](cross-device.md) and [feature contract](../../authentication-portal-cross-device/SKILL.md) |
| `session` | `.Message`, continuation/logout action, confirmation button, fresh-login link with optional `.Data.login_return_url`, external refresh client and data attributes (`data-next` is the continuation or logout destination) |

Handlers live in `pkg/authn/handle_http_login.go`,
`handle_http_sandbox.go`, `handle_http_portal.go`, `handle_register.go`,
`handle_http_whoami.go`, `handle_http_apps_sso.go`,
`handle_http_apps_mobile_access.go`, and `handle_http_session.go`. Generic
responses also come from shared response/error handlers. Inspect these for the
exact data supplied to an affected branch.

OIDC rendering is adapted by `pkg/authn/oidc_ui.go`, with snapshots and response
policies owned by `pkg/oidc/pages.go`. Its nested `.Data.oidc` model differs from
the top-level `.Message` used by `session`. Read the owning contract above before
moving OIDC forms or scripts into a common shell.

## Login, Sandbox, and Registration DOM

The HTML login starts by submitting `username` and `realm` to
`{{ pathjoin .ActionEndpoint "/login" }}` using POST. Password authentication
is a later sandbox view with `secret`; do not collapse these into an invented
single-step password form.

`.Data.login_return_url` is the page's trusted destination, or empty, and
`.Data.login_fresh` is true on a `fresh=1` login. Append both to the login form
target as the query `fresh=1` and `redirect_url={{ . }}` (each only when set), and
the destination as `?redirect_url={{ . }}` after each identity-provider
`.endpoint` whose `.login_return_url_enabled` is `yes`, inside `with`, so the URL
query context encodes it. The portal sets that flag for OAuth and SAML endpoints
only: an HTTP login provider rejects any query on its first request, so its link
must stay bare.
When `.Data.login_elsewhere_enabled` is true, give the `login.js` script tag
`data-whoami` (the mounted identity endpoint with `probe=login`) and
`data-return-url` (the destination, else the mounted portal page). The script then
sends a waiting tab to that destination once another tab completes the login. Omit
both attributes otherwise, notably for a `fresh=1` login. The sandbox `terminate`
view's start-over link receives the same two keys and builds the same login page
query. The portal also supplies runtime `Args.LoginNavigation`. After Go template
execution, the renderer carries the destination (including explicit empty
`redirect_url=`) across known local forms, submit overrides and navigation links,
and configured OAuth/SAML initiation endpoints. Root and nested mounts work.
Filesystem templates from before these keys therefore keep flow isolation.
GET navigation forms receive hidden `redirect_url` and, when applicable,
`fresh` controls: browsers replace a GET action's query when submitting it.
Existing controls in that form lose those reserved `name`/`dirname` attributes
when the renderer supplies their replacement. This includes externally associated
controls before the form: document order would otherwise let their old values
win. Ordinary field names/values and the ability to activate submit buttons stay
intact. Preserve a theme's own freshness controls when no replacement is needed.
Compute effective actions and methods for every submit button, including controls
associated by `form="id"` outside the form. GET method overrides on POST forms
need these fields too. Match `method`, `formmethod` and input/button `type`
keywords using ASCII-only case folding, with their HTML invalid-value defaults.
Unicode folding can mistake `poſt` for POST or `reſet` for a non-submitting reset
button, causing lost navigation or disclosure to a foreign action. See the
[HTML keyword rules](https://html.spec.whatwg.org/multipage/common-microsyntaxes.html#keywords-and-enumerated-attributes).
Shared fields must not be added when any submission can
target an external URL, callback or provider-owned protocol endpoint. Such mixed
forms need separate forms or explicit per-submission handling by the theme.
Identify each form by its parsed element and source position, never by matching
opening-tag text: the HTML parser can discard nested forms, and identical real
tags can have different submitters. Inert template forms receive no fields.
Malformed table/form nesting can leave controls with a parser-only form owner
outside their DOM ancestry. Withhold shared fields when their placement is
ambiguous, and conservatively account for submitters that could retain such an
owner. Correct malformed themes before relying on automatic GET adaptation.
Use the first duplicate attribute, as browsers do, when classifying core script
sources; a later ignored `src` must not override it.
An explicit empty `action` or `formaction` stays empty: it submits to the current
document URL, whereas adding only a query would resolve against the HTML base.
See the [HTML form submission contract](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#form-submission-algorithm).
Fragment-only links stay unchanged. Resolve navigation using the first active
HTML `<base href>`; bases inside inert templates do not apply. Only relative
bases can be resolved as local from this runtime context. Absolute/foreign bases
must not cause the adapter to attach destinations to links or core-asset tags;
custom themes using such bases must carry navigation explicitly.
The adapter fills core script attributes, including `data-login-destination`
for realm-dependent registration links. `data-return-url` may instead point to
`portal?redirect_url=` for an empty choice. Refresh continuation receives
`data-next`, and cross-device request scripts receive `data-return-url`.

Preserve ordinary HTML navigation and core assets when customizing themes.
External URLs, HTTP provider protocol routes, callbacks, unrelated parameters
and inline script text remain unchanged. Custom scripts which create or replace
links at runtime must carry `redirect_url` themselves; `showLoginForm` does this
for registration. Do not use raw HTML or JavaScript interpolation for URLs.
`TestLegacyThemeNavigation` covers escaped/long/empty values and root/nested
mounts; the real Chrome waiting-tabs test also runs the pre-feature filesystem
login template with an 8 KiB destination and real GET/default/override/empty-action
submissions, including conflicting controls before their form and `dirname` fields. It also
loads a core script with duplicate sources. External submit overrides and malformed
nested/table/ancestor-closed forms submit to a separate TLS receiver; no navigation
fields may reach that receiver. `TestLegacyThemeFormOverrides` also covers ownership,
duplicate IDs, inert controls, ASCII/Unicode keyword boundaries and provider-protocol exclusions. Keep
`TestLegacyThemeFormIdentity`, `TestLegacyThemeScriptFirstSource` and
`TestLegacyThemeReservedFormControls` alongside these browser checks.
Fresh login never watches another tab.
See [per-flow login destinations](../../threat-hunting/references/redirects.md#per-flow-login-destinations).

`core/js/login.js` uses `loginform`, `authenticators`, `username`, `realm`,
`user_actions`, `user_register_link`, `forgot_username_link`,
`contact_support_link`, `bookmarks`, `qr`, `show-qrcode`, `qrcode`, and
`close-qrcode`. Keep the existing
`showLoginForm`, `hideLoginForm`, `showQRCode`, and `hideQRCode` calls and their
arguments. Preserve `.hidden` and `sm:block` semantics; blanket display rules
can expose inactive forms or break toggling. Identity-provider `.endpoint`
links and local-realm form selection are distinct paths through the loop.

### QR controls

The basic login's `qr` panel belongs inside `.app-container`, after the login
form and authenticator list; it does not append a second panel below the card.
The container remains a DOM wrapper even when the phone stylesheet removes its
visual surface. `showQRCode(path)` records the visible `loginform` and/or
`authenticators`, hides them, replaces `qrcode`'s children with one image, and
reveals `qr`. Repeated opening is a no-op. `hideQRCode()` removes the image,
hides `qr`, and restores only the recorded panels; repeated closing is a no-op.

Preserve the username, selected realm, and registration/recovery/support links.
Do not call `showLoginForm()` to close QR mode: it clears the username and may
select a different view. Single-realm login, provider selection, a selected
local realm, and external-provider-only markup must all remain usable.

Use `type="button"` for `show-qrcode`, `qrcode`, and `close-qrcode`; the latter
two call `hideQRCode()`. Keep the visible Close QR Code label and accessible
names on the icon and image buttons. The bookmark has `aria-controls="qr"` and
updated `aria-expanded`. Opening focuses Close QR Code; closing focuses the
bookmark, or a restored login control if a narrow resize has hidden it. Escape
closes only an open QR view. Keep keyboard focus visible on the borderless image.

The bookmark's `hidden sm:block` classes expose it at widths of 640px and above,
including tablets. Phones do not get a new QR opener. A QR view opened before
resizing stays usable at phone widths and can still be closed. Preserve these
responsive semantics when adjusting markup or CSS.

Build the image request from `.ActionEndpoint` and `/qrcode/login.png`.
`pkg/authn/respond_qrcode.go` generates its PNG at runtime; this image is not a
brand asset or the sandbox's OTP-enrollment QR. The UI change does not add an
authentication method. Older filesystem login templates need the new panel and
close controls; replacing JavaScript alone does not relocate their QR view.

### Sandbox and registration hooks

In `sandbox.template`, preserve form action paths containing `.Data.id`, input
names, hidden values, and all MFA views. In particular, U2F code uses
`mfa-u2f-auth-form`, `mfa-add-u2f-form`, `webauthn_request`,
`webauthn_register`, `webauthn_challenge`, the submit controls, and `-rst`
elements. OTP setup uses fields such as `label`, `comment`, `secret`, `period`,
`digits`, `email`, `type`, `barcode_uri`, and `passcode`, plus QR/setup controls.
This is a guide to fragile areas, not a replacement for inspecting all selectors.

Retain conditional `sandbox_mfa_add_app.js`, `cbor.js`, and
`sandbox_mfa_u2f.js` loads and the WebAuthn initialization blocks. Some scripts
also depend on child structure: for example `getQRCode` in
`sandbox_mfa_add_app.js` accesses the no-camera link via `childNodes[1]`.
Changing wrappers can therefore break a page even when its IDs survive.

Registration uses `registrant`, `registrant_password`, `registrant_email`,
`first_name`, `last_name`, `registrant_code`, `accept_terms`, and
`registration_code`, with conditions and validation attributes from the server.
Its inline scripts reference these fields, `alerts`, and `registered-section`;
preserving `register.js` alone does not preserve those interactions. Avoid
adding theme scripts that read or persist credentials.

## Refresh-Aware Portal and Session Pages

Older themes can predate both the session page and the portal refresh hook.
Add the current functional pieces when updating such a theme for a newer
runtime. Keep this portal block with its condition and attributes:

```html
{{ if .Data.refresh_enabled }}
<script src="{{ pathjoin .ActionEndpoint "/assets/js/refresh.js" }}" data-base="{{ .ActionEndpoint }}" data-session="{{ .Data.refresh_session }}" data-expires="{{ .Data.refresh_expires }}"></script>
{{ end }}
```

For a custom `session.template`, keep `id="session-message"`, conditionally
render `id="session-logout"` for logout with `type="button"`, retain the sign-in
link ending in `/login?fresh=1`, and retain the no-JavaScript explanation. Keep
the client element from the current baseline:

```html
<script src="{{ pathjoin .ActionEndpoint "/assets/js/refresh.js" }}" data-base="{{ .ActionEndpoint }}" data-action="{{ .Data.session_action }}" data-next="{{ .Data.session_next }}"></script>
```

`handle_http_session.go` sets `default-src 'self'; frame-ancestors 'none';
base-uri 'none'`. Use same-origin external styles, images, fonts, and scripts on
this page. Inline `<style>`, `style=` attributes, inline scripts, and event
handlers will not work under this policy. Style the existing action button
without changing its behavior. Add the normal CSS hook to the session head:

```html
{{ if .CustomCSSEnabled }}
<link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
{{ end }}
```

The current basic session template includes `.basic-theme`, `.app-page`, a
responsive content wrapper, logo, banner, metadata, favicon, and this custom
CSS hook. The card and banner are visible at tablet/desktop widths; the
[phone rules](basic-theme.md#phone-layout) remove their decoration. Older
filesystem copies may lack them; carry over the current structure and stylesheet
order when updating such a copy. There is no custom JavaScript hook.
[refresh-token-transports](../../refresh-token-transports/SKILL.md) owns renewal,
logout, and redirect behavior independently of template presentation.

## Optional cross-device login

Preserve `.Data.cross_device_enabled` when copying `login.template`. The action
must remain available even when registration/recovery/support links are hidden,
and in local-only, provider-only and mixed configurations. The `cross_device`
alias uses same-origin external assets and a restrictive CSP, so do not add
inline event handlers or scripts. Its data attributes and element IDs are
consumed by `core/js/cross_device.js`. Preserve explicit confirmation, matching
codes and cancellation controls. The ordinary login QR bookmark remains separate.
