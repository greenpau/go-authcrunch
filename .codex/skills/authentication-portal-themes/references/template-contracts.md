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

Use `pathjoin` for path segments only; append a query string after the joined
path. Do not use it to construct an absolute `https://` URL. Keep Go's contextual
HTML/URL/JavaScript escaping and avoid introducing raw HTML helpers for branding.

## Pages and Their Functional Content

| Alias | Preserve while changing presentation |
| --- | --- |
| `login` | `.Data.login_options` branches, authenticator loop, username/realm POST, registration/recovery/support visibility, QR controls |
| `sandbox` | Every `.Data.view` branch, server-provided sandbox ID, credential forms, MFA setup/challenge controls, cancel/retry/error views |
| `portal` | `.PrivateLinks` loop with target/icon flags, sign-out navigation, conditional refresh script |
| `register` | `register`, `registered`, `ack`, `ackfail`, `acked` views; realm/registration IDs, policy attributes, terms/code conditions, alerts and inline DOM consumers |
| `generic` | `.Data.message`, optional `.Data.go_back_url`, page title; used for more than a single success screen |
| `whoami` | Escaped `.Data.token` JSON display, Highlight.js assets/initialization, portal and logout links |
| `apps_sso` | Numeric `.Data.role_count`, `.Data.roles` entries with `ProviderName`, `AccountID`, and `Name`, generated role links and empty state; this is the AWS SSO role-selection page |
| `apps_mobile_access` | Instructional content and navigation; the current baseline does not itself render a mobile QR image |
| `oidc` | All `.Data.oidc.Kind` branches: consent CSRF/decisions, form-post action/values/nonce/manual Continue, and local error message; see the [owning contract](../../authentication-portal-oidc/references/browser-pages.md#page-and-template-contract) |
| `session` | `.Message`, continuation/logout action, confirmation button, fresh-login link, external refresh client and data attributes |

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
order when updating such a copy. There is no custom JavaScript hook. For changes
to renewal, logout, or redirects, use
[refresh-token-transports](../../refresh-token-transports/SKILL.md).
