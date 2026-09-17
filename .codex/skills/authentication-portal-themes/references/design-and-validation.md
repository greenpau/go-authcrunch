# Visual Design and Validation

## Branded Page Structure

Keep the original form/conditional structure and page scripts, then apply a
common visual layer to metadata, logo, background, surfaces, inputs, buttons,
tables, alerts, and responsive layout. Use separate assets for the small brand
mark, visible card accent, and decorative page background. A metadata/share
banner is a separate deliverable when requested.

Follow the user's brand identity without hardcoding an industry, motif, or
palette into the workflow. An older custom theme may predate `session` or
`oidc`; use the current baseline to extend the chosen design onto enabled pages.

## Theme Structure and CSS

The current basic theme already maps shared `--brand-*` tokens to its portal
and OIDC components. Use [basic-theme.md](basic-theme.md) for the implementation,
variables, artwork hooks, and stylesheet order. The guidance below also applies
to older or substantially different filesystem themes.

Define a small set of brand variables for ink, muted text, surface, background,
primary/hover colors, border, shadow, and corner radius. Apply them to existing
portal components. Use a theme-specific class such as `brand-body` to scope
overrides, including any overrides of utility classes. Retain page-specific
base styles and then load the shared theme styles.

For a theme with common CSS repeated inline in each template, a shared
`theme.css` is often easier to maintain and can also work on the session page.
Keep Go expressions in `.template` files, not static CSS. Use relative asset
URLs as described in
[configuration.md](configuration.md#filesystem-paths-versus-browser-urls).

Do not rely on new Tailwind-style utility names being compiled for filesystem
templates: the shipped page CSS is already built. Define actual CSS for new
colors and components. Load overrides after view-specific CSS too. Current
basic templates put conditional sandbox styles before `basic.css` and custom
CSS; older copies may load `mfa_app.css` or `password.css` after their custom
hook. Correct that ordering when upgrading, then check all sandbox views.

Useful component groups:

| Surface | Existing selectors and design considerations |
| --- | --- |
| Page shell | `.app-page`, `.app-content`; full-height background, readable foreground, responsive margins |
| Content wrapper | `.app-container` on ordinary pages, including generic/session; `.oidc-card` on OIDC views; floating card only at tablet/desktop widths |
| Logo/header | `.logo-box`, `.logo-col-box`, `.logo-img`, `.logo-txt`, `.logo-col-txt`; retain page titles and configurable alt text |
| Credentials | `.app-inp-box`, `.app-inp-txt`, `.app-inp-code-txt`, `.app-inp-sel`, `.app-gen-inp-txt`, `.app-inp-prf-img`; align icons, keep visible focus and unclipped controls |
| Actions | `.app-btn-pri`, `.app-btn-sec`, `.app-login-btn-*`, `.app-portal-btn-*`; distinguish primary, secondary, hover, focus, disabled states |
| Feedback/data | `#alerts`, `.toast-error`, tables, `pre`; preserve readable error messages and overflow for long identities/roles |
| QR controls | `#bookmarks`, `#show-qrcode`, `#qr`, `#qrcode`, `#close-qrcode`; replace active login items and restore their state; keep the code borderless with visible keyboard focus |
| OIDC | `.oidc-page`, `.oidc-card`, `.oidc-account`, `.oidc-permissions`, `.oidc-actions`, `.oidc-button`; distinct markup with shared brand tokens and custom CSS loaded last |
| Branding | `body.basic-theme`, `.brand-banner`; shared page background, card artwork, semantic colors, and a configured logo/icon |

One approach uses `isolation: isolate` on the page with decorative fixed
pseudo-elements behind the content and `pointer-events: none`. This makes
layered backgrounds possible without intercepting form interaction. A plain
background image is also suitable; do not require blur or animation. Maintain
an opaque-enough surface when backdrop filtering is unavailable.

Use separate widths for narrow credential flows and wide registration,
identity, or role-list pages. The built-in basic theme becomes a full-page
layout below 640px: remove the outer card and ribbon, use one page gutter, and
retain the tablet/desktop shell above that breakpoint. See the
[phone layout contract](basic-theme.md#phone-layout) before changing these rules.
Keep the logo optically readable, allow form columns to stack, and scroll long
code/tables within their own regions. Avoid fixed heights that crop MFA
enrollment. Check long labels, translated strings, and errors as well as the
initial login view. If adding
motion, include a reduced-motion alternative.

## Logo, Favicon, Banner, and Background

Use [brand-assets-and-color.md](brand-assets-and-color.md) for suggested sizes,
SVG/raster exports, logo clear space, banner composition, background cropping,
file-size budgets, and light/dark palettes. These are design choices rather
than AuthCrunch configuration requirements. Use
[configuration.md](configuration.md) for asset registration and template URLs.

Give the card accent and page background distinct compositions. Reusing a
backdrop fragment above the form creates a second competing band. In the basic
theme at tablet/desktop widths, a slim saturated accent anchors the card while
larger flowing contours and radial light frame the viewport. Keep decorative detail outside the main
reading area, and review a wide desktop capture as well as mobile crops.

## Validate the Theme That Will Ship

First parse every custom file using `ui.NewTemplate(alias, filePath)` from the
application's pinned AuthCrunch version. A parse only checks syntax; render
representative branches with `ui.Factory.Render` and handler-shaped `ui.Args`
to catch missing fields, incorrect comparisons, and escaping problems. Use
`GetArgs()` and `BaseURL()` instead of inventing template helpers or treating
the templates as static HTML.

`pkg/authn/ui/ui_test.go` contains examples for factory loading and page data.
A minimal login render in a temporary Go harness looks like this (the imports
are `fmt`, `log`, `os`, and `github.com/greenpau/go-authcrunch/pkg/authn/ui`):

```go
f := ui.NewFactory()
f.Title = "Example sign-in"
f.MetaTitle = "Example Company"
f.LogoURL = "/assets/images/brand-logo.svg"
f.CustomCSSPath = "theme.css" // Enables the link in Args; does not serve CSS.
if err := f.AddTemplate("login", os.Args[1]); err != nil {
    log.Fatal(err)
}
args := f.GetArgs()
args.BaseURL("/xauth")
args.Data["i18n_provide_username_or_email"] = "Username or email"
args.Data["i18n_proceed_action"] = "Continue"
args.Data["login_options"] = map[string]interface{}{
    "form_required": "yes",
    "realm_dropdown_required": "no",
    "authenticators_required": "no",
    "hide_links": "yes",
    "default_realm": "local",
    "realms": []map[string]string{{"realm": "local", "default": "yes"}},
    "authenticators": []map[string]string{{"realm": "local"}},
}
page, err := f.Render("login", args)
if err != nil {
    log.Fatal(err)
}
fmt.Print(page.String())
```

Write temporary preview output outside tracked source. Supply synthetic data,
never real passwords, tokens, OTP enrollment secrets, or identity dumps. Inspect
rendered asset/form URLs, escaping sentinels such as `ZgotmplZ`, and missing
content. Verify both root and a non-root mount. Render checks do not execute
JavaScript or prove a working login.

Validate the consuming server's configuration with its actual entrypoint,
then use headless Chrome against a local preview or the application's approved
test environment for browser checks. Follow the repository's
[browser engine policy](../../testing-and-ci/SKILL.md#browser-engine); do not use
Firefox for theme testing. Serve assets at the same mount as the preview; a `file://` view
of HTML with `/xauth/assets/...` URLs is not a valid asset-loading test. Exercise
the applicable cases:

- Single local realm and multiple local/external authenticators; selection and
  back controls; registration/recovery/support visibility. Exercise the
  [QR transitions](template-contracts.md#qr-controls) from both selection and
  username views: click the image or Close QR Code, use Enter/Escape, reopen,
  and resize while open. Confirm values and focus survive the round trip.
- Password failure/retry, OTP authentication/enrollment, U2F/WebAuthn views,
  cancellation, and the longest enabled registration/acknowledgment view.
- Portal links/logout, generic feedback, identity overflow, and empty/populated
  SSO roles. Confirm the separate profile app behaves as expected when linked.
- Refresh enabled/disabled; continuation, logout confirmation, and fresh sign-in.
  Check the session page's actual CSP response for blocked inline resources.
- OIDC when enabled: consent with short/long identities and permissions, Allow
  and Deny, automatic and JavaScript-disabled form-post continuation, and local
  browser errors. Use the [OIDC validation matrix](../../authentication-portal-oidc/references/browser-pages.md#validation)
  for actual native-form/CSP behavior and the repository Chrome journey.
- Phone/tablet/desktop layouts, keyboard focus, readable contrast, error visibility,
  missing assets/MIME types, and console errors. Use hardware/browser testing
  when claiming WebAuthn behavior, not just a rendered enrollment screenshot.

Check component proportions beyond viewport overflow: rendered mark size,
label/input left edges and vertical gaps, text/icon centers, input/action
heights, and multi-line labels. Inspect provider and application rows while
hovering each panel and while focused by keyboard. Separate child corner radii
or backgrounds can hide the parent's outline even when the row's bounds are
correct. The [basic-theme component contract](basic-theme.md#component-proportions-and-interaction-states)
and Chrome geometry checks cover these regressions.

For phone-only changes, capture matching resting states before and after at
tablet/desktop widths; the style change should stay inside the phone media
query. Inspect 320px/360px forms, the 430px phone composition, and both sides of
the 639/640px boundary. Verify the phone shell has no card border, shadow, or
reserved banner gap, and that its background supports text directly. Keep
hover and keyboard focus reviews separate: a softer hover border does not mean
removing the focus outline. The QR image has no decorative frame in its resting
state, while the Close QR Code action remains an ordinary button.

Repository tests exercise embedded templates; they do not automatically load
files from the consuming application's theme directory. The OIDC tests also
exercise synthetic filesystem overrides; they still do not validate arbitrary
deployment theme files. If library UI source changes, use the `testing-and-ci`
skill, including
`make test TEST_DIR='./pkg/authn/ui'` and the affected handler tests; run
`make test-ui` for login or refresh client changes. For an external theme,
validate its actual files and runtime wiring. `make templates` is license
maintenance, not a custom-theme compiler; profile asset regeneration is a
different workflow.

On upgrades, compare the custom files with the new version's built-ins before
reapplying visual edits. Look especially for new aliases, changed form fields,
conditional views, and script hooks. Report the checks actually performed and
any untested flow instead of claiming a complete theme from one login render.
