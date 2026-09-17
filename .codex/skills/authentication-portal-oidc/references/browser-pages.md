# OIDC browser pages and portal themes

## Rendering boundary

`pkg/oidc/pages.go` owns browser page data, readable permission descriptions,
error negotiation and page response policies. `Options.RenderPage` is an
optional runtime callback, not persisted configuration. It accepts a `Page`
snapshot and context and returns complete escaped HTML or an error. The provider
calls it concurrently, after releasing its state and identity locks. A failure
returns a generic 500 JSON error and discards partial output. Never log the page:
its CSRF value and form-post fields are credentials.

Keep rendering outside the protocol decision and identity transaction. Handlers
queue a page in `oidcHTTPResponse`; `HandleHTTP` defers `sendResponse` until their
locks have been released. The callback receives `r.Context()` and a fresh page,
and must be safe for simultaneous requests. Buffer template execution before
returning bytes; never share a mutable per-request buffer or use a page snapshot
as authentication proof. A failed renderer must not send its partial form or
error text, automatically approve consent, or retry code issuance. The provider
owns status, headers, and delivery; the callback returns only HTML or an error.

The standalone provider uses `pkg/oidc/page.template`, with a nonce-bound
stylesheet and no dependency on a portal asset server. Portal construction wires
`Portal.renderOIDCPage` from `pkg/authn/oidc_ui.go` into that callback in
`pkg/authn/oidc_runtime.go`. It renders
`pkg/authn/ui/page_templates/basic/oidc.template` through the existing UI factory;
keep `pkg/oidc` independent of `pkg/authn/ui`. A nil `Options.RenderPage` selects
the standalone fallback. This runtime dependency has no parser directive or
serialized config field; portal overrides use the existing UI configuration.

## Page and template contract

The template alias is **`oidc`**, covering all three page kinds. A filesystem
override replaces the complete alias, so it must handle each branch:

| `Page.Kind` | Browser view | Required behavior |
| --- | --- | --- |
| `consent` | Account and requested permissions | POST `csrf` and `decision=allow` or `decision=deny` to `Page.Action` |
| `form_post` | Return to the registered application | POST every value for every key in `Page.Values` to `Page.Action`; preserve the manual Continue button and nonce-bound auto-submit script |
| `error` | Invalid, expired or unavailable authorization | Show `Page.Message`; do not invent a return URL or retry a consumed request |

The portal passes `Page` as **`.Data.oidc`** inside ordinary `ui.Args`.
`.ActionEndpoint` is the issuer mount, `.PageTitle` is the page title, and the
normal logo and metadata settings apply. Built-in pages load the local Roboto
font, `assets/css/oidc.css`, shared `assets/css/basic.css`, then
`assets/css/custom.css` when configured. Root and nested issuer mounts are
supported.

Inside `{{ with .Data.oidc }}`, dot is `oidc.Page`; outside it, dot is `ui.Args`.
The standalone template receives `Page` directly. Do not copy a standalone
template into a portal override without adapting that data root.

| Page data | Meaning and handling |
| --- | --- |
| `Kind`, `Title`, `Message` | Provider-selected view and copy; error content is `Page.Message`, not the outer `ui.Args.Message` |
| `BasePath` | Issuer mount used by the portal adapter's `Args.BaseURL`; join assets onto the outer `.ActionEndpoint` |
| `ClientName`, `Username` | Escaped display labels; neither is authentication evidence |
| `Permissions` | Requested scope descriptions with `Title` and `Description` |
| `UserInfoClaims`, `IDTokenClaims` | Readable claim labels for distinct disclosure locations; preserve separate groups |
| `Action` | Validated absolute consent or callback URL; use it directly, without `pathjoin`, normalization, or a theme-supplied replacement |
| `CSRF` | Hidden consent value; submit with exactly one `decision=allow` or `decision=deny` |
| `Values` | Form-post protocol fields, including success or error responses; render nested ranges rather than assuming one value or a successful code |
| `Nonce` | Fresh per-response CSP nonce; use on the form-post script and any permitted style block, never cache or reuse it |

Form-post is also used for registered error responses; its presence does not
mean access was granted. Keep `id="response"`, the POST form, and a real submit
button functional without JavaScript. Consent uses native submit buttons and
requires no script. The Foundation harness in
`server_oidc_conformance_e2e_test.go` currently clicks the first `name="decision"`
element; keep Allow before Deny in DOM order, or deliberately update and validate
that consumer with a layout change.

## Filesystem override

Use the existing `ui.Parameters.Templates` map; no new directive grammar or
configuration field is introduced:

```json
{
  "ui": {
    "templates": {"oidc": "/srv/auth-theme/oidc.template"},
    "custom_css_path": "/srv/auth-theme/theme.css"
  }
}
```

Copy the current built-in `oidc.template` before customizing. The complete
file is independently parsed by `html/template`. Keep contextual escaping,
form field names/values and actions, the form-post `id="response"`, and its
`nonce="{{ .Nonce }}"` script within the `.Data.oidc` context. Standard UI
`pathjoin` remains available for portal asset paths. Restart/reconfigure after
changing template or asset files. Configuring a theme does not change OIDC
registration or enable its provider.

The portal stylesheet is `pkg/authn/ui/core/css/oidc.css`. It uses `.oidc-page`,
`.oidc-card`, `.oidc-account`, `.oidc-permissions`, `.oidc-actions`, and
`.oidc-button` instead of the older `.app-*` components. The basic portal theme
adds shared `--brand-*` tokens, banner, background, and vector favicon; use the
[basic-theme owner](../../authentication-portal-themes/references/basic-theme.md)
for palette/artwork customization and the
[phone layout contract](../../authentication-portal-themes/references/basic-theme.md#phone-layout)
for the responsive shell. The portal's phone view removes the outer card and
ribbon and stacks its actions; the standalone provider template is a separate
surface and does not inherit those rules. OIDC's `--oidc-ink`, `--oidc-muted`,
`--oidc-accent`, and `--oidc-border` default to corresponding brand variables and
remain available for OIDC-only overrides. Scope component changes to `.oidc-page`
and check hover/focus states too. Keep custom CSS after the base stylesheets
using outer `.CustomCSSEnabled`.

Retain the title/section heading relationships, readable permission lists,
logo alt text, visible keyboard focus, and both consent actions. Allow long
application/account names and expanded claims to wrap and the document to
scroll on small screens. Avoid fixed card heights or clipping the action area.
The default buttons are at least 46px high at tablet/desktop widths and 56px
on phones. The browser test requires 44px and 56px targets respectively.
Preserve usable contrast and forced-colors borders when restyling.

## Response policy

The provider owns response status, no-store caching, referrer policy,
anti-framing and CSP. Styles, fonts and logos must be served from the same
origin; use registered local assets for remote branding. Styles may also use
the supplied nonce on a `<style>` element; that does not authorize `style=`
attributes. Data URLs and remote asset origins are not enabled by the policy.
Consent and error pages do not permit scripts; the only script permission on
form-post pages is the per-response nonce. The built-in OIDC template does not
load custom JavaScript. Custom head markup remains subject to these policies.

| Page kind | Referrer policy | Form destinations |
| --- | --- | --- |
| `consent` | `same-origin` | Self plus the validated effective callback origin |
| `form_post` | `no-referrer` | Validated effective callback origin |
| `error` | `no-referrer` | Self; the built-in view has no form |

Do not add unsafe-inline or relax form-action to make a theme work. Consent
allows the callback origin because Chrome checks the redirect after the
same-origin POST too. Use the effective authorized redirect, including the
selected port for an allowed native loopback client; do not infer it from the
client name or accept a destination from template input. Server validation
still binds the complete redirect URI, not merely its CSP origin.

Consent's `same-origin` referrer policy keeps native form POST Origin headers
compatible with strict server origin checks and withholds cross-origin
referrers. Replacing it with `no-referrer` causes Chrome to serialize the POST
Origin as `null`, and valid consent is then rejected. Do not accept
`Origin: null` or bypass CSRF to compensate. See the
[Fetch Origin algorithm](https://fetch.spec.whatwg.org/#append-a-request-origin-header)
and [CSP form-action checks](https://www.w3.org/TR/CSP/#directive-form-action).

## Disclosure and errors

Consent describes requested scopes once, with extra individual UserInfo claims
and ID-token claims in separate readable groups. An individual UserInfo claim
already described by a scope is omitted only from the duplicate presentation;
consent tracking still records every scope and individual location/name. Claims
sent directly during sign-in remain explicit even if their scope is requested.
Do not describe pending permissions as approved or display actual claim values.

Only local errors at `/oidc/authorize` and `/oidc/continue` become HTML when
`Accept` explicitly allows `text/html` with positive quality at least as high as
`application/json`. Wildcard-only/no-Accept callers and protocol endpoints retain
JSON errors. Combine repeated `Accept` fields before comparing quality values;
splitting a media list across header lines must not change the chosen format.
Status codes and safe registered error redirects remain unchanged;
`prompt=none` still returns protocol errors to the registered client without
interaction. `Vary: Accept` documents browser error negotiation. HEAD responses
have no body. These rules do not replace registered error redirects with local
HTML or turn token/UserInfo errors into web pages.

Local browser errors show generic recovery instructions; a 503 gets the
temporary-unavailability message. Renderer failures always return a generic
500 JSON `server_error`, even for an HTML request. Do not add an unchecked
return link, expose parser/template error details, or replay a consumed request.

## Diagnose rendering failures

| Symptom | Inspect first |
| --- | --- |
| Correct content with no styling or logo | Issuer-mounted asset URLs, status/MIME types, actual CSP violations, and local asset registration |
| Custom theme changes other pages but not OIDC | `oidc` override key, `.oidc-*` selectors, `.CustomCSSEnabled`, stylesheet order, and reconfiguration/cache state |
| Consent looks correct but POST fails with 403 | Native request Origin, effective Referrer-Policy, pending session and CSRF; exercise the real form rather than injecting an Origin header |
| Allow works but the callback is blocked | CSP `form-action` and the validated effective callback origin; test the redirect following consent as well as the form-post response |
| Continuation only works with JavaScript | `response` form ID, method/action, all hidden values, and a working manual submit button |
| An HTML request receives 500 JSON | Template execution or custom renderer failure; reproduce with synthetic page data without logging credential-bearing values |

Use `pages.go` and `oidc_ui.go` as the boundary when diagnosing a failure;
the template owns presentation, while the provider owns protocol decisions.

## Validation

- `pkg/oidc/pages_test.go`: permission presentation, escaping, content
  negotiation, nonce/form-action policies, renderer integration and failure.
- `pkg/authn/ui/oidc_test.go`: embedded/filesystem parity, every view, branding,
  escaping, stylesheet order and root/nested mounts.
- `pkg/authn/oidc_ui_e2e_test.go`: `TestE2EOIDCPortalTemplates` covers real TLS
  password login, root/nested mounts, built-in/custom templates and CSS, asset
  responses, invalid CSRF and null/foreign Origin rejection, denial, code
  exchange and independently verified ID tokens. Rejected submissions leave
  the original consent usable. `TestE2EOIDCTemplateExecutionFailure` checks that
  execution failures expose no partial template.
- `pkg/authn/oidc_ui_browser_e2e_test.go` and
  `pkg/authn/ui/testdata/oidc_browser_e2e.cjs`: `TestE2EOIDCThemedBrowser` covers
  Chrome password forms, desktop/mobile layout,
  focus, assets/CSP, extended permissions, allow/deny, automatic form-post and
  manual continuation with JavaScript disabled. The relying party receives real
  TLS callbacks and each successful code is independently redeemed and verified.
  It runs default/custom branding with refresh enabled and also exercises login,
  password, TOTP passcode submission, portal, identity, and logout pages. It checks
  320px/360px controls, the 430px phone composition, the 639/640px breakpoint,
  768px tablet views, and long application/account/brand labels. It also opens
  and closes the login QR view without losing form state. The
  [theme validation owner](../../authentication-portal-themes/references/basic-theme.md#validation)
  documents component geometry, QR controls, and responsive screenshot checks.
  A separate browser context tests logout so it cannot revoke the OIDC codes
  before Go redeems them.
- `pkg/oidc/provider_e2e_test.go`: standalone styled consent with its own host.
- `pkg/authn/ui/pages_test.go`, `static_test.go`, and
  `internal/tag/tag_test.go`: template/asset paths and MIME types, plus runtime
  struct registration and serialization exclusions. Update inventories when
  adding assets rather than relying on render tests alone.

The browser test runs in the default Go suite and uses Node 24 and headless
Chrome under the [browser engine policy](../../testing-and-ci/SKILL.md#browser-engine),
never Firefox. It uses the existing Chrome discovery helper (`refreshBrowserExecutable`); set
`AUTHCRUNCH_TEST_BROWSER` to an executable path if discovery fails. A missing
browser fails validation. The standard-library CDP driver needs no npm install;
`make test-ui` exercises login/QR and refresh JavaScript in Node simulations;
it does not launch Chrome or run this OIDC journey.
The Go fixture owns two local TLS servers, a disposable browser profile,
fixture-specific certificate SPKI trust, bounded execution, and process cleanup.
Keep that isolation instead of using a personal profile or global certificate
trust/bypass settings. The fixture's password goes to the driver on stdin.

The browser checks actual consent POST Origins, no cross-origin callback
Referer, loaded styles/logo, no CSP or script errors, visible Tab focus, and no
horizontal overflow at phone, tablet, and desktop widths. Go verifies callback method,
issuer/state binding, denial without a code, and independently verifies issued
ID tokens. The larger permission list and long-label layout are separate checks;
screenshots alone do not prove protocol behavior or accessibility compliance.

Custom-template E2E temporarily replaces the process-global `ui.StaticAssets`
registry and restores it in cleanup. Keep these cases nonparallel, or redesign
that shared-state isolation before parallelizing them.

Choose the commands for the affected layer; run the browser journey when
changing markup, styling, form behavior, or response policies:

```sh
make test TEST_DIR='./pkg/oidc/... ./pkg/authn/ui ./internal/tag' COVERAGE_DIR=.coverage/oidc-ui-packages
make test TEST_DIR='./pkg/authn' TEST='^TestE2EOIDC(PortalTemplates|TemplateExecutionFailure)$' COVERAGE_DIR=.coverage/oidc-ui-portal
AUTHCRUNCH_OIDC_SCREENSHOT_DIR="$PWD/.coverage/oidc-ui-screenshots" make test TEST_DIR='./pkg/authn' TEST='^TestE2EOIDCThemedBrowser$' COVERAGE_DIR=.coverage/oidc-ui-browser
```

Without `AUTHCRUNCH_OIDC_SCREENSHOT_DIR`, screenshots go to a temporary directory.
With the example above, inspect `consent-desktop.png`, `consent-mobile.png`,
`permissions-mobile.png`, `continuation-mobile.png`, and `error-mobile.png` in
the ignored output directory. Failure capture uses `failure.png`. All fixtures
also capture `login-desktop.png`, `login-mobile.png`, `password-mobile.png`,
`mfa-mobile.png`, `portal-mobile.png`, and `logout-mobile.png`. `login`, `portal`,
and `consent` also have `-phone.png` (430px) and `-tablet.png` (768px) captures.
The basic fixture adds provider-selection captures; QR captures use `qr-login`
and, for the basic fixture, `qr-providers`. Custom branding is under `custom/`.
The fixtures use disposable identities; diagnostics must not print codes, CSRF, credentials,
or full authorization/callback URLs. Keep artifacts out of tracked source.

Use `make ci-check` for the full implementation gate. Skill-only edits need
skill validation and source/reference checks, not another browser run. Chrome
coverage does not establish behavior in other engines, assistive-technology
usability, or Foundation certification. If changing selectors or error copy,
inspect the Foundation harness's interaction and evidence matchers too; use the
[conformance workflow](conformance.md) when actual plan execution is required.
