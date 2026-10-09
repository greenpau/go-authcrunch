# Portal internationalization

## Language and ownership

The existing `ui.Parameters.Language` setting selects a portal language. Codes
and full English language names are normalized by `pkg/translate`; the portal
rejects unsupported configured values. An omitted setting selects English.
There is no browser-header negotiation or runtime JSON catalog import.

`pkg/translate/data/messages.json` is the compiled catalog. Every message form
must contain en, de, fr, ja, zh, he, ar and ru, with the same interpolation
placeholders in each language. Messages are plain text. Keep stable message IDs,
translate complete sentences, and keep credentials, protocol values, account
names, application names and operator-authored branding out of translation.

Built-in portal templates, sandbox/MFA, registration, cross-device, session and
OIDC browser pages use the selected language. The bundled React profile app is
built in its separate source project; template localization does not translate
that app. Filesystem template copies also need their own markup updates.
Provider-supplied custom titles and policy hints remain provider-owned.
Default page titles, logo descriptions and page metadata are localized; explicit
operator overrides are preserved. Persisted credential labels and ASCII-constrained
MFA enrollment defaults remain data rather than translated interface copy.

## Template and script contract

`ui.Factory.GetArgs` snapshots the normalized language into `ui.Args.Language`.
Use `{{ .LanguageCode }}` and `{{ .Direction }}` on the document element. Arabic
and Hebrew use `rtl`; other supported languages use `ltr`. Zero-value rendering
arguments fall back to English. Keep verification codes, including registration
email confirmation and MFA inputs, JSON and sign-in URLs explicitly `dir="ltr"`;
use `dir="auto"` for account/application names. Translate surrounding labels
without changing the code's direction or validation rules.

Use `{{ .Translate "message_id" }}` for static copy, including alt text,
accessible names, validation hints and buttons. One optional argument supplies
`{{.Value}}`, for example `{{ .Translate "mfa_lifetime" 30 }}`. Existing
handler-populated `.Data.i18n_*` bindings remain supported for custom templates.

External scripts receive only the messages they need:

```html
<script src="{{ pathjoin .ActionEndpoint "/assets/js/cross_device.js" }}"
  data-base="{{ .ActionEndpoint }}"
  data-i18n="{{ .Messages "cross_device_waiting" "cross_device_cancelled" }}"></script>
```

`Messages` returns an ordinary JSON string. Let `html/template` escape the
attribute; parse it with `JSON.parse` and assign resulting text with `textContent`
or a text node. Do not use `template.HTML`, `template.JS`, `innerHTML`, inline
translation catalogs or relaxed CSP. Existing inline template scripts must keep
Go's contextual JavaScript escaping for translated strings. Retain English script
fallbacks for older filesystem templates that omit message attributes. Translate recovery messages
instead of displaying browser-dependent exceptions; keep protocol status values
and decision/form fields unchanged.

Sandbox HTML failures display localized recovery copy while retaining the
original error in diagnostic logging. Shared generic HTML errors also need
localized headings and document titles: handler-supplied `http.StatusText`
values bypass template translation. Cover common statuses and a translated
fallback for other errors, preserving the numeric HTTP status, media type,
cache policy and diagnostic text. Plain-text and JSON protocol errors remain
separate from browser-page copy. `registry.LocalizedUI` is an optional
provider capability for the default title and username/password policy hints;
the local registry implements it without changing validation rules. Custom
providers that omit it retain their existing methods and text.

The portal passes its language to runtime `oidc.Options.Language`. Provider page
snapshots contain localized titles, permission/claim descriptions and errors,
plus `Page.Language`. The standalone template and portal OIDC template share
`Page.Translate`; no new provider/client configuration directive is introduced.
OIDC consent, form-post hidden values, origin checks and CSP remain unchanged.

## Validation and visual review

Run the focused package tests and real browser journey:

```sh
make test TEST_DIR='./pkg/authn/ui ./pkg/translate ./pkg/registry ./pkg/oidc' \
  TEST='Test(I18N|Catalog|Localized|OIDCLocalizedPages)'
make test TEST_DIR='./pkg/authn' TEST='TestI18N'
AUTHCRUNCH_I18N_SCREENSHOT_DIR="$PWD/tmp/i18n-review/screenshots" \
  make test TEST_DIR='./pkg/authn' TEST='^TestE2EI18NBrowser$'
make test-ui
```

Catalog checks reject missing languages, mismatched placeholders, markup and
accidental mixing of Arabic and Hebrew scripts. These checks complement a review
of the actual wording; valid Unicode and a complete catalog do not prove a
translation is correct.
The template inventory rejects untranslated visible/accessible literals and
renders every built-in branch in all eight languages at root/nested mounts.
Preserve unit cases for escaped interpolation, JSON attribute round trips,
independent portal language snapshots, registry policy bounds and OIDC claim
labels. Add browser/consumer coverage with tests, not just source scans.

Chrome exercises French, Arabic, Hebrew and Japanese through real TLS
generic HTTP error pages (including missing registration realms and invalid
sandbox sessions), registration rejection, delivered-email confirmation,
wrong-code rejection and confirmation replay; password rejection/retry;
cross-device copying/cancellation/approval with independent requester/approver
contexts; OIDC denial and manual
form-post redemption; identity, logout, TOTP, MFA enrollment and session recovery.
Registration browser tests consume the delivered confirmation email, not portal
cache state, and verify that rejection/replay cannot send another notification.
Security-key browser rejection is injected after a real login to verify localized
recovery without requiring physical hardware. It checks default metadata,
document direction, LTR codes and small-phone/desktop geometry. Existing English
browser journeys still guard custom themes, legacy templates and protocol behavior.

Inspect screenshots as well as overflow assertions. A button can fit its box
while wrapping a label into a tall column. Registration actions stack on phones
so translated labels remain readable. Keep account names, codes and control
focus visible in RTL layouts and long translations. Give ordered lists space for
their markers at the inline start; left-only indentation leaves RTL markers
outside the content column even when the page has no horizontal overflow.

Wait for the document, fonts and visible images before capturing. Reset scroll
and wait for animation frames before a full-page screenshot. Use viewport captures
when all content fits; unnecessary full-page clipping can shift RTL captures
after viewport resizing even when DOM geometry is correct. For wrapped inline
links, click an actual client rectangle: the aggregate bounding box can contain
empty space between lines and make an otherwise valid browser journey time out.
