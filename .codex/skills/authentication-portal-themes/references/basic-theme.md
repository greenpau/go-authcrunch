# Basic theme branding and customization

Read this reference when changing the library's default `basic` theme or
branding a deployment that keeps its markup. Use
[configuration](configuration.md) for adapter syntax and filesystem/browser
paths, [template contracts](template-contracts.md) for functional markup, and
[brand assets](brand-assets-and-color.md) for artwork and contrast guidance.

Jump to [component proportions](#component-proportions-and-interaction-states),
[phone layout](#phone-layout), [palette generation](#changing-the-default-palette-and-svg-artwork),
[deployment overrides](#deployment-example-without-template-copies), or
[validation](#validation).

## Implementation and stylesheet order

All ten built-in aliases use `body.basic-theme`: login, sandbox, portal,
register, generic, whoami, apps_sso, apps_mobile_access, session, and oidc.
Each loads its original view CSS, then `assets/css/basic.css`, then optional
`assets/css/custom.css`. Sandbox's conditional MFA/password styles come before
both branding stylesheets. The shared stylesheet is handwritten source; changing
it does not require a Tailwind build, React rebuild, or `make templates`.

`pkg/authn/ui/core/css/basic.css` owns semantic brand tokens and the shared
card, heading, input, action, logo, banner, and background rules. Existing view
CSS still owns layout utilities and conditional content. Keep the shared rules
scoped to `.basic-theme`; do not override `.hidden`, authenticator brand colors,
or the profile application's CSS globally. Wider registration and identity
views use `.app-content-wide`; login and ordinary feedback use the narrower card
at tablet/desktop widths. The phone rules remove that outer card surface.

OIDC retains `oidc.css` and `.oidc-*` markup, with its color/surface defaults
bound to the shared brand tokens. Existing `--oidc-*` overrides still work for
OIDC-specific styling. The standalone `pkg/oidc/page.template` has its own
embedded styles and does not load this portal stylesheet. Its host can provide
`Options.RenderPage`; see the [OIDC owner](../../authentication-portal-oidc/references/browser-pages.md).

All built-ins use outer `.CustomCSSEnabled` from `ui.Factory.GetArgs()` for the
custom CSS link. A configured path registers the stylesheet and enables this
flag. Direct render fixtures must set the factory's `CustomCSSPath`; merely
creating `.Data.ui_options.custom_css_required` does not enable the new hook.
Filesystem overrides remain independent copies and must retain or add this hook.

## Shared token contract

Set variables on `.basic-theme` in custom CSS. Defaults are declared on `:root`
so body-scoped deployment overrides apply across the portal and OIDC views.

| Variables | Purpose |
| --- | --- |
| `--brand-page`, `--brand-page-image` | Viewport fallback color and image/gradient; `none` disables artwork |
| `--brand-surface`, `--brand-soft` | Card/control surface and secondary/account/permission regions |
| `--brand-ink`, `--brand-muted` | Main text and supporting copy |
| `--brand-primary`, `--brand-on-primary`, `--brand-primary-hover` | Primary actions, their text, and hover color |
| `--brand-border`, `--brand-control-border` | Decorative separators and visible input/secondary-action outlines |
| `--brand-focus` | Keyboard focus outline; check it against adjacent surfaces |
| `--brand-radius`, `--brand-shadow` | Card shape and elevation at tablet/desktop widths; the phone shell removes both |
| `--brand-logo-size` | Ordinary portal logo box, 96px at every width; OIDC independently uses 36px at tablet/desktop widths and 48px on phones |
| `--brand-banner-image`, `--brand-banner-height` | Card accent artwork and painted height, default 8px; hidden on phones |

The default palette is blue `#245bca`, navy `#172b4d`, muted slate `#52637a`,
white surfaces, and soft blue backgrounds. Action hover uses `#194ba9`;
control borders use `#8191a8`. Status colors and authenticator provider icons
remain distinct from the brand accent. Preserve readable red/green feedback and
QR contrast when extending the palette.

The default opaque pairs have calculated contrast of 14.10:1 for ink on white,
5.86:1 for muted copy on the soft surface, 6.13:1 for primary button text,
8.01:1 on primary hover, and 3.21:1 for control borders on white. Check the actual
composited colors after customization; these pairs do not certify every page.

Use a complete mapping for a palette change, for example:

```css
.basic-theme {
  --brand-page: #f1f5f9;
  --brand-page-image: url("../images/brand-background.svg");
  --brand-surface: #ffffff;
  --brand-soft: #f8fafc;
  --brand-ink: #0f172a;
  --brand-muted: #475569;
  --brand-primary: #1d4ed8;
  --brand-on-primary: #ffffff;
  --brand-primary-hover: #1e40af;
  --brand-control-border: #64748b;
  --brand-border: #dce4ef;
  --brand-focus: #1d4ed8;
  --brand-banner-image: url("../images/brand-banner.svg");
  --brand-banner-height: 8px;
}
```

These URLs are relative to the served CSS at `assets/css/custom.css`. They
work at root and nested mounts without a hardcoded portal prefix. To remove
decoration, use `--brand-page-image: none` and `.basic-theme .brand-banner {
display: none; }`. A gradient can replace either image variable. To use a
wide wordmark, override `.basic-theme .logo-img` with a bounded width and
`height: auto`; preserve `.LogoURL` and configured alt text. Use explicit OIDC
logo-row rules for a wide wordmark there.

## Component proportions and interaction states

The Soft Square SVG includes clear space for avatar crops. Its 96px image box
produces an approximately 68px visible mark; judge the artwork's optical size,
not only the element bounds. Adjust `--brand-logo-size` for a deployment rather
than removing the source SVG's safe area. Ordinary headings use 32px on desktop
and 28px on narrow screens.

`basic.css` also overrides legacy component geometry, not just colors. Field
labels use 18px text, 1.5 line height, left alignment, and a 16px gap before the
input. Text inputs and form actions have a 56px minimum height. Prefix icons
receive their own input inset; fields without icons retain ordinary padding.
`.app-form-actions` uses a 12px gap and wraps when needed; the password/MFA
submit action can occupy a full row below its secondary controls on mobile.
Preserve the action DOM order when changing responsive layout.

Provider and application rows use a fixed 64px icon column and vertically
centered 24px labels; below 640px these become 56px and 22px.
Rows share a 10px outer radius. Only the outer row owns the rounded
outline and clips its child backgrounds. Child panels must not retain their own
radii or shadows, which create seams. Provider icon colors remain independent.
Hover darkens the item surface when the pointer is over either panel, without
changing border thickness or geometry. Its background mixes `--brand-soft`
with 6% `--brand-ink`; its border uses 15% ink in the same surface color.
These tones follow palette overrides without using the saturated primary color
for hover. The containing link is a block with the
same radius so its keyboard focus ring follows the complete row. Keep that ring
outside the clipped row. `.app-link-list` leaves 24px below the Applications
introduction and 12px between rows. Measure the rendered introduction-to-row
gap; margins can collapse through its wrapper rather than add together.

The login QR view replaces the active login items within the content area while
keeping the brand heading. `.app-qr-image` is a borderless, square-cornered button
with a white quiet area around the generated code. Its 280px outer width and
12px padding preserve the 256px image size; it shrinks within narrow viewports.
Keep this background white even with a dark custom palette. Do not add a
decorative frame or remove its keyboard focus outline. `.app-qr-close` leaves
a 24px gap below the image button. Both the image and Close QR Code restore the
previous login view; see the [QR contract](template-contracts.md#qr-controls)
for state and keyboard behavior. The dynamically generated QR PNG is functional
content, separate from the SVG-only brand assets.

The default card accent is an 8px blue/navy horizon, separate from the viewport
artwork. Its element retains a minimum height equal to the card radius so the
painted strip follows the full top corner curve; it does not round an 8px-high
rectangle independently. `--brand-banner-height` sets the painted image height,
and larger custom banners still work. The decorative element clips itself,
without cropping form controls or focus rings elsewhere in the card.

## Phone layout

Below 640px, ordinary portal pages and OIDC views use the page background as
their surface. Keep `.app-container` and `.oidc-card` in the DOM for their
structure and scripts, but remove their background, border, radius, shadow, and
padding. Hide `.brand-banner` completely, including custom artwork; it must not
leave an empty strip. The existing SVG background and palette still apply.

The page shell supplies one 24px side gutter, 32px top spacing, and 40px bottom
spacing, each augmented by the corresponding safe-area inset. `100svh` provides
a minimum page height without imposing a fixed height on long forms. Keep
natural scrolling and visible focus outlines. Avoid adding a second gutter to
the container or OIDC sections. Ordinary logo/title rows stack on phones, with
the existing 96px logo and 28px heading. OIDC keeps a compact 48px brand row and
uses full-width, vertically stacked actions with 56px minimum touch height.

The phone rules are confined to `max-width: 639px` in `basic.css` and
`oidc.css`; this is a viewport breakpoint, not device detection. A rotated
phone whose viewport becomes 640px or wider uses the tablet/desktop shell.
From 640px upward, retain the existing card, ribbon, spacing, and typography.
Filesystem custom CSS still loads last and can override these rules. The
separate embedded React profile application does not inherit this stylesheet.

Check phone text and focus contrast against the actual page background after
palette changes: the desktop card no longer shields them from that artwork.
Use the [palette guidance](brand-assets-and-color.md#color-palettes-and-tokens)
when a deployment combines a dark page with a light card.

## Artwork ownership and replacements

The default vector assets are under `pkg/authn/ui/core/images/`. The selected
Soft Square mark uses short blue/navy links, thick even bands, and open crossings:

| Asset | Role and replacement |
| --- | --- |
| `logo.svg` | Transparent Soft Square mark; override with `logo_url` plus a registered local file |
| `favicon.svg` | Larger Soft Square mark on a light rounded badge; every basic page declares this SVG icon |
| `banner.svg` | Saturated blue/navy horizon with a light upper edge, used as a slim card accent; replace its registered key or CSS image variable |
| `background.svg` | Layered radial light and flowing contour lines concentrated at the viewport edges, with a quiet center behind the card; no logo repetition |

The PNG/ICO branding files and their template fallback links have been removed.
Update older filesystem templates that still reference those files to use
`assets/images/favicon.svg` with `type="image/svg+xml"`.

SVG artwork uses explicit colors and cannot inherit CSS variables through an
`<img>` or background URL. Changing `--brand-primary` does not recolor the icon,
banner, or background file. Supply matching assets or a CSS gradient when
changing a palette. Keep essential instructions and titles in HTML, and use
decorative artwork without baked-in text. Check the favicon at 16px and 32px;
inspect the background at phone and desktop widths and the visible banner at
tablet/desktop widths. Neither decorative asset repeats the chain-link mark.

The built-in vector favicon has the fixed URL `assets/images/favicon.svg`.
Register a replacement at that key to customize it without changing templates.
Keep file content, extension, and MIME type consistent. For a different favicon URL
or additional icon sizes, override the affected templates' `<head>` markup.
A banner here is visible decoration, not an Open Graph/share image. Metadata
preview banners require separate head markup and crawler-compatible assets.

## Changing the default palette and SVG artwork

`assets/branding/palette.json` is the single color source for the checked-in
defaults. `assets/branding/soft-square.svg` is the editable geometry source;
its `brand-primary` and `brand-ink` path IDs bind the two palette colors.
SVG title/description metadata may be omitted or reordered; the generator adds
the favicon description and places its badge behind the source geometry.
Keep their link geometry, proportional curves, and transparent crossings intact
when changing color. Edit the palette rather than each generated SVG:

```sh
make brand-assets
make brand-assets-check
```

`primary` and `ink` color the mark and matching accents; `primary_hover`,
`on_primary`, `muted`, `surface`, `soft`, `page`, `border`, and `control_border`
control the shared UI colors. `banner_edge` colors the accent's upper highlight;
`background_start`, `background_middle`, `background_end` set the backdrop wash.
The background's radial light and contours use `primary`, `ink`, and `surface`
with explicit opacity, so recoloring does not require editing individual stops.
Use six-digit hex values and update the complete palette for a new color scheme.
Recheck foreground/background contrast after recoloring.

`assets/scripts/update_brand_assets.py` regenerates the four core SVGs, their
three profile copies, the marked color block in `basic.css`, and profile theme
metadata. It preserves the rest of the CSS and profile HTML. `--check` reports
drift without writing; `make ci-check` includes this check. Inputs are validated
and all outputs rendered before writing. Generated SVGs contain native paths
and explicit colors, with no embedded raster image or external dependency.
This workflow changes build-time defaults, not portal configuration or runtime
CSS inheritance. Deployment overrides can still use `custom.css` and registered
replacement SVGs without rebuilding the library.

The embedded profile's `logo.svg`, `favicon.svg`, and `images/banner.svg` use
the same artwork. Its manifest points to the SVG logo with `sizes: any`, and
its head declares the SVG favicon. The PNG Apple touch-icon link is removed.
Maintain `pkg/authn/ui/apps.go` registrations and these metadata links when
refreshing the embedded profile assets; this command does not rebuild its React
application. Old profile PNG/ICO icons and the JPEG banner are no longer bundled.

## Deployment example without template copies

This is the `ui` object inside a portal configuration, not a complete server
configuration. Every path must exist in the server's runtime environment:

```json
{
  "theme": "basic",
  "meta_title": "Example Company",
  "meta_description": "Sign in to Example Company services",
  "logo_url": "/assets/images/brand-logo.svg",
  "logo_description": "Example Company",
  "custom_css_path": "/srv/auth-theme/theme.css",
  "static_assets": [
    {"path": "assets/images/brand-logo.svg", "content_type": "image/svg+xml", "fs_path": "/srv/auth-theme/logo.svg"},
    {"path": "assets/images/favicon.svg", "content_type": "image/svg+xml", "fs_path": "/srv/auth-theme/icon.svg"},
    {"path": "assets/images/brand-banner.svg", "content_type": "image/svg+xml", "fs_path": "/srv/auth-theme/banner.svg"},
    {"path": "assets/images/brand-background.svg", "content_type": "image/svg+xml", "fs_path": "/srv/auth-theme/background.svg"}
  ]
}
```

Pair this with the CSS above. Reconfigure/restart to reload files, then refresh
browser caches. No new UI fields, theme names, or directive parser are introduced;
these are existing `ui.Parameters` hooks and static CSS variables.

The static asset registry is process-global. Fixed favicon/custom CSS keys are
shared across portals in the same process. Independent simultaneous brands
need distinct asset keys and template links, including favicon links. Do not
promise per-portal isolation from different filesystem paths alone.

## Page policies and upgrade compatibility

Session pages use the shared responsive shell, logo, metadata, favicon, and
custom CSS hook, including the card and banner at tablet/desktop widths.
Preserve `session-message`, conditional `session-logout`, the fresh-login link,
and the external refresh script's attributes. These pages still block
inline CSS/JavaScript. OIDC's stricter resource and form policies are owned by
the [OIDC reference](../../authentication-portal-oidc/references/browser-pages.md#response-policy).
Use local assets for a theme intended to work on every enabled page. The custom
CSS hook does not enable custom JavaScript on session or OIDC pages.

Older filesystem themes may omit `basic.css`, `body.basic-theme`, the banner,
the vector favicon, or the custom CSS hook. Compare them to the current baseline
before adopting these features. Existing pages using `.app-*` remain separate
from OIDC markup, even though shared variables now style both. Do not remove
view-specific styles or scripts while adding the common visual layer.

Keep interactive actions outside cropped decorative regions. Long registration,
MFA, permission, and identity content must scroll without clipping controls.
Preserve focus outlines, forced-colors boundaries, and at least 44px touch
targets for the main actions. Artwork validation is not an accessibility claim.

## Validation

Asset renames also affect browser journeys outside the theme tests.
`pkg/authn/ui/testdata/cookie_browser_e2e.cjs` checks `/favicon.svg` and its MIME
type after real login across cookie-prefix configurations. Run
`TestE2ECookieBrowserLogout` when changing that public asset alongside the theme
and OIDC checks below.

`pkg/authn/ui/basic_theme_test.go` renders every alias and sandbox/registration/
session/OIDC branch with custom CSS enabled and disabled, root/nested mounts,
escaped branding, and embedded/filesystem parity. It checks final stylesheet
ordering, single/multiple-authenticator forms and links, and the session
DOM/script contract. `static_test.go` verifies all
embedded asset paths, MIME types, and counts.

`TestBasicThemeBrandAssets` checks that the portal and profile libraries serve
matching SVG artwork, the profile manifest resolves to a registered SVG icon,
and retired PNG/ICO files are absent. The portal template E2E checks the real
mounted asset URLs and removal of the old files. The branding automation tests
exercise palette validation, native path preservation, executable recoloring,
read-only drift detection, and rejection before any output is rewritten. They
also verify that decorative paint uses the supplied palette and all local SVG
paint references resolve uniquely, without external resources.

`TestE2EOIDCThemedBrowser` runs the real TLS portal with default branding and a
custom palette/logo/favicon/banner/background. Its Chrome driver checks login,
password, OIDC consent/continuation/errors, portal, identity, and logout pages;
it submits real login, consent, and logout controls. It verifies computed colors,
asset decoding, focus, responsive layout, and CSP while preserving independent
code exchange and ID-token verification. The OIDC owner documents fixture
isolation and [browser commands](../../authentication-portal-oidc/references/browser-pages.md#validation).
Custom asset cases restore the global registry and must not run in parallel.
The mobile action-row regression checks 320px and 360px password views and
asserts that controls stay inside their content area, not merely inside the
viewport.
The default browser fixture configures four real local realms to exercise
provider selection and Back; the custom-theme fixture retains single-realm
login. Both include application links with different icons. Geometry checks
cover logo size, label line height/insets, label-to-input and introduction-to-list
gaps, text/icon centering, input-to-action spacing, and multi-line navigation
labels.
Pointer and keyboard checks verify the rounded hover/focus outline and absence
of layout shifts. These checks complement visual review; overflow checks alone
do not establish good proportions.

`make test-ui` includes `login_client_test.cjs` for QR state restoration,
repeated toggles, entered values, and keyboard/focus handling. The Chrome journey
opens and closes the real generated QR from provider selection and local login,
using the image, Close QR Code, and Escape. It checks keyboard opening and
closing, mounted image loading, content-area placement, mobile resizing, and
restored form state. Inspect `qr-providers-desktop.png`, `qr-login-desktop.png`,
and their `-mobile.png` variants for the borderless code and close-button gap.

Phone shell assertions verify transparent, borderless content with no shadow
or ribbon and a single side gutter. Responsive sweeps also check the 430px
phone preview, both sides of the 639/640px breakpoint, and 768px tablet views
for provider selection, local login, Applications, and OIDC consent. Screenshot
names ending in `-phone.png` and `-tablet.png` capture those layouts; retain the
existing desktop captures when checking that a phone-only edit stays scoped.

The Chrome driver measures resting colors after moving the pointer off controls
and considers only visible primary actions. Keep those distinctions when a
view hides the login form, such as QR mode. Hover checks deliberately move the
pointer over both panels; focus checks use keyboard events. Do not weaken the
geometry checks to compensate for a hidden control or leftover hover state.

Choose checks for the changed surface: template/CSS work uses the UI package
tests and Chrome journey; login interaction changes also use `make test-ui`;
palette/generator changes use `make test-automation` and `make brand-assets-check`
alongside the relevant asset/browser tests. Use `make ci-check` for the full
implementation gate. Skill-only edits need skill validation and source/link
checks rather than another implementation test run.

```sh
make test TEST_DIR='./pkg/authn/ui' COVERAGE_DIR=.coverage/basic-theme-render
AUTHCRUNCH_OIDC_SCREENSHOT_DIR="$PWD/.coverage/basic-theme-screenshots" make test TEST_DIR='./pkg/authn' TEST='^TestE2EOIDCThemedBrowser$' COVERAGE_DIR=.coverage/basic-theme-browser
make test-ui
make brand-assets-check
```

Inspect login, password, consent, continuation, error, portal, and logout
captures; custom-brand captures are in the `custom/` subdirectory. Test the
actual deployment's theme files separately. Theme fixtures do not certify all
external assets, assistive technologies, or browsers.
Provider and portal captures also include `*-hover.png` and `*-focus.png`;
review those corners at full resolution alongside the resting state.
`providers-wide.png` shows the 1700px viewport composition. Check the background
as a complete page and the banner at its actual painted height; opening each
SVG alone does not validate its crop or visual balance around the card.
Compare pre/post screenshots at the same viewport and state when preserving
tablet/desktop appearance. PNG screenshots and generated QR images are test or
functional content; the SVG-only rule applies to the shipped branding assets.
