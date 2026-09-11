# Brand Assets and Color

## Suggested Sizes

AuthCrunch does not impose a standard logo, banner, or background size. Use the
following as practical starting sizes, then adapt them to the user's brand and
actual layout. Raster dimensions are image pixels; display sizes are CSS pixels.
For a raster logo displayed at 96 by 96 CSS pixels, export at least 192 by 192
image pixels for a 2x display. An SVG's `viewBox` defines its drawing coordinates,
not a fixed display resolution. See [MDN's viewBox reference](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Attribute/viewBox).

| Asset | Suggested source or export size | Typical use |
| --- | --- | --- |
| Square logo | SVG with a square `viewBox`, e.g. `0 0 64 64`; PNG fallback at 256 by 256 or 512 by 512 | Display at 64–96 CSS px on desktop, 48–72 on mobile |
| Horizontal wordmark | SVG preserving the brand's ratio; e.g. a 400 by 100 artboard and 800 by 200 PNG export | Display about 160–240 CSS px wide; preserve height proportionally |
| Favicon | SVG with a simple square mark; PNG at 16 by 16 and 32 by 32; optional ICO containing 16, 32, and 48 px versions | Browser tabs; review at the actual 16 px size |
| Metadata/share banner | 1200 by 630 PNG or JPEG, approximately 1.9:1; retain an editable vector source if appropriate | `og:image` for link previews; check the target service's current requirements |
| Visible page banner | Start at 1600 by 400, a 4:1 ratio; use SVG for simple artwork | A wide strip in the page; adapt height to the actual card/header layout |
| Desktop background | 1920 by 1080 raster; 2560 by 1440 if the artwork benefits from more detail; SVG for patterns/geometry | Full viewport decoration with `background-size: cover` |
| Optional mobile background | 1080 by 1920 portrait raster or a separate vector composition | Use when the landscape crop loses its subject or becomes distracting |

Keep the SVG source for geometric artwork and export raster variants only when
needed. A 1600 by 1000 SVG background is also suitable: the composition and
cropping behavior matter more than matching a screen's exact aspect ratio.
Do not upscale a small raster source and call it a higher-detail asset.

## Logo and Favicon

Use the user's established mark when supplied. Prepare a full logo for the
portal and a simplified mark for small contexts if its wordmark/detail becomes
illegible. Start with roughly 10–15 percent clear space around the visible mark
unless the brand guide specifies otherwise. Inspect the optical size: excessive
empty space inside the file can make a correctly sized `<img>` look too small.

Preserve the source aspect ratio. Use `object-fit: contain`, never crop a logo
to fill its box, and set its display dimensions explicitly. For a square mark:

```css
.brand-body .brand-logo {
  display: block;
  width: clamp(3rem, 8vw, 5.25rem);
  height: clamp(3rem, 8vw, 5.25rem);
  object-fit: contain;
}
```

For a wordmark, use a bounded width with `height: auto` instead of this square
rule. Add the `brand-logo` class to the existing configurable logo element and
keep its `.LogoURL` and `.LogoDescription` bindings. Use meaningful alt text;
use empty alt text for a purely decorative duplicate of adjacent branding.
Give the standalone SVG a meaningful `<title>` and, for complex artwork, a
short `<desc>`; these do not replace the HTML image's alt text.

Provide light-surface and dark-surface variants if necessary. Inspect transparent
PNGs for a white/dark fringe and transparent SVGs against both surfaces. Do not
use a CSS inversion filter as a substitute for an approved logo variant; it
changes brand colors. If the mark relies on a badge, include the badge in its
artwork so it remains visible in browser tabs and across themes.

Simplify favicon strokes and omit small lettering. Register each exported file
and set the correct `type` and raster `sizes` on its icon link. Browsers choose
among icon candidates using attributes such as type and sizes; test the actual
targets rather than assuming one SVG handles every client. See
[MDN's icon link guidance](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Attributes/rel#icon).
App installation/touch icons are additional deliverables only when requested;
registering a portal logo does not configure a web app manifest.

## Banners

A metadata banner and a visible page banner have different jobs. Set `og:image`
for previews; add an `<img>` or a background region explicitly for an image that
should appear on the page. Do not automatically put a large marketing banner
above the sign-in form, especially on short mobile screens.

For a 1200 by 630 metadata banner, start with a 60 px inset on all sides, a
clear brand mark, a short title, and a restrained background. This inset is a
composition suggestion, not a guarantee against platform cropping. Keep
important content away from edges and review at a small preview size. Avoid
fine print, detailed UI screenshots, or credentials/personal information.

For social previews, start with PNG for flat artwork/text or JPEG for photos
and verify the target crawler's format support before using SVG or newer image
formats. Use a configured absolute public HTTPS image URL when needed; do not
derive a public hostname from `.ActionEndpoint`. The
[Open Graph protocol](https://ogp.me/#structured) supports `og:image:type`,
`og:image:width`, `og:image:height`, and `og:image:alt`. Set them to the exported
image's actual values. AuthCrunch does not supply a separate banner parameter;
register the asset and reference it in the custom template.

For a visible banner, keep essential headings/instructions in HTML. If the
whole graphic must remain visible, use `width: 100%; height: auto`. If the
design requires a fixed-height crop, choose a decorative image and use
`object-fit: cover` with a deliberate focal point. Preview both wide and narrow
layouts; do not crop a brand name or essential instruction.

## Backgrounds

Use the background to establish atmosphere while keeping the form easy to find.
Simple gradients, quiet geometry, or subdued photography are useful options.
Keep the center or intended form area quiet; distribute stronger visual detail
toward the edges. Avoid baked-in logos/text that will be cropped, repeated, or
covered by the card. A CSS gradient may be sufficient without an image file.

`cover` preserves the image ratio while cropping overflow; a landscape image
can lose most of its sides on a portrait phone. Adjust `background-position`
for the focal point or use a mobile composition. Use `contain` only when empty
space is intentional, and repeat only artwork designed to tile. See
[MDN's background sizing reference](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/Properties/background-size).

Example for an external stylesheet served at `assets/css/custom.css`:

```css
.brand-body .app-page {
  background-color: var(--brand-page);
  background-image: linear-gradient(rgb(0 0 0 / 20%), rgb(0 0 0 / 40%)),
    url("../images/brand-background.svg");
  background-position: center;
  background-size: cover;
  background-repeat: no-repeat;
}
```

Choose the overlay for the artwork and palette; the dark overlay above is an
example, not a requirement for light themes. Use an opaque card or a sufficiently
opaque surface over photography. Do not reduce the entire page's `opacity`,
which also fades its inputs and text. Preserve a solid fallback color when an
image cannot load. Keep decorative layers from intercepting input and avoid
expensive animated filters behind credential forms.

## Color Palettes and Tokens

Start from brand colors, then assign semantic roles. Use a neutral surface and
text pair, one primary action color, and explicit hover/focus/status colors.
Accent colors used in artwork need not be suitable for button labels or body
text. Choose colors for their assigned use rather than inferring that a hue
universally communicates an industry's values.

These three starting palettes can be adapted. All values are opaque
sRGB; `on-primary` is the button's text color, not another background color.

| Token | Paper / charcoal | Light / blue | Dark / teal |
| --- | --- | --- | --- |
| `--brand-page` | `#111111` | `#F1F5F9` | `#030712` |
| `--brand-surface` | `#F7F7F5` | `#FFFFFF` | `#111827` |
| `--brand-ink` | `#191919` | `#0F172A` | `#F9FAFB` |
| `--brand-muted` | `#5F5F5F` | `#475569` | `#9CA3AF` |
| `--brand-primary` | `#1F1F1F` | `#1D4ED8` | `#5EEAD4` |
| `--brand-on-primary` | `#FFFFFF` | `#FFFFFF` | `#042F2E` |
| `--brand-primary-hover` | `#111111` | `#1E40AF` | `#2DD4BF` |
| `--brand-control-border` | `#767676` | `#64748B` | `#6B7280` |
| `--brand-focus` | `#1F1F1F` | `#1D4ED8` | `#5EEAD4` |

The paper palette uses light cards over a dark page, so its form controls still
use a light color scheme. Use a subtler separate border for decorative card
dividers if desired; do not reuse an almost invisible divider as the only way
to identify a text input.

Calculated contrast ratios for the opaque pairs above, rounded for display:

| Foreground / background | Paper / charcoal | Light / blue | Dark / teal |
| --- | --- | --- | --- |
| Ink / surface | 16.39:1 | 17.85:1 | 16.98:1 |
| Muted / surface | 5.95:1 | 7.58:1 | 6.99:1 |
| On-primary / primary | 16.48:1 | 6.70:1 | 9.78:1 |
| On-primary / primary-hover | 18.88:1 | 8.72:1 | 7.77:1 |
| Control-border / surface | 4.23:1 | 4.76:1 | 3.67:1 |

Apply the chosen tokens to the actual components; declaring variables alone
does not change the built-in CSS. A light/blue excerpt:

```css
.brand-body {
  color-scheme: light;
  --brand-page: #F1F5F9;
  --brand-surface: #FFFFFF;
  --brand-ink: #0F172A;
  --brand-primary: #1D4ED8;
  --brand-on-primary: #FFFFFF;
  --brand-primary-hover: #1E40AF;
  --brand-focus: #1D4ED8;
  color: var(--brand-ink);
  background-color: var(--brand-page);
}
.brand-body .app-container,
.brand-body .brand-surface {
  color: var(--brand-ink);
  background-color: var(--brand-surface);
}
.brand-body .app-btn-pri {
  color: var(--brand-on-primary);
  background-color: var(--brand-primary);
  border-color: var(--brand-primary);
}
.brand-body .app-btn-pri:hover {
  background-color: var(--brand-primary-hover);
  border-color: var(--brand-primary-hover);
}
.brand-body :is(a, button, input, select, textarea):focus-visible {
  outline: 3px solid var(--brand-focus);
  outline-offset: 3px;
}
```

Complete the mapping for secondary actions, inputs, muted copy, alerts, and
page-specific wrappers using the component guide in
[design-and-validation.md](design-and-validation.md#theme-structure-and-css).
Check focus outlines against the surface immediately around each control;
links outside a card may need a different focus color. Keep the outline visible
when wrappers use `overflow: hidden`.

Offer dark mode when requested or supported by the brand. Switch the complete
token set, logo variant, and background together, and set `color-scheme: dark`
for dark form surfaces. If following `prefers-color-scheme`, put the rules in
the external stylesheet so they also work on the session page. Do not assume
that switching only the page background makes the existing UI a dark theme.

## Contrast and Status Messages

Use at least 4.5:1 for normal text and 3:1 for large text (at least 18 pt regular
or 14 pt bold) when targeting WCAG AA text contrast. Include labels, help text,
placeholders, and button text in the check. See
[W3C's text contrast guidance](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html).
Visual cues needed to identify controls and their states generally need 3:1
against adjacent colors; see
[W3C's non-text contrast guidance](https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html).

Measure the final composited colors, including overlays, image crops, hover
states, and transparency. Do not round a failing ratio up to the threshold.
The palette calculations are starting-pair checks, not a claim that the whole
theme meets accessibility requirements.

Use explicit error/success/warning tokens instead of treating the brand accent
as every status color. For example, start with dark red/green/amber on light
surfaces and lighter equivalents on dark surfaces, then calculate contrast
against the actual alert fill. Keep an icon and descriptive text so a message
does not rely on hue alone. Make registration errors and MFA failures at least
as readable as the form labels. Keep QR codes crisp and strongly contrasted;
avoid recoloring their modules or putting a logo over them as part of a theme.

## Export and Review

Use these as initial performance budgets, not hard limits: roughly 5–30 KB for a
simple SVG logo, under 100 KB for a vector background, 100–300 KB for a raster
banner, and 200–500 KB for a desktop raster background. Inspect visible quality
after compression; simplify noisy textures and excessive SVG paths/filters
before increasing the budget. A static auth form rarely needs a multi-megabyte
decorative download.

Prefer SVG for marks/geometry, PNG for transparency or crisp flat artwork, and
JPEG/WebP for photographic backgrounds after checking target support. Custom
assets use an explicit content type: when changing a format, update the asset
registration, filename, CSS/template URL, and relevant metadata together. Do
not merely rename a file's extension. Retain an editable source, remove unused
editor data, and avoid SVG scripts or remote font/image dependencies. Text in
SVG needs available fonts; use approved outlined lettering for a stable mark
while keeping portal instructions and headings as real HTML text.

Review logos at 16, 32, 64, and 96 px, banners as small thumbnails, and backgrounds
on desktop, portrait mobile, and long registration/MFA pages. Check image
failure, light/dark surroundings, crop, legibility, and transferred bytes.
Test 320–390 px viewport widths as well as a wide desktop. Reuse or edit existing
SVG/vector assets where suitable; use image generation when bitmap artwork
benefits the request. Asset creation does not require image generation.
