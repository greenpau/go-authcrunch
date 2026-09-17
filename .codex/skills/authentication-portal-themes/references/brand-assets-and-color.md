# Brand Assets and Color

For the shipped AuthCrunch assets, CSS variables, and a complete deployment
example, read [basic theme branding](basic-theme.md). This reference covers how
to choose or prepare replacement artwork and palettes; its suggested dimensions
are design starting points rather than runtime requirements.

## Shipped identity versus replacement artwork

The built-in identity is the blue/navy Soft Square chain mark. Its logo,
favicon, banner, and background are native SVGs generated from the
[palette and source geometry](basic-theme.md#changing-the-default-palette-and-svg-artwork).
Keep that identity unless a new direction is requested. Do not reintroduce
PNG/ICO branding fallbacks, shrink its 96px ordinary-page logo box on phones,
or turn the mark into a repeated banner/background motif. The two decorative
assets have separate abstract compositions and contain no logo or text.

The generic sizes and raster formats below are options for other requested
deliverables, such as photographic backgrounds or social previews. They do not
replace the [built-in component sizes](basic-theme.md#component-proportions-and-interaction-states).
Runtime-generated QR PNGs and browser screenshot PNGs are separate from the
shipped brand files. Image generation is unnecessary for edits to the existing
native SVG geometry or CSS layout.

## Suggested Sizes

AuthCrunch does not impose a standard logo, banner, or background size. Use the
following as practical starting sizes, then adapt them to the user's brand and
actual layout. Raster dimensions are image pixels; display sizes are CSS pixels.
For a raster logo displayed at 96 by 96 CSS pixels, export at least 192 by 192
image pixels for a 2x display. An SVG's `viewBox` defines its drawing coordinates,
not a fixed display resolution. See [MDN's viewBox reference](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Attribute/viewBox).

| Asset | Suggested source or export size | Typical use |
| --- | --- | --- |
| Square logo | SVG with a square `viewBox`, e.g. `0 0 64 64`; raster exports only for a requested compatibility target | Choose display size from the mark's optical size; basic uses 96 CSS px on desktop and phone |
| Horizontal wordmark | SVG preserving the brand's ratio; e.g. a 400 by 100 artboard and 800 by 200 PNG export | Display about 160–240 CSS px wide; preserve height proportionally |
| Favicon | SVG with a simple square mark; additional raster/ICO exports only for a requested compatibility target | Browser tabs; review at the actual 16 px size |
| Metadata/share banner | 1200 by 630 PNG or JPEG, approximately 1.9:1; retain an editable vector source if appropriate | `og:image` for link previews; check the target service's current requirements |
| Visible page banner | Start at 1600 by 400, a 4:1 ratio; use SVG for simple artwork | A wide strip in the page; adapt height to the actual card/header layout |
| Desktop background | 1920 by 1080 raster; 2560 by 1440 if the artwork benefits from more detail; SVG for patterns/geometry | Full viewport decoration with `background-size: cover` |
| Optional mobile background | 1080 by 1920 portrait raster or a separate vector composition | Use when the landscape crop loses its subject or becomes distracting |

Keep the SVG source for geometric artwork and export raster variants only when
needed. A 1600 by 1000 SVG background is also suitable: the composition and
cropping behavior matter more than matching a screen's exact aspect ratio.
Do not upscale a small raster source and call it a higher-detail asset.

## Logo and Favicon

When the user requests a new identity, explore distinct simple silhouettes
before adapting the selected mark to the theme. AuthCrunch concepts include
verified identity, trusted access, and protected boundaries; avoid packing
every security metaphor into one symbol. A small mark should not need its
wordmark or slogan to remain recognizable.

For round and square avatars, keep the complete symbol inside a centered safe
area with generous clear space. Preview both crops, including 24px/32px versions,
and check that negative spaces and separate parts remain distinguishable.
Transparent originals support light and dark preview surfaces without baking
an avatar crop into the source. Do not assume a square image survives a circle
crop just because its center looks good.

For concept options, save each named candidate separately in the user-requested
directory and provide a comparison page with round, square, and small-size
previews. Keep generation prompts with generated concept assets so choices can
be refined consistently. Use image generation for new bitmap concepts and
native SVG editing for established vector artwork; a raster image embedded in
an SVG wrapper is not an editable vector logo. Carry an agreed design into the
logo, favicon, and artwork palette together when applying it to the theme.

When SVG output is requested, create actual vector paths or primitives. A
bitmap concept can guide the design, but rebuild simple geometry with explicit
coordinates, radii, and colors. Keep repeated parts identical through transforms;
use concentric curves for even bands and proportionate inner spaces. Shortening
a shape should reduce its straight sections without distorting its curves or
thickening the stroke. Retain a small parameter/source file when generating
several related variants so later geometry and palette changes stay consistent.

Keep cutouts transparent, rather than painting them the preview background
color. Validate SVG XML, the square viewBox, safe avatar bounds, and absence of
embedded raster images or external resources. Inspect the rendered result at
actual icon sizes: valid paths can still have crowded crossings or weak strokes.
The comparison page may supply a background; the source mark should retain
transparency unless a badge is part of the requested design.

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
image's actual values. AuthCrunch does not supply a separate metadata banner
parameter; register the asset and reference it in the custom template. The
visible basic-theme card banner has a `--brand-banner-image` CSS hook and an
embedded `banner.svg`; it does not configure Open Graph metadata.
That accent is visible at tablet/desktop widths and hidden by the
[phone layout](basic-theme.md#phone-layout). Review a replacement at its actual
painted height, not just by opening its source artboard.

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
On basic-theme phones, text sits directly on the backdrop, so also inspect its
contrast where the desktop card would normally hide the artwork. Keep any
strong edge contours out of the reading area at narrow and long-page crops.

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
example, not a requirement for light themes. Use a sufficiently opaque reading
surface over photography; for the basic phone layout, use a page-level wash or
quieter background rather than restoring the removed card. Do not reduce the
entire page's `opacity`, which also fades its inputs and text. Preserve a solid fallback color when an
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
use a light color scheme. When applying it to the basic theme, account for the
transparent phone shell: dark ink would otherwise sit directly on the dark
page. For example, retain the light reading surface at phone widths with:

```css
@media (max-width: 639px) {
  .basic-theme {
    --brand-page: var(--brand-surface);
    --brand-page-image: none;
  }
}
```

This is an adjustment for that example palette, not a change to the shipped
blue theme. Check actual page/background and foreground colors at each
breakpoint. Use a subtler separate border for decorative card
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

Current basic pages consume these `--brand-*` variables through `basic.css`;
set them on `.basic-theme` and also select matching background/banner artwork.
For older or independent themes without that shared stylesheet, map the tokens
to their components explicitly. A light/blue excerpt for such a theme:

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
For the basic theme, follow the [viewport and interaction checks](basic-theme.md#validation),
including 430px phones, the 639/640px boundary, tablets, and wide desktops.
Reuse or edit existing SVG/vector assets where suitable; use image generation when bitmap artwork
benefits the request. Asset creation does not require image generation.
