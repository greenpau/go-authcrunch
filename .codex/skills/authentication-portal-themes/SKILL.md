---
name: authentication-portal-themes
description: Build, customize, or update AuthCrunch authentication portal themes using Go HTML templates, CSS, logos, favicons, banners, and backgrounds. Use for filesystem template overrides and their UI/static-asset configuration; the embedded React profile application has a separate build.
---

# Authentication Portal Themes

Create a deployable theme in the consuming application's theme directory, with
the user's branding, working portal flows, and matching configuration. Start
from the built-in templates for the AuthCrunch version the application runs.
Use an existing custom theme as a design reference, then carry its styling onto
those templates. Filesystem overrides do not inherit later upstream changes.

## Choose the Customization Surface

- For colors, typography, spacing, and a logo, prefer UI parameters and custom
  CSS. Keep the built-in markup when it meets the request.
- For a branded page shell, favicon/metadata, or different layout, copy and
  override the affected templates. Unspecified aliases keep their built-in
  templates. A complete theme should account for every page the application
  exposes, including session continuation and logout confirmation when enabled.
- Keep application themes in the consuming application. Editing
  `pkg/authn/ui/page_templates/basic` changes the library's default UI and is
  appropriate only when that is the requested scope.

The React profile app under `pkg/authn/ui/profile` is a separate asset surface;
portal template overrides do not rebuild or restyle it automatically.

## Build the Theme

1. Inspect the application's AuthCrunch version, current UI configuration,
   portal mount, theme directory, brand assets, and exposed flows. Infer visual
   choices from supplied references; ask only for missing choices that affect
   the result. Do not assume a particular company, realm, hostname, or palette.
2. Read [configuration.md](references/configuration.md) when selecting overrides,
   wiring files, or debugging asset URLs. The registered theme remains `basic`;
   a custom folder name is not a new value for `ui.theme`.
3. Before changing markup, read
   [template-contracts.md](references/template-contracts.md) and inspect the
   corresponding current template, handler, and scripts. Keep authentication
   forms, conditional views, navigation, translations, and script hooks intact.
4. Use [brand-assets-and-color.md](references/brand-assets-and-color.md) for
   suggested logo/banner/background sizes, formats, composition, and color
   palettes. Use [design-and-validation.md](references/design-and-validation.md)
   for page layout, CSS ordering, and validation. Produce shared styles plus
   page-specific adjustments instead of forcing a narrow login card onto
   registration forms or identity/SSO tables.
5. Deliver the templates/assets and the exact UI configuration needed to load
   them. Report which aliases changed, which use defaults, the required runtime
   paths, and which rendering/browser checks ran.

## Compatibility Essentials

Use Go `html/template`, not a frontend component language. Each custom file is
parsed independently; shared template partials require preprocessing into each
file. The repository supplies `pathjoin` and `brsplitline`, not Sprig or an
`include` function. Preserve contextual escaping.

Build local navigation and asset paths from `.ActionEndpoint`, which is the
portal mount, not the login URL. Keep `.LogoURL` and `.LogoDescription` useful
when the theme is meant to accept configuration. Do not embed credentials,
application-specific redirect scripts, or hardcoded user/role lists in a theme.

Preserve the current portal refresh script and the `session` template's DOM and
script attributes. The session response blocks inline CSS/JavaScript: load
theme CSS from the same origin. Do not relax its Content Security Policy to
reuse an inline style block. Read `refresh-token-transports` if changing session
behavior; visual changes alone do not require redesigning the refresh flow.

## Source of Truth

Paths below are relative to the repository root:

- `pkg/authn/ui/params.go`: UI configuration fields.
- `pkg/authn/portal.go`, `configureUserInterface`: default and override loading.
- `pkg/authn/ui/ui.go`: template functions, `Args`, `BaseURL`, and rendering.
- `pkg/authn/ui/page_templates/basic/`: current template baselines.
- `pkg/authn/ui/core/css/` and `pkg/authn/ui/core/js/`: styles and DOM consumers.
- `pkg/authn/handle_http_static.go`: public asset routing and caching.
- `pkg/authn/handle_http_session.go`: session rendering and response policy.

Use the application's pinned dependency when it differs from this checkout.
Recompare overrides with that baseline on upgrades; do not copy an older theme's
functional omissions into a new theme.
