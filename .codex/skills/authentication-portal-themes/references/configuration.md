# Theme Configuration and Asset Paths

## Files and Aliases

`ui.Parameters` in `pkg/authn/ui/params.go` owns library configuration.
`configureUserInterface` in `pkg/authn/portal.go` loads the selected built-in
theme, fills aliases without overrides, and loads custom template files.
Currently only `basic` is registered in `ui.Themes`.

The current aliases are `login`, `sandbox`, `portal`, `register`, `generic`,
`whoami`, `apps_sso`, `apps_mobile_access`, and `session`. Use bare aliases in
configuration, such as `login`, rather than `basic/login` or `login.template`.
`basic/login` is the embedded asset name used by factory APIs, not the override
key used by the portal. There is no directory autodiscovery for custom themes.

For a new full theme, copy the files from
`pkg/authn/ui/page_templates/basic/*.template` into the application's chosen
theme directory. Copy only missing files when updating an existing theme, then
merge upstream changes deliberately. Keep filenames aligned with aliases for
clarity, though the configured filesystem path determines what is loaded.

An ordinary theme directory contains the chosen `.template` files, `theme.css`,
`logo.svg`, `banner.svg`, and `background.svg`. Add custom JavaScript only for a
requested behavior that the shipped scripts do not supply. Template files and
assets are read during configuration; changing them requires reconfiguration
or restart, followed by a browser cache refresh.

## Caddy Security Integration

The following `ui` block belongs inside an existing `authentication portal`
block in a server using `caddy-security`. It illustrates a full override set;
omit entries for pages that should use defaults. Set `AUTH_PORTAL_THEME_ROOT`
to an absolute directory visible to the server process, and create the named
files before validating the server configuration.

```caddyfile
ui {
    theme basic
    language en
    logo url /assets/images/brand-logo.svg
    logo description "Example Company"
    meta title "Example Company"
    meta author "Example Company"
    meta description "Sign in to Example Company services"
    custom css path {env.AUTH_PORTAL_THEME_ROOT}/theme.css
    static_asset "assets/images/brand-logo.svg" "image/svg+xml" {env.AUTH_PORTAL_THEME_ROOT}/logo.svg
    static_asset "assets/images/brand-banner.svg" "image/svg+xml" {env.AUTH_PORTAL_THEME_ROOT}/banner.svg
    static_asset "assets/images/brand-background.svg" "image/svg+xml" {env.AUTH_PORTAL_THEME_ROOT}/background.svg
    static_asset "assets/images/brand-favicon.svg" "image/svg+xml" {env.AUTH_PORTAL_THEME_ROOT}/logo.svg
    template login {env.AUTH_PORTAL_THEME_ROOT}/login.template
    template sandbox {env.AUTH_PORTAL_THEME_ROOT}/sandbox.template
    template portal {env.AUTH_PORTAL_THEME_ROOT}/portal.template
    template register {env.AUTH_PORTAL_THEME_ROOT}/register.template
    template generic {env.AUTH_PORTAL_THEME_ROOT}/generic.template
    template whoami {env.AUTH_PORTAL_THEME_ROOT}/whoami.template
    template apps_sso {env.AUTH_PORTAL_THEME_ROOT}/apps_sso.template
    template apps_mobile_access {env.AUTH_PORTAL_THEME_ROOT}/apps_mobile_access.template
    template session {env.AUTH_PORTAL_THEME_ROOT}/session.template
}
```

This only configures appearance. Retain the application's existing identity
stores/providers, registration, links, cookie settings, mount, and authorization
configuration. A page override does not enable its backend feature.

The Caddy grammar belongs to `caddy-security/caddyfile_authn_ui.go`, outside this
library. Validate with the consuming application's actual Caddy binary or Go
entrypoint and pinned adapter version. Environment placeholders are adapter
features, not expansion performed by `ui.NewTemplate` or `StaticAssets.AddAsset`.
Container/service paths must resolve in that runtime, not just the developer's
shell. Do not commit a developer's home directory into shared configuration.

For a direct library consumer, these are corresponding fields in the portal's
`ui` JSON object; this is a partial example, not a full server configuration:

```json
{
  "theme": "basic",
  "logo_url": "/assets/images/brand-logo.svg",
  "logo_description": "Example Company",
  "meta_title": "Example Company",
  "custom_css_path": "/srv/auth-portal-theme/theme.css",
  "templates": {
    "login": "/srv/auth-portal-theme/login.template",
    "session": "/srv/auth-portal-theme/session.template"
  },
  "static_assets": [
    {
      "path": "assets/images/brand-logo.svg",
      "content_type": "image/svg+xml",
      "fs_path": "/srv/auth-portal-theme/logo.svg"
    }
  ]
}
```

Register every asset referenced by the chosen templates/CSS. `title` supplies
the configured sign-in heading, while `meta_title` supplies brand metadata;
other handlers often replace `.PageTitle` with a translated page title.

## Filesystem Paths Versus Browser URLs

For a portal mounted at `/xauth`, the same logo has three distinct paths:

| Purpose | Example |
| --- | --- |
| Runtime file | `/srv/auth-portal-theme/logo.svg` |
| Static asset registry key | `assets/images/brand-logo.svg` |
| Browser URL | `/xauth/assets/images/brand-logo.svg` |

Registry keys start with `assets/`, without a leading slash or portal mount.
Use the configured content type, such as `image/svg+xml` or `text/css`.
Registering an asset makes it available for a template to reference; it does
not insert an image or stylesheet into the page.

In Go templates:

```html
{{ if .LogoURL }}
  <img class="logo-img brand-logo" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" />
{{ end }}
<link rel="icon" type="image/svg+xml" href="{{ pathjoin .ActionEndpoint "/assets/images/brand-favicon.svg" }}" />
<meta property="og:image" content="{{ pathjoin .ActionEndpoint "/assets/images/brand-banner.svg" }}" />
```

`Args.BaseURL` already adds the mount to local `.LogoURL` values. Do not join
it a second time. A deliberate fixed logo can instead use `pathjoin` like the
favicon example, but then the `logo_url` setting no longer controls that image.
The banner example exposes a local metadata asset; if a social preview is a
deliverable, verify the consumer's crawler requirements, absolute public URL,
and supported image format separately.

`custom_css_path` and `custom_js_path` are filesystem paths. They register the
fixed URLs `assets/css/custom.css` and `assets/js/custom.js`. Ordinary built-in
pages conditionally include these using `.Data.ui_options`; `session` needs an
explicit stylesheet link in its override. Put the CSS hook after all base and
view-specific styles when the theme should take precedence.

Static CSS is served verbatim, so `{{ pathjoin ... }}` inside `theme.css` will
not be evaluated. With CSS served as `assets/css/custom.css`, this URL remains
valid at both `/` and `/xauth`:

```css
.brand-body .app-page {
  background-image: url("../images/brand-background.svg");
}
```

The asset library is process-global, and `AddAsset` replaces an existing key.
For different themes on multiple portals in one process, use distinct asset
keys, including distinct stylesheets linked by each custom template. The fixed
`custom.css`/`custom.js` keys cannot hold separate content per portal. The
custom HTML header mechanism also mutates built-in template assets; it is not
an include mechanism for filesystem overrides and does not reach the current
session template. Prefer explicit head markup for a custom template set.

Static responses use ETags and `Cache-Control: max-age=7200`. When changes appear
missing, check runtime loading, the requested URL, and the browser cache before
rewriting the CSS. Versioned asset filenames can help deployed theme updates.
