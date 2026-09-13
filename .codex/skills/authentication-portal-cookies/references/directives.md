# Cookie Directives

Contents: [application](#application), [grammar](#grammar),
[runtime boundaries](#runtime-boundaries).

## Application

`pkg/authn/cookie/parser.NewCookieConfigFromDirectives(statements []string)`
returns `(*cookie.Config, error)`. Statements include the `cookie` keyword,
without braces. The embedding adapter owns tokenization and placeholder
expansion; encode each statement once, preserving argument boundaries.

```go
config, err := cookieparser.NewCookieConfigFromDirectives([]string{
    cfgutil.EncodeArgs([]string{"cookie", "prefix", "PORTAL"}),
    cfgutil.EncodeArgs([]string{"cookie", "oidc", "session", "id", "name", "LOGIN_SESSION"}),
    cfgutil.EncodeArgs([]string{"cookie", "oidc", "request", "id", "name", "LOGIN_REQUEST"}),
})
if err != nil {
    return err
}
if err := portalConfig.ConfigureCookies(config); err != nil {
    return err
}
```

Here `cookieparser` imports `pkg/authn/cookie/parser`, `cfgutil` imports
`pkg/util/cfg`, and `portalConfig` is an `*authn.PortalConfig`.
Collect every statement before parsing. Explicit names override the prefix
regardless of statement order, including names equal to old defaults.
Empty input returns default cookie configuration. The parser returns nil on
error, omits raw values from errors, and performs no file or network operations.

`ConfigureCookies` clones the full configuration, validates it, and replaces the
portal's cookie settings before construction. It is not a partial merge. Changes
to the original config or its domain map cannot alter the applied snapshot.
Serialized names and attributes survive decoding and factory construction.

Typed consumers changing an initialized configuration use:

```go
config := cookie.NewConfig()
if err := config.SetCookieNamePrefix("PORTAL"); err != nil {
    return err
}
config.OIDCSessionIDCookieName = "AUTHP_OIDC_SESSION_ID" // Intentional override.
if err := portalConfig.ConfigureCookies(config); err != nil {
    return err
}
```

Directly assigning `CookieNamePrefix` after `NewConfig` does not rebase the
already populated names. `SetCookieNamePrefix` rebases names matching the old
prefix and role suffix; apply an explicit name equal to that old default last.

## Grammar

```text
cookie prefix PORTAL
cookie oidc session id name LOGIN_SESSION
cookie oidc request id name LOGIN_REQUEST
```

Every role accepts `cookie <role> name <value>`:

| Role | Default complete name |
| --- | --- |
| `session id` | `AUTHP_SESSION_ID` |
| `referer` (alias `redirect url`) | `AUTHP_REDIRECT_URL` |
| `sandbox id` | `AUTHP_SANDBOX_ID` |
| `identity token` (alias `id token`) | `AUTHP_ID_TOKEN` |
| `access token` | `AUTHP_ACCESS_TOKEN` |
| `refresh token` | `AUTHP_REFRESH_TOKEN` |
| `oidc session id` | `AUTHP_OIDC_SESSION_ID` |
| `oidc request id` | `AUTHP_OIDC_REQUEST_ID` |

Shared attributes and per-domain settings use:

```text
cookie path /auth
cookie lifetime 3600
cookie same site lax
cookie insecure disabled
cookie strip domain enabled
cookie guess domain disabled
cookie domain example.test
cookie domain example.test path /auth
cookie domain example.test lifetime 600
cookie domain example.test same site strict
cookie domain example.test insecure disabled
cookie domain example.test strip domain enabled
```

`same site` accepts `lax`, `strict`, or `none`, case-insensitively; `samesite`
is an alias. Boolean states use `enabled` or `disabled`. Lifetimes use signed
decimal integers with the existing factory semantics; these are not the
OIDC-session or opaque-refresh lifetimes. `guess domain` is global only.

A domain's first appearance determines its `Seq` precedence. An attribute may
introduce a domain before its bare declaration. Domain keys normalize case and
a leading dot. Reject repeated declarations, repeated attributes within a
scope, duplicate prefix/name settings across aliases, and final name collisions.
Quoted values retain their boundaries; combining several keywords into one
quoted argument fails. Unknown settings, incorrect arity, empty/blank values,
invalid UTF-8, and multiline records fail. Reject empty arguments before encoding
because `EncodeArgs` can trim a trailing empty field.

## Runtime Boundaries

`Config.Validate` owns defaults, name/collision and path/domain validation, and
SameSite normalization. The factory retains lifetime/domain selection behavior.
Per-domain stripping removes the emitted Domain attribute without changing
which host selects that entry. Issue and delete with the same effective scope.

OIDC and opaque refresh cookies retain their stricter security, path, and
lifetime rules. Explicit `__Host-` compatibility names must satisfy their
feature's root-path requirements. Prefixes do not disable security checks.
Provider-owned upstream identity cookie names and gatekeeper policy overrides
must be coordinated with the corresponding consumer; a shared cookie parser
does not implicitly rewrite those separate configurations.

This API is library integration support. External configuration handlers must
call it from their own repositories; do not edit sibling projects here.
