# Reusing the Go OpenID Provider

Import `github.com/greenpau/go-authcrunch/pkg/oidc`. Applications can construct
`*oidc.Provider` directly, use it through `oidc.OpenIDProvider`, and serve it as
an `http.Handler`. No authentication portal or local-store implementation is
required. The host supplies authentication and an `oidc.IdentityVerifier`.

## Construction

```go
func newProvider(verifier oidc.IdentityVerifier) (*oidc.Provider, error) {
    return oidc.NewProvider(&oidc.Config{
        Enabled: true,
        Issuer: "https://login.example.com/auth",
        Realms: []string{"employees"},
        SigningKeyFiles: []string{"/etc/example/oidc-rsa.pem"},
        Clients: []*oidc.ClientConfig{{
            ClientID: "desktop-app",
            TokenEndpointAuthMethod: "none",
            RedirectURIs: []string{"http://127.0.0.1:8400/callback"},
        }},
    }, verifier, oidc.Options{
        LoginURL: "https://login.example.com/auth/sign-in?fresh=1",
        SessionCookieName: "APP_OIDC_SESSION_ID",
        RequestCookieName: "APP_OIDC_REQUEST_ID",
    })
}
```

`NewProvider` requires enabled configuration and a non-nil verifier. It validates
and snapshots the configuration without changing the caller's value. All
clients, redirect URIs, realms, and limits are fixed for that provider instance.
The example uses a public client, which requires S256 PKCE. See
[configuration and clients](configuration-and-clients.md) for protocol options.

`Options.LoginURL` defaults to `<issuer>/login?fresh=1`. A custom URL must stay on
the issuer origin and inside its mount so browser interaction cookies reach it.
Cookie names default to `AUTHP_OIDC_SESSION_ID` and `AUTHP_OIDC_REQUEST_ID`.
Choose names that do not collide with the host's other cookies. Cookies remain
host-only, Secure, HttpOnly, SameSite=Lax, and scoped to the issuer mount.

Supply `Options.ExcludedSigningKeys` with public keys trusted for other token
purposes in the host. Construction rejects matching OIDC signing keys. The
portal adapter supplies its access-token verification keys automatically.

`Options.RenderPage` optionally renders consent, form-post continuation and local
browser errors through host templates. Nil uses the styled standalone fallback.
The callback receives a `Page` snapshot without provider locks; preserve its form
contract and contextual escaping. See [browser pages](browser-pages.md) for the
runtime API, portal `oidc` template alias, response policies and tests.

## Provider settings directives

Import `github.com/greenpau/go-authcrunch/pkg/oidc/parser` as `oidcparser`.
`NewOIDCProviderConfigFromDirectives(statements, applications)` accepts the body
of a provider block, separately from each `oauth application <nickname>` block:

```caddyfile
oidc provider {
    issuer https://auth.example.com/auth
    realms local
    signing key files /etc/auth/oidc-active.pem /etc/auth/oidc-previous.pem
    applications website desktop
    session lifetime 28800
    token lifetime 300
    max sessions 10000
    max pending requests 1024
    max grants 10000
}
```

| Directive | Arguments and behavior |
| --- | --- |
| `enabled` / `disabled` | Standalone, mutually exclusive states; enabled by default. |
| `issuer` | One canonical HTTPS issuer, including its mount. |
| `realms` | One or more distinct identity realms. |
| `signing key files` | One or more distinct dedicated RSA PEM paths; first signs, all publish. |
| `applications` | One or more distinct registered application nicknames, in selection order. |
| `session lifetime` / `token lifetime` / `refresh lifetime` | One integer in seconds; zero selects the validator default. |
| `max sessions` / `max pending requests` / `max grants` / `max refresh tokens` | One integer capacity; zero selects the validator default. |

The numeric defaults and bounds are in
[configuration and clients](configuration-and-clients.md#lifetimes-reloads-and-deployment).
`acr <value> <method>...` is repeatable with unique values and requires all listed
verified authentication methods. Other settings occur once; use one line for a list. Keywords are separate tokens,
not underscore keys or one quoted multiword key. Boolean literals are not valid
provider states. Unknown settings, duplicates, missing/empty values, extra scalar
arguments, malformed quoting, embedded newlines, and overflowing integers fail.
Errors do not include raw statements, values, registrations, or secrets.

Collect application registrations first, then parse provider settings and assign
the result to the portal before normal root configuration validation:

```go
// registrations is map[string]*oidc.ClientConfig, keyed by configuration nickname.
// Build it from persisted registrations or the application parser before this call.
provider, err := oidcparser.NewOIDCProviderConfigFromDirectives([]string{
    cfgutil.EncodeArgs([]string{"issuer", "https://auth.example.com/auth"}),
    cfgutil.EncodeArgs([]string{"realms", "local"}),
    cfgutil.EncodeArgs([]string{"signing", "key", "files", "/etc/auth/oidc signer.pem"}),
    cfgutil.EncodeArgs([]string{"applications", "website", "desktop"}),
    cfgutil.EncodeArgs([]string{"token", "lifetime", "120"}),
}, registrations)
if err != nil {
    return err
}
portal := &authn.PortalConfig{
    Name: "login",
    IdentityStores: []string{"localdb"},
    OIDCProvider: provider,
}
// Include portal in authcrunch.Config.AuthenticationPortals before NewServer.
```

The same result is usable directly with `oidc.NewProvider` outside the portal.
The parser package has no dependency on `authn` or any embedding server.

Nicknames are exact host-owned labels, independent of the generated client ID
and display name. Detect duplicate nicknames while collecting application blocks;
a Go map cannot retain duplicate keys. The parser resolves only explicitly named
applications, copies each registration through `Config.AddClient`, then performs
final provider validation. Unselected registrations are ignored. Missing/nil
registrations, repeated references, invalid clients, and duplicate client IDs
fail without returning partial configuration or changing the supplied registry.
These checks also apply to explicitly selected applications when disabled.
Concurrent parsing may share the registry only while callers leave it unchanged.

A standalone `disabled` body needs no other settings. Disabled scalar settings
retain `Config.Validate`'s existing opt-out behavior, but directive syntax and
explicit application references are always checked. An absent block should remain
nil. No placeholder expansion, credential generation, key-file IO, or provider
startup occurs during parsing. Persist provisioned clients and keys separately;
server construction still validates local realms, portal mounts, and key material.
Application declarations can follow a provider block in the embedding syntax:
collect all registrations before resolving any provider body, then run final
portal/root validation. Never provision clients again just to resolve a reference.

The provider parser accepts encoded body statements; it does not parse enclosing braces
or install an HTTP server's outer block grammar. Consumer adapter integration is
separate work in its owning repository. All implementation and tests here remain
inside this repository.

## Named application registration and reloads

`oidc.OAuthApplicationConfig` contains `Name` (the configuration nickname) and
`Client` (the provisioned `*oidc.ClientConfig`). `oidc.NewOAuthApplicationConfig`
validates and copies these values without generating credentials. The nickname
does not replace the client's protocol identifier or display name.

Use `oidcparser.NewOAuthApplicationConfigFromDirectives(header, body, persisted)`
when adapting an `oauth application <nickname>` block. It recognizes the encoded
header, reuses the existing client field decoder, and returns a named registration.
Encode the header and each body line separately with `cfgutil.EncodeArgs`; omit
braces, preserve argument boundaries, and expand host placeholders first. The
embedding server owns token traversal and recognition of enclosing block scopes.

The third argument is an optional previously saved `*oidc.OAuthApplicationConfig`:

- Explicit `client_id` and `client_secret` take precedence. Empty values fail.
- Omitted credentials are restored only from a valid, matching nickname.
- Changing the client ID requires an explicit secret for a confidential client;
  the previous identity's secret is never carried to a different ID.
- Public clients never inherit secrets. Changing from public to confidential
  requires supplying a secret. Switching Basic/POST preserves an omitted secret
  when the client ID is unchanged.
- All other fields come from current directives and normal defaults. Old callback
  URIs, scopes, consent policy, display name, and PKCE policy are not inherited.
- Missing or invalid persisted credentials cause an error; adaptation never
  generates replacements. Header/body errors never echo supplied values.

For first-time generation, call `NewOIDCClientConfigFromDirectives` or
`oidc.NewClientConfig` as an explicit provisioning operation, wrap the result with
`oidc.NewOAuthApplicationConfig`, and persist it before activation. On every
reload, load the saved registration and pass it to the adaptation API. Explicit
credential rotation must also be persisted before activation. Signing keys are
provider-owned and must be retained independently of client registrations.

Storage is owned by the embedding application. The library does not choose a
filesystem path, write credentials while parsing, or keep a process-global cache.
Use the host's secret store, or an owner-only credential file (0600) in a trusted
private directory, with atomic publication/replacement and serialized writers.
Treat a failed read, invalid registration, or failed write as an adaptation failure;
do not bootstrap replacement credentials on a reload error. Do not use a generic
configuration dump with broad file permissions as a credential store.

Root `authcrunch.Config` provides the integration surface:

| API | Contract |
| --- | --- |
| `OAuthApplications` | Serializable ordered registrations under `oauth_applications`; includes secrets. |
| `AddOAuthApplication(application)` | Validate/copy one registration; reject duplicate nicknames, including identical definitions. |
| `GetOAuthApplication(nickname)` | Return an independent named registration; exact lookup, error if missing or registry invalid. |
| `GetOAuthApplications()` | Return a validated, independent `map[string]*oidc.ClientConfig` for standalone provider parsing. |
| `ConfigureOIDCProvider(portal, statements)` | Resolve provider application references against this Config, validate, and attach a snapshot to the portal. |

`Config.Validate` checks all declared applications, including unused entries.
Duplicate client IDs are rejected when selected together by a provider; nicknames
are unique across root configuration. Provider attachment rejects a second
definition and ensures OIDC defaults run even if the portal was validated earlier.
All mutation methods configure a new object graph before `NewServer`; they do not
modify running providers. Selected client snapshots are serialized in the existing
`oidc_provider.clients` field, so a normalized Config can be loaded directly.
Changing a registry entry later does not change those snapshots; re-adapt the
provider body on reload to apply changed application settings.

An adapter collects all application blocks first, then resolves saved provider
bodies. This permits application declarations after a provider in the source.
Use a fresh root Config each time: the saved registry supplies credentials only;
removed or undeclared applications must not become registered implicitly.

```go
// saved is the Config loaded from trusted credential storage.
previous, err := saved.GetOAuthApplication("website")
if err != nil {
    return err
}
application, err := oidcparser.NewOAuthApplicationConfigFromDirectives(
    cfgutil.EncodeArgs([]string{"oauth", "application", "website"}),
    []string{
        "redirect_uri https://app.example.com/callback",
        "scopes openid profile email",
    }, previous,
)
if err != nil {
    return err
}
next := authcrunch.NewConfig()
if err := next.AddOAuthApplication(application); err != nil {
    return err
}
portal := &authn.PortalConfig{Name: "login", IdentityStores: []string{"localdb"}}
if err := next.ConfigureOIDCProvider(portal, []string{
    "issuer https://auth.example.com/auth",
    "realms local",
    "signing key files /etc/auth/oidc.pem",
    "applications website",
}); err != nil {
    return err
}
if err := next.AddAuthenticationPortal(portal); err != nil {
    return err
}
// Configure localdb, validate next, persist its registrations privately, and
// construct authcrunch.NewServer. Handle storage failures before activation.
```

This library supplies reusable header handling and root configuration integration;
it does not install an outer HTTP server's directive handler. Consumer adapter
changes remain separate work. The executable examples live in
`pkg/oidc/parser/application_example_test.go` and
`config_oauth_applications_example_test.go`. The portal TLS reload/rotation test
is `pkg/authn/oidc_application_e2e_test.go`.

## Provisioning clients and signing keys

### OAuth application directives

This subsection describes explicit initial provisioning. For normal configuration
adaptation, use [named application registration](#named-application-registration-and-reloads),
which shares this grammar and requires explicit or saved credentials.

For a block such as:

```caddyfile
oauth application myapp {
    client_id myapp
    client_name "My application"
    client_secret <persisted-client-secret>
    redirect_uri https://app.example.com/oidc/callback
    redirect_uri https://app.example.com/other/callback
    scopes openid profile email
    require_pkce yes
    skip_consent no
}
```

Import `github.com/greenpau/go-authcrunch/pkg/oidc/parser` as `oidcparser` and
call its public `NewOIDCClientConfigFromDirectives` constructor with the nickname
and body statements:

```go
client, err := oidcparser.NewOIDCClientConfigFromDirectives("myapp", []string{
    "client_id myapp",
    `client_name "My application"`,
    "redirect_uri https://app.example.com/oidc/callback",
    "redirect_uri https://app.example.com/other/callback",
    "scopes openid profile email",
    "require_pkce yes",
})
if err != nil {
    return err
}
if err := config.AddClient(client); err != nil {
    return err
}
```

The Go example omits the secret for initial generation. A Caddy adapter collects
each line with `cfgutil.EncodeArgs(append([]string{key}, args...))`, just as the
crypto adapter does. `oidcparser.NewOIDCClientConfigFromDirectives` decodes each
statement with `cfgutil.DecodeArgs`; pass the body without the header or braces.
Preserve token boundaries with the encoder rather than joining arguments with spaces. Resolve
host-specific placeholders before encoding. The library has no Caddy dependency
and this change does not install the outer `oauth application` Caddyfile grammar.

| Directive | Values |
| --- | --- |
| `client_id` | One identifier; generated if omitted. |
| `client_name` | One display name; defaults to the block nickname. |
| `client_secret` | One secret; generated for confidential clients if omitted. |
| `token_endpoint_auth_method` | One of `client_secret_basic` (default), `client_secret_post`, or `none`. |
| `redirect_uri` | Exactly one callback URI per statement; repeat to append in declaration order. At least one is required. Exact matching except the authorization port for public HTTP literal-loopback clients. |
| `scopes` | One or more supported scopes; defaults to `openid profile email`; address, phone and offline_access require explicit registration. |
| `request_object_key` | Repeatable `kid modulus exponent`; public RSA JWK base64url integers, 2048–8192 bits. |
| `request_object_signing_alg` | Optional `none` or `RS256` pin; RS256 requires registered keys. |
| `require_pkce` | One boolean; defaults to true; public clients cannot disable it. |
| `skip_consent` | One boolean; defaults to false. |

A public native registration may use `http://127.0.0.1/callback` and/or
`http://[::1]/callback`. Select `token_endpoint_auth_method none`; S256 PKCE
remains mandatory. Bind a local ephemeral listener and include its actual port
in authorization. Only that port may differ from registration; preserve all
other URI bytes. Token exchange must repeat the actual authorized URI exactly.
Use `configuration-and-clients.md` for the callback and CORS boundaries.

Booleans follow `cfgutil.ParseBoolArg`: true/yes/on/1 and false/no/off/0,
case-insensitively. Only `redirect_uri` may repeat; each occurrence takes exactly
one URI. `scopes` takes multiple values on one line and may occur once.
`redirect_uris` is not an alias: reject it even when mixed with singular
statements. The JSON/XML/YAML `redirect_uris` array and typed `RedirectURIs`
field remain unchanged, preserving stored registrations. One callback per
statement lets reviewers inspect, add, or remove one registration independently;
keep that append behavior in this reusable parser, not in each embedding host.
Do not trim, normalize, deduplicate, or reorder callback values. Duplicate URIs
remain typed-validation errors. Unknown directives, wrong argument counts, empty supplied values,
invalid quoting, and embedded newlines fail without echoing credential values.
An explicit empty secret or ID is an error; omission requests generation only
in the provisioning constructor. The named application adaptation API restores
saved credentials or fails instead.

The nickname is a host configuration label and supplies the default display
name. The host owns nickname lookup and uniqueness; `Config.AddClient` checks
client ID uniqueness. Persist generated registration values before using this
constructor during another adaptation. Supplying the saved ID and secret
preserves them. PKCE is enabled by default; unlike `NewClientConfig`, this parser
also honors an explicit `require_pkce false` for confidential clients.

### Typed configuration and keys

Embedders such as `caddy-security` can provision a confidential application with
only its name and exact callback URI. Typed provisioning helpers belong to the
public `oidc` package; directive parsing belongs to `oidc/parser`. No portal
runtime is needed to create configuration.

```go
func provisionProvider(issuer, keyFile string) (*oidc.Config, error) {
    client, err := oidc.NewClientConfig(oidc.ClientConfig{
        ClientName: "My application",
        RedirectURIs: []string{"https://app.example.com/oidc/callback"},
    })
    if err != nil {
        return nil, err
    }
    config := &oidc.Config{
        Enabled: true,
        Issuer: issuer,
        Realms: []string{"local"},
        SigningKeyFiles: []string{keyFile},
    }
    if err := config.AddClient(client); err != nil {
        return nil, err
    }
    if err := config.Validate(); err != nil {
        return nil, err
    }
    if err := oidc.GenerateSigningKeyFile(keyFile); err != nil {
        return nil, err
    }
    return config, nil
}
```

This is an initial provisioning operation. Persist the returned configuration
securely before serving it, and provision the relying party with its client ID
and secret through a protected channel. Do not call this operation on every
Caddyfile adaptation or reload: load the saved registration and key instead.
The returned config can be assigned directly to `authn.PortalConfig.OIDCProvider`.
This library change does not add Caddyfile directives or a management endpoint.

`NewClientConfig` accepts a `ClientConfig` value and returns an independent,
validated copy. Missing client IDs and confidential-client secrets each receive
32 random bytes encoded with unpadded base64url. Supplied credentials remain
unchanged. It defaults to `client_secret_basic`, scopes `openid profile email`,
and S256 PKCE; consent remains required unless `SkipConsent` is explicitly set.
To provision a public client, set `TokenEndpointAuthMethod: "none"` and omit the
secret. To use POST client authentication, set `"client_secret_post"`. Invalid
values still fail validation; the helper does not repair bad redirect URIs or
replace invalid supplied secrets. It always enables PKCE; a confidential client
can explicitly clear `RequirePKCE` on the result before `AddClient` if required
for compatibility. Public clients cannot disable it.

`Config.AddClient` validates and appends its own copy, preserving supplied
credentials and PKCE policy and rejecting duplicate IDs. It neither generates
credentials nor updates a running provider. Plain `ClientConfig.Validate` and
`NewProvider` continue to reject missing credentials. Callers needing individual
values can use `GenerateClientID()` and `GenerateClientSecret()`.

`GenerateSigningKey()` returns a dedicated 3072-bit RSA private key as PKCS#8 PEM
for caller-owned persistence. `GenerateSigningKeyFile(path)` creates a complete
owner-only file (0600 before umask), refuses existing files and symlinks, and
returns an error wrapping `fs.ErrExist` when another provisioner wins. Its parent
directory must already exist, be trusted, and support hard links. It never loads
or silently replaces an existing key. Retain the path in `SigningKeyFiles` on
reload; ID-token signing keys belong to the provider, independently of clients.

The executable examples are in `pkg/oidc/provisioning_example_test.go`. The TLS
E2E test persists generated configuration and keys, restores a fresh provider,
and reuses the original client credentials and public signing key.

## Identity boundary

Implement the public interface:

```go
WithIdentity(context.Context, oidc.Authentication, func(oidc.Identity) error) error
```

`Authentication` contains the realm, backend namespace, username, immutable
`Evidence.UserID`, backend and credential versions, original authentication
time, and completed methods/challenges. Generate this evidence after actual
server-side authentication. Do not populate it from unverified HTTP claims or
an arbitrary bearer token.

The verifier checks current account status, immutable identity, version evidence,
and authentication policy. It invokes the callback exactly once, synchronously,
under the lock or transaction that serializes account revocation. Finish fallible
backend work first, then return the callback's result without further fallible
work. Return `oidc.ErrIdentityDenied` without calling the callback when evidence
is stale or ineligible. Do not retain or reenter the callback or provider: the
provider already holds its state lock. This preserves atomic identity checks
through code/token issuance.

Return current attributes as `oidc.Identity`. Assert `EmailVerified` only when
the backend has verified ownership. Subjects are derived from backend, realm,
and immutable user ID; attribute updates do not redefine identity.

## HTTP and browser lifecycle

| Public method | Integration |
| --- | --- |
| `ServeHTTP` | Standard handler for discovery and `<issuer>/oidc/*`; unmatched requests return 404. |
| `HandleHTTP` | Returns false without changing unmatched requests, for hosts with their own router. |
| `ValidateLoginRequest` | Checks origin before the host processes browser credentials; writes 403 on rejection. |
| `CompleteLogin` | Verifies completed login evidence and creates the browser session. A `Location` header resumes pending authorization. Unsupported realms clear the old session. |
| `ClearSession` | Revokes the old browser session while retaining its pending authorization, for a fresh login. |
| `Logout` | Revokes the browser session and pending interaction, then clears both cookies. The host must first authorize logout. |
| `SupportsRealm` | Reports whether a realm is configured. |
| `Discovery`, `JWKS` | Return fresh public metadata maps. |
| `Close` | Releases runtime sessions/grants; retains attached durable snapshots; safe to call repeatedly. |
| `ConfigurePersistentState` | Attaches a trusted `*state.Record` before use; standalone hosts own storage and bindings. |
| `LogoutWithError`, `ClearSessionWithError` | Error-returning composition APIs; stop before success when persistence fails. |

The host owns its login page, credential parsing, required challenges, and logout
authorization. Call `ValidateLoginRequest` before handling browser credentials,
then `CompleteLogin` only after successful authentication. These methods use
browser cookies; native credential transports should not call them. The host
also owns trusted proxy normalization. Keep protocol requests behind the public
HTTP dispatcher, which applies issuer, method, parsing, and CORS checks.

Provider state is bounded and volatile by default. Restarting then requires new
browser authentication. [Runtime state](../../runtime-state/SKILL.md) provides an
opt-in encrypted local snapshot through `ConfigurePersistentState`. Restore before
publication, retain spent history, and drain/close before another storage owner
opens. Bind records to current issuer/client/identity/key configuration. The
standalone E2E example is
`pkg/oidc/provider_e2e_test.go`; it implements the host using only `pkg/oidc` and
the standard library.

Persistent admission uses `Record.PrepareEncode` to reject an oversized candidate
without disabling shared storage. On `state.ErrCapacity`, undo new browser
sessions, grants, consent additions, and token rotation mutations; retain the old
access credential, refresh digest/history, and pre-narrowing scopes. HTTP code
issuance and token endpoints return `temporarily_unavailable`. Failed disk commits
still fail closed. Keep revocation encoding the same size for live and revoked
grants so replay revocation does not need extra capacity. The initial supported
grant DTO uses nonzero `Revocation` markers 1 (live) and 2 (revoked); zero or
unknown markers fail restoration. Test actual record limits,
restart, unrelated record writes, and durable revocation over TLS.

A host composing `CompleteLogin` with its own credential issuance must clean up
undelivered authority and suppress staged success headers on any completion error,
including recoverable capacity errors. The AuthCrunch portal deletes its new
session and revokes its undelivered refresh family using bounded cleanup that
survives request cancellation. Preserve prior completed revocations.

For an existing AuthCrunch portal, `Portal.GetOIDCProvider()` returns the public
interface, or nil when disabled. The portal keeps its existing `oidc_provider`
configuration and cookie-prefix behavior. `authn.OIDCProviderConfig` and
`authn.OIDCClientConfig` remain aliases of `oidc.Config` and `oidc.ClientConfig`.


## Claims and refresh integration

`oidc.Identity.Profile` is an optional `*identity.Profile`. Supply current,
explicit attributes from inside the verifier transaction. The portal adapter
copies `identity.User.Profile` through `identity.RefreshIdentity`; stored values
are authoritative, while transforms still enforce denial and challenge policy.
Do not place arbitrary maps or authentication evidence in profile attributes.
See [provider capabilities](provider-capabilities.md) for supported fields,
consent, ACR mapping, client keys, refresh state and consumer tests.
