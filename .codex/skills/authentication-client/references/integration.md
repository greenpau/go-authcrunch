# Embedding portal authentication

Import `github.com/greenpau/go-authcrunch/pkg/authclient`. The package uses the
portal's JSON `/login` protocol and does not need the admin API. Password, TOTP,
and combined MFA selection match the authentication previously implemented in
`cmd/authdbctl`; API key login uses the portal's existing key verifier through
the same JSON endpoint. Browser OAuth/SAML login, U2F/WebAuthn assertions, refresh-token
renewal, and logout are outside this API.

## Application integration

The following helper shows the intended boundary for a future
`caddy-authenticator` command. The application loads its configuration and
supplies terminal input through `PromptFunc`; it decides where to persist the
returned credentials. This repository does not install that command.

```go
package main

import (
    "context"
    "os"
    "path/filepath"

    "github.com/greenpau/go-authcrunch/pkg/authclient"
)

func authenticate(ctx context.Context, cfg *authclient.Config, prompt authclient.PromptFunc) (*authclient.Credentials, error) {
    home, err := os.UserHomeDir()
    if err != nil {
        return nil, err
    }
    store, err := authclient.NewFileTokenStore(filepath.Join(
        home, ".config", "caddy-authenticator", "token.jwt",
    ))
    if err != nil {
        return nil, err
    }
    client, err := authclient.NewClient(cfg, authclient.Options{
        Prompt: prompt,
        UserAgent: "caddy-authenticator",
    })
    if err != nil {
        return nil, err
    }
    credentials, err := client.Authenticate(ctx)
    if err != nil {
        return nil, err
    }
    if err := store.Save(credentials); err != nil {
        return nil, err
    }
    return credentials, nil
}
```

Typical `Config` values are `BaseURL: "https://auth.example.com/auth"`,
`Username: "jsmith"`, and `Realm: "local"`. The base URL identifies the portal
root, not `/login`. Trailing slashes are normalized. User information, query
strings, and fragments are rejected. Use HTTPS for remote credentials.

The application can load the same authentication YAML keys as authdbctl:
`base_url`, `username`, `realm`, `password`, `totp_secret`, `totp_code_length`,
and `totp_code_lifetime`. `access_token_name` is an optional fallback; by default
it is `authp_access_token`. A portal-supplied name is lowercased and takes priority
for the new result. Config-file discovery, env names, flags, and YAML parsing
remain application concerns. `Config` includes secrets and must not be logged.

`PromptFunc` receives context and a `PromptKind`, not a preformatted terminal
message. Return the password for `PromptPassword`, the current code for
`PromptTOTP`, or `totp`/`webauthn` for `PromptMFA`. Respect cancellation and do
not include entered values in errors. The authdbctl adapter maps its numbered
MFA menu to these choices and owns its thirty-second input timeout. A WebAuthn
selection can negotiate the next challenge, but assertion handling returns
`ErrUnsupportedChallenge`.

Without a prompt, supply `Password` and, when required, `TOTPSecret`. Missing
input returns `ErrInputRequired` instead of blocking on stdin. A configured
secret can answer combined MFA without a selection prompt. The secret is raw
AuthCrunch shared-secret text, not the base32 secret from an `otpauth://` URI.
TOTP defaults to six digits, thirty seconds, and SHA-1.

For API key login, supply `BaseURL`, `Realm`, and `APIKey` (`api_key` in YAML).
Omit `Username`, `Password`, and `TOTPSecret`; mixing these with a key is an error.
The key's owner supplies the identity, so this mode never asks for a username,
password, or TOTP code. It sends one JSON request to `/login` and returns an access
token. An API key is a separate credential even for accounts enrolled in MFA.
Disabled, expired, revoked, unknown, or malformed keys cannot authenticate.
This path requires a portal built with this repository's API key JSON login
support; older portals reject the `api_key` field.

API key login never creates a renewable session, even when the realm enables
refresh. It sets no cookies and returns no refresh credential. It cannot be
combined with native refresh transport or a sandbox challenge. Existing access
JWTs retain their normal lifetime when a key is subsequently revoked.

An optional `Options.HTTPClient` permits application transport settings such as
a custom CA pool. The client is copied, with transport and any supplied jar
shared. Redirects remain disabled; a cookie jar is created if missing. With no
injected client, requests use a ten-second timeout and the standard transport.
A supplied client's timeout remains the caller's choice. Each client represents
one identity; serialize interactive logins when sharing a terminal prompt.

## Credentials and persistence

`Authenticate` returns new credentials without reading/writing any file. An
application that only needs credentials in memory can omit the store entirely.
Use `Credentials.Authorization()` to obtain AuthCrunch's `name=token` header
value, or use `AccessToken` for an explicitly chosen downstream transport. The
caller must restrict delivery to the intended trusted service. The package
neither parses nor verifies JWTs; portal-provided expiry/session fields are
metadata, not proof of current authorization.

`FileTokenStore` accepts an exact path. Use separate application directories:

| Application | Config file chosen by application | Token store path |
| --- | --- | --- |
| authdbctl | `~/.config/authdbctl/config.yaml` | `~/.config/authdbctl/token.jwt` |
| future caddy-authenticator | `~/.config/caddy-authenticator/config.yaml` | `~/.config/caddy-authenticator/token.jwt` |

Expand `~` or join `os.UserHomeDir()` in the application before constructing the
store. The store does not infer the application name or consult environment
variables. For multiple portals/users, choose separate profile paths; legacy
credential files contain no portal/identity binding. Authentication does not
look up a cache implicitly, so callers decide when an existing credential may
be reused and when fresh login is required.

The historical `token.jwt` file is a JSON object. Old files with
`access_token`, optional `access_token_name`, `refresh_token`, and `created_at`
continue to load. Missing files return a wrapped `os.ErrNotExist`; malformed,
empty-token, or oversized files return errors without including their contents.
`Load` preserves an omitted token name so the CLI can apply its flag fallback;
`Authorization` itself defaults an omitted name to `authp_access_token`.

Save replaces the complete file, so a new login without a refresh token clears
any old refresh token. It creates missing directories with 0700 and a temporary
file with 0600, then syncs, closes, and renames it over the destination. Existing
directory permissions remain unchanged. Atomic visibility depends on platform
rename guarantees; Windows uses filesystem ACLs. This is not an OS keychain or
a refresh-token rotation lock. The application must select a private directory.

Refresh-related response fields are retained when returned by the portal. The
client preserves the existing default login transport: it does not opt into
native refresh-token delivery or call refresh/logout endpoints. Read the owning
refresh skills before extending this behavior.

## authdbctl adapter

The existing CLI keeps all commands and flag/env names. `Config` embeds
`authclient.Config` with YAML inline mapping while retaining `token_path` and
legacy `cookie_name`. The latter is retained for configuration compatibility;
credential attachment uses the access token's name.

The CLI loads token files, then passes config and its terminal callback to
`NewClient`. `connect` calls `Authenticate`, saves the result, and prints the
token path. Database commands reuse loaded credentials; when a management
response says `access denied` and another attempt remains, the command wrapper
performs a fresh login before retrying. These admin endpoints and retry rules
remain entirely in `cmd/authdbctl/requests.go` and its command handlers.
