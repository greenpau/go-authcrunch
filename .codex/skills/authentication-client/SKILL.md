---
name: authentication-client
description: Maintain pkg/authclient portal login, password/TOTP challenges, API key authentication, real-portal E2E tests, opaque credential files, and cmd/authdbctl authentication wiring. Use when embedding authentication in another CLI such as caddy-authenticator; this client does not use the admin API.
---

# Authentication Client

## Ownership

`pkg/authclient` is the importable consumer of `pkg/apiauth` JSON login types.
It owns `Config`, `Client`, `Options`, `PromptFunc`, `Credentials`, and
`FileTokenStore`. It sends only `POST <base_url>/login`; authentication does not
require `enable admin api`. Keep server handlers in `pkg/authn` and management
operations in `cmd/authdbctl`.

Read [references/integration.md](references/integration.md) when embedding the
client, choosing credential paths, or changing the CLI adapter. Public contracts
also live beside the exported Go declarations and in `pkg/authclient/doc.go`.

The reusable package does not discover config, select application directories,
read terminal input, log credentials, or dispatch CLI commands. Do not add
`urfave/cli`, `term`, or application-name defaults to it. Applications own prompt
presentation, config loading, user-agent identity, and credential persistence.

## Protocol Invariants

- `NewClient` validates a copy of configuration. `Authenticate(ctx)` starts a
  fresh exchange, returns credentials, and has no token-file side effects.
- Keep each response newly decoded. Missing sandbox fields must not inherit
  previous response values. Continue only with a sandbox ID, sandbox secret,
  and next challenge; success requires a nonempty usable access token.
- Keep the ten-request bound, response-size limit, context propagation, and
  refusal to follow redirects, including with an injected HTTP client.
- Configured password/TOTP values avoid input prompts. `PromptMFA` returns
  `totp` or `webauthn`; the CLI translates numbered choices. Without a prompt,
  a configured TOTP secret can answer a combined MFA challenge directly.
- `APIKey` selects a separate, single-request login with `Realm`; reject mixed
  username/password/TOTP configuration. Send the key only in the JSON body,
  never in the URL. Do not fall back to challenges or prompt after key rejection.
  The portal derives the identity using its existing proxy API key verifier.
  Keys are independent credentials, including for accounts enrolled in MFA.
  Key login issues an access token only, sets no cookies, and cannot create a
  refresh family. `refresh_transport: body` is rejected for this mode.
- TOTP uses raw secret bytes and SHA-1, matching `identity.MfaToken` and existing
  authdbctl config. Do not silently interpret the secret as base32. Defaults are
  six digits and thirty seconds; accepted digits match the portal's four-to-eight
  range and the period must be positive.
- U2F/WebAuthn assertion handling remains unsupported. Return
  `ErrUnsupportedChallenge` without echoing server challenge payloads. Missing
  input uses `ErrInputRequired`; HTTP failures expose a status via `HTTPError`.
- Each login returns only its new credentials. Never merge an old refresh token
  into a fresh result. Token syntax checks are not JWT verification.

Server API key handling lives in `pkg/authn/handle_json_api_key_login.go` and
dispatches from the JSON login handler before sandbox/refresh processing.
Keep disabled/expired-key and disabled-account checks in the shared identity
lookup so every consumer enforces them. For password/TOTP checkpoints, retain
the canonical sandbox subject after resolving a username or email; never replace
it with the caller's alias before comparing the completed identity.

## Credential Files and CLI Compatibility

`FileTokenStore` takes an explicit path; constructing it performs no filesystem
IO. Preserve the legacy JSON keys in `Credentials`, including optional token
name, refresh token, and `created_at`. Missing files remain inspectable with
`errors.Is(err, os.ErrNotExist)`; malformed files fail instead of being silently
replaced. Save through a private temporary file and rename, with 0700 new
folders and 0600 files on Unix. Do not truncate the destination before success.

Legacy files have no portal/identity binding. The application must choose the
correct store per portal and identity. File replacement is not cross-process
refresh rotation coordination. The client does not request native refresh
transport or implement renewal/logout; changes to those contracts belong with
`refresh-token-transports` and `refresh-token-implementation`.

`cmd/authdbctl/Config` embeds the authentication config with YAML inline fields.
Keep `token_path`, legacy `cookie_name`, `AUTHDBCTL_*` flags/env names, and the
`~/.config/authdbctl` defaults in the CLI. YAML `token_path` wins over the flag;
a cached token name wins over the flag fallback, and a returned portal token
name wins for newly acquired credentials. `connect` always performs fresh login.
Management commands reuse the loaded credentials and own their reauthentication
and retry decisions. Requests with access-token attachment disabled never
trigger reauthentication; exhausted retries do not start an unused login.

## Validation

Use `pkg/authclient/client_test.go` for login-only HTTP exchanges, portal-compatible
TOTP, TLS client injection, malformed or oversized responses, sandbox isolation,
redirect refusal, request limits, and canceled input/HTTP. Token-store tests
exercise legacy JSON, application path isolation, private replacement, failure
cleanup, and readers during atomic saves. `example_test.go` compiles and runs as
an external consumer. CLI tests verify unchanged YAML/flag wiring, login without
admin endpoints, cache use, and management reauthentication. Its separate
`cmd/authdbctl/e2e_test.go` builds and runs the executable against a real portal;
keep those executable tests alongside the external-consumer package E2E suite.

`e2e_test.go` uses the external `authclient_test` package and a real `authn.Portal`
served over local TLS, backed by a temporary local identity database. Keep these
tests in the default suite without build tags or external-service requirements.
They cover configured/prompted passwords and TOTP, email and mixed-case usernames,
combined MFA, API keys, root/subpath mounts, custom token names, and rejected or
missing credentials. API key cases include wrong secrets with a valid prefix,
unknown/malformed keys, disabled and revoked keys, disabled users, unknown realms,
MFA-enrolled accounts, and access-only login in refresh-enabled realms. Admin and profile
APIs stay disabled; assert that authentication requests only the login endpoint.
After saving and reopening credentials under an application-selected path, use a
separate client without login cookies to call `/whoami`. Check identity, roles,
and remaining lifetime, plus rejection of missing tokens and tampered signatures.
Preserve this real portal test boundary when changing the public client contract;
scripted HTTP response tests alone do not establish portal compatibility.
Password/TOTP fixtures use the default login transport with refresh disabled.
API key fixtures also check refresh-enabled realms without minting refresh tokens;
these tests do not establish native refresh or renewal support.

`pkg/authn/handle_json_api_key_login_test.go` checks the server's mixed-credential
and refresh-transport rejection, cookie-free response, and no-store policy.
`pkg/identity/database_test.go` covers expired/disabled key and owner state through
the real verifier. The CLI's API key connect test verifies YAML loading and
credential persistence without a username or terminal input. Browser OAuth/SAML,
hardware WebAuthn assertions, SSH/GPG login, and refresh renewal are not supported
client flows; do not describe unit mocks as E2E coverage for those methods.

`io_test.go` covers failed response reads, request construction, and credential
header rejection. Token-file failure tests inject a private factory on each
`FileTokenStore` and wrap real temporary files to exercise creation, partial
write, sync, and close failures. Verify preservation of the existing file,
temporary-file cleanup, descriptor closure, and recovery after a failed save.
Keep fault injection per instance so tests can run concurrently.

The package has a focused 100% statement-coverage gate. Keep the threshold scoped
to this package; it is not the repository-wide coverage threshold. Scalar-only
JSON marshaling and the standard cookie-jar constructor have documented
infallibility assumptions in code; revisit those assumptions if their types or
dependencies change instead of adding synthetic failures for impossible states.

```sh
go test -race ./pkg/authclient ./cmd/authdbctl
make test TEST_DIR='./pkg/authclient' TEST='^TestE2E' COVERAGE_DIR='.coverage/authclient-e2e'
make test TEST_DIR='./pkg/authclient' COVERAGE_DIR='.coverage/authclient' MINIMUM_COVERAGE=100
make test TEST_DIR='./pkg/authclient ./cmd/authdbctl'
make ci-check
```

The E2E-only run uses the repository's default coverage threshold; the 100% gate
requires the entire package suite. The complete gate is appropriate for changes
spanning both packages. New tests use temporary directories and local HTTP
servers; never use real credentials or a live portal. Check changed skill
frontmatter with the default skill-creator
validator and inspect integration links and concrete exported names.
