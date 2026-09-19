# Profile authentication-flow API

## Endpoint and ownership

Both operations use **POST `<portal base>/api/profile`** with
`Content-Type: application/json`. For the UI at `/auth/profile/`, this is
`/auth/api/profile`. They require an authenticated, current local-user session
with `authp/user` or `authp/admin`, and `PortalConfig.API.ProfileEnabled`.
They do not require the administrative API or an administrator account.

The server selects the original login account using `profile_identity.go`.
Neither transformed JWT `sub`/`email` nor body fields such as `username`,
`realm`, or `user_id` select the account. Every backend access must retain the
bound immutable identity and credential version. Use ordinary profile cookies
or the existing token transport; never send password, factor secrets, or
identity evidence to these operations.

`api_fetch_user_auth_challenges.go`, `api_overwrite_user_auth_challenges.go`,
and `profile_auth_challenges.go` own the HTTP behavior. Nonempty rule arrays
are validated by
`pkg/authchal/parser.NewAuthenticationChallengeConfigFromDirectives` and
persisted through the bound `operator.OverwriteAuthChallengeRules` operation.
There is no separate flow grammar or new portal configuration flag. The
response metadata is runtime state, not another configuration surface.

## Read and replace

Fetch the saved preference and the effective policy preview:

```json
{"kind":"fetch_user_auth_challenges"}
```

Replace the entire ordered rule list, for example preferring WebAuthn with
password/TOTP and then password fallbacks:

```json
{
  "kind": "overwrite_user_auth_challenges",
  "challenges": [
    "u2f",
    "password totp if u2f not available",
    "password if u2f and totp not available"
  ]
}
```

Reset the user's preference to the backend defaults:

```json
{"kind":"overwrite_user_auth_challenges","challenges":[]}
```

An explicit empty array is the only reset representation. Missing, null,
scalar, mixed-type, empty-string, duplicate, or malformed rules return 400;
the server must not discard invalid elements and save a partial list. It
rejects explicit email challenges/conditions because the portal has no email
checkpoint. At least one rule must select a currently available supported
flow; enrollment must happen before choosing a factor-only policy. Generic
`mfa` needs an enabled TOTP or WebAuthn credential. Rejections do not change
the stored rules or credential version.

Each string is a **rule body**, with no `require auth challenges` prefix or
braces. `password totp` requires both; `u2f or totp` selects the first
available alternative. Rule order matters. Conditions and alternatives follow
the shared authchal parser, not client-side string splitting. An explicit
policy that later has no eligible rule denies login. To retain recovery after
factor removal, include appropriate fallback rules.

## Successful response

Both operations return HTTP 200 with the common `status: 200` and `timestamp`
envelope, plus:

| Field | Meaning |
| --- | --- |
| `entries: string[]` | Canonical stored rule bodies, in order. Empty means backend defaults. |
| `registered_methods: string[]` | Enabled supported methods, using `password`, `totp`, and `u2f`. Inventory only; it proves no authentication. |
| `effective_challenges: string[]` | Ordered checkpoints for a fresh login in the current request context, including portal requirements. Generic `mfa` can appear when the factor is chosen during login. |
| `additional_challenges: string[]` | Additive legacy portal `require` actions before checkpoint deduplication. |
| `policy_source: "default" \| "user" \| "portal"` | Source of the selected base sequence. Additional requirements still apply. |
| `reauthentication_required: true` | Present after successful replacement/reset. Start fresh login immediately. Omitted on fetch. |

All four lists are arrays, including `[]`, never null. Responses contain no
credential material or AMR authentication evidence. Example after selecting a
registered passkey without a mandatory portal password requirement:

```json
{
  "status": 200,
  "timestamp": "2026-09-19T12:00:00Z",
  "entries": ["u2f"],
  "registered_methods": ["password", "u2f"],
  "effective_challenges": ["u2f"],
  "additional_challenges": [],
  "policy_source": "user",
  "reauthentication_required": true
}
```

Display the saved preference separately from the effective preview. A matching
portal `require auth challenges` policy overrides the user's base sequence;
legacy `require password`, `require totp`, and similar actions remain additive.
A user can save a preference while `policy_source` remains `portal`; saving
does not remove the administrator's requirements. Backend defaults ordinarily
require password plus an enrolled MFA method; clearing a preference does not
disable these requirements or delete credentials.

A nonempty saved preference also constrains direct authentication. Basic login
must satisfy the effective sequence, so it cannot complete a TOTP-only or
WebAuthn-only flow. API-key login proves none of the configured password/MFA
checkpoints and is denied under any explicit stored preference, even
`["password"]`. With `entries: []`, API keys retain their separate legacy
behavior unless a portal replacement or additive requirement applies. Preserve
this distinction when explaining a flow change in the Profile UI.

The preview uses current backend identity attributes and inventory, the
server-cached login's backend/realm, and the current request's source/issuer
context mapped to the login path. It shares sandbox claim construction,
transform evaluation, and checkpoint injection with real login. It creates no
sandbox or token. Future login, refresh, and OIDC issuance recheck policy; a
preview is not an authorization promise after credential, configuration, or
request-context changes.

For request-dependent portal transforms, `addr` is the current source address
and transform-time `iss` includes the endpoint path. The preview maps that path
to `/login`; subsequent sandbox, refresh, and OIDC operations use their own
paths and current source addresses. A portal URL prefix is appropriate when
the administrator intends the same requirement across the whole flow. OIDC
backchannel requests can come from a relying party server. The UI must not
treat the preview as a guarantee that every later request has identical context.

## Fresh login and errors

A successful save/reset atomically increments the credential version. Old
profile authority, unfinished logins, refresh credentials, and OIDC login
evidence cannot acquire the new policy. Existing access JWTs can remain valid
until expiry for consumers that only verify the JWT; they cannot authorize
another profile mutation with stale server evidence. Do not silently upgrade
the cached session or retry the save through refresh.

Direct Basic/API-key exchanges, including encrypted remote authentication,
recheck current identity and policy inside their issuance transaction. A
concurrent save cannot leave them signing against
the account's earlier preference or roles. API keys remain distinct credentials;
they cannot satisfy the newly selected password/TOTP/WebAuthn requirements.

On `reauthentication_required: true`, navigate to
`<portal base>/api/refresh_token` using the existing Profile UI
`reAuthenticateUser()` helper. This compatibility **GET navigation** leads to
`/login?fresh=1`, clears the stale access cookie, and starts a fresh login with
the selected flow. It works with portal refresh tokens disabled or enabled.
It is different from a POST refresh-token rotation request. Handle 401 from
subsequent profile operations with the same recovery navigation.

| HTTP status | Client action |
| --- | --- |
| 400 | Correct invalid/missing rules or enroll a required factor; no update occurred. Also used when the candidate cannot resolve against portal policy. |
| 401 | Current local login evidence is missing, stale, or revoked; authenticate again. |
| 403 | Authentication/role or same-origin checks rejected the request; preserve normal profile access/error handling. |
| 409 | Fetch could not resolve the current saved policy in this context. Offer correction/reset where a current session remains valid; portal configuration may need administrator attention. |
| 415 | Send `application/json`; text/plain JSON is not supported. |
| 500 | Backend read/write failed; show an error. The bound transaction rolls back failed writes. |
| 501 | The profile account uses an unsupported, non-local authentication backend. |

Do not infer a successful write from a timeout or automatically replay it:
the server may have committed before the response was lost. A fresh login
followed by fetch establishes the persisted policy.

## Separate Profile UI consumer

The source checkout is `../../authcrunch/authcrunch-ui/frontend/profile/`.
Its `src/Config.ts` exposes `config.getAppPath()`; existing services such as
`src/components/custom/MultiFactorAuthenticatorListing/service.tsx` use
`${config.getAppPath()}/api/profile` with Axios POST and the profile's normal
authentication setup. Reuse that pattern and the helper in
`src/components/builtin/auth/index.tsx` for future flow controls. Label `u2f`
as WebAuthn/passkey and `totp` as authenticator code without changing wire names.
Keep this backend contract in go-authcrunch; UI source changes, asset builds,
and generated embedded bundles belong to a separately requested UI change.

## Validation

`pkg/authn/profile_auth_challenges_test.go` covers strict decoding, policy
preview, failure responses, and revocation between read and write.
`profile_auth_challenges_e2e_test.go` drives real TLS profile operations and
password, TOTP, and signed WebAuthn login against a temporary database. It
reopens persisted state, tests transformed identities and forged selectors,
checks rejected writes and session continuity, verifies administrative
precedence, and checks save/reset revocation and fresh-login recovery with
refresh/OIDC disabled and enabled. Access AMR is independently verified through
JWKS after the selected checkpoints complete.

```sh
make test TEST_DIR='./pkg/authn' TEST='^(TestProfileAuthChallenge|TestProfileIdentity|TestE2EProfileAuthenticationFlow|TestE2EProfileCredentialMutationUsesCanonicalIdentity|TestE2EProfileRejects|TestE2EProfileRequiresJSON)' COVERAGE_DIR='.coverage/profile-auth-challenges'
make ci-check
```
