# Source and contract review

## Select the implementation

Trace native host dispatch through the root server into local portal/policy
handlers, serializers, validators and configuration. All evidence paths are
relative to this checkout. The reviewed source inventory fingerprints root
configuration/runtime, `pkg/httpserver`, `cmd/authdb`, authentication/authorization,
wire models, identity stores/providers, OIDC, keys, registry, challenges, tagging,
random encodings and utility validators. It detects newly added handlers and
ignores tests. Review external dependency changes separately.
Redirect policy, URL construction/sanitization, forwarded-address helpers and
their WAF validators are also contract inputs: changing these can alter browser
destinations, issuer URLs, origin checks and cookie domains without editing a
handler. Keep their sources in the review gate.

Release metadata normalization is limited to known versioned literals in the
authdb entry point and identity database. Source changes in their constructors
or serializers still require review. Keep HTTP host behavior separate from
library behavior; an embedding server owns catch-all routing and error output.

## Trace the surfaces

Paths below are relative to this repository. Every documented path is relative to the shared configured mount.
Direct OAuth uses the reference's `/oauth2` suffix with explicit policy wiring;
it inherits the same document server as portal federation and the other APIs.

| Surface | Implementation evidence | Review decisions |
| --- | --- | --- |
| Host boundary | Root `server.go`, `pkg/httpserver/server.go`, `cmd/authdb/main.go` | Provisioning, lifecycle, portal/policy mount, handled callback responses, trusted metadata |
| Portal dispatch | `pkg/authn/serve_http.go`, `respond_api.go`, `respond_json.go`, `respond_http.go`, `extract_base_path.go` | Route/method negotiation, guard ordering, trailing mount, disabled feature behavior |
| JSON/API-key login | `pkg/apiauth/*.go`, `pkg/authn/handle_json_login.go`, `handle_json_api_key_login.go` | 1024-byte limit, strict decoding, evolving sandbox secret, MFA checkpoints, access-only versus refresh success |
| Refresh/session/logout | `pkg/authn/handle_api_refresh_token.go`, `token_refresh_*.go`, `pkg/authn/cookie/*.go` | Body/cookie transport, exact HTTPS origin, CSRF header, preconditions, replay, capacity and invalidation |
| Claims/beacon | `pkg/authn/handle_json_whoami.go`, `handle_json_beacon.go`, `handle_http_whoami.go`, `pkg/util/request_id.go` | Exact Accept negotiation, HTML redirects versus JSON denial, custom/transformed claims, probe precedence, raw `OK` with JSON media type |
| Public signing keys | `pkg/authn/handle_http_jwks.go`, `pkg/kms/*` | Public GET/HEAD, first eligible signer, HMAC-only absence, no secrets/export dependency, empty errors |
| Profile | `pkg/authn/handle_api_profile.go`, `api_*.go`, `profile_auth_challenges.go`, `pkg/identity/*` | Stored local browser session and canonical identity, kind discriminator, credential ownership, factor mutations and invalidation |
| Administration | `pkg/authn/handle_api_{list_realms,list_users,realm_info,reload_realm,crud_user,metadata,private_keys}.go`, `pkg/identity/*` | Feature flags, administrator role, per-operation JSON, status within HTTP 200, key export formats and independent public JWKS |
| System | `pkg/authn/handle_api_system.go`, `pkg/system/*` | AuthCrunch encrypted wire content and footer key ID, encrypted authenticated success, JSON error envelopes on failure |
| Portal OpenID Provider | `pkg/oidc/*`, local `caddyfile_oauth_application.go`, `caddyfile_authn_oidc.go` | Discovery versus portal JWKS, Authorization Code/PKCE, client auth, consent, opaque access tokens, rotating OP refresh, revoke, registered redirect trust |
| Cross-device | `pkg/authn/cross_device*.go` | Explicit approval, requester/approver browser binding, code and secret, CSRF, polls, terminal states, one-time cookie issuance |
| Injected HTTP provider | `pkg/authn/handle_provider_login.go`, `pkg/idp/http_login.go` | GET-only realm route, provider-owned query/proof, HTML negotiation, safe results/cookies, federated evidence |
| Browser/federation | `pkg/authn/handle_http_*.go`, `handle_basic_login.go`, `pkg/idp/oauth/*`, `pkg/idp/saml/*` | HTML and redirects, sandbox form challenge, provider callbacks, RelayState/browser binding, browser-only evidence |
| Registration/SSO | `pkg/authn/handle_register.go`, `handle_http_apps_sso.go`, `pkg/sso/*`, `pkg/registry/*` | Required registration realm (bare `/register` has no default), acknowledgement form versus code submission, form results, reachable metadata versus unimplemented assume handlers |
| Direct OAuth | `pkg/authz/oauth*.go`, root server delegation | Protected-app callback and logout, own cookie/CSRF/origin boundary; never a fictional fixed REST authorize resource |

Glob/table shorthand means inspect the current concrete files, not literal file
names. `x-source-files` in each operation provides concrete current anchors.
Review route additions against the dispatcher even when no matching method
annotation exists. Read tests for edge cases, but use the runtime serializer
for final field names and omissions.

## Preserve protocol distinctions

- An endpoint's existence depends on configuration. State disabled behavior;
  do not imply that JSON adaptation enables it by default. Portal OP, refresh,
  cross-device, registration, admin and private export are independent gates.
- Portal bearer/cookie access, stored profile browser evidence, refresh tokens,
  OP tokens/client authentication and cross-device proofs are not interchangeable.
  Native JSON login does not establish the OP's browser login evidence.
- Browser form and JSON login share a path. Keep media types and redirects
  separate; `Accept: application/json` or `format=json` selects JSON routing.
- Refresh browser bodies contain metadata, with credentials only in cookies.
  Native bodies require explicit configuration and opt-in at each checkpoint.
  Model replay as a terminal failure, not an automatically retryable rotation.
- The default portal access cookie is `AUTHP_ACCESS_TOKEN`, but deployments can
  rename it. A security scheme's example name is not a guarantee for every server.
- `/api/profile` is one operation-dispatched endpoint. Do not invent REST paths
  for its password, challenge, API-key, SSH, legacy PGP/RSA, TOTP or WebAuthn
  operations. Profile policy can be reset with an empty array; administrative
  policy overwrite has a different nonempty requirement.
- Realm/user metadata and profile entries vary by operation/backend. Keep open
  portions explicit instead of inventing exhaustive DTOs. Admin mutation HTTP
  200 can represent application failure; unknown realms have handler-specific
  empty, null or 404 responses.
- `/api/server/metadata` writes JSON with a text media type; `/beacon` emits
  non-JSON `OK` with a JSON media type. JWKS errors can have no body. Document
  and test those wire behaviors instead of silently normalizing them.
- Public portal JWKS and OP JWKS have different signing/availability rules.
  Private export needs two explicit flags and admin authorization. Never place
  private keys or real tokens in examples, diagnostics or test failure output.
- Direct OAuth uses the policy's explicitly configured callback base at runtime.
  In the reference layout, configure it as the shared mount plus `/oauth2`.
  Portal browser GET `/logout`, session POST `/api/logout`, and direct POST
  `/oauth2/logout` retain distinct paths and credential boundaries.
- Browser pages, MFA, WebAuthn, SAML and cross-device journeys cannot be completed
  by a generic OpenAPI request panel alone. Keep forms, state, cookies and
  redirects described without promising an interactive login wizard.

## Deployment and mount review

Do not introduce path/operation `servers` overrides. They can make Scalar ignore
the document's selected origin and mount, including saved browser settings.
Check the actual request URL, not only the operation header (which displays the
relative path). The generator rejects overrides; canonical YAML contains just
the shared `{origin}{portalBasePath}` server.

| Surface | Path relative to the shared mount | Default absolute path |
| --- | --- | --- |
| Portal login | `/login` | `/auth/login` |
| Portal browser logout | `/logout` | `/auth/logout` |
| Portal session logout | `/api/logout` | `/auth/api/logout` |
| Portal external OAuth login | `/oauth2/{realm}` | `/auth/oauth2/{realm}` |
| Portal external OAuth callback | `/oauth2/{realm}/authorization-code-callback` | `/auth/oauth2/{realm}/authorization-code-callback` |
| Direct OAuth callback | `/oauth2/authorization-code-callback` | `/auth/oauth2/authorization-code-callback` |
| Direct OAuth logout | `/oauth2/logout` | `/auth/oauth2/logout` |
| Portal OP token endpoint | `/oidc/token` | `/auth/oidc/token` |
| Portal signing keys | `/.well-known/jwks.json` | `/auth/.well-known/jwks.json` |

The direct policy needs `oauth base path /auth/oauth2` for this default layout;
the runtime default remains `/_authcrunch/oauth2/POLICY` when omitted. Keep that
distinction explicit. Match the exact direct callback/logout paths to the gatekeeper
before a catch-all portal route. Portal OAuth realm routes still belong
to the portal; a broad direct `/auth/oauth2/*` matcher would swallow them.
Avoid realm names `authorization-code-callback` and `logout` when sharing this
namespace. A deployment choosing another direct namespace must adapt the authored
relative paths or use a separately scoped reference, rather than silently bypass
the shared origin/mount with operation server overrides.

Audit every operation's server inheritance and path. Browser validation visits
all operations and checks their generated curl URL prefixes; it revisits both
OAuth modes after editing settings, reload, nested mounts and an empty mount.
The live native HTTP contract suite verifies portal login/JWKS and real direct-provider
login, callback, protected access and logout at `/auth`, `/team/auth` and root.

## Validation evidence and limits

The generator applies three layers: strict YAML/reference checks, repository
operation invariants, and the vendored official OpenAPI 3.1 schema plus offline
JSON Schema 2020-12 compilation/examples. Its schema source URL and original
JSON checksum are recorded at the top of `internal/openapi/oas31-schema.yaml`.
When upgrading that schema, preserve its upstream source and checksum, review
its dialect requirements and run rejection tests. Do not add external loading
as a validation fallback. The Go schema library is pinned in `go.mod`.

The syntax traversal distinguishes OpenAPI/schema objects from named maps and
literal JSON. Unit cases and the real Make/server journey preserve claim examples
containing `$ref`/`$id`, while actual remote schema references remain rejected.
Paths, Responses and Components extensions are opaque too; component names
starting with `x-` still resolve, and extension-only paths/responses are rejected.
Serving tests also reject file and directory symlinks introduced after generation,
including encoded URL aliases for private files inside the documentation root.
The review inventory retains required module/files fields and participates in
the repository's exported-struct tag compliance checks.

`pkg/authn/openapi_contract_e2e_test.go` validates actual TLS native responses against
schema pointers in the bundled document. It reuses real public constructor/provisioning
fixtures and browser/native password flows. Checks cover content types, payload
schemas, missing/invalid credentials, public GET/HEAD JWKS, profile/account
metadata, refresh rotation and logout. Errors with credentials withhold bodies.
Extend this suite when a changed contract needs new wire samples; never hard-code
the expected response into a stub and call that native HTTP coverage.

For complete authentication/OIDC/cross-device/provider journeys, retain and run
the affected existing suites described in
[testing surfaces](../../testing-and-ci/SKILL.md). Their
success alone does not validate every documented schema, and these sampled
contract tests do not replace their state/security checks. Official OP
conformance is separate and opt-in. Schema validation is neither certification
nor a guarantee that arbitrary transformed claims fit a closed model.

The real Scalar browser test verifies rendering and navigation using the exact
pinned bundle. It does not send credentials to an external deployment, prove
that CORS is configured for API calls, or test all Scalar client generators.
