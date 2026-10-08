# Field semantics and validation

## Trace the complete acceptance path

For each request field, read decoding, normalization, handler validation,
backend constructors, and the state-dependent consumer. For response fields,
read the serializer and generation path. A regex declaration, struct type or
configuration flag alone does not establish the HTTP contract.

Use descriptions for meaning, units, omission/empty/null behavior, ownership,
normalization, configuration gates and conditional requirements. Use `enum`,
`const`, `pattern`, length/numeric bounds, `required`, `dependentRequired` and
schema variants where the selected runtime supports them. Preserve open claims
and backend-specific records. Regex validation cannot prove that a key parses,
a signature verifies, a CSRF token matches, or a credential is current.

JSON Schema lengths count Unicode characters; Go `len(string)` counts UTF-8
bytes. Document byte limits explicitly (`x-minBytes`/`x-maxBytes` supplement prose where
useful); do not represent a configurable or byte-dependent rule as an exact
universal character bound. For example, eight four-byte characters satisfy a
32-byte client-secret minimum. JSON numbers decoded to `float64` and then cast
to `int` can accept fractional values before enum validation; the TOTP handlers
do this for periods and digit counts. Formats such as `date-time` and `int64` are useful
annotations but do not replace runtime validation. Use patterns compatible with
both the Go schema compiler and browser ECMAScript; Go regex `\s` is ASCII,
whereas browser `\s` includes more Unicode whitespace. Preserve trimming where
the actual handler applies it, and do not normalize secrets speculatively.
OIDC `prompt` uses Go's Unicode-aware `strings.Fields`; its explicit whitespace
class must accept Unicode separators while excluding the byte-order mark.
Registration terms acceptance is configuration dependent, so `on` is an example
and a documented conditional requirement, not an unconditional enum.

Trace decoder consumption as well as nominal reader limits. A single Decode
without an EOF check can accept unread trailing values and oversized suffixes;
use `x-maxDecodedBytes` for that boundary rather than claiming a total body
limit. Case aliases, repeated members, null-to-string decoding and empty
normalized fields can change mode selection without changing a Go struct.
Test those through raw HTTP; canonical JSON Schema objects cannot express
member ordering or trailing bytes. Do not copy OAuth Basic decoding rules onto
the portal's legacy browser Basic parser.

## Implementation map and consequential details

Paths below are relative to this repository. The source inventory includes
these handlers, credential owners and utility validators.
For delegated parsing, also resolve and inspect the selected transitive module.
The source inventory does not fingerprint every transitive dependency. Crypto
library changes therefore require the public-key contract tests and parser review
even when the AuthCrunch wrapper's fingerprint is unchanged.

| Fields | Owners | Contract details |
| --- | --- | --- |
| Portal token `exp`, `iat`, `nbf`, refresh expiry deadlines | `pkg/user/user.go`, `pkg/authn/token_issuer.go`, `pkg/authn/handle_json_whoami.go`, `pkg/authn/token_refresh/manager.go` | Whole Unix seconds (UTC), not milliseconds or date strings. `expires_in` is a duration; a probe computes it after token validation, so do not impose a positive minimum. OP `auth_time` refers to the actual login, not refresh issuance. Do not reuse this integer restriction for Request Object inputs. |
| Login variants | `pkg/apiauth/auth_request.go`, `pkg/authn/handle_json_login.go`, `pkg/authn/sandbox_user.go` | Trimmed required identity/challenge fields, rotated sandbox secrets, API-key exclusion, and body/cookie transport. Omitted/empty transport selects cookie. Temporary IDs/secrets use the random helper's exclusive upper length bound. |
| Refresh and OP opaque tokens | `pkg/authn/token_refresh/token.go`, `pkg/oidc/provider.go` | Portal refresh is `acr1_` plus canonical base64url of 32 bytes; OP credentials are 43-character base64url without that prefix. Refresh session IDs are 64 lowercase hex characters. Canonical final base64 bits matter. |
| Profile titles, descriptions, API keys, labels/tags | `pkg/authn/handle_api_profile.go`, `pkg/authn/api_add_user_*.go`, `pkg/tagging/tag.go` | Title validators differ for API/SSH, PGP and authenticators. Description is required but may be empty; otherwise its ASCII regex applies. Tag key/value are both required strings, including empty strings. Key upload trims content; test-key comparison does not necessarily trim it. |
| TOTP | `pkg/authn/api_*multi_factor_authenticator*.go`, `pkg/identity/mfa_token.go`, `pkg/identity/qr/qr.go` | A raw 10–200 alphanumeric-byte HMAC secret is Base32-encoded by QR generation; the API field is not pre-encoded Base32. Passcodes are digit strings with leading zeros. Save and QR construction reject period 15 downstream even though the handler recognizes it; the diagnostic candidate check accepts 15. Digit count and code/time validation remain separate. |
| Profile password changes | `pkg/authn/api_update_user_password.go`, `pkg/identity/identity_request.go`, `pkg/identity/database.go`, `pkg/identity/user.go`, `pkg/identity/password.go` | Old/new values are trimmed; old password is verified. Serialized hash imports are forbidden here. Byte-length policy is configurable and bcrypt has a 72-byte ceiling. Do not infer enforcement of every reported policy flag. |
| Account and challenge administration | `pkg/authn/handle_api_crud_user.go`, `pkg/ids/local/store.go`, `pkg/authn/profile_auth_challenges.go`, `pkg/authchal/` | Username/email jointly select the account. Local creation policy differs from registration. Profile `challenges: []` restores defaults; admin replacement requires a nonempty list. Grammar, registered factors and portal transforms determine whether a flow is usable. |
| Registration | `pkg/authn/handle_register.go`, `pkg/authn/validators/user_input.go`, `pkg/util/charset/utils.go`, `pkg/util/random.go` | Handle validation folds case and also accepts İ/K; its limit is 25 bytes. The selected email length conditional has no effective limit, so do not invent a 254-character maximum. Domain/MX checks and terms/invitation codes are configuration dependent. Confirmation ID/code generation uses exclusive upper length bounds. |
| OIDC authorization, PKCE and grants | `pkg/oidc/authorization.go`, `token.go`, `request_object.go`, `claims.go`, `config.go`, `redirect.go` | Canonical S256 digest, verifier alphabet/length, prompt combinations, duplicate parameters, exact redirect/client bindings, claims JSON and Request Object trust. Authorization filters unregistered scopes; refresh accepts only a unique subset. The revocation token-type hint is ignored, so do not add a rejecting enum. |
| External-provider hints | `pkg/idp/oauth/authenticate_setup.go`, `pkg/authz/authenticate.go`, `pkg/util/validate/` | The portal provider forwards hints; an authorization policy separately requires opt-in and validates them before forwarding. Do not apply that gatekeeper validator to direct portal requests. |
| External callback proof | `pkg/idp/oauth/authenticate.go`, `authenticate_setup.go`, `state.go`; `pkg/idp/saml/authenticate.go`, `state.go`; `pkg/authn/inject_saml_session_id.go` | OAuth state and SAML RelayState are different encodings and browser bindings, both with five-minute lifetimes. SAML requires body-only proof, known Content-Length 500–30000 and the exact form media type. Trace admission versus consumption ordering. |
| Cross-device and WebAuthn proof | `pkg/authn/cross_device_http.go`, `cross_device_store.go`, WebAuthn handlers and `pkg/identity/` | Describe browser/session/origin bindings and one-use state, not only string formats. Code, requester secret and approval CSRF are distinct capabilities. |
| Public/private keys | `pkg/kms/jwks.go`, private export, `pkg/identity/public_key.go` | Key-type-dependent required JWK fields and public-only parameters; PEM/base64 DER/private JWK depend on export mode. PGP/SSH uploads need real parser validation beyond armor/prefix checks. |

## Validate meanings and boundaries

Returned values need their own review, even where request validators are already
documented. The selected serializers currently have these consequential behaviors:

- Profile `entry` and `entries` have named credential, dashboard, user-info,
  enrollment and diagnostic variants. They do not echo the request `kind`.
  `success: false` can accompany HTTP 200; some WebAuthn preparation errors
  serialize an `error` as `message: {}`.
- User public-key records require category-specific ID and fingerprint semantics.
  Trace input parser, stored representation and returned encoding independently;
  a stored PEM label does not prove its DER round-trips through the upload parser.
  Check supported algorithms against both the crypto entity reader and the
  application metadata switch. An armor label does not prove public-only packet
  content. Verify whether the parser rejects, retains or strips secret packets
  using disposable synthetic material without logging it. Trace duplicate comparison, disabled records and fetch/delete
  selectors separately. The [profile public-key owner](../../identity-public-keys/SKILL.md)
  records current SSH/OpenPGP formats, entity admission, first-armor-block behavior, empty-MD5
  collisions and owned-ID deletion without a usage check.
- Go zero `time.Time` values survive `omitempty` as
  `0001-01-01T00:00:00Z`. Empty response tag properties and false booleans can
  disappear. Request tag fields remain required. Credential IDs, timestamps,
  password verifier records, API-key hashes, and MFA secret fields must be
  described from the returned structs rather than assumed redacted.
- Profile `token` is a JSON string containing claims. QR `uri_encoded` is
  padded Base64 of the `otpauth` URI, not image bytes. WebAuthn timeouts are
  milliseconds, signature counters are unsigned integers, and TOTP counters
  count time steps rather than Unix seconds.
- WebAuthn creation, enrollment proof, login and profile diagnostics are
  separate verification paths. The selected profile assertion diagnostic
  verifies signature/RP hash/type/presence but does not compare the signed
  origin/challenge or enforce/persist counter advancement. Do not describe it
  as completing login. Preparation/test/save retain the original creation
  challenge as the enrollment lookup key; the proof carries a different fresh
  challenge. Trace each consumer before claiming a binding or replay check.
- Login assertion options use `mfa:u2f:` followed by standard Base64 JSON,
  a 64-character alphanumeric challenge, a millisecond timeout and credential
  transports encoded as a comma-separated string. Enrollment uses different
  challenge generation and an array of transports. Preserve original signed
  `clientDataJSON` and authenticator bytes; parsed replacements cannot verify a
  signature. The `mfa` checkpoint accepts a TOTP code directly or `webauthn`,
  not a literal `totp` method selector. Sandbox policy failures can return HTML
  even when the client requested JSON.
- Cross-device responses are action/state-specific. A pending poll contains
  only status; approved polling adds `next` and issues browser cookies, never
  bearer JSON. The next target may be a path or trusted absolute URL. Cancel
  bypasses the polling interval, consumes even an approved unredeemed transfer,
  and cannot subsequently be replayed. Use separate response variants instead
  of making every property optional for every action.
- Refresh admission distinguishes an absent header from an empty header:
  native transport rejects even empty Origin/Sec-Fetch headers and any nonempty
  Cookie value. Browser
  fetch-metadata values are constrained, duplicate refresh cookies fail, and
  session lookup is browser-only. These checks precede token validation.
  Multiple Set-Cookie values are separate header lines, not a comma list.
- Initial registration requires Content-Length 15–1000 and the exact form
  media type; adding a charset or sending an unknown length fails with an
  HTTP 200 HTML message. Acknowledgement uses ordinary form parsing instead.
  Confirmation consumes volatile pending state before writing the separate
  dropbox, then attempts administrator notification; it does not activate a
  login account. The selected pending-cache default is 3600 seconds; trace the
  implementation rather than copying a different lifetime from an email template.
- Admin `info` serializes the full local account; mutation results instead use
  status/timestamp and operation-specific fields. Unknown realms can produce
  JSON null. Preserve this distinction from metadata-only user listings.
- Trace account selectors by operation: ordinary local lookup folds case without
  trimming, but enable scans disabled records with exact case. Disabled users
  remain in listings after lookup indexes are removed. Local user/metadata
  queries are ignored. Creation email syntax permits single-label domains and
  has no overall length ceiling or ownership check; registration differs.
  Role parsing trims Go Unicode whitespace (not ECMAScript `\s`), splits on the
  first slash, permits empty components and ignores duplicate normalized roles.
  Reusable `LocalAccountEmail`, `LocalRoleInput`, `IdentityName`, `IdentityEmail`
  and `IdentityRole` models are checked against the selected constructors.
- A failed local role mutation can leave partial in-memory changes. Describe
  HTTP 200/status=failure without promising rollback. Add/reset ignore supplied
  passwords and return generated plaintext; validate the stored verifier in the
  disposable native TLS fixture. Documentation must describe observed behavior
  without implicitly changing runtime semantics.
- Admin decoding reads one JSON value, unlike profile's full-body read. A
  bounded decoder does not imply all trailing bytes are consumed or rejected.
  Use `x-maxDecodedBytes` for that reader limit, rather than an unconditional
  total-body `x-maxBytes` promise.
  Profile accepts MIME parameters and rejects trailing JSON. Both APIs use an
  optional Origin/Sec-Fetch-Site guard before authentication, distinct from
  refresh: empty headers fail, Site=none passes, and Mode/Dest are not checked.
- HTML whoami only needs valid access claims; the dashboard also needs stored
  browser state and can return a trusted 303. Exact Accept negotiation comes
  from `pkg/util/request_id.go` and is source-inventoried. Test lists/parameters,
  HTML unauthenticated redirects and beacon's HTML 404. Browser cookie deletion
  alone does not revoke a copied stateless access JWT.
- OIDC UserInfo fields are scope- and claims-request-dependent projections of the stored identity
  profile. Do not invent validation for unvalidated stored strings. ID tokens
  remain compact JWT strings on the wire; the separate decoded-claims model
  explains `auth_time`, audience and the canonical 16-byte `at_hash` encoding.
  CORS origins compare registered public-client scheme/host/port exactly,
  including configured HTTP native-loopback origins; redirect port exceptions
  do not automatically apply to CORS.
- OIDC refresh scope omission preserves the grant; an explicitly empty or
  Unicode-whitespace-only value fails. Unique scopes must remain a subset of
  the current grant. Removing `openid` omits the next ID token; removing
  `offline_access` does not terminate an existing refresh family. Explicit
  UserInfo claim requests survive scope narrowing. Test actual disclosure,
  not just the returned scope string.
- Code and refresh replay checks precede new redirect/PKCE or scope checks for
  the owning client. Fresh invalid bindings/scope do not spend the credential;
  replay revokes successors even when the new request is otherwise invalid.
  Rotation removes the old access-token index: revoking that old access token
  is a no-op, while a retained spent refresh token still revokes its family.
  Foreign-client revocation and unknown tokens return empty 200, and independent
  grants survive. Trace these state transitions in `pkg/oidc/token.go` and
  `refresh.go`; schema keywords cannot express them.
- Token/refresh/revocation and UserInfo form decoding reject all duplicate
  fields and any query, including a bare `?`; MIME parameters are accepted.
  UserInfo also accepts a single case-insensitive Bearer header, including on
  a bodyless POST, but body `access_token` conflicts with any Authorization
  header, even an empty one. Discovery/JWKS ignore query parameters. A denied
  ordinary token Origin suppresses CORS readability without rejecting the
  request; denied preflights return 403. Public OIDC CORS echoes a nonempty
  Origin, including `null`. Keep these distinct from consent/browser guards.
- OIDC claims requests use JSON strings in form/query parameters and embedded
  objects inside Request Objects. Model each location and claim requirement:
  null, essential booleans, mutually exclusive value/values, and sub/acr string
  restrictions. General values arrays may contain null. Unsupported claims are
  still parsed before being ignored. Essential/value preferences are not
  universally enforced; account selection and essential ID-token ACR have
  explicit checks. Registered scopes govern permissible individual claims.
- Request Object NumericDate fields accept fractional Unix seconds; max_age
  instead requires an integer literal and rejects decimal/exponent notation.
  JSON Schema cannot distinguish all lexical numeric spellings, so state that
  rule and test it through HTTP. RS256 requires registered keys plus issuer and
  audience bindings. Unknown extensions and jti do not establish identity or
  replay protection. The Go audience decoder tolerates null array entries as
  empty strings, but one entry must still match the issuer. Do not conflate
  these inputs with the provider's returned ID-token claims.
- OIDC consent permits absent Origin, but rejects empty/duplicate/foreign
  values when supplied. Sec-Fetch-Site also permits none. Refresh endpoints
  have stricter rules. Pending OP requests last ten minutes and a new interactive
  request replaces the browser's previous one; external-provider state lasts
  five minutes. Keep these independently owned lifetimes separate.
- Portal OAuth requires exactly one state but takes the first non-state
  query value, prioritizes error over code and ignores the iss query hint.
  Token issuer/signature/nonce validation remains separate. Direct OAuth has
  stricter callback admission. SAML requires exactly one response and RelayState
  in the POST body; successful browser-state admission consumes the transaction
  before XML validation. A wrong-browser attempt does not consume it.
- Redirects can have a short HTML link body or no body/content type, depending
  on the handler. Both use Location. Do not infer that every redirect is empty
  from sampling only the portal's own redirect helper.
- System API inner messages require a nonempty caller address but do not parse
  it as an IP address. Requests have no expiry or replay-ID field. Describe the
  selected AuthCrunch encryptor's envelope, not generic PASETO interoperability.
  Only successful authentication returns an encrypted response with
  `authenticated: true`; failures use the HTTP error envelope.
- Public and private JWK schemas are distinct. Never extend a closed public
  schema with `allOf` to add secret fields: its `additionalProperties: false`
  would reject them. Private JWKs require `d`, RSA CRT factors, or an Ed25519
  32-byte seed as appropriate. Standard Base64 DER and unpadded base64url JWK
  parameters have different encodings. RSA integers use minimal positive
  unsigned bytes; EC coordinates/scalars retain zero padding to 32/48/66 bytes
  for P-256/P-384/P-521. Encode curve/algorithm pairings, canonical final bits
  and forbidden cross-family fields. The OP JWKS requires dedicated RSA keys
  and a SHA-256 public-key thumbprint `kid`; portal key IDs may be omitted.
- Private export selectors are case-sensitive; empty/repeated selectors fail.
  `format=json` aliases PKCS8, not JWK. PKCS1 requires RSA, SEC1 requires EC,
  and Ed25519 supports PKCS8/JWK. Exported material is unencrypted. Successful
  portal JWKS HEAD includes GET's exact byte length, while OIDC HEAD does not
  calculate it. HEAD error responses also have no body. Model shared OIDC
  response headers without copying potentially divergent constant values.

`internal/openapi/contract_schema_test.go` checks positive/negative field
boundaries, canonical token encodings, tag structure, timestamp types and
registration patterns against the selected exported validators. It exercises
real credential serializers, System message validation/encryption, and Unicode
client-secret byte limits. It also checks schema examples and schema-level source evidence. Extend these with meaningful
accept/reject cases, rather than tests that only match descriptions.

`pkg/authn/openapi_contract_e2e_test.go` and its `openapi_*_e2e_test.go`
companions validate native TLS login, Basic admission, claims, browser navigation,
profile records/QR encodings, API-key and TOTP behavior, account administration,
private export and encrypted System messages. Registration uses a disposable file
outbox and separate dropbox through confirmation/replay. Error output withholds
credential-bearing bodies.

`pkg/authn/openapi_journeys_e2e_test.go` reuses independent native OIDC,
cross-device and signed WebAuthn journeys. Its explicitly scoped response hook
in the OIDC fixture validates matching documented operations and requires actual
samples of token/UserInfo/revocation, cross-device and refresh/logout protocols.
Normal feature tests retain their own assertions and do not load the spec.
`openapi_oauth_e2e_test.go` checks root-server direct OAuth login, callback,
application access, replay and logout at `/auth`, `/team/auth` and root.

`internal/openapi/oidc_key_contract_test.go` checks actual KMS public/private
exports for all five key families/curves, canonical encodings and algorithm
bindings. `login_profile_contract_test.go` compares the actual JSON decoder and
SSH/OpenPGP metadata parser with authored models. `credential_contract_test.go`
checks stored bcrypt/Argon2 encodings, parser parameter limits and lifecycle flags.
Keep independent state/security assertions alongside schema validation; permissive
schema branches must not hide regressions. These are sampled contracts, not
exhaustive branch coverage, and do not replace each owning feature suite.
Run the affected existing OIDC, cross-device,
profile and provider journeys when their contracts change. Browser qualification
must confirm the field meaning is visible in Scalar; a correct JSON document
does not prove a viewer preserves `$ref` sibling descriptions.
Check conditional and forbidden properties in the rendered model too. The
pinned viewer can hide properties behind an extra `allOf` wrapper and displays
bare false schemas without explaining their restriction. Direct `if`/`then`
and an equivalent `not: {}` with a description preserve validation while making
these fields readable; retain rejection tests when adjusting the representation.
For `oneOf` records with shared lifecycle properties, reference individual
lifecycle fields directly instead of nesting the common object under `allOf`
when that wrapper hides the fields. Exercise both SSH and OpenPGP selections;
seeing a summary paragraph does not prove the conditional fields rendered.

Update field evidence and constraints with code changes. Source hashes are a
review trigger, not a substitute for the acceptance-path analysis above.
