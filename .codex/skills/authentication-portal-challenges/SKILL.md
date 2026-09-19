---
name: authentication-portal-challenges
description: Maintain conditional authentication challenge policies, reusable authchal and user-transform FromDirectives parsers, safe claim substitution, registered-factor inventory, passwordless WebAuthn selection, verified AMR access claims, and policy revalidation across portal login, refresh, OIDC, and direct authentication.
---

# Authentication Challenge Policies

## Ownership and public configuration

`pkg/authchal/config.AuthenticationChallengeConfig` owns typed ordered rules and
validation. `authchal.Rule` and `authchal.Ruleset` remain aliases, and
`authchal.NewRuleset` preserves its rule-body signature by calling the parser.
`pkg/authchal/parser.NewAuthenticationChallengeConfigFromDirectives(statements)`
accepts encoded **rule bodies after `auth challenges`**, without the prefix or
braces. It returns `*config.AuthenticationChallengeConfig`. Its `Statements`
can be applied through `local.IdentityStore.OverwriteUserAuthChallengeRules`;
its typed `Rules`, `Validate`, and `ResolveChallenges` support other consumers.
Stored policies with no eligible rule deny login; an empty stored policy clears
explicit selection and restores backend defaults. Validate a replacement before
mutating the user. Policy changes invalidate credential evidence.

Authenticated self-service uses the existing profile operations documented in
[the profile authentication-flow API contract](../authentication-portal-profile/references/authentication-flows.md).
Keep UI request/response fields, registered/effective policy previews, reset,
and reauthentication guidance there. The profile adapter consumes this same
public rule parser; it must not introduce a second grammar.

`pkg/authn/transformer/config.Config` owns the established serialized `Matchers`
and `Actions` string lists; `transformer.Config` is its compatible alias.
`pkg/authn/transformer/parser.NewUserTransformerConfigFromDirectives(statements)`
accepts one **transform user block body**, without header or braces, and returns
that configuration. Append the result to `PortalConfig.UserTransformerConfigs`.
`CompileUserTransformerConfig` owns decoding and validation of typed/persisted
string lists as well; `transformer.NewFactory` uses its detached `RuntimeConfig`.
Keep decoding in the parser, not a second implementation in the runtime.
These lower configuration packages avoid parser/runtime import cycles.

Both parsers use `cfgutil.DecodeArgs`; adapters tokenize and call `EncodeArgs`.
Reject empty tokens before encoding, raw CR/LF, malformed operator sequences,
unknown directives, and duplicate challenge rules. Errors must not echo input.
Matcher/action order is significant; ordinary repeated actions are intentional.
Parsing starts no network/file activity or workers. Preserve quote boundaries,
caller-owned input, independent results, and JSON serialization/reload behavior.

```text
match realm local
require auth challenges u2f
require auth challenges password totp if u2f not available
require auth challenges password if u2f and totp not available
```

## Custom claim actions

The same transform compiler validates custom claim syntax before portal startup.
`parser.ParseCustomFieldValues` and `parser.ParseCustomNestedFieldValues` own the
shared decoded-token grammar used by both compilation and runtime application.
Do not restore independent custom-field decoders in the transformer runtime.

`add <field> <value> as string` requires one encoded value. Lists require at least
one value and accept `as list`, `as string list`, or legacy `as string_list`.
Nested actions use `add nested <key> [<key> ...] with <values> as <type>`;
`add nested <key> [<key> ...] as map` creates an empty object and takes no values.
Reject missing paths/values/types, extra scalar values, unsupported types, and
`overwrite` on unsupported custom fields. Preserve encoded multiword values,
redacted errors, detached output slices, and nil results on failure.

Substitution expands `{claims.field}` only in the configured template. Inserted
claim values and existing string/list entries are literal data, never additional
templates. This prevents self-references, recursive expansion and malformed
brace values from looping or panicking. Repeated placeholders in a template
remain supported. Nested custom values retain their established literal behavior.
A nested parent that is a scalar, list, null or nil map returns an error; it must
not panic or replace the parent with an object. Later authentication policy may
not be issued from a failed transformation.

## Selection contract

A rule lists a required sequence (`password totp`) or ordered alternatives
(`u2f or totp`). Alternatives select the **first available single method**;
they must not become multiple required checkpoints. An optional suffix
`if u2f and totp not available` requires every condition method to be absent.
Do not accept partial suffixes or mixed sequences/alternatives. Password is
available under the local/LDAP account contract. Generic `mfa` selects an MFA
checkpoint; the portal supports TOTP and WebAuthn, not email checkpoints.
The reusable authchal model retains email for existing identity configurations;
transformer policies reject explicit email methods/conditions and do not count
email alone as usable generic MFA.

The first eligible rule across matching transforms wins. Later claim, legacy
require, and deny actions still execute. If any matching transform declares a
policy but none is eligible, deny; do not silently restore password defaults.
A transform that does not match the user imposes no policy.

A selected `require auth challenges` sequence **replaces backend challenges**.
This permits U2F-only authentication even when the backend defaults to password
plus MFA. Legacy `require mfa`, `require totp`, `require u2f`, and `require
password` remain additive. Specific factor requirements supersede generic MFA
without losing other explicit factors. Document this administrative precedence
when integrating a new consumer.

`identity.User.GetRegisteredAuthMethods` supplies enabled, distinct credential
types without collapsing them to generic MFA. `requests.User.AuthMethods` and
`identity.RefreshIdentity.AuthMethods` are server-only inventory, not completed
authentication. Carry fresh inventory through identification and transactional
issuance snapshots. Never derive it from a transformed/JWT/client claim.

Portal code uses `Factory.TransformWithAuthMethods(claims, inventory)`, whose
return value is the optional replacement sequence; legacy requirements remain
in `claims["challenges"]`. `transformUser` updates the request's selected
challenges. The compatibility `Transform` entry point consumes `auth_methods`
from its input map and returns combined selected/additive challenges.
Neither entry point permits arbitrary claim actions to inject challenge policy
or leak the inventory into the token.

Re-evaluate fresh policy in `token_issuer.go`, `token_refresh_runtime.go`, and
`oidc_runtime.go`, under the existing identity transaction. Each adapter must
supply fresh inventory and validate selected plus additive checkpoints against
completed evidence. Direct Basic/API-key issuance cannot claim selected factors
it did not verify; API keys do not substitute for password/MFA checkpoints.

Context-dependent matchers must receive the current request's `addr` and `iss`
when policy is re-evaluated. Refresh supplies both from its request context;
the OIDC adapter uses the provider's
[request metadata contract](../authentication-portal-oidc/SKILL.md#protocol-invariants).
Do not reuse the original login address for later requests. Token/UserInfo
requests may originate from a relying party's server. `iss` at transform time
is the current endpoint URL, so use a portal URL prefix for a policy intended
to cover login, sandbox, refresh, and OIDC routes; exact endpoint matches are
intentionally specific to that operation. A stronger current policy requires
fresh authentication, never an upgrade of stored AMR.

`requests.User.AuthChallengePolicy` records an explicit stored policy or a
matching portal replacement; local identification must reset stale markers
and distinguish stored rules from backend defaults. Basic authentication checks
the entire effective sequence **after** transforms, including additive legacy
requirements. A valid password cannot satisfy TOTP or WebAuthn. Both the public
`BasicAuth` embedding API and `/basic/login/<realm>` must enforce this decision;
denied HTTP Basic policy checks return 403, never a successful status.

API keys retain their separate legacy login behavior only when there is no
explicit stored/portal policy and no additive requirement. Any explicit
password/MFA policy, including a saved `["password"]`, rejects API-key login
because that credential proves none of these checkpoints. Cover the public
`APIKeyAuth` embedding API and JSON `/login` equally. Clearing stored rules
restores defaults but does not bypass portal requirements. JSON login must pass
its current HTTP issuer and cancellation context to the internal `apiKeyAuth`
helper. Calling the public proxy API from that HTTP adapter loses request
metadata and can bypass issuer-dependent rules. Public `BasicAuth` and
`APIKeyAuth` have no HTTP request and retain their established `authp` issuer
at transform time. JSON API-key tokens consequently default their signed `iss`
to the current HTTP login URL, without its query; this replaces the previous
`authp` default for that HTTP adapter. Explicit issuer claim transformations
still apply. Keep this distinction explicit when sharing issuance code and
integrating a consumer that validates the token's issuer.

`direct_authentication_identity.go` holds the local identity transaction across
fresh attribute/inventory loading, transformation, policy checks, and signing
for both public proxy APIs, HTTP Basic login, and encrypted `/api/system`
authentication assertions. A successful earlier credential
check must not authorize issuance from stale identification data. Preserve the
verification proof across API-key identification; lookup-only evidence is not
authentication. `RefreshIdentity.AuthChallengePolicy` carries the current stored
policy marker, including an explicit password-only preference. Deliver tokens
and update sessions after the callback releases the identity lock. Other stores
retain their existing authentication contract. Exact API-key binding and
revocation are owned by [local identity transactions](../local-identity-database/SKILL.md).

Remote gatekeepers consume `system.AuthResponseMessage.UserData` as authenticated
identity data. Apply the same direct policy and authoritative AMR before encrypting
that response; encryption alone does not prove password/MFA policy completion.
The system path supplies the authenticated message's client `addr` and the current
HTTP endpoint `iss` to transforms. Strip internal challenge/inventory/UI fields
from successful responses. Invalid API keys return 401, and unmet factors return
403. Preserve exact-key evidence across system-request identification too.
Assign an error status before rendering body-read failures: exceeding the 1 MiB
limit returns 413; other read failures return 400. Never let an unset response
code reach `WriteHeader`, and keep the body bound for chunked requests too.

## Factor-only configuration

Enroll and enable the factor before choosing it. A transform block body for
one local account can select WebAuthn alone:

```text
exact match realm local
exact match sub alice
require auth challenges u2f
```

Replace the last line with `require auth challenges totp` for authenticator-code
only login. These replace the backend password/MFA sequence; separately matching
legacy `require password` actions still add password. The first eligible policy
wins, so an earlier matching replacement can take precedence. Trigger fresh
login after changing policy. User-owned preferences use the profile API's
`["u2f"]` or `["totp"]` rule arrays instead of transform syntax.

These flows still identify the account by username/email. `u2f` selects the
existing WebAuthn assertion protocol, not a new discoverable-credential login.
See [portal MFA](../authentication-portal-mfa/SKILL.md) for user-presence and
user-verification behavior; do not promise UV-required passkey authentication.

## Verified authentication methods

`user.Checkpoint.Method` is server-only and set exclusively after successful
backend password, TOTP, or WebAuthn verification. `recordLoginEvidence` collects
and deduplicates these values into `User.LoginMethods` for **all** password/MFA
sandbox logins, including refresh/OIDC-disabled and excluded realms. Request fields and
registration/enrollment must not supply method evidence. Enrollment persists a
credential but requires a fresh completed login; it must not issue credentials
from the old sandbox. Preserve the original authentication time.

Use existing mappings `password -> pwd`, `totp -> otp`, and `u2f -> hwk`.
The WebAuthn mapping is the repository's convention, not new device attestation
or physical-hardware certification. Record the concrete factor chosen for a
generic MFA checkpoint. JSON WebAuthn first obtains a server challenge with
`challenge_response: webauthn`, then submits the signed assertion under the
`u2f` checkpoint; requesting a challenge does not complete it.

`issueSandboxAccessToken` and the refresh manager write authoritative `amr`
after claim transformations, before signing. Ordinary Basic authentication
reports `pwd`; API-key issuance strips fabricated password/MFA AMR.
`user.Claims.AuthenticationMethods` validates list input, snapshots values, and
exposes AMR through the signing map and ACL data. `pkg/acl` recognizes `amr` as
a string-list field, allowing policies such as `match amr hwk`. Clones must not
share method slices. Registered credentials alone never justify these claims.

## Validation

`transformer/parser/custom_fields_test.go` covers directive and typed-config
rejection, the shared value decoders, snapshots, and a public constructor example.
`transformer/custom_fields_test.go` covers literal substitutions, self-references,
existing claim text and nested type collisions. Fuzz both
`FuzzUserTransformerLiteralClaims` and `FuzzUserTransformerCustomFields` when
changing these boundaries. `authentication_challenges_claims_e2e_test.go` checks
parser-configured scalar/list/map claims with TOTP-only HTML/JSON login, profile
previews, renewal and OIDC, plus collision errors without credential issuance.

Unit and executable-example coverage belongs in the public parser packages;
keep typed policy validation and resolver tests with their owning configuration.
`pkg/authn/authentication_challenges_e2e_test.go` consumes both parsers through a
real TLS portal, temporary identity database, actual password/TOTP and signed
WebAuthn assertions, independent JWKS verification, a second TLS application
protected by an AMR gatekeeper, refresh, and OIDC token exchange. It also tests policy failure, additive requirements,
credential revocation, direct Basic policy rejection, API-key separation, and
wrong-factor/key/challenge rejection for JSON WebAuthn. Preserve hardware-only cases with
both TOTP and U2F registered to catch accidental backend-password retention.
TOTP-only cases cover HTML/JSON with refresh and OIDC independently enabled or
disabled, reject password submission, and verify `otp` alone after login and
renewal. `authentication_challenges_direct_e2e_test.go` checks stored policies,
portal replacements, default compatibility, and additive requirements through
both public embedding APIs in a TLS server and the portal's direct routes.
`authentication_challenges_transaction_e2e_test.go` arranges committed policy,
role, password/key revocation, and account lifecycle changes between direct
identification, verification, and issuance. Cover public Basic/API-key APIs,
HTTP Basic, JSON API-key login, and encrypted system Basic/API-key requests, with
unchanged-account controls and independent JWT verification or authenticated
message decryption. Keep deterministic store hooks rather than timing sleeps.
The direct policy matrix also checks encrypted system requests, including
default MFA, explicit preferences, replacements, additive requirements and AMR
forgery. `authentication_challenges_system_e2e_test.go` covers current issuer/
client-address policy and rejected credentials through the real TLS endpoint,
plus bounded malformed/chunked request bodies and a subsequent valid login.
`authentication_challenges_apikey_context_e2e_test.go` checks issuer-dependent
additive, replacement, and deny policies through JSON `/login`, including path
and source-address controls, independently verified allowed tokens, and absence
of browser-session cookies. Its unit companion checks query exclusion, public
proxy issuer compatibility, and cancellation before transactional issuance.
`authentication_challenges_sequence_e2e_test.go` covers WebAuthn first, last,
and between other required factors, including an additive password. JSON must
return an assertion challenge before visiting the next checkpoint.
`authentication_challenges_context_e2e_test.go` covers issuer/address matching
and context changes at OIDC authorization, code exchange, UserInfo, OIDC refresh,
and portal refresh. Keep both successful factor-only issuance and rejection of
inadequate earlier evidence when a later request adds requirements.

`login_identity_e2e_test.go` checks automatic AMR across HTML/JSON, access-only,
refresh, OIDC-only, combined, and excluded-realm logins. Keep tests proving that
transforms cannot forge AMR, and that renewal does not upgrade authentication.
Synthetic WebAuthn signatures establish protocol behavior, not browser/device
certification. Factor verification and enrollment belong to
[portal MFA](../authentication-portal-mfa/SKILL.md).

```sh
make test TEST_DIR='./pkg/authchal/... ./pkg/authn/transformer/... ./pkg/user ./pkg/acl ./pkg/identity ./pkg/ids/local ./pkg/ids/ldap ./pkg/authn ./internal/tag' COVERAGE_DIR='.coverage/authentication-challenges'
make ci-check
go test ./pkg/authchal/parser -run '^$' -fuzz '^FuzzAuthenticationChallengeDirectives$' -fuzztime=10000x -parallel=2
go test ./pkg/authn/transformer/parser -run '^$' -fuzz '^FuzzUserTransformerAuthenticationChallenges$' -fuzztime=10000x -parallel=2
```

Embedding-server directive wiring belongs to the consumer repository. Publish
these reusable parser APIs and validate them here; do not edit sibling projects.
