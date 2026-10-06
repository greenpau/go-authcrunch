# AuthCrunch Plugin Categories

This catalog adds nine extension categories alongside the existing
[secrets plugins](../../secrets-plugins/SKILL.md). It describes current integration
points and the contracts needed to develop a backend. Example services and
proposed interfaces are design options, not declarations of published support.

Production backends normally live in separate repositories. Apply the
[repository workflow](repository-workflow.md) to load this guidance from another
workspace, bootstrap its `AGENTS.md` and local skills, or layer a host companion.
In-repository synthetic references belong under `plugins/<category>/<name>` and
follow the [reference contract](synthetic-reference.md); inspect availability
before assuming a category has a runnable example.

Select a category:
[identity stores](#identity-stores), [identity providers](#identity-providers),
[credential authenticators](#credential-authenticators), [messaging](#messaging),
[registration workflows](#registration-workflows),
[session and refresh storage](#session-and-refresh-storage),
[cryptographic signing](#cryptographic-signing),
[external authorization](#external-authorization), or
[claims enrichment](#claims-enrichment).

## Interpret integration status

An exported interface, a place to supply its implementation, and configuration
that constructs it are three separate capabilities. Verify all three for the
requested consumer. Root `authcrunch.NewServer`, direct `authn.NewPortal`, a
standalone refresh manager, and a host-framework adapter are different consumers.

The sections below distinguish **current APIs** from **implementation contracts**
for new plugins. Apply the [development blueprint](development-blueprint.md) for
module layout, typed configuration, the dedicated public `parser` package,
construction, compatibility, and test workflow. Existing settings and raw
instruction parsers do not imply that a generic plugin parser exists. Any new
configuration surface needs its own reusable parser and consumer coverage.

Configure and attach plugins before serving requests. Use detached config and
runtime objects on replacement, keep the active runtime usable if construction
fails, and explicitly dispose caller-owned clients/workers. New backend tests
must exercise the actual consuming workflow; the existing tests linked below
establish only their current implementations' behavior.

## Identity stores

**Purpose:** own accounts, credential verification, and supported account
operations in a database such as PostgreSQL, DynamoDB, or Consul. An account
store has stronger identity and mutation responsibilities than a secrets reader.

**Current APIs:** [ids.IdentityStore](../../../../pkg/ids/store.go) includes
identity metadata, authentication requests, configuration, and account-management
operations. A Go host can construct/configure an implementation and supply it in
`authn.PortalParameters.IdentityStores`; select its `GetName()` in
`PortalConfig.IdentityStores`. `NewPortal` requires `Configured()` to be true.
The [shared config](../../../../pkg/ids/config.go) and factory accept only `local`
and `ldap`. A new root-config kind therefore needs validator, parser, factory,
and server integration. Direct portal injection avoids that factory requirement,
but still must satisfy the consuming authentication flow and metadata/icon APIs.

**Implementation contract:**

- Bind operations to the configured realm and backend instance. Use stable,
  immutable account identity independently of usernames or display claims.
- Declare supported operations. A read-only directory must reject unsupported
  writes explicitly instead of reporting success or modifying another backend.
- Define transaction and revocation semantics for deletion, disablement, password
  changes, roles, and factor changes. Snapshot returned attributes; do not retain
  mutable caller data or let account recreation revive old identity evidence.
- Treat optional feature capabilities separately. Refresh checks
  `WithRefreshIdentity(context.Context, requests.AuthenticationEvidence,
  func(identity.RefreshIdentity) error) error`; its callback must serialize
  issuance with security mutations. The portal's downstream OIDC adapter also
  requires a `local` store kind. Profile operations require a current local login
  and `ids.IdentityRequestStore`. Do not impersonate the `local` kind to bypass
  these limits or claim that base-interface conformance enables every feature.

Audit every exposed issuance route for a new kind. On `/basic/login/<realm>`,
the [authentication path](../../../../pkg/authn/handle_authenticate_basic_auth_request.go)
sets the method from `GetKind()`, while
[login issuance](../../../../pkg/authn/handle_http_login.go) applies its direct
identity transaction and challenge-policy checks only to `local`/`ldap` methods.
Implementing `WithRefreshIdentity` alone does not enable those guards for another
kind on this route. Integrate the new kind into the required enforcement paths,
or have the host explicitly exclude unsupported routes, before claiming the
same guarantees. A login success alone cannot establish equivalent protection.

**Acceptance:** real login through the selected realm; unknown, disabled, and
recreated accounts; rejected cross-realm operations; concurrent credential
mutation versus issuance; challenge-policy rejection on every exposed login
route; explicit unsupported operations; fresh config/reload and caller-owned
cleanup. Trace current composition in
[portal tests](../../../../pkg/authn/portal_test.go), capability checks in
[refresh integration](../../../../pkg/authn/token_refresh_runtime.go),
[OIDC integration](../../../../pkg/authn/oidc_runtime.go), and
[profile binding](../../../../pkg/authn/profile_identity.go). The
[local identity contract](../../local-identity-database/SKILL.md) owns existing
transactional local behavior; another backend must document its own guarantees.

## Identity providers

**Purpose:** authenticate through an upstream federation service or protocol,
returning verified identity evidence and attributes. A new OAuth vendor often
fits existing OAuth configuration or a driver extension; that does not require
a new provider category or protocol kind.

**Current APIs:** [idp.IdentityProvider](../../../../pkg/idp/provider.go) exposes
configured metadata and `Request(operator.Type, *requests.Request) error`.
Supply a configured implementation through
`authn.PortalParameters.IdentityProviders`, selected by name in
`PortalConfig.IdentityProviders`. The [shared configuration](../../../../pkg/idp/config.go)
and factory support `oauth` and `saml`. Injection alone does not install callback
routes, browser-state handling, or a new protocol's login UI: trace
[portal routing](../../../../pkg/authn/respond_http.go) and the actual request flow.

**Implementation contract:** bind issuer/tenant and immutable upstream subject;
validate protocol state, destination, audience, signatures, and replay at the
provider boundary. Construct claims only after successful verification. Keep
upstream credentials and refresh tokens separate from portal session credentials.
Define cancellation, logout, and browser correlation according to the protocol;
check legacy interface constraints before promising request-context propagation.

The reusable downstream OpenID Provider has a different boundary:
`oidc.NewProvider(config, verifier, options)` accepts
[oidc.IdentityVerifier](../../../../pkg/oidc/identity.go). That verifier checks
current identity and serializes revocation with issuance; it is not an upstream
OAuth driver. Supporting that API independently does not remove the portal
adapter's local-store restrictions.

**Acceptance:** a local provider fixture completes the real browser/HTTP flow;
untrusted issuer, wrong audience, stale state, replay, and rejected credentials
cannot mint portal credentials. Verify exact claims, realm selection, logout,
and provider shutdown. Existing [OAuth](../../oauth-identity-provider/SKILL.md)
and [SAML](../../saml-identity-provider/SKILL.md) contracts own those protocols;
the [downstream OIDC owner](../../authentication-portal-oidc/SKILL.md) owns its
separate verifier and issuance contract.

## Credential authenticators

**Purpose:** validate HTTP Basic credentials or API keys through an external
credential service without implementing an interactive federation protocol.
This is distinct from fetching a configured secret or evaluating resource access.

**Current APIs:** [authproxy.Authenticator](../../../../pkg/authproxy/authenticator.go)
has `GetName() string`, `BasicAuth(*authproxy.Request) error`, and
`APIKeyAuth(*authproxy.Request) error`. Attach implementations with
[Gatekeeper.AddAuthenticators](../../../../pkg/authz/gatekeeper.go). Configure
`PolicyConfig.AuthProxyConfig` realm entries and their enabled credential methods;
`PortalName` must match the authenticator's `GetName()`. Registration filters by
that name. A successful attachment call alone does not prove every realm has a
backend; validate mappings with `HasAuthProxies()` before serving.

The [request/response model](../../../../pkg/authproxy/request.go) carries source
address, realm, presented secret, and a response payload. The
[credential parser](../../../../pkg/authz/validator/auth.go) supplies Basic's
base64-encoded credential string as `Secret`; API-key input is the trimmed header
value. In [validator consumption](../../../../pkg/authz/validator/sources.go),
`IsPlainPayload` selects trusted JSON identity data parsed by `user.NewUser`
versus a signed token verified by the keystore. Plain identity data does not
receive JWT signature verification. The authenticator must establish its trust
before returning it.

**Implementation contract:** honor those input representations and declare
which methods are supported; verify first, then populate an independent response.
Reject credentials for the wrong realm and never return a success payload after
a backend error. Credential success remains subject to gatekeeper policy. Keep
secrets out of metadata, errors, and cache keys exposed to operators.

The current methods and request model carry no `context.Context`. A backend can
bound its own network calls, but automatic HTTP-request cancellation requires an
additive context-aware interface and consumer wiring. Authentication results can
be cached by the validator: specify revocation/expiry behavior at that consumer,
not merely in the external credential service. The current credential cache key
contains payload class, address, realm, and a secret digest, but omits the
Basic/API-key method. When both methods are enabled, identical presented secret
strings can therefore share a cached identity. Independent method authority
requires consumer cache isolation; do not promise it from plugin handlers alone.
Attach once before concurrent use; the host retains lifecycle ownership of
manually supplied authenticators.

**Acceptance:** exercise real protected requests with valid/invalid Basic and
API-key credentials, wrong realm, disabled method, unmapped name, backend outage,
and local ACL denial after successful authentication. Check fresh and cached
identity paths, cross-method cache isolation, and the documented revocation
window. Use the real
[validator auth path](../../../../pkg/authz/validator/auth.go), not only a direct
call to the plugin method.

## Messaging

**Purpose:** deliver registration, confirmation, approval, or notification
messages through email APIs or other delivery backends. SMS is a possible
extension if its addressing and content requirements are modeled explicitly.

**Current APIs:** [messaging.Provider](../../../../pkg/messaging/provider.go)
defines `Validate`, `AsMap`, `Kind`, and `Send(*messaging.SendInput) error`.
[SendInput](../../../../pkg/messaging/send_input.go) has subject, body, recipients,
and credentials. The factory and [Config](../../../../pkg/messaging/config.go)
recognize concrete email and file providers. Registration's
[delivery selection](../../../../pkg/registry/local_user_registry.go) also branches
on those provider types. Implementing `Provider` alone does not make a new
backend configurable or selectable by that consumer.

**Implementation contract:** specify typed sender/destination configuration,
credential references, supported content/recipient formats, and bounded delivery.
Add parser, selection, config storage, and consumer wiring together. A generic
provider collection is a possible design change, not an existing public field.
The current `Send` method has no context; cancellation support requires an API
extension rather than a documentation promise.

Define whether success means provider acceptance or final delivery; existing
`Send` returns only an error. Design delivery IDs/status separately if needed.
Bound retries and account for ambiguous acceptance so a timeout does not send
unlimited duplicate verification messages. Keep template rendering and escaping
with its owner, and ensure metadata does not disclose credentials or message
bodies. A messaging plugin does not make SMS/email an available MFA checkpoint.

**Acceptance:** trigger a real registration notification and inspect the message
received by a local delivery fixture. Cover recipient selection, hostile template
values, authentication rejection by the service, timeouts, bounded retries, and
duplicate-delivery policy. Current
[provider tests](../../../../pkg/messaging/provider_test.go) and
[registration email tests](../../../../pkg/registry/local_user_registry_email_test.go)
are useful starting points, not coverage of a new channel.

## Registration workflows

**Purpose:** manage invitations, confirmations, approvals, and account creation.
Delivery belongs to messaging; durable authenticated account operations belong
to the identity store. Full directory synchronization or a SCIM HTTP service
would require additional protocol/application APIs beyond registration.

**Current APIs:** [registry.Provider](../../../../pkg/registry/provider.go)
includes validation/activation, credential and messaging binding, pending-entry
operations, policy presentation, notifications, and `AddUser`. Direct consumers
can attach an initialized provider through
[Portal.AddUserRegistry](../../../../pkg/authn/portal.go). The portal config must
have user registries configured; attachment maps the provider by its identity
store name and refuses multiple registries for the same store. The method does
not construct or activate the plugin. Validate the configured registry name,
store, and realm associations in the embedding layer before attachment.

[registry.Config](../../../../pkg/registry/config.go) stores only local provider
configurations, and [NewServer](../../../../server.go) constructs their runtimes
with `NewRuntime`. A custom provider therefore needs root configuration and
construction changes if it must be selected through that path. Directly attached
providers remain caller-owned; `Portal.Close` does not close registries.

The portal's [confirmation handler](../../../../pkg/authn/handle_register.go)
reads and verifies the pending code, deletes the registration entry, and then
calls `AddUser`, passing the registration ID as `req.Query.ID`. These are separate
operations; the interface does not expose a combined atomic consume-and-create
operation. A failed `AddUser` follows evidence deletion. Stronger atomicity and
recoverable enrollment may require changes to the consumer and public API,
beyond implementing a new provider.

**Implementation contract:** define the enrollment states and authorized
transitions, expiry, single-use confirmation/approval, username/email conflicts,
and duplicate request handling. Bind pending entries to their intended identity
store. Complete account creation and consume approval evidence under a documented
transaction/idempotency strategy; do not report account creation merely because
notification delivery succeeded. Protect pending credentials and keep raw
registration entries out of `AsMap`, which the portal may log.

**Acceptance:** a real submission, confirmation/approval, and account creation
permits subsequent login; expired/replayed evidence, duplicate users, wrong
store binding, and interrupted creation do not create unauthorized accounts.
Verify failure recovery and cleanup without disposing another runtime's state.
[Registry runtime tests](../../../../pkg/registry/runtime_test.go) demonstrate
separation of local config/runtime and worker ownership.

## Session and refresh storage

**Purpose:** retain refresh families and support atomic issuance, rotation,
revocation, and replay detection across consumers. A SQL or Redis-backed store
is a potential implementation; a generic key/value cache is insufficient.

**Current APIs:** [tokenrefresh.Store](../../../../pkg/authn/token_refresh/store.go)
defines `Create`, `Lookup`, `Rotate`, and `Revoke` with contexts.
`tokenrefresh.NewManager(store, identity, signer, policy, binding)` accepts a
custom store. Optional `ReplacementStore` and `SessionValidator` add atomic
fresh-login replacement and non-rotating liveness checks.

The [portal integration](../../../../pkg/authn/token_refresh_runtime.go) constructs
`MemoryStore` itself and retains that concrete type. Configurable portal backend
selection needs new typed configuration/parser/application wiring and lifecycle
handling. [Persistent state](../../../../pkg/state/store.go) uses a concrete
filesystem store; OIDC grants and portal-free OAuth sessions have their own
state. A refresh-store implementation does not automatically distribute all
portal sessions or replace those independent stores.

**Implementation contract:** implement the atomic and binding rules on the
`Store` declaration across all clients/processes. Rotation must recheck revision,
current digest, revocation, and deadlines at commit; spent-token replay revokes
the matching family. Retain replay history while descendants remain usable and
keep caller-owned snapshots independent. Never persist raw refresh credentials.

Define transaction isolation, capacity admission, expiry, outage, ambiguous
commit, restart, and durability/failover behavior. Losing acknowledged revocation
or spent-token history must not silently revive authority. Implement optional
capabilities only when their atomic contracts can be met; do not approximate
replacement with a non-atomic revoke-then-create sequence. Shared storage alone
does not establish consistent identity policy or cross-instance signing keys.

**Acceptance:** use independent clients against the same local backend fixture;
race rotations and replacements, replay a spent token, restart a client, revoke
from another client, and simulate failed commits. Assert family isolation,
retained replay history, and no credentials issued from failed operations. The
[refresh owner](../../refresh-token-implementation/SKILL.md) and
[identity owner](../../refresh-token-identity/SKILL.md) define issuance/identity
ordering; [capacity tests](../../../../pkg/authn/token_refresh/capacity_test.go)
illustrate the required atomic replacement behavior.

## Cryptographic signing

**Purpose:** sign approved token claims using a selected local or remote key,
including a KMS/HSM-backed implementation that retains its private key remotely.
A secrets plugin retrieves material; a signing plugin performs the operation.

**Current APIs:** [tokenrefresh.Signer](../../../../pkg/authn/token_refresh/manager.go)
exposes `Sign(context.Context, map[string]any) (string, error)` and is injected
into `NewManager`. Its input is canonical claims; the output is a signed token.
The portal supplies its own signing adapter. General portal access-token signing
uses concrete [kms.CryptoKeyStore](../../../../pkg/kms/crypto_keystore.go) and
[CryptoKey](../../../../pkg/kms/crypto_key.go) paths. Downstream OIDC has
[separate key loading/signing](../../../../pkg/oidc/keys.go). None of these facts
establishes a general remote-signer registration or arbitrary `crypto.Signer`
injection into portal configuration.

The working [local RSA-PSS reference](../../cryptographic-signing/SKILL.md)
lives at `plugins/cryptographic-signing/rsapss`. It provides PS256 signing, a
public directive parser, detached public JWKS, and refresh-engine consumer tests.
Core RSA verification accepts its PS256 tokens with the required salt length;
core RSA signing defaults remain unchanged. This is local-key, engine-level
composition, not a remote backend or automatic portal/OIDC selection.

**Implementation contract:** select allowed algorithm, key identity, token
purpose, and key version through trusted configuration. Preserve supplied claims
and deadlines; the signer must not grant roles, extend a session, or choose an
algorithm from untrusted request data. Specify signing-input/digest handling and
signature encoding for the backend, and independently verify generated tokens.

General integration also needs public verification-key discovery, stable `kid`
selection, rotation/verification overlap, and consumer-specific issuer/token
rules. A non-exportable private key remains non-exportable through configuration
and administrative APIs; public JWKS material has separate ownership. Bound
remote calls, dispose owned clients, and preserve the engine's sign/commit order:
a successful remote signature alone is not permission to publish credentials.

**Acceptance:** verify tokens with an independent public-key verifier, reject
wrong algorithm/key/purpose, preserve exact claims, and test key rotation and
remote failure before session commit. Exercise full portal issuance/JWKS or
OIDC only when those integrations are implemented. The
[JWKS owner](../../authentication-portal-jwks/SKILL.md) and
[OIDC owner](../../authentication-portal-oidc/SKILL.md) define their distinct
publication and token contracts.

## External authorization

**Purpose:** evaluate whether an authenticated subject may perform an action on
a resource, using an external policy service. OPA-style policy evaluation or a
relationship-based service are potential backends. Credential verification and
claim retrieval remain separate operations.

**Current APIs:** `pkg/authz/external.Backend` supplies context-aware `Decide`
calls with typed `Request`/`Result`. `external.New` validates and snapshots the
policy and identity binding. `Gatekeeper.SetExternalAuthorizer` and
`TokenValidator.SetExternalAuthorizer` attach required decisions before serving.
The working backend lives at `plugins/external-authorization/httpjson` and has
its own transport config/parser; core has a separate binding config/parser.
The [owning contract](../../external-authorization/SKILL.md) defines exact public
APIs, grammar, JSON protocol, deadlines, lifecycle and consumer acceptance.

Local authentication, constraints and ACLs must allow before external evaluation.
A remote allow cannot override local denial. The shared enforcement path covers
fresh and cached credentials, Basic/API-key authentication, and authenticated
OAuth sessions. Explicit bypass routes remain bypasses. Every request path
interpretation requires an explicit allow within one total deadline; service
failures deny access. There is no decision cache or implicit claims/header mutation.
Only selected authenticated attributes are sent; query/body/credential forwarding
is not implicit. Unsupported response fields and obligations fail closed.

The host owns backend construction, attachment and disposal. This public runtime
hook does not create a root JSON backend factory or host-module registration.
**Acceptance:** real TLS login and protected requests, an actual HTTP decision
service, no forwarding on required rejection, local/remote denial precedence,
authentication-cache and OAuth-session reevaluation, domain isolation, malformed
responses, timeouts and endpoint failure. The portable consumer also runs in an
isolated external module. See the owner for test paths and validation commands.

## Claims enrichment

**Purpose:** retrieve trusted organization, group, entitlement, or other identity
attributes for a known subject. The result supplies data; the relevant transform,
challenge, issuance, or authorization policy decides what that data permits.

**Current APIs:** `pkg/authz/enrichment.Backend` supplies context-aware lookups.
`enrichment.New` validates and snapshots its typed binding configuration;
`Gatekeeper.SetClaimsEnricher` and `TokenValidator.SetClaimsEnricher` attach it
before serving. The validator uses detached attributes for each ACL decision,
including cached users and `AuthorizeUser`. The runnable reference lives at
`plugins/claims-enrichment/static`, with its dedicated public parser and a real TLS
login-to-protected-resource test also executed from an isolated external module.
See the [implemented contract](../../claims-enrichment/SKILL.md) for exact APIs,
configuration, trust boundaries, lifecycle, and coverage.

This is request-time enrichment. Portal transforms and issuance remain separate;
there is no automatic root-config or authdb plugin loader. Only declared
custom fields can enter the detached claim map, with explicit identity/source
binding. Values support all JSON types; ACL matching retains its string and
string-list types.
Backend data does not rewrite JWTs, normalized roles, authentication evidence,
headers or cached users. Plain custom keys are additive; authenticated-claim
collisions fail. Missing data replaces earlier `enrichment.*` values; errors fail
authorization. Already completed decisions are snapshots, not transactions
with directory changes.

**Broader extension contract:** define a context-aware lookup receiving the server-selected
immutable identity plus issuer/backend/realm or tenant binding, requested
attribute names, and relevant audience/purpose. Return a fresh typed attribute
set with defined source/version/freshness information. Never key a cross-provider
lookup by mutable email, display name, or caller-supplied username alone.

Allowlist output fields and their types; distinguish absent, null, empty,
malformed, and explicitly removed values. Define collision and source precedence
before merging. Protect subject/issuer/audience, token times and identifiers,
credential versions, authentication evidence (`amr`, `acr`, `auth_time`), factor
inventory, and provider-owned claims. Ordinary enrichment must not manufacture
those values. Role/entitlement additions require an explicit trusted source and
mapping; retain provenance so data from a user-editable profile cannot grant
privileges merely because it later appears in a signed token.

Select and implement the lifecycle deliberately:

- **Issuance-time enrichment:** obtain verified subject attributes before the
  selected transform/challenge/claim-issuance phase. Define consistent behavior
  for initial login, refresh, direct authentication, and downstream OIDC. The
  existence of a transform call in several paths does not automatically install
  a remote client safely in all of them.
- **Request-time enrichment:** use a detached authenticated identity and feed the
  result to the request's authorization decision. Do not mutate a shared cached
  user or imply the new attributes were signed into an existing JWT.

Required security attributes fail the operation on outage, wrong type, or stale
validity. Optional presentation data can be omitted under an explicit policy;
that policy must not retain stale privileges. Bound/cache lookups by complete
identity and source/policy version, isolate tenants, and define how removed
entitlements reach the final consumer. Already issued access tokens retain their
claims until expiry or an implemented revocation/request-time check; backend
updates alone do not rewrite them.

Remote work must respect existing identity transactions and locks. Do not insert
an unbounded network call into a callback that serializes credential mutation
with issuance. Design a bounded acquisition plus freshness/version validation
strategy, or an explicitly bounded transaction contract, and test mutation
races before promising atomic revocation.

**Acceptance:** a verified login obtains a synthetic entitlement and the actual
protected-resource policy observes it; a different tenant with the same display
identity does not. Reject reserved-field overwrite, forged provider claims,
wrong types, and malformed JSON; treat recursive template text as literal data.
Verify unchanged caller/cached maps and entitlement removal on refresh and request-time checks as applicable.
Cover outage/expiry and races with account or role changes. Existing
[transform/challenge guidance](../../authentication-portal-challenges/SKILL.md),
[refresh identity guidance](../../refresh-token-identity/SKILL.md), and
[OIDC verifier contract](../../../../pkg/oidc/identity.go) own the authentication
and transaction guarantees this extension must preserve.
