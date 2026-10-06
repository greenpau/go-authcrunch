# AuthCrunch Plugin Development Blueprint

This blueprint describes how to develop a plugin and prove its integration.
It is a design workflow, not an existing generic plugin SDK. For the concrete
secrets example, pair it with the [secrets contract](../../secrets-plugins/SKILL.md)
and [working-client example](../../secrets-plugins/references/consumer-example.md).
For the other categories, select the corresponding contract in the
[plugin category catalog](plugin-categories.md) before designing an interface.
For a new separate repository, first apply the
[repository bootstrap workflow](repository-workflow.md), including its upstream
and local `AGENTS.md` routes. In-repository examples instead follow the
[synthetic reference layout](synthetic-reference.md).

## 1. Define the capability and its consumer

Write a short contract before choosing a repository name:

| Decision | Secrets example | Another category |
| --- | --- | --- |
| Responsibility | Retrieve a secret record or field | Retrieve an identity, deliver a message, or perform another bounded domain operation |
| Consumer | Configuration assembly before AuthCrunch startup | The actual store/provider/delivery dispatcher or caller |
| Selection | Provider kind plus a configured instance ID | A domain-specific kind/name or explicit constructor |
| Backend locator | Static record or remote secret name/ARN | Store partition, provider tenant, or delivery destination |
| Output | Secret data, never authentication success by itself | A typed domain result with explicit authority |
| Activation | Direct Go construction or a separate host adapter | Existing injection point, or a proposed core extension |

Use `go-authcrunch-<category>-<backend>` as a naming convention, following the
existing `secrets` modules; it has no discovery semantics. Keep provider labels
stable once configuration persists them. Instance IDs should be unique within
the consumer's namespace. Define locator and key grammar without deriving it
from a module path.

For new categories, inspect the owning package's interface, validator, factory,
and call sites. Specify unsupported operations and optional capabilities. For
example, implementing an identity-store interface must not imply support for
transactional local profile changes or refresh identity evidence. Those
capabilities have separate contracts and must fail closed when unavailable.

Deliverable: a capability statement, exact consumer entry point, and a list of
required integration changes. Mark any missing core API as proposed.

Identify the execution phase as part of that contract. Secrets can supply a
startup configuration snapshot; stores and identity providers participate in
authentication; authenticators validate request credentials; registration and
messaging perform workflow operations; storage and signing participate in
credential issuance; external authorization evaluates protected requests; claims
enrichment supplies attributes at an explicitly chosen trust boundary. A
constructor or configuration-time fetch is not a substitute for these runtime
operations. The category catalog distinguishes implemented injection points,
partial integration, and proposed APIs for each phase.

For identity stores/providers, there are two concrete integration choices.
A plain Go host can already inject configured implementations through
`authn.NewPortal(authn.PortalParameters{...})`, selecting their names in
`PortalConfig` and retaining ownership of backend cleanup. Root
`authcrunch.NewServer` instead constructs implementations from shared
configuration and its fixed factories. A new shared-dispatch kind requires
validator/factory/parser changes; direct portal injection does not. Review the
[portal constructor](../../../../pkg/authn/portal.go) and the exact domain
interface before selecting one. This does not establish compatibility of any
particular third-party identity-store implementation.

## 2. Choose module and package boundaries

Develop production backend plugins in separate repositories. A useful layout
for a new standalone backend module is:

```text
go-authcrunch-<category>-<backend>/
    AGENTS.md                  shared AuthCrunch guidance and local skill routes
    .codex/skills/              backend-specific implementation guidance
    go.mod, go.sum              independent module and pinned dependencies
    client.go                  public constructor, focused API, runtime state
    config.go                  exported typed config and semantic validation
    client_test.go             retrieval/operation and failure behavior
    parser/
        config.go              public typed directive constructor
        config_test.go         external-package grammar tests
        config_example_test.go executable public API example
    consumer_e2e_test.go        public parser -> runtime -> observable result
```

Add transport files, fixtures, or `internal/` helpers only when the backend
needs them. This is a new-module layout, not a claim that the two reference
plugins already have typed public configs or parser packages. Host adapters
remain separately owned; they import this library, never the reverse.
AuthCrunch's own examples belong under `plugins/<category>/<name>` and normally
share the root module; do not put every production backend there or introduce a
nested module merely to copy the standalone layout. The repository workflow
provides the complete from-scratch guidance and `AGENTS.md` templates.

Prefer a small interface at the caller and a concrete implementation behind the
constructor. A constructor that can fail returns a runtime object and `error`.
Accept context explicitly for I/O. Inject the narrow backend client or transport
when useful for testing; configure it before publishing the runtime. Keep mock
credentials and fixtures out of a new production API.

Decide whether the backend module can remain independent of go-authcrunch. The
reference clients do. Reusing AuthCrunch's encoded-directive helpers creates an
explicit core-module dependency; a separate parser module is an option when
preserving a dependency-light backend matters. Do not copy parsing helpers to
hide that dependency, or pull a host framework into the reusable client.

## 3. Define typed configuration and a reusable parser

Apply the [configuration parser contract](../../coding-directives/references/configuration-parsers.md).
For a hypothetical remote secrets module, an appropriate *new API design* is:

```text
Config: ID, endpoint/region as applicable, resource path, bounded request timeout
Config.Validate(): required fields, defaults, cross-field/backend constraints
parser.NewSecretsBackendConfigFromDirectives(id, statements): (*Config, error)
NewClient(ctx, cfg, backendDependency): (Client, error)
```

Replace `SecretsBackend` with the actual subject. These names are illustrative,
not exported by either existing plugin. Preserve existing constructors during an
additive migration. Document the exact type, import path, signature, grammar,
defaults, and application API once implemented.

Keep body/header parsing separate and preserve token boundaries using the
shared encoded-statement contract. A possible new body grammar is `region <r>`,
`path <resource>`, and `request timeout <duration>`; JSON field names alone do not
make these supported directives. Parse the complete subject, reject duplicates,
unknown settings, wrong arity, empty required values, and raw CR/LF, and return
no config on failure. Parsing performs no secret retrieval or network calls.

The consumer resolves host placeholders, parses a fresh candidate, and applies
validated typed results. Secret data is a separate runtime input or protected
configuration field, not debug metadata. Omission, empty records, defaults,
whitespace, and disabled behavior need explicit semantics.

## 4. Specify operations and lifetime

For each method, define inputs, output types, whether it performs I/O, ownership
of returned data, cancellation, and error outcomes. Cover at least:

- **Construct:** validate first; acquire resources only after input is acceptable;
  publish no partial runtime after failure.
- **Read/operate:** propagate context, bound calls and payload sizes, distinguish
  missing resources/keys from authorization, cancellation, and transport errors.
- **Share:** initialize clients safely, keep options immutable, and define whether
  concurrent calls are supported. Copy mutable maps/slices at ownership boundaries.
- **Refresh:** choose per-call retrieval, startup snapshot, or an explicit cache
  policy. Define TTL, expiry, retries, coalescing, and stale-on-error behavior only
  if a cache is actually needed. Fail closed by default for missing credentials.
- **Reload/close:** build a fresh candidate; publish only after full validation;
  keep the previous runtime intact on failure; cancel workers and close only
  owned resources. Do not close a caller's shared transport without agreement.

Use typed/sentinel errors where callers need reliable classification, and wrap
safe causes. Do not expose payloads, authentication headers, raw configuration,
or backend response bodies in diagnostics. Missing-key errors can identify an
operation or approved identifier; they must never echo the value.

For rotation, follow the value all the way to its consumer. Fetching a new secret
is not enough if a database bootstrap or signing-key store retains the old value.
Decide and test when the final consumer adopts it and how old credentials are
retired. A secret provider does not implement password hashing, MFA policy, JWT
key overlap, or credential-version invalidation on behalf of those owners.

## 5. Integrate through the real boundary

For a plain Go consumer:

1. Import a pinned module version with an unambiguous package alias.
2. Parse and validate configuration, construct dependencies, and complete the
   category's required configuration/activation before publishing the runtime.
3. Bind backend arguments such as resource locators or realm/name selection to
   the consumer-facing interface. Use an existing injection point when suitable;
   otherwise implement the planned public application API and call sites.
4. Execute operations in the phase selected above. For secrets, retrieve and
   validate a coherent record before applying its values to configuration. For
   other categories, pass typed runtime inputs and interpret the result under
   that category's authentication, delivery, transaction, or decision contract.
5. Preserve the downstream consumer's validation and commit ordering. Storage
   success, signature creation, delivery acceptance, and an authorization allow
   are different outcomes; none implies that all later operations succeeded.
6. Own plugin and consumer lifetimes explicitly. Directly injected objects do
   not automatically become the property of the root server or portal.

Resolve values as data once. Do not recursively interpret retrieved content as
another secret reference, expand template syntax inside it, or reconstruct
statements with whitespace joining. Use a private runtime configuration so
resolved secrets do not flow back into an administrative config view or dump.
An explicit request to persist credentials belongs to the credential owner's
private-storage workflow.

For runtime data, follow the category's separate refresh and invalidation rules.
Do not use startup secret replacement as an authorization decision or claim
enrichment hook. Decide whether enrichment is issuance-time or request-time and
keep it consistent across authentication, renewal, and cached requests. Required
external authorization must run on every selected protected path, including
paths reusing an authenticated identity, according to its cache policy.

For a host module, additionally implement that host's registration, config
adaptation, validation, provisioning, and cleanup. Test the compiled consumer
with the adapter included. A blank import of the backend library does not
register a host module. Use the host's actual plugin-development guidance in
addition to AuthCrunch's category contract and the companion repository's local
skills. The host skill should extend these shared rules with its own contracts;
the companion owns the concrete adapter. Follow the
[companion workflow](repository-workflow.md#companion-host-plugins) for discovery,
version binding, ownership, and validation in the authorized repository.

When core dispatch itself must change, implement the typed model, parser,
validator allowlist, factory/application path, and root assembly together.
Prefer an instance-owned factory collection if runtime registration is required;
state duplicate/unknown-kind behavior and freeze it before serving. Do not add
mutable process-global registries merely to imitate another framework.

## 6. Prove the contract

Use the repository's [testing requirements](../../testing-and-ci/SKILL.md) for
code developed here. In a separate plugin project, use its authorized test
workflow; do not run maintenance commands in a sibling checkout.
When implementing core category integration, add an appropriate runnable
synthetic/mock plugin under `plugins/<category>/<name>` and exercise it through
the real consumer. The [reference contract](synthetic-reference.md) defines its
configuration, isolation, and CI requirements. External plugin development can
consume that evidence without modifying the core reference from its own task.

| Layer | Evidence required |
| --- | --- |
| Public API | Independent package compiles and calls the constructor; exact interface conformance; no host-framework dependency in the backend |
| Config/parser | Typed defaults and errors; complete grammar; quoted values; duplicates; input immutability; executable parser example |
| Backend | Successful operation and real error mapping; missing record/key; malformed/wrong-type/oversized data; canceled and timed-out requests |
| State | Concurrent first use under the race detector; mutation isolation; snapshot/cache/rotation semantics; failed construction and close behavior |
| Consumer E2E | Public parser constructs the real client against a local fixture; the actual consumer observes the value or operation; failure leaves the prior state usable |
| Exposure | Synthetic canaries absent from metadata, errors, logs, config exports, and failing test reports |

For secrets consumed by AuthCrunch authentication, the strongest consumer journey
is secret retrieval → config assembly → local TLS login/signing → independent
verification of the expected identity or signature. If an example only proves
retrieval and adaptation, report exactly that narrower scope. No cloud account
or production credential is needed in the default suite.

For a new category, derive E2E assertions from its operation: an identity-store
extension authenticates and enforces account state; a messaging extension
reaches a controlled recipient fixture. Do not relabel a mocked method call as
end-to-end validation.

The [category acceptance scenarios](plugin-categories.md) identify additional
evidence: realm binding for authenticators, single-use registration, concurrent
refresh/replay, independent signature verification, external decision failures
on cached identities, and claim provenance across renewal. Existing tests linked
there are starting points, not evidence that a proposed backend is supported.

## 7. Package and document compatibility

Pin backend and adapter revisions in reproducible tests. Record the supported
Go toolchain, backend SDK, core consumer, and host adapter versions separately;
a `VERSION` file is not proof that the matching Git tag exists. Verify module
paths and tags before publishing dependency instructions. Preserve public
constructors, provider labels, serialized fields, and error contracts, or plan
an explicit breaking release and migration.

Publish concise onboarding in the plugin's own README: responsibility, supported
payload, constructor, configuration, permissions where relevant, lifecycle,
local verification, and the adapter needed by each supported host. Keep detailed
AuthCrunch engineering guidance in the owning local skill. Add the module under
its actual category in AuthCrunch's README; keep speculative categories out of
the supported-plugin list. The separate category overview may describe proposed
extension contracts, with their implementation status stated explicitly.

Completion means a consumer can construct, configure, use, fail, and dispose the
plugin through documented public APIs, and the claimed compatibility has
corresponding evidence. A module that compiles but has no consumer wiring is a
backend implementation with integration still outstanding.
Its `AGENTS.md` must also make the shared category guidance and repo-local skills
discoverable from a fresh clone. A companion, when part of the task, must record
the host guidance and independently demonstrate the claimed host integration.
