---
name: plugin-development
description: Develop AuthCrunch plugins in separate repositories, maintain category reference plugins under plugins/, and compose companion host plugins. Covers repository bootstrapping, shared and local guidance, category contracts, existing APIs, and integration gaps; secrets providers have a specialized workflow.
---

# Plugin Development

## Select the extension boundary

Production AuthCrunch plugins normally live in separate repositories as
independently versioned Go modules. In-repository category references use
`plugins/<category>/<name>`, including synthetic/mock implementations that prove
the integration contract. This directory convention is not runtime registration.
The two working secrets plugins are ordinary importable packages with explicit
constructors. Neither uses Go's `plugin.Open`, RPC, side-effect registration, or
an AuthCrunch plugin SDK. Neither imports go-authcrunch or Caddy. Both declare
`package secrets`, so consumers importing both need distinct aliases.

Keep three responsibilities distinct:

1. **Backend library:** retrieve or operate on backend data through a focused Go
   API; own backend configuration, validation, transport, and data conversion.
2. **Consumer adapter:** select and construct the library, bind backend-specific
   arguments, satisfy the consumer's interface, and own host registration,
   placeholder resolution, provisioning, and disposal.
3. **AuthCrunch runtime:** consume validated configuration and enforce identity,
   authentication, authorization, and credential semantics in the owning package.

The reusable dependency direction is consumer → adapter → backend library.
A consumer can also call a library directly. Importing a module only makes its
API available; it does not add a kind to AuthCrunch's configuration dispatch.

The separate [static host adapter](https://github.com/greenpau/caddy-security-secrets-static-secrets-manager/blob/14ad68f1c1b7b6389a5e6b34e62bb2bbb7536625/plugin.go)
and [AWS host adapter](https://github.com/greenpau/caddy-security-secrets-aws-secrets-manager/blob/b9e0e4ac82fe8a0fa6fd88f72ba14ad3426b2a39/plugin.go)
provide concrete evidence of that boundary. Their registration and provisioning
are host-framework behavior, not capabilities exported by the backend modules.

Use [secrets-plugins](../secrets-plugins/SKILL.md) to integrate or develop secrets
providers, compare the static and AWS clients, bind secret references, and
verify retrieval, data types, metadata, and refresh behavior.

Use [claims-enrichment](../claims-enrichment/SKILL.md) to maintain request-time
attribute backends, their gatekeeper/validator hooks, and the static claims plugin.

Read the [development blueprint](references/development-blueprint.md) when
starting a plugin, introducing a category, or reviewing whether an extension
has a complete consumer integration and validation plan.

## Select the repository workflow

Read [repository ownership and bootstrapping](references/repository-workflow.md)
to create a standalone plugin from scratch, write its `AGENTS.md` and local
skills, load AuthCrunch guidance from another checkout or GitHub revision, or
design a companion host plugin's guidance. A standalone repository must route
agents to AuthCrunch's shared plugin/category contracts **and** its own local
implementation skills. Keep guidance revisions separate from runtime versions.

Read [synthetic reference plugins](references/synthetic-reference.md) to implement
an in-repository category example under `plugins/<category>/<name>`, such as
`plugins/secrets/mock`, with a typed parser and real consumer acceptance.
Inspect availability first; the layout and acceptance contract do not imply a
reference implementation or new category API already exists.

Many backend plugins also need a separate companion for an upstream host such
as `caddy-security`. That host's plugin-development skills should depend on
AuthCrunch's shared guidance and supplement it with host-local contracts. The
companion then adds its own backend-to-host binding and tests. Keep this
dependency directional; a plain backend does not require host guidance or
host-framework imports. Templates and source-resolution rules are in the
repository workflow reference.

## Choose a plugin category

Read the relevant section of the [category catalog](references/plugin-categories.md)
to select a consumer, check current support, define configuration and lifecycle,
and choose category-specific acceptance tests. These are architectural categories;
the README separates working secrets modules from additional project scaffolds.
A category or repository name alone does not establish an implementation.

| Category | Responsibility | Current extension boundary |
| --- | --- | --- |
| Secrets | Retrieve values for configuration | External libraries and consumer adapters; specialized skill above |
| [Identity stores](references/plugin-categories.md#identity-stores) | Account lookup, authentication, and supported account operations | Configured `ids.IdentityStore` injection into `NewPortal` |
| [Identity providers](references/plugin-categories.md#identity-providers) | Authenticate through a federation/protocol backend | Configured `idp.IdentityProvider` injection; protocol routes still matter |
| [Credential authenticators](references/plugin-categories.md#credential-authenticators) | Validate Basic credentials or API keys | `authproxy.Authenticator` through `Gatekeeper.AddAuthenticators` |
| [Messaging](references/plugin-categories.md#messaging) | Deliver registration or notification messages | `messaging.Provider` exists; configuration and consumers use concrete built-ins |
| [Registration workflows](references/plugin-categories.md#registration-workflows) | Manage enrollment, confirmation, approval, and account creation | `registry.Provider` through `Portal.AddUserRegistry`; root dispatch is local-only |
| [Session and refresh storage](references/plugin-categories.md#session-and-refresh-storage) | Store token families and enforce atomic rotation/revocation | `tokenrefresh.Store` injection into the engine; portal storage selection needs wiring |
| [Cryptographic signing](references/plugin-categories.md#cryptographic-signing) | Sign approved claims with a selected key | `tokenrefresh.Signer` at engine level; general portal/OIDC signing needs integration |
| [External authorization](references/plugin-categories.md#external-authorization) | Evaluate an authenticated subject's access to a resource | Proposed public decision interface and gatekeeper call sites |
| [Claims enrichment](references/plugin-categories.md#claims-enrichment) | Retrieve and validate additional identity attributes | `enrichment.Backend` and validator/gatekeeper attachment; static claims plugin available |

## Current core boundaries

Check these files before proposing an API. Names in a plugin repository or
README are not proof of a core registration point.

| Concern | Current authority | Consequence for extensions |
| --- | --- | --- |
| Root assembly | [Config](../../../config.go), [NewServer](../../../server.go) | No plugin registry, plugin configuration list, or secrets-manager loader exists here. Resolve external values before validation/construction. |
| Identity stores | [config](../../../pkg/ids/config.go), [dispatch/interface](../../../pkg/ids/store.go) | The shared dispatcher accepts `local` and `ldap`; implementing the interface alone does not register another kind. |
| Identity providers | [config](../../../pkg/idp/config.go), [dispatch/interface](../../../pkg/idp/provider.go) | The shared dispatcher accepts `oauth` and `saml`; a new OAuth driver is different from a new provider kind. |
| Direct portal composition | [PortalParameters and NewPortal](../../../pkg/authn/portal.go) | A Go host can inject configured identity stores, identity providers, and SSO providers directly, without using the shared factories. |
| Credential records | [configuration](../../../pkg/credentials/config.go), [credential dispatch](../../../pkg/credentials/credential.go) | `credentials.Config` holds credential definitions; it is not a secrets-backend registry. |
| Standalone server | [authdb entry point](../../../cmd/authdb/main.go) | Installing a Go module does not make it loadable through `authdb` JSON. An embedding integration must be implemented explicitly. |

For direct composition, construct/configure the backend and pass it through
`authn.PortalParameters.IdentityStores`, `IdentityProviders`, or
`SingleSignOnProviders`. Select its `GetName()` in the corresponding
`PortalConfig` name list; `NewPortal` requires `Configured()` to be true. Check
the current interface and any feature-specific capability checks, not just the
constructor. The embedding host owns those injected backends: `Portal.Close`
releases portal resources but does not close shared stores/providers. This is
an existing injection path; adding a new `Kind` to root `Config`/`NewServer`
or `authdb` remains separate dispatcher work.

A secrets provider supplies configuration values. An identity store owns account
lookup and operations; an identity provider owns authentication evidence. A
messaging extension would own delivery. Choose an interface matching that
responsibility instead of forcing every category through `GetSecret` or a
universal map-based `Execute` method.

For a new category, first identify an existing public injection point. When
there is none, describe the necessary core change as proposed work: typed
configuration, reusable parser, dispatch/application API, lifecycle ownership,
and consumer tests. Do not document invented `RegisterPlugin`, `pkg/plugins`,
or `pkg/secrets` APIs as available. A factory registry is a design choice that
needs its own ownership, duplicate-name, concurrency, and lifecycle contract.

## Preserve responsibility and compatibility

- Keep backend SDK dependencies in the backend module and host-framework
  dependencies in its adapter. Do not make core depend on every backend.
- Record module path, import alias, provider kind, configured instance ID, and
  backend resource locator separately. They identify different things.
- Prefer consumer-owned interfaces with compile-time conformance checks. Go
  method signatures must match exactly; similarly named methods are insufficient.
- Preserve published constructors when extending working modules. A typed config
  constructor or optional capability can be additive; an incompatible method
  change needs a deliberate versioning and adapter migration plan.
- Keep declarative configuration apart from mutable clients, caches, resolved
  secrets, and goroutines. Treat a failed construction or reload as unpublished
  state and dispose resources already acquired.
- Assign ownership explicitly. [Server.Close](../../../server.go) closes the
  components it constructs and owns; it cannot discover arbitrary clients an
  embedding application created beforehand.

The repository scope, parser architecture, and test contracts remain owned by
[coding-directives](../coding-directives/SKILL.md) and
[testing-and-ci](../testing-and-ci/SKILL.md). A task in this checkout stays here;
external implementations can be inspected as evidence. A separately authorized
plugin-repository task applies this portable guidance in its own workspace.
Reusable bootstrap templates and companion guidance belong in these references;
task-specific Caddy implementation handoffs still belong only in ignored `tmp/`.

## Acceptance decisions

- A new standalone plugin can be built from category guidance without a global
  AuthCrunch skill installation or assumed sibling checkout. Its `AGENTS.md`
  routes to verified upstream guidance and its existing local implementation skill.
- A synthetic plugin uses `plugins/<category>/<name>`, exercises public consumer
  APIs, and participates in repository validation; a directory alone is not
  proof of an implemented plugin or loader.
- A companion's guidance layers core, host, and local contracts without adding
  host dependencies to the reusable backend or implying another repository was
  modified by a core-only task.
- A new secrets backend can be used by a plain Go consumer without importing a
  host framework; a host adapter separately proves registration and lifecycle.
- Static and path-addressed clients are compared by exact signatures; an adapter
  binds a path rather than claiming the clients implement the same interface.
- A proposed identity-store backend distinguishes direct `NewPortal` injection
  from root configuration dispatch. It identifies validator/factory changes
  only when the requested integration needs a new shared-dispatch kind.
- A new plugin type gets its own domain contract and, when warranted, a narrow
  skill routed from this skill. It does not inherit secrets-only methods.
- Messaging/registration interfaces are traced through their concrete config
  containers and consumers before claiming a configurable backend exists.
- Engine-level storage/signing injection is distinguished from full portal
  integration; request-time claims enrichment has explicit validator/gatekeeper
  attachment, while external authorization remains proposed.
- Documentation distinguishes inspected source, tests actually executed, desired
  new behavior, and integration that remains unavailable.
