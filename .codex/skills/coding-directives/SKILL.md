---
name: coding-directives
description: Apply AuthCrunch coding contracts when creating, modifying, or reviewing repository code. Covers package ownership, dedicated configuration parsers, public APIs, validation, errors, logging, serialization, and security boundaries, and routes to the owning implementation skill.
---

# Coding Directives

## Overview

Apply these directives when editing or reviewing go-authcrunch code. Prefer
small, package-local changes that preserve AuthCrunch's existing runtime shape:
top-level `authcrunch.Config` and `Server` wire package-owned configs,
constructors, validators, providers, stores, portals, gatekeepers, registries,
and crypto key stores.

Do not import or use `reflect` in non-test code. Use typed APIs, explicit type
switches, and generic helpers where needed. Reflection-based test helpers belong
in `_test.go` files and must not become production dependencies.

Go changes must meet the [testing requirements](../testing-and-ci/SKILL.md).
[scripts-and-automation](../scripts-and-automation/SKILL.md) owns Make targets,
generated assets, and dependency commands;
[release-and-versioning](../release-and-versioning/SKILL.md) owns version invariants.
The root routes select those workflows when their tasks are in scope.

## Keep Skills Current

Treat relevant repo-local skill maintenance as part of completing every code
change. After updating implementation and tests, review the owning skills and
their linked references and update affected guidance in the same task, before
reporting completion. Do not wait for a separate documentation request.

Use [skill-authoring](../skill-authoring/SKILL.md) to synchronize the relevant
skills with implemented behavior, configuration, ownership, and validation
changes, including corrected paths or examples after a refactor.

## Implementation workflows

- Use [authorization-policy-acl](../authorization-policy-acl/SKILL.md) to
  change typed custom ACL claims, their parser, condition compilation, policy
  configuration, and gatekeeper evaluation across cached and fresh identities.
- Use [refresh-token-implementation](../refresh-token-implementation/SKILL.md) to
  change portal refresh configuration, issuance, rotation, replay, storage, or
  lifecycle; follow its routes for login evidence and transport boundaries.
- Use [authentication-portal-themes](../authentication-portal-themes/SKILL.md) to
  build custom portal templates, CSS, branding, and UI configuration, including
  OIDC consent, continuation, and browser-error pages.
- Use [authentication-portal-cookies](../authentication-portal-cookies/SKILL.md) to
  change shared cookie directives, prefixes, names, factory attributes, and
  interoperability across portal features and gatekeepers.
- Use [oauth-identity-provider](../oauth-identity-provider/SKILL.md) to change
  upstream OAuth directive parsers, shared configuration adapters, discovery,
  JWKS/static PEM and EdDSA verification, key refresh, and real portal OAuth tests.
- Use [authorization-policy-oauth](../authorization-policy-oauth/SKILL.md) to
  implement OAuth login without a portal, provider selection, directives,
  callbacks, opaque sessions, ACL revalidation, logout, and embedding lifecycle.
  This feature owns policy cookies; upstream protocol verification remains with
  the OAuth identity provider.
- Use [authentication-portal-jwks](../authentication-portal-jwks/SKILL.md) to
  change portal public signing-key discovery, base-path routing, reusable admin
  API directives, opt-in private-key export, issuer selection, and serialization.
- Use [local-password-authentication](../local-password-authentication/SKILL.md) to
  change local bcrypt/Argon2 password creation, import, changes, resets,
  verification, hashing configuration/parser, and authentication work equalization.
- Use [identity-public-keys](../identity-public-keys/SKILL.md) to change user-owned
  GPG/SSH key parsing, profile registration, persisted compatibility, and OpenPGP
  dependencies. Portal signing-key publication and admin private-key export
  remain with the portal JWKS owner.
- Use [authentication-portal-oidc](../authentication-portal-oidc/SKILL.md) to
  change the reusable `pkg/oidc` OpenID Provider and its local-user portal adapter:
  discovery, clients, code/PKCE, consent, ID-token keys, UserInfo, revocation,
  browser rendering/response policies, and conformance.
- Use [local-identity-database](../local-identity-database/SKILL.md) to change
  file locking, atomic persistence, cross-instance credential revocation, TOTP
  state, and identity-bound operations.
- Use [authentication-portal-profile](../authentication-portal-profile/SKILL.md) to
  change local self-service authorization, canonical identity, browser-origin
  checks, credential operations, and per-user authentication-flow selection.
- Use [authentication-portal-mfa](../authentication-portal-mfa/SKILL.md) to change
  TOTP/WebAuthn login checkpoints, verification, and enrollment.
- Use [saml-identity-provider](../saml-identity-provider/SKILL.md) to change signed
  upstream assertions, SP-initiated browser binding, ACS validation, and
  authoritative signing-certificate pins.
- Use [authentication-portal-challenges](../authentication-portal-challenges/SKILL.md) to
  change conditional challenge selection, challenge/user-transform parsers,
  registered-factor inventory, verified AMR, and policy revalidation at issuance.
  Factor verification and enrollment remain with the portal MFA owner.
- Use [authentication-client](../authentication-client/SKILL.md) to change
  reusable JSON portal login clients, credential files, and authentication
  protocol wiring. This client uses `/login` without the admin API.
- Use [authdbctl](../authdbctl/SKILL.md) to change management CLI commands,
  configuration, terminal behavior, database retries, output, and executable E2E tests.
- Use [authdb](../authdb/SKILL.md) to change the standalone HTTP server,
  `pkg/httpserver` listener configuration/parser, portal mounts, TLS, shutdown,
  executable tests, and deployment guidance.
- Use [runtime-state](../runtime-state/SKILL.md) to change host-independent durable
  keys and sessions, directory parsing, refresh/OIDC replay history, local identity
  epochs, storage ownership, restart tests, and embedding lifecycle contracts.
- Use [logging](../logging/SKILL.md) to change diagnostic skip rules, their public
  parser, immutable Zap filters, root logger wiring, and host logging integration.

## Repository Scope

Keep all repository changes inside `go-authcrunch`. Never change sibling
directories. Sibling projects will be updated separately; these workflows have
no cross-repository exception or approval path.

This prohibition covers creating, editing, deleting, restoring, staging, or
committing files, and changes to code, tests, fixtures, dependency files, skills,
generated artifacts, or repository metadata. Do not run commands that can write
to sibling directories, including build, test, formatting, license, dependency,
or cleanup commands. Compatibility fixes and failing consumer tests do not
permit sibling changes.

Provide reusable APIs and test their public workflows in this repository.
References to dependencies, consumer wiring, or compatible directive syntax
are context only. Describe any remaining consumer integration as separate
work; do not perform it or request to expand this task into sibling directories.

Write Caddy integration agent handoff notes only in the repository-root ignored
`tmp/` directory. Do not commit them or store them in package code, tracked
documentation, skill bodies, or skill reference files. Keep reusable,
host-independent library contracts in their owning skills; temporary handoffs
may link to those contracts, but skills must not depend on temporary handoffs.

For embedding-server configuration and reload work, read the
[integration boundaries](references/embedding-integration.md). They identify
the public parser/application APIs and distinguish persisted configuration
from runtime state and resource ownership.

## Package Boundaries

Put behavior in the package that owns the AuthCrunch surface:

- `pkg/authn`: authentication portals, portal HTTP/API handlers, sessions,
  cookies, MFA/WebAuthn/TOTP/GPG/SSH/API-key profile operations, UI serving,
  and portal-specific config.
- `pkg/authn/token_refresh` (Go identifier `tokenrefresh`): opaque refresh
  tokens, session storage, and atomic issuance/rotation. Portal configuration,
  login evidence, and HTTP adapters remain in `pkg/authn`.
- `pkg/authz`: authorization gatekeepers, access policy config, token
  validators, bypass rules, auth redirects, header injection, and auth proxy
  integration.
- `pkg/ids` and `pkg/idp`: shared dispatch config and interfaces for identity
  stores and identity providers. Put provider-specific behavior in
  `pkg/ids/local`, `pkg/ids/ldap`, `pkg/idp/oauth`, or `pkg/idp/saml`.
- `pkg/sso`, `pkg/kms`, `pkg/registry`, `pkg/messaging`, `pkg/identity`,
  `pkg/user`, `pkg/translate`, and focused utility packages own their models,
  validation, and tests. Configuration directive parsers have separate public
  packages under their owning domain.
- `pkg/oidc` owns the reusable OpenID Provider, public configuration, identity
  verifier interface, protocol handlers, and browser-session lifecycle. Portal
  identity, sandbox, and refresh adapters remain in `pkg/authn`.
- `pkg/authclient` owns the JSON portal login client, challenge orchestration,
  opaque credential results, and optional token-file persistence. It uses the
  login endpoint without depending on the admin API or a CLI framework.
- `pkg/httpserver` owns standalone listener configuration, portal mounts, TLS,
  request draining, and root runtime disposal; its `parser` package owns HTTP
  directives. `cmd/authdb` owns file loading, flags, logging, and signals.
- `cmd/authdbctl` owns configuration discovery, application paths, flags,
  terminal prompts, database commands, management request retries, and output.

Do not add cross-package shortcuts when an existing dispatcher, interface, or
config object already models the boundary. When adding a provider/store kind,
update the shared config validator, dispatch constructor, concrete package
constructor, and package tests together.

In shared packages, qualify feature filenames with the complete domain name.
Portal token-refresh files use `token_refresh_`, including runtime adapters and
browser, capacity, and session tests. Use the same feature prefix for their
test drivers in shared fixture directories. Short filenames such as `manager.go`
are appropriate inside the dedicated `pkg/authn/token_refresh` package. Rename
maintained callers and skill references together; source-file cleanup does not
rename established HTTP routes, serialized fields, or served asset URLs.

## Design and structure

Model stateful business rules with cohesive structs and methods, using
composition and small consumer-owned interfaces at dispatch boundaries. Keep
stateless parsing/formatting helpers separate; reuse `pkg/util`, `pkg/util/cfg`,
`internal/tests`, and `internal/testutils` where they already own the operation.
Avoid pipelines that obscure authentication state, error handling, or lifetime.

Export only what consumers need. Keep runtime-only fields out of serialization;
use matching JSON/XML/YAML tags on public persisted models. Split growing types
by owned responsibility instead of adding cross-package shortcuts. Prefer
package-local changes and preserve established constructors and interfaces.

Do not add mutable process-global runtime state; existing shared registries and
key buffers have explicit ownership contracts. Name repeated configuration keys,
cookie/header names, provider kinds, and defaults with package-local constants.

## Configuration

Keep external config structs serializable with matching `json`, `xml`, and
`yaml` tags. Use snake_case tag names and `omitempty` unless the surrounding
type deliberately preserves false/zero values.

In shared packages, name public configuration types for the complete feature:
use `authn.TokenRefreshConfig` for token refresh. Keep the type, constructor
return type, owning filenames, consumers, tests, examples, and skill references
consistent when renaming a feature. Preserve established serialization keys and
distinct protocol concepts; do not retain an ambiguous type as a new alias.

Treat `Validate` methods as the repository's normalization boundary for typed
configuration: defaults, compiled expressions, derived values, and semantic
checks belong there. Some existing validators also decode raw directives; when
working on that configuration, move decoding into its dedicated parser package
under the contract below. Preserve intentional normalization and `validated`
state handling without creating a runtime-to-parser import cycle.

Keep constructors strict:

- Return `(*Type, error)` or `(Interface, error)` for runtime objects that can
  fail.
- Check required dependencies such as config and `*zap.Logger` before doing
  work.
- Call `Validate` before configuring runtime state.
- Configure package-owned defaults, icons, crypto stores, and raw directives
  close to the config type that owns them.

### Reusable Directive Parser Packages

Every configuration surface must have a dedicated public package named
`parser` under its owning domain or feature. A typed config, serialization tags,
validator, or embedding application's directive handler alone does not satisfy
this requirement. It applies to small configurations and single boolean options
as well as larger blocks. When adding or changing configuration, implement or
extend its parser in the same feature change; the rule is not limited to parser
extractions or substantial refactors.

Use `pkg/<domain>/parser` or `pkg/<domain>/<feature>/parser` according to feature
ownership. Related configuration subjects may share that feature's parser
package, with separate files and public constructors. Nested settings are
covered through the owning parser; do not create a package per field or a
repository-wide parser containing unrelated features. A file named `parser.go`
inside the runtime package or a wrapper around private runtime parsing is not
a dedicated parser package.

Read [configuration parser shape](references/configuration-parsers.md) when
introducing configuration, exposing settings, or extracting a parser. It defines
the package layout, API signatures, input grammar, typed result, composition,
validation ownership, and migration boundaries. Existing configurations without
this structure are implementation gaps to address within the authorized feature
work; a skills-only update does not authorize a repository-wide code migration.

The [parser contract](references/configuration-parsers.md) owns constructor
names, typed results, statement encoding, validation, application snapshots,
acyclic dependencies, shared dispatch, and migration. Record only concrete
feature bindings in an implementation skill.

### Cookie Configuration

The [cookie owner](../authentication-portal-cookies/SKILL.md) owns portal role
names, prefix changes, directive parsing, factory attributes, and issuance/deletion
compatibility. New portal features must use that shared configuration and factory;
feature-owned transport and lifetime rules still apply.

## Errors

Use `pkg/errors.StandardError` constants for stable package and public-surface
errors when the surrounding package already has an error catalog. Wrap them
with `.WithArgs(...)` for contextual values.

Use `fmt.Errorf` for narrowly local errors, simple helper failures, and test
expectations. Use `%w` when crossing IO, network, filesystem, YAML/JSON, or
runtime construction boundaries where callers may inspect the cause.

Do not panic in library or CLI code. Panics are acceptable only in test helper
setup paths that intentionally fail fast. Preserve exact error strings when
tests assert them.

## Security

This repository handles tokens, cookies, API keys, passwords, TOTP secrets,
private keys, OAuth client secrets, LDAP credentials, and identity data. Keep
secret values out of errors, test diffs and command output. For logging, apply
the [diagnostic logging exceptions](../threat-hunting/references/debug-logging.md)
to intentional claims and authentication diagnostics.

When adding `zap` logs, include the operation, package context, realm/name, and
non-sensitive identifiers. Outside those accepted diagnostic boundaries,
redact or omit token bodies and full credential structs. Continue omitting
password material, private keys and unrelated shared secrets even when older
code logs something similar. Do not remove intentional diagnostic visibility
solely to silence CodeQL, promote debug payloads to ordinary logging levels,
or treat claims as globally safe to log.

`pkg/util/random.go` supplies session identifiers, nonces, and credential data
to multiple authentication flows. Keep it cryptographically secure without a
`math/rand` fallback. Follow the existing Go 1.26 `crypto/rand.Read` contract:
fill the buffer or terminate on unrecoverable entropy failure. Preserve helper
length/charset contracts and unbiased bounded sampling. Verify failure behavior
in isolated subprocesses, never by replacing `rand.Reader` in parallel tests.

Prefer explicit permission bits already used in the repo for sensitive files
and directories, such as `0600` for token and serialized configuration files
and `0700` for private directories. Publish complete secret-bearing files by
atomic replacement through an owner-only temporary file. Token and newly
created configuration files must not inherit a destination's broader mode.
Existing identity-database commits preserve the file's mode as an explicit
compatibility contract owned by [local-identity-database](../local-identity-database/SKILL.md);
do not silently change that persistence behavior during unrelated file work.

## HTTP And Runtime Flow

Use `context.Context` as the first parameter when work participates in request
flow, ACL evaluation, cancellation, or potentially blocking operations. For
HTTP behavior, use `httptest` and package-level helpers rather than live
services.

Keep request parsing, authentication, authorization, and response writing close
to the handler or runtime object that owns the flow. Preserve existing cache,
cookie, sandbox, token source, and redirect semantics unless the task
explicitly changes them.

Put an explicit `http.MaxBytesReader` boundary in front of every public HTTP
body decoder or reader, including authenticated administrative endpoints;
authentication does not constrain memory consumption. Return HTTP 413 for
`http.MaxBytesError` and reserve HTTP 400 for malformed content within the
accepted size. Share a boundary helper across handlers with the same request
class so new routes inherit the limit and status contract.

Bound every outbound HTTP response before `io.ReadAll` or decoding, including
responses from configured/trusted peers. Check declared `Content-Length` early
and retain a limiting reader for chunked or dishonest responses. Return a typed
or sentinel size error so retrying consumers can fail without repeating a
deterministic oversized response. Never include remote response bodies in error
messages or logs.

Treat certificate and private-key files as fallible configuration input. Check
for a nil block after every `pem.Decode` before reading its type or bytes, and
return DER/key parser errors from construction. Do not publish a runtime object
with nil or partially parsed cryptographic material for a later request path to
dereference.

Render every HTML context, including HTML email, with `html/template`; reserve
`text/template` for plain-text output such as mail subjects. MIME or
quoted-printable transport encoding is not contextual HTML escaping. Exercise
both text-node and URL/attribute values with hostile markup in regression tests.

## Tests

Apply the mandatory [corresponding tests requirement](../testing-and-ci/SKILL.md#corresponding-tests)
to every Go code change, including CLI code, internal helpers, and refactors.
Follow its [required E2E coverage](../testing-and-ci/SKILL.md#required-end-to-end-coverage)
whenever developing tests.
Also follow its [diagnostics in agent changes](../testing-and-ci/SKILL.md#diagnostics-in-agent-changes)
workflow during each coherent edit: inspect applicable diagnostics and remediate
confirmed problems immediately within the code the agent creates or edits.

Add focused table-driven tests beside the package being changed. Use
`github.com/google/go-cmp/cmp` and `internal/tests` helpers such as `Unpack`,
`UnpackDict`, `EvalErrWithLog`, and `EvalObjectsWithLog` when comparing
normalized config or exact errors.

Cover both success normalization and meaningful malformed inputs for config and
parser changes. Follow [test placement and filenames](../testing-and-ci/SKILL.md#test-placement-and-filenames)
when choosing a test's owning package and filename, including root configuration
and server integration tests. For authn/authz HTTP behavior, prefer `httptest` and
`internal/testutils` token, user, ACL, and crypto helpers.

Keep fixture paths package-relative when the surrounding tests use that style.
Do not commit generated coverage, report, binary, temp, or regenerated UI
artifacts unless the user asked for that workflow.

## Style

Run `gofmt` on edited Go files. Keep imports grouped consistently with nearby
code and remove stale commented imports.

Include the repository Apache license header on new Go files. Keep exported
comments useful and sentence-like; avoid comments that only restate the
identifier. Add comments for security-sensitive behavior, non-obvious config
normalization, parser grammar, or concurrency decisions.

Keep names idiomatic and aligned with AuthCrunch vocabulary: portal,
gatekeeper, identity store, identity provider, SSO provider, registry,
keystore, token validator, authenticator, realm, role, and access list. Prefer
clear package-local constants for defaults, directive keywords, cookie/header
names, provider kinds, and repeated status values.

## Imports

Group imports in this order when the language supports explicit import groups:

1. Standard library imports
2. Third-party imports
3. Local package imports

Let `gofmt` organize imports and keep blank lines between standard library,
third-party, and local module imports.

Use side-effect imports only for registration or bootstrapping and include a
short comment when the reason is not obvious.
