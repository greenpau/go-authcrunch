---
name: coding-directives
description: go-authcrunch repository coding standards and implementation directives for Go library, CLI, authentication, authorization, identity store/provider, SSO, KMS, registry, messaging, translation, embedded UI, and test code. Use when creating, modifying, or reviewing repository code; designing configuration and its required dedicated parser package; choosing package boundaries, constructors, validation, errors, logging, serialization tags, security handling, or tests; or deciding how a feature fits existing AuthCrunch packages.
---

# Coding Directives

## Overview

Apply these directives when editing or reviewing go-authcrunch code. Prefer
small, package-local changes that preserve AuthCrunch's existing runtime shape:
top-level `authcrunch.Config` and `Server` wire package-owned configs,
constructors, validators, providers, stores, portals, gatekeepers, registries,
and crypto key stores.

Use the repo-local `testing-and-ci` skill for every Go code change and when
choosing, adding, or running tests. Use `scripts-and-automation` for Makefile
targets, generated assets, dependency commands, and release/version workflows. Use
`refresh-token-implementation` and its identity/transport owners when changing
portal refresh behavior; use `release-and-versioning` for version invariants.
Use `authentication-portal-themes` for custom portal templates, branding assets,
and their UI configuration and template contracts.
Use [authentication-portal-cookies](../authentication-portal-cookies/SKILL.md)
for shared cookie directives, prefix/name configuration, and consumer behavior.
Use [oauth-identity-provider](../oauth-identity-provider/SKILL.md) for upstream
OAuth directive parsers and shared configuration adapters, OAuth/OIDC token
trust, and key ingestion and refresh.
Use [authentication-portal-jwks](../authentication-portal-jwks/SKILL.md) for
portal public signing-key discovery, reusable admin API directive configuration,
opt-in private-key export, issuer selection, and JWK serialization.
Use [local-password-authentication](../local-password-authentication/SKILL.md)
for local-store password verification and bcrypt work equalization.
Use [identity-public-keys](../identity-public-keys/SKILL.md) for user-owned public
key parsing, profile registration, persisted formats, and OpenPGP dependencies.
Use [authentication-portal-oidc](../authentication-portal-oidc/SKILL.md) for the
portal acting as a downstream OpenID Provider, including client registration,
authorization grants, consent, dedicated keys, and conformance.
Use [local-identity-database](../local-identity-database/SKILL.md) for durable
identity transactions, [authentication-portal-profile](../authentication-portal-profile/SKILL.md)
for self-service credential operations, [authentication-portal-mfa](../authentication-portal-mfa/SKILL.md)
for factor checkpoints/enrollment, and [saml-identity-provider](../saml-identity-provider/SKILL.md)
for upstream SAML trust and browser binding.
Use [authentication-portal-challenges](../authentication-portal-challenges/SKILL.md)
for challenge selection/parsers, registered-method inventory and verified AMR.
Use `authentication-client` for reusable portal login clients and CLI credential
handling. Use `authdbctl` for CLI commands, terminal behavior, and executable E2E
tests. Use [authdb](../authdb/SKILL.md) for the standalone HTTP server, listener
configuration/parser, portal routing, TLS, and process lifecycle.

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

## Design

Use cohesive structs with methods for stateful runtime concepts such as
`Server`, `Portal`, `Gatekeeper`, `IdentityStore`, `IdentityProvider`,
validators, caches, registries, stores, and CLI wrappers.

Keep interfaces small and consumer-facing at dispatch or boundary packages.
Follow existing names and method shapes before inventing new generic
abstractions.

Use package helpers for stateless parsing, formatting, matching, and validation
logic. Prefer existing helpers in `pkg/util`, `pkg/util/cfg`,
`internal/tests`, and `internal/testutils` before adding new ones.

Avoid global mutable state outside package constants, defaults, registries, and
CLI initialization patterns that already exist. Avoid broad refactors while
fixing localized behavior.

Use object-oriented design where it is natural. Translate object-oriented
intent into focused structs with methods, small interfaces at package
boundaries, and package organization that models ownership.

Use utility functions only when they are stateless, narrowly scoped, and do not
naturally belong to a type.

Prefer object-oriented design for business rules and data processing.
Encapsulate related data and behavior within structs with methods. Favor
composition and define small consumer-owned interfaces.

Avoid functional pipelines that obscure state transitions, error handling, or
the lifecycle of an operation.

## Structure

Keep structs focused on a single responsibility. Avoid large types that perform
unrelated tasks. When a type grows beyond a clear responsibility, refactor
functionality into supporting structs or packages.

Export only the types, fields, methods, and functions needed outside the
package. Keep implementation details unexported.

For exported structs intended for external or persisted data, keep serialization
tags consistent across `json`, `xml`, and `yaml`.

Keep methods small and focused. A method should perform one logical operation.
Extract complex logic into private methods or unexported helpers when it
improves readability and maintainability.

## Constants

Avoid hard-coded values. Define reusable constants in `const` groups.

Use `const` for stable values and `var` only when a value must be computed or
mutated. Keep configuration keys, route names, tag names, and well-known status
values named.



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

Name directive constructors `New<Domain><Subject>ConfigFromDirectives`.
Include the complete domain and subject, even when the package path supplies
that context: use `NewTokenRefreshConfigFromDirectives` for token refresh,
`NewAdminAPIConfigFromDirectives` for admin API settings, and
`NewOIDCClientConfigFromDirectives` for OIDC clients. Preserve Go initialisms
such as `API` and `OIDC`. Apply the same name to declarations, public comments,
callers, unit tests, executable examples, and owning skill references whenever
changing the API or extracting it into a package.

Keep argument encoding in `pkg/util/cfg` and use `cfgutil.DecodeArgs` for encoded
statements. Keep semantic validation, defaults, and provisioning in the owning
configuration API; the parser calls that API rather than duplicating its rules.
Return the owning feature's typed configuration and an error without a partial
result. In shared packages, use a dedicated feature type such as
`authn.AdminAPIConfig`, rather than returning an aggregate containing unrelated
settings. Reuse that model across typed and directive configuration; preserve
established aggregate serialization through a typed application method when
needed, as `PortalConfig.ConfigureAdminAPI` does for the existing `APIConfig`.
Document credential generation or other intentional provisioning behavior.

Keep dependencies acyclic: parser packages may import their domain's public
configuration API, while the runtime does not import a parser that depends on it.
If both layers require shared types, give those types a lower-level owner rather
than duplicating models. When extracting a parser, move its implementation and
unit tests together, update consumers and examples, and identify changed import
paths and entry points. Do not leave the parsing implementation behind a wrapper
in the runtime package.

Preserve unsupported-field checks in shared config dispatchers so malformed
config fails early instead of being silently ignored. Use the external-package
unit tests and consumer E2E requirements in `testing-and-ci` for every new or
changed configuration parser.

### Cookie Configuration

Use `pkg/authn/cookie.Config` and `cookie.Factory` as the owners of portal cookie
names. Honor `CookieNamePrefix`, the `AUTHP_<SUFFIX>` defaults, and explicit name
overrides. New cookie roles belong in that package's constants, configuration,
defaults, parser, and collision checks. Public cookie-name constants are suffixes;
use initialized config/factory fields for complete names. After initialization,
change prefixes with `SetCookieNamePrefix`, not a raw prefix-field assignment.
The [cookie owner](../authentication-portal-cookies/SKILL.md) defines ordering,
directive application, and consumer compatibility. Feature-specific naming
aliases must resolve to the shared setting before factory construction;
runtime reads, writes, response
metadata, and deletion all use the factory's effective name.

Do not generate separate hashed cookie names or require `__Host-`/`__Secure-`
namespaces for a feature. Those prefixes may be explicitly configured and must
retain their attribute validation. Ordinary examples and fixtures use portal
defaults or explicit conventional names; prefix-specific cases test compatibility.
Keep Secure, HttpOnly, SameSite, lifetime, and domain/path requirements explicit
and independent of naming. Issuance and deletion must match name, domain, and
path, including cleanup of a legacy cookie at a different path. Verify actual
cookie-jar login, rotation, and logout behavior in consumer E2E tests.

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
and directories, such as `0600` for token files and `0700` for private
directories.

## HTTP And Runtime Flow

Use `context.Context` as the first parameter when work participates in request
flow, ACL evaluation, cancellation, or potentially blocking operations. For
HTTP behavior, use `httptest` and package-level helpers rather than live
services.

Keep request parsing, authentication, authorization, and response writing close
to the handler or runtime object that owns the flow. Preserve existing cache,
cookie, sandbox, token source, and redirect semantics unless the task
explicitly changes them.

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
