# Repository Guidelines

## Project Summary

go-authcrunch is a Go library for AuthCrunch Authentication, Authorization, and
Accounting (AAA) security functions. It provides the core runtime used for
authentication portals, authorization gatekeepers, identity stores, identity
providers, single sign-on providers, user registration, messaging, credentials,
and cryptographic key handling.

The top-level `authcrunch.Config` and `Server` wire together the repository's
major packages. Authentication portal behavior lives mostly under `pkg/authn`,
authorization policy and gatekeeper behavior under `pkg/authz`, identity store
dispatch under `pkg/ids`, identity provider dispatch under `pkg/idp`, local and
LDAP stores under `pkg/ids/local` and `pkg/ids/ldap`, OAuth and SAML providers
under `pkg/idp/oauth` and `pkg/idp/saml`, and crypto key management under
`pkg/kms`.

The repository also includes the `authdbctl` management CLI in `cmd/authdbctl`,
embedded portal/profile UI assets under `pkg/authn/ui`, shared identity and user
data models under `pkg/identity`, user registration under `pkg/registry`,
messaging providers under `pkg/messaging`, i18n helpers under `pkg/translate`,
and test fixtures under `testdata`.

## Scripts and Automation

Use the repo-local `scripts-and-automation` skill when choosing, running, or
documenting Makefile targets, repository scripts, build/test/report workflows,
generated artifacts, dependency automation, or release/version procedures.

## Coding Directives

Use the repo-local `coding-directives` skill when creating, modifying, or
reviewing repository code; choosing package boundaries, config and validation
patterns, constructors, errors, logging, serialization tags, security handling,
or test structure; or deciding how a new feature should fit existing
AuthCrunch packages.

## Testing and CI

Use the repo-local `testing-and-ci` skill for every Go code change to enforce
its corresponding tests and required E2E coverage, and when choosing or running
tests, adding or updating test coverage, interpreting CI failures, reproducing
GitHub Actions locally, or documenting validation for this repository.

### Localhost Test Listeners

Go tests that use `httptest.NewServer`, `httptest.NewTLSServer`, or local
`net.Listen` loopback sockets are expected and allowed for repository
validation. If the Codex sandbox blocks localhost binding, rerun the exact
focused or full `go test` command with `sandbox_permissions: require_escalated`
and explain that the test binds a localhost socket.

## Threat Hunting

Use the repo-local `threat-hunting` skill when auditing the repository for
security issues, triaging vulnerability reports, threat-modeling authentication
or authorization flows, reviewing bypass/ACL/path matching, redirects, token
sources, cookies, sessions, provider trust boundaries, input parsing,
concurrency, secret logging, dependency vulnerabilities, or documenting security
findings and remediation plans.

## Source Code Management

Use the repo-local `source-code-management` skill for commit message rules and
for the workflow used when asked to create a commit message for a change.

## Repository Knowledge

This repository has no `docs/` directory. Keep durable implementation,
configuration, integration, and operational guidance in the narrow owning
`.codex/skills` skill or its linked references. Keep this file to routing and
cross-cutting invariants, and README to onboarding and common commands.
Use `skill-authoring-patterns` with the default `skill-creator` for skill work.

## Refresh Tokens

Use `refresh-token-implementation` for portal refresh configuration, issuance,
rotation, replay, storage, and lifecycle. Use `refresh-token-identity` for login
proof, MFA, sandbox redemption, and credential-version invalidation. Use
`refresh-token-transports` for HTTP/cookies, native transport, browser
coordination, continuation, and logout.

## Authentication Portal Themes

Use `authentication-portal-themes` for custom portal templates, CSS, branding
assets, theme configuration, and compatibility with current portal pages.

## Local Password Authentication

Use `local-password-authentication` for local password creation, imports,
changes, resets, verification, bcrypt work equalization, and regression tests.

## OAuth Identity Providers

Use `oauth-identity-provider` for upstream OAuth/OIDC discovery, JWKS and static
public PEM verification, EdDSA/Ed25519 validation, key refresh, shared provider
configuration dispatch, and real portal OAuth E2E tests.

## Portal Signing-Key Discovery

Use `authentication-portal-jwks` for the portal `/.well-known/jwks.json`
endpoint, public signing-key serialization, issuer selection, and base-path
routing, plus opt-in admin private-key export.

## Authentication Clients

Use `authentication-client` for `pkg/authclient`, JSON portal login consumers,
credential files, and authentication protocol wiring. Use `authdbctl` for
`cmd/authdbctl` commands, configuration, terminal input, and executable E2E tests.
The reusable client uses `/login` without the admin API; database management
commands and their retry policy stay in `cmd/authdbctl`.

## Versioning and Releases

Use `release-and-versioning` for the fixed `1.<minor>.<patch>` namespace,
version synchronization, versioned CI artifacts, and patch/minor releases.
`make test` uses pinned `tested`; `make ci-check` is the complete quality gate.
`make release` and `make minor-release` publish commits and tags and are only
run when an actual release is requested.
