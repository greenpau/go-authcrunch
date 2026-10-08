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

The repository also includes the standalone `authdb` HTTP server in `cmd/authdb`,
the `authdbctl` management CLI in `cmd/authdbctl`,
embedded portal/profile UI assets under `pkg/authn/ui`, shared identity and user
data models under `pkg/identity`, user registration under `pkg/registry`,
messaging providers under `pkg/messaging`, i18n helpers under `pkg/translate`,
and test fixtures under `testdata`. Canonical HTTP API YAML and the Scalar
reference live in `assets/openapi/`; `cmd/openapi` and `internal/openapi` own
validation, generated JSON and the local reference server.

## Scripts and Automation

Use [scripts-and-automation](.codex/skills/scripts-and-automation/SKILL.md) to
choose, run, or document Makefile targets, repository scripts, build/test/report
workflows, generated artifacts, dependency automation, or release/version
procedures.

HTTP-facing changes must evaluate the YAML contract in the same change; the
scripts router delegates this workflow to `openapi-generation`.

`make test` uses pinned `tested`; `make ci-check` is the complete quality gate.
`make release`, `make minor-release`, `make fast-release`, and
`make fast-minor-release` publish commits and tags and are only run when an
actual release is requested.

## Coding Directives

Use [coding-directives](.codex/skills/coding-directives/SKILL.md) to create,
modify, or review repository code; choose package boundaries, config and
validation patterns, constructors, errors, logging, serialization tags, security
handling, or test structure; or decide how a new feature fits existing AuthCrunch
packages. Follow its routes to the implementation skill that owns the feature.

Every configuration surface must have a dedicated, reusable `parser` package.
Follow the `coding-directives` configuration parser contract for package shape,
typed constructors, validation ownership, and modular integration, with unit
and consumer E2E coverage from `testing-and-ci`.

## Testing and CI

Use [testing-and-ci](.codex/skills/testing-and-ci/SKILL.md) to enforce
corresponding tests and required E2E coverage for every Go code change, choose
or run tests, add or update coverage, interpret CI failures, reproduce GitHub
Actions locally, or document validation for this repository.

### Localhost Test Listeners

Go tests that use `httptest.NewServer`, `httptest.NewTLSServer`, or local
`net.Listen` loopback sockets are expected and allowed for repository
validation. If the Codex sandbox blocks localhost binding, rerun the exact
focused or full `go test` command with `sandbox_permissions: require_escalated`
and explain that the test binds a localhost socket.

## Threat Hunting

Use [threat-hunting](.codex/skills/threat-hunting/SKILL.md) to audit security
issues, triage vulnerability reports, model authentication or authorization
threats, review bypass/ACL/path matching, redirects, token sources, cookies,
sessions, provider trust boundaries, input parsing, concurrency, secret logging,
or dependency vulnerabilities, and document findings and remediation plans.

## Source Code Management

Use [source-code-management](.codex/skills/source-code-management/SKILL.md) to
create or review commit messages and prepare their required message files.

## Repository Knowledge

This repository has no `docs/` directory. Keep durable implementation,
configuration, integration, and operational guidance in the narrow owning
`.codex/skills` skill or its linked references. Keep this file to routing and
cross-cutting invariants, and README to onboarding and common commands.
Use [skill-authoring](.codex/skills/skill-authoring/SKILL.md) to create, revise,
route, or validate repository skills with the default `skill-creator` workflow.
