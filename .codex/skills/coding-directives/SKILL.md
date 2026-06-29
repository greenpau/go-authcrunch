---
name: coding-directives
description: go-authcrunch repository coding standards and implementation directives for Go library, CLI, authentication, authorization, identity store/provider, SSO, KMS, registry, messaging, translation, embedded UI, and test code. Use when creating, modifying, or reviewing repository code; choosing package boundaries, config and validation patterns, constructors, errors, logging, serialization tags, security handling, or test structure; or deciding how a new feature should fit existing AuthCrunch packages.
---

# Coding Directives

## Overview

Apply these directives when editing or reviewing go-authcrunch code. Prefer
small, package-local changes that preserve AuthCrunch's existing runtime shape:
top-level `authcrunch.Config` and `Server` wire package-owned configs,
constructors, validators, providers, stores, portals, gatekeepers, registries,
and crypto key stores.

Use the repo-local `testing-and-ci` skill when choosing, adding, or running
tests. Use `scripts-and-automation` for Makefile targets, generated assets,
dependency commands, and release/version workflows.

## Package Boundaries

Put behavior in the package that owns the AuthCrunch surface:

- `pkg/authn`: authentication portals, portal HTTP/API handlers, sessions,
  cookies, MFA/WebAuthn/TOTP/GPG/SSH/API-key profile operations, UI serving,
  and portal-specific config.
- `pkg/authz`: authorization gatekeepers, access policy config, token
  validators, bypass rules, auth redirects, header injection, and auth proxy
  integration.
- `pkg/ids` and `pkg/idp`: shared dispatch config and interfaces for identity
  stores and identity providers. Put provider-specific behavior in
  `pkg/ids/local`, `pkg/ids/ldap`, `pkg/idp/oauth`, or `pkg/idp/saml`.
- `pkg/sso`, `pkg/kms`, `pkg/registry`, `pkg/messaging`, `pkg/identity`,
  `pkg/user`, `pkg/translate`, and focused utility packages own their own
  parsing, validation, models, and tests.
- `cmd/authdbctl` owns CLI configuration, flags, interactive prompts, request
  wrappers, and command output.

Do not add cross-package shortcuts when an existing dispatcher, interface, or
config object already models the boundary. When adding a provider/store kind,
update the shared config validator, dispatch constructor, concrete package
constructor, and package tests together.

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

## Configuration

Keep external config structs serializable with matching `json`, `xml`, and
`yaml` tags. Use snake_case tag names and `omitempty` unless the surrounding
type deliberately preserves false/zero values.

Treat `Validate` methods as the repository's normalization boundary. Existing
validators commonly fill defaults, compile regexps, parse raw directive
strings, build derived config, and set `validated bool` to avoid repeat work.
Follow that pattern when validation is intentionally mutating.

Keep constructors strict:

- Return `(*Type, error)` or `(Interface, error)` for runtime objects that can
  fail.
- Check required dependencies such as config and `*zap.Logger` before doing
  work.
- Call `Validate` before configuring runtime state.
- Configure package-owned defaults, icons, crypto stores, and raw directives
  close to the config type that owns them.

For raw directive strings, use existing parsers such as `cfgutil.DecodeArgs` or
domain-specific parsers. Preserve unsupported-field checks in shared config
dispatchers so malformed config fails early instead of being silently ignored.

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
private keys, OAuth client secrets, LDAP credentials, and identity data. Never
add logs, errors, test diffs, or command output that expose secret values.

When adding `zap` logs, include the operation, package context, realm/name, and
non-sensitive identifiers. Redact or omit token bodies, password material,
private keys, shared secrets, and full credential structs, even if older code
logs something similar.

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

Add focused table-driven tests beside the package being changed. Use
`github.com/google/go-cmp/cmp` and `internal/tests` helpers such as `Unpack`,
`UnpackDict`, `EvalErrWithLog`, and `EvalObjectsWithLog` when comparing
normalized config or exact errors.

Cover both success normalization and meaningful malformed inputs for config and
parser changes. For cross-package wiring, update top-level `config_test.go` or
`server_test.go`. For authn/authz HTTP behavior, prefer `httptest` and
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
