# Commit Change Indicators

This repository uses change indicators as package and subsystem labels, plus a
small set of maintenance labels. Prefer the most specific AuthCrunch package,
CLI, provider, store, or runtime surface when the change is clearly anchored in
one component. Use a maintenance label when the change is repository plumbing,
documentation, tests, release work, or a deliberately cross-cutting fix.

Selection rules:

- Use exactly one indicator. Do not combine indicators or add parenthesized
  scopes.
- Prefer names that match repository packages, CLI names, or externally visible
  AuthCrunch concepts. For example, use `authn`, `authz`, `oauth`, `ldap`,
  `kms`, or `authdbctl` when a change is anchored there.
- Use `config` only for top-level `authcrunch.Config`, `Server` wiring,
  cross-surface validation, reload plumbing, or shared config exposure. For
  package-local config parsing, use the package indicator.
- Use `authn` for authentication portal behavior and portal API or HTTP
  handlers. Use `ui` for embedded portal/profile UI assets, templates, static
  assets, icons, profile UI bundles, and UI-specific serving behavior. Use
  `cookie` for cookie-specific issuing, reading, deletion, domain, and name
  config, even when the code lives under `pkg/authn/cookie`.
- Use `authz` for authorization gatekeepers and policies. Use `acl` when the
  change is really the shared ACL engine, and `authproxy` when it is
  remote/basic/API-key auth proxy configuration or authenticators.
- Use `idp` and `ids` for shared identity provider or identity store config,
  interfaces, and dispatch. Use `oauth`, `saml`, `ldap`, or `local` when the
  change is specific to that provider or store implementation.
- Use `identity` for identity and user data models, local user database
  records, roles, passwords, MFA tokens, API keys, WebAuthn/U2F/GPG/SSH keys,
  lockouts, QR codes, and `pkg/user`.
- Use `registry` for user registration providers, local registry behavior, and
  domain restriction rules.
- Use `kms` for crypto keys, keystores, token encryption/decryption, and crypto
  config parsing. Use `system` for system API protocol messages, request
  parsing, generated keys, and system API auth messages.
- Use `redirects`, `authchal`, `credentials`, `messaging`, `translate`, `waf`,
  `apiauth`, `errors`, `requests`, `shared`, `tagging`, or `util` when the
  primary change is in that package or its testdata.
- Use `authdb` for the standalone server under `cmd/authdb` and its HTTP-host
  behavior. Use `authdbctl` for the CLI under `cmd/authdbctl`, including its README,
  config, commands, output, and command behavior. Use `build` only when build
  output or Makefile build behavior changes.
- Use `breakfix` for a reported break-fix issue, regression, panic, or shipped
  behavior that is visibly broken for users. Use `fix` for narrower correctness
  fixes that are not tied to known user breakage.
- Use `security` for vulnerability fixes, hardening, dependency-audit work, or
  disclosure-policy changes. If a security fix is tightly scoped to one runtime
  surface, prefer the surface only when the issue is being handled as ordinary
  correctness rather than as a vulnerability.
- Use `tests`, not `unittest`, for Go tests, fixtures, golden data, `testdata`,
  and coverage-only changes. If tests accompany a product change, choose the
  product indicator instead.
- Use `skills` for AI agent skills, skill metadata, or agent-facing repository
  instructions. Prefer it over `docs` or `ops` when the primary purpose is
  helping AI agents work with this repository.
- Use `ops` for dependency, Go toolchain, generated license/version metadata,
  release, or repository maintenance changes. Use `github` for GitHub Actions,
  issue templates, CLA workflow/assets, Funding metadata, or other GitHub
  repository metadata.
- Automated patch and minor releases use `ops: released v<VERSION>`.
  [release-and-versioning](../../release-and-versioning/SKILL.md) owns publication.
  Hand-written release workflow changes also use `ops`.
- Use `various` only when a commit intentionally spans unrelated surfaces and no
  more specific indicator is honest.
- Normalize older repository labels when creating new messages: use
  `feat` for `feature`, `fix` or `breakfix` for `bug`/`bugfix`, `authdbctl`
  for `cmd` changes to the CLI, `github` for `cla` bot/workflow metadata, and a
  specific package indicator instead of `auth`, `api`, `hosting`, `misc`, or
  `chore`.
- Use colon form for new dependency bumps, such as
  `ops: upgrade golang.org/x/crypto to v0.48.0`, even though older history has
  subjects without a change indicator.

Use one of these package or product-surface indicators:

- `acl`: shared ACL conditions, path matching, rule parsing, and rule
  evaluation
- `apiauth`: API authentication request/response envelope types
- `authchal`: authentication challenge rule parsing and evaluation
- `authdb`: standalone AuthCrunch server, HTTP listener, TLS, routing, and shutdown
- `authdbctl`: AuthDB management CLI, CLI config, commands, output, and CLI
  docs
- `authn`: authentication portals, login/logout/recovery/register/profile/admin
  API handlers, MFA/WebAuthn/TOTP/GPG/SSH/API-key portal operations, sessions,
  portal config, and portal runtime behavior
- `authproxy`: auth proxy config, remote authenticators, basic auth proxying,
  and API-key auth proxying
- `authz`: authorization gatekeepers, policies, bypasses, token validators,
  header injection, auth redirects, and authorization runtime behavior
- `config`: top-level AuthCrunch config, server wiring, validation, and shared
  config/reload plumbing
- `cookie`: authentication cookie factories, names, domains, reading, issuing,
  and deletion
- `credentials`: credential config, generic credentials, and credential provider
  integration points
- `errors`: typed error catalog and error wrapping helpers
- `identity`: identity/user models, user databases, roles, passwords, MFA
  tokens, API/GPG/SSH/WebAuthn keys, locations, organizations, lockouts, and QR
  helpers
- `idp`: shared identity provider config, provider interfaces, and provider
  dispatch
- `ids`: shared identity store config, store interfaces, and store dispatch
- `kms`: crypto key config, keystores, token operators, parsers, and encryption
- `ldap`: LDAP identity store config, authentication, DN parsing, and group
  mapping
- `local`: local identity store config, file-backed store behavior, and local
  user authentication
- `messaging`: email/file messaging providers, send inputs, templates, and
  delivery behavior
- `oauth`: OAuth/OIDC providers, provider drivers, state, PKCE, claims, JWKS,
  user info, token validation, and provider-specific logout
- `redirects`: trusted redirect URI parsing, matching, and validation
- `registry`: user registration providers, local registry behavior, cache, and
  domain restrictions
- `requests`: request helper models shared by authn/authz flows
- `saml`: SAML providers, metadata, certificates, ACS URLs, and SAML
  authentication
- `shared`: shared in-memory buffer behavior
- `sso`: single sign-on provider config, metadata, requests, and provider
  behavior
- `system`: system API message types, generated keys, encryption, parsers, and
  basic/API-key system auth messages
- `tagging`: public or internal tag helper behavior
- `translate`: i18n framework, message catalog, template translation,
  languages, and formatters
- `ui`: embedded portal/profile UI templates, CSS, JavaScript, images, fonts,
  icons, static files, and UI serving
- `util`: shared utility helpers, config parsing helpers, validators,
  sanitizers, redirect helpers, request IDs, logging helpers, and
  file/addr/data helpers
- `waf`: malformed input checks and WAF helpers

Use one of these maintenance indicators:

- `breakfix`: reported regression, panic, or user-visible breakage fix
- `fix`: correctness fix without a known production breakage
- `feat`: user-facing capability that does not fit a more specific product
  surface indicator
- `docs`: documentation-only changes
- `tests`: test additions, fixture updates, or coverage improvements
- `refactor`: behavior-preserving code restructuring
- `skills`: AI agent skills, skill metadata, `AGENTS.md`, or agent-facing
  repository instructions
- `ops`: dependency, Go, toolchain, release, version-reference, generated
  license/version metadata, or repository maintenance changes
- `build`: Makefile, build output, packaging, or local build behavior
- `github`: GitHub Actions, issue templates, CLA workflow, or repository GitHub
  metadata
- `security`: vulnerability, dependency audit, hardening, or disclosure-policy
  changes
- `various`: intentionally mixed changes that do not fit one indicator
