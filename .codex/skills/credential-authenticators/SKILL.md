---
name: credential-authenticators
description: Maintain injected credential authenticators, method-isolated caching, request-context propagation, and the pure-Go SQLite API-key plugin. Excludes interactive portal password authentication and identity-store provisioning.
---

# Credential Authenticators

`pkg/authproxy.Authenticator` is the legacy Basic/API-key boundary. Configure the
policy's realm/method/portal bindings, attach instances with
`Gatekeeper.AddAuthenticators`, then require `HasAuthProxies()` success before
serving. Attachment is construction-time only; hosts drain users and close their
own backend handles. No root factory or automatic plugin loader is installed.

Use `ContextAuthenticator` to receive the protected request context in
`BasicAuthContext`/`APIKeyAuthContext`. The validator falls back to legacy methods
when absent, and checks cancellation before and after either call. This cannot
interrupt work inside a legacy method. Configured backend timeouts still apply.

`FreshAuthenticator.RequireFreshAuthentication()` is a stable lifetime
capability. True bypasses credential cache reads and writes, including the
validator's second payload lookup and explicit `CacheUser` calls. The runtime
sets server-only cache flags; claims cannot enable or disable this policy.
Ordinary cacheable authenticators preserve their existing behavior. Cache keys
separate payload class, Basic/API-key method, source address, realm, and a SHA-256
secret digest with unambiguous field boundaries. Do not cache reusable plaintext.

## SQLite API keys

`plugins/credential-authenticators/sqlite` implements API keys only; Basic always
rejects and clears stale response data. Password accounts belong to identity
stores. Import its public parser and call
`NewSQLiteCredentialsConfigFromDirectives([]string)` with `name`, `path`, `realm`,
and optional `timeout`, each exactly once with one value. Name/realm are required;
path is absolute; timeout defaults to 1s and accepts 1ms through 30s. Parsing is
pure. `sqlite.New(ctx, config)` snapshots validated settings.

Trusted provisioning calls `Issue(ctx, subject, email, roles, expires)` to obtain
a generated 256-bit base64url key after commit. No caller-selected weak key or
plaintext password is accepted. Only the SHA-256 digest is stored. Subject and
roles are bounded; email must be a bare address; roles contain 1–32 identifiers;
expiry is a future Unix second within 30 days. Issuance prunes expired entries and
limits the database to 10,000 live keys. `Revoke(ctx,key)` is idempotent and
realm-bound. Lost/uncertain issuance results must not be blindly retried.

Each authentication reads current database state; revocation or expiry becomes
effective at the next lookup. Already authorized requests are not canceled.
Plain payload claims include subject, email, roles, realm origin, `amr=api_key`,
and bounded timestamps. The gatekeeper still evaluates its ACL. Incorrect,
missing, revoked, expired, and wrong-realm keys produce generic denial and no
claims. Database failures return no fallback identity. API keys are bearer
credentials: hosts require TLS, safe header logging, and request admission limits.

`GetConfig` exposes only name/kind/realm identifiers. `Close` belongs to the host.
Read [private SQLite backends](../plugin-development/references/sqlite-backends.md)
for pure-Go, local POSIX, private-file, schema, transaction, and uncertain-commit
contracts. This plugin owns a distinct database application and cannot share a
file with other category schemas. Multiple instances may share the same database
and realm; different realms are isolated even in one credential database.

## Validation

Units prove digest-only storage, malformed input rejection, realm isolation,
expiry, revocation, concurrency, cancellation and reopening. The public consumer
fixture uses the parser, a serialized config, two real database handles, TLS,
`AddAuthenticators`, and ACL enforcement. It proves immediate revocation and
closed-backend rejection after successful requests; repeat it externally with
`internal/tests.RunExternalModule`. The core regression
`TestE2ECredentialCacheSeparatesMethods` first fills a Basic cache and rejects the
identical presented bytes as an API key. Context and no-cache capability tests
also cover validator callers that explicitly invoke `CacheUser`.

```
make test TEST_DIR='./plugins/credential-authenticators/sqlite/... ./pkg/authproxy ./pkg/authz/... ./pkg/requests ./pkg/user ./internal/tag'
```

Run plugin units/parser/public E2E with CGO_ENABLED=0 separately from the
race-enabled external-module driver. Never infer production CGO dependencies
from the race detector's toolchain requirement.
