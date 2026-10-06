---
name: external-authorization
description: Maintain required external authorization decisions, gatekeeper and validator hooks, the HTTP JSON plugin, reusable parsers, and protected-request E2E coverage. Excludes credential authentication and claims enrichment.
---

# External Authorization

## Ownership and integration

`pkg/authz/external` owns the public `Backend.Decide(context.Context, Request)
(*Result, error)` interface, identity/policy binding, bounded request snapshots,
and `Authorizer`. `plugins/external-authorization/httpjson` implements the HTTP
transport. Core production packages must not import the plugin.

An embedding host parses both configurations, constructs `httpjson.New(config,
client)`, constructs `external.New(binding, backend)`, and calls
`Gatekeeper.SetExternalAuthorizer` or `TokenValidator.SetExternalAuthorizer`
before serving. Nil/unconstructed gatekeepers and closed validators reject
attachment without panic. An invalid/nil attachment cannot disable enforcement.
Hosts own backend lifetime and must drain requests before replacement or disposal.
There is no root JSON plugin loader, process-global registry, or automatic host
module registration. The runtime hook is opt-in; omitted attachment preserves
existing authorization behavior.

Local credential verification, source/path restrictions, enrichment and every
local ACL check must pass before consulting the backend. An external allow is
an additional requirement and cannot override local denial. Enforcement covers
fresh JWTs, authentication-cache hits, Basic/API-key authentication and
`AuthorizeUser`, including OAuth callback admission and existing OAuth sessions.
`AuthorizeUser` and `Authorizer.Authorize` require an already authenticated
identity; neither authenticates arbitrary caller claims.

Explicit bypass routes retain their existing behavior and do not invoke the
backend. OAuth protocol endpoints retain their separate admission rules. Denial,
transport/protocol failure and cancellation map to `ErrAccessNotAllowed` through
the validator, using the existing forbidden response (normally HTTP 403, or a
configured forbidden redirect), without disclosing service details or clearing
valid credentials merely because the service denied access.

## Policy configuration

`external.Config` has policy, version, issuer, realm, subject_claim, tenant_claim,
attributes and timeout fields. The dedicated parser is
`pkg/authz/external/parser.NewExternalAuthorizationConfigFromDirectives`.
It accepts a complete encoded block body without braces/header:

```text
policy reports
version v1
issuer https://login.example.test/auth/login
realm local
subject claim sub
tenant claim tenant
attribute roles
attribute department
timeout 500ms
```

Policy, version, issuer and realm are required. Subject claim defaults to `sub`.
Tenant claim is optional; when configured, the authenticated value must be a
nonempty string and is included in the decision identity. The service owns
cross-tenant policy evaluation. Subject and tenant bindings must differ.
Issuer/realm are exact trusted configuration matches against normalized identity.
They are opaque values, not URLs to normalize or discover. Portal direct Basic
and API-key tokens use issuer `authp`; portal login uses its login URL; direct
OAuth sessions use the gatekeeper origin and provider realm.

Attributes are unique, explicitly selected, literal top-level claim names;
omitted configuration sends none. Missing selected attributes remain absent;
JSON null remains null. Only the original authenticated identity supplies them.
Request-time enrichment remains ACL-only and cannot replace external identity or
attributes. Hosts must select authoritative claims; a signed user-editable value
is not inherently suitable for granting access.

Binding strings/claim names are nonempty UTF-8, at most 1024 bytes, without
control characters or surrounding whitespace. At most 16 attributes are selected.
`Request.Snapshot` reuses the bounded JSON copy contract from claims enrichment
and bounds the complete serialized request to 64 KiB. Precise `json.Number`
values survive copying. Unsupported Go values, cycles and excessive depth/size
fail before network I/O. No request body, query, host, incoming header, cookie,
or bearer credential is forwarded implicitly.

Timeout defaults to 1s, allowed range 1ms–30s. The effective total deadline is
also bounded by the caller context and any nonzero authenticated expiration.
Check cancellation/deadline after the backend returns; a late allow cannot grant
access. Callers own lifetime checks for non-JWT identities without expiration.
Backends must honor contexts; arbitrary in-process code cannot be forcibly stopped.

Settings occur once except repeated, unique `attribute` entries. Both parsers use
`cfgutil.DecodeArgs`; hosts should use `cfgutil.EncodeArgs` for values with spaces.
Unknown settings, duplicate settings, wrong arity, empty values, raw CR/LF/NUL,
and invalid UTF-8 fail without echoing values. Parsing performs no I/O. Typed
constructors validate and snapshot their inputs; both configs survive JSON reload.

## HTTP plugin and wire protocol

`httpjson.Config` contains endpoint and timeout. Its parser is
`plugins/external-authorization/httpjson/parser.NewHTTPJSONAuthorizerConfigFromDirectives`:

```text
endpoint https://policy.example.test/decide
timeout 1s
```

Endpoint is required, at most 4096 UTF-8 bytes. HTTPS is required except for HTTP
on literal loopback IPs. Reject credentials, query strings and fragments in the
endpoint; explicit ports must be within 1–65535. Timeout has the same
default/range as the core binding and limits each
standalone backend call; the core deadline bounds all calls for one request.
A nil client creates an owned transport with system TLS roots and no ambient
proxy. An injected client is copied; its transport can supply private roots,
mTLS or service authentication. The host owns that transport and its trust
configuration. Cookies and redirects are disabled on the copy. A shorter client
timeout is retained. Never forward end-user credentials as service credentials.

The backend posts `Content-Type: application/json` and `Accept: application/json`.
For example:

```json
{
  "policy": "reports",
  "version": "v1",
  "identity": {
    "issuer": "https://login.example.test/auth/login",
    "realm": "local",
    "subject": "alice",
    "tenant": "north"
  },
  "action": "GET",
  "resource": "/reports",
  "attributes": {"roles": ["viewer"]}
}
```

Resource is a path and action is the current HTTP method. Core evaluates every
path interpretation returned by the existing request-path policy, even when
local method/path checks are disabled. Every interpretation needs an allow under
one total deadline. Encoded separators and invalid/ambiguous paths fail closed.
Do not replace this with one cleaned path, client claim or header override.
Preserve valid path data such as a trailing encoded space.

A successful protocol response is HTTP 200, `application/json`, and exactly one
object with these three case-sensitive string fields:

```json
{"decision":"allow","policy":"reports","version":"v1"}
```

Use `deny` for an explicit rejection. A nil error from `Backend.Decide` means a
valid response, including deny; `Authorizer.Authorize` returns nil only after
every decision allows. Echo the requested policy/version. Empty,
missing, unknown, duplicate or incorrectly typed fields, extra JSON values,
invalid UTF-8, mismatched binding, unsupported obligations and other status/media
types fail closed. Redirects are never followed. Bound both declared and streamed
response bodies to 4096 bytes, including decompressed bodies. Oversize responses
return `httpjson.ErrResponseTooLarge`; other backend failures expose no endpoint,
remote body or private transport diagnostic. `ErrDenied` covers rejected identity
or request bindings as well as explicit backend denial. Core distinguishes it from
`ErrUnavailable` for direct callers, while gatekeepers deny both.

There is no application retry or authorization-decision cache. Each selected
protected request consults the service again, including authentication-cache hits.
Services should evaluate decisions without side effects. `Backend.Close` rejects
new work and closes idle connections only on owned transports. It is idempotent;
callers drain requests and close injected transports themselves.

## Acceptance and validation

[Core tests](../../../pkg/authz/external/authorizer_test.go) cover binding,
request ownership, precise JSON values, denial by later path interpretations,
one shared deadline across all interpretations, cancellation, configuration and
concurrent use. External parser packages include
executable constructor examples. [HTTP tests](../../../plugins/external-authorization/httpjson/backend_test.go)
cover protocol rejection, the exact response-size boundary, compressed responses
whose decoded bodies exceed the limit, redirects, cookies, outages, timeout,
and cancellation while reading a stalled response body.

The [portable TLS journey](../../../plugins/external-authorization/httpjson/consumer_e2e_test.go)
uses real local password login, signed bearer tokens, Basic/API-key authentication,
an actual TLS decision endpoint and an observed downstream handler. It exercises
fresh/cached credentials, policy changes, local/remote denial precedence, identity
domain isolation, method/path changes, explicit bypass, malformed results,
endpoint failures, in-flight cancellation, rejected configuration replacement,
and close. It also rejects oversized compressed responses and a cleaned path
after the original path was allowed. The external-module driver copies
that public workflow into an isolated temporary module with network resolution
disabled. Keep both in the default suite.

[Guardian coverage](../../../pkg/authz/validator/external_authorization_e2e_test.go)
checks all eight guardian combinations, signed/cached credentials and authenticated
users. It composes both hooks: local ACLs consume current enrichment, the remote
service receives original signed claims, and local enrichment rejection prevents
the remote call. [OAuth coverage](../../../server_external_authorization_oauth_e2e_test.go)
uses real TLS OAuth exchanges and session cookies, checking denial at callback
admission and on existing sessions after decisions change.

```sh
make test TEST_DIR='./pkg/authz/... ./plugins/external-authorization/httpjson/... . ./internal/tag' COVERAGE_DIR='.coverage/external-authorization'
make ci-check
```

Register new exported structs in `internal/tag`, preserve CI plugin discovery,
and keep diagnostics and validation evidence under the repository testing rules.
