---
name: claims-enrichment
description: Maintain request-time claims enrichment, its public backend and parser APIs, gatekeeper and validator hooks, and the static claims-enrichment plugin. Excludes portal issuance-time transforms and token signing.
---

# Claims Enrichment

## Ownership and integration

`pkg/authz/enrichment` owns the `Backend.Lookup(context.Context, Request)`
interface, `Config`, `Identity`, `Result`, and `New(config, backend)` constructor.
`plugins/claims-enrichment/static` adds configured JSON claims in the root Go
module. Its `New` and `Lookup` APIs require no external service, credential, host
framework, registration side effect, or cleanup. It supplies the same configured
values to each identity accepted by the consumer's binding.

Construct a backend and enricher, then call
`Gatekeeper.SetClaimsEnricher(*enrichment.Enricher)` or
`TokenValidator.SetClaimsEnricher(*enrichment.Enricher)` before serving requests.
A nil attachment fails without changing the active attachment. Closed validators
reject attachment. The host owns backend cleanup; drain requests before replacing
an attachment or closing the backend. Construct a new detached runtime for reload.
There is no global registry or JSON backend loader in root `Config` or `authdb`.

The validator invokes enrichment after authentication and before all eight ACL
request guardians, once per decision even when a path has multiple interpretations.
JWT and credential cache hits and public `AuthorizeUser` evaluations take this
path. Direct OAuth policy sessions use `AuthorizeUser`; its input must still
satisfy this feature's explicit issuer, realm, subject, tenant and audience binding.
An OAuth provider that does not produce those claims cannot use the hook without
a trusted adapter supplying them. Explicit gatekeeper bypass routes remain bypasses.

Enriched claims are only used by the ACL decision. The returned authenticated
user, cache, identity headers, request identity, and original JWT retain their
original claims. Neither initial portal issuance, refresh issuance nor downstream
OIDC issuance runs this hook. Renewed tokens are enriched when subsequently used
on an attached protected route. Do not describe this as token revocation or an
issuance-time enrichment feature.

When composed with [external authorization](../external-authorization/SKILL.md),
the required remote decision also receives the original authenticated claims.
Enrichment can satisfy local ACL conditions but cannot alter remote identity or
attribute input. A local rejection prevents the external call. The validator's
`external_authorization_e2e_test.go` verifies both hooks together across every
guardian, fresh/cached JWTs and already authenticated identities.

## Trust and data contracts

The host selects one source and source-contract version per attachment. The
backend receives only the complete immutable identity tuple (issuer, realm,
subject, tenant), configured audience, fixed `authorization` purpose, and requested
attribute names. It never receives credentials or the full authenticated claim map.
Issuer and realm must exactly match configuration, and the authenticated audience
must contain the selected audience. Subject and tenant come from explicitly named
string claims; no email, username or display-name fallback exists.

The host must ensure `SubjectClaim` is immutable and non-reassignable within that
issuer/realm/tenant. A signature does not establish this property for arbitrary
profile claims. Local portal `sub` is normally a username, so do not choose it as
an immutable directory identifier. The portable fixture binds its single known
account's actual database ID through an operator-owned transform; production
integration must maintain the binding across account recreation.

Only explicitly declared literal custom keys can be returned. Names are nonempty,
at most 256 UTF-8 bytes, without control characters or surrounding whitespace.
Punctuation, case, and URI-shaped names are literal; dots do not traverse objects.
`AttributeConfig.Validate` rejects canonical identity/token claims and aliases,
authentication evidence, known GitHub fields and the `authcrunch_` prefix.
Subject and tenant input claim keys cannot also be outputs.

Plain custom names such as `foo` are additive: any collision with an authenticated
claim denies the decision before lookup, including provider fields unknown to core.
For `enrichment.*` names, the selected backend owns the whole namespace; signed
or cached values there are removed before applying the current response.

There are 1–32 declarations with types `string`, `string_list`, or `json`.
String values are at most 4096 UTF-8 bytes without control characters or surrounding
whitespace (empty is allowed); nonnull string lists contain at most 128 strings.
JSON values support strings, numbers, booleans, null, arrays and objects, including
nested structures. JSON strings preserve whitespace and escaped control characters.
Each JSON attribute is bounded to 16 container levels, 4096 nodes and 64 KiB of
encoded JSON; strings and object keys are at most 4096 UTF-8 bytes, and numeric
literals at most 128 bytes. Cycles, unsupported Go types, invalid UTF-8 and
nonfinite floating-point values fail.
Use decoded `map[string]any`/`[]any` shapes; `[]string` and native numeric scalars
also work. Typed nil maps/slices normalize to JSON null and count as scalar nodes,
including at the nesting limit; nonnil empty maps/slices still count as containers.
`json.Number` preserves large integer precision; callers decoding typed config JSON should use
`json.Decoder.UseNumber` when that precision matters.

Values are literal data, never templates. No claim value assigns normalized roles
or changes authentication evidence. Map string or string-list attributes explicitly
with the existing typed custom [ACL fields](../authorization-policy-acl/SKILL.md).
Other JSON types are preserved in the detached claim map; the current ACL grammar
does not coerce or query numbers, booleans, nulls or nested objects. A referenced
ACL field with the wrong type denies authorization.

Responses echo identity, audience, purpose, source and version exactly. Observed
and expiration timestamps must be present, observation cannot be in the future,
and both age and total validity must fit `MaxAge`. Expiration must be strictly in
the future. An absent attribute supplies no value; JSON null remains a present
value and is distinct from absence. Null and mixed lists are invalid for typed
string-list declarations. Wrong types, undeclared fields, stale validity and source
mismatches fail the complete decision.

Backend errors and malformed results become an access denial before any ACL
allow-stop, without including backend values in errors. There is no fail-open mode
or enrichment cache. Results and caller maps are detached. The response remains
a snapshot: a concurrent backend update after lookup cannot invalidate a decision
already in progress. No remote IO runs inside a local identity database issuance
transaction.

Lookup receives the earliest of the request deadline, configured timeout, and
the authenticated identity's nonzero `exp`. A credential at or past expiration
never reaches the backend; one expiring during lookup denies the decision even
when the backend returns success. Recheck cancellation and the actual deadline
before returning, since timer scheduling can lag CPU-bound work. Identities with
no `exp` may use externally managed lifetimes; their caller still owns that check.
Do not accept late successful results.
Backends must honor deadlines and support concurrent calls. An in-process backend
that ignores context cannot be forcibly interrupted; do not add leaking goroutines
to simulate this guarantee. The enricher owns no workers or backend resources.

## Configuration and parsers

`pkg/authz/enrichment/parser.NewClaimsEnrichmentConfigFromDirectives([]string)`
returns `*enrichment.Config`. It accepts a complete body without header/braces:

```text
source static
version v1
issuer https://issuer.example.test
realm staff
subject claim directory_id
tenant claim tenant_id
audience application
attribute foo string
attribute permissions string list
attribute settings json
timeout 1s
max age 1m
```

Scalar directives occur once; attributes repeat with unique names. All bindings
and at least one attribute are required. Timeout defaults to 1s, is positive,
and is at most 30s. Maximum age defaults to 1m, is positive, and is at most 24h.
`New` snapshots the config before validation; later caller edits have no effect.
Subject and tenant claim keys must differ and cannot depend on enrichment.

`plugins/claims-enrichment/static/parser.NewStaticClaimsEnrichmentConfigFromDirectives`
returns `*static.Config`. Its body contains repeatable declarations:

```text
claim foo bar
claim permissions json ["read","write"]
claim settings json {"enabled":true,"quota":5}
claim optional json null
```

Use `cfgutil.EncodeArgs` to encode each statement. A complete JSON value is one
token; for example, encode `[]string{"claim", "settings", "json", jsonText}`.
The three-token form supplies a literal string. The four-token form requires the
`json` keyword and one complete JSON document of at most 64 KiB; numbers use
`json.Number`. Use the JSON form for empty strings. Duplicate claim names,
unsupported keywords, incorrect arity, malformed/trailing JSON, invalid UTF-8 and
raw CR/LF/NUL fail with nil results and redacted errors. Validate UTF-8 before JSON
decoding so malformed literal values and object keys cannot silently become
replacement characters. Do not concatenate tokens or expand
claim values as directives. Both parsers call their typed config's validation.

The equivalent typed plugin config is `static.Config{Claims: map[string]any{...}}`.
It requires 1–32 claims and reuses core name and JSON-value validation. The host
binding selects which configured claims reach authorization; unknown or duplicate
requested names fail. Source and version are fixed as `static` and `v1` (exported
as `static.Source` and `static.Version`). Each lookup returns fresh observation
time and one-minute validity, so the binding's `MaxAge` must be at least one minute.
Identity and audience selection belong to the consumer binding.

## Static backend state and evidence

`static.New` deeply snapshots configuration and `Lookup` returns independent
nested maps/lists. Configuration is immutable after construction; construct a new
backend and enricher to reload, then replace the attachment after draining requests.
There are no directory records, update APIs, delay/outage controls, workers or
cleanup resources. Fault injection belongs in test-only backend implementations.
Nil or unconstructed backends reject lookups. Canceled contexts fail before data
is returned.

The portable [consumer journey](../../../plugins/claims-enrichment/static/consumer_e2e_test.go)
shows parser → static backend → enricher → public gatekeeper attachment → real TLS
password login → protected resource. It supplies every JSON value type, matches
string and string-list claims in ACLs, checks cached requests and realm isolation,
and rejects missing claims, literal template text, wrong ACL types, expired data,
reserved fields, outage before allow-stop, timeout and HTTP cancellation. It also
accepts typed nil JSON leaves at the maximum depth, rejects an additional
container level, and rejects a malformed replacement config while the active
backend keeps serving.
`external_module_e2e_test.go` copies that same public-only journey into a temporary
external module and runs it with the race detector and a local module replacement;
it validates this checkout, not a published version. No internal test imports or
repository-relative signing keys are permitted in that portable file.

`pkg/authz/enrichment/enrichment_test.go` owns response trust, types, freshness,
cancellation, custom-claim collisions and mutation isolation. Virtual-clock tests
check expired credentials, late successful lookups and the earliest deadline
without wall-clock sleeps. `json_test.go` covers
JSON types, precision, recursive copies, cycles and resource bounds, including
equivalent null representations at the container depth limit. Both parser
packages have external unit tests and executable examples. Backend unit tests
cover nested snapshots, configuration bounds, requested attribute selection,
cancellation and concurrent calls. The validator's
`claims_enrichment_e2e_test.go` exercises every guardian through TLS for authenticated
and cached identities. Its credential-expiry journey starts valid requests with
fresh JWTs, cached JWTs and authenticated users, then crosses expiration during
lookup and requires denial. Preserve source-address, method/path and path-claim guards.

```sh
make test TEST_DIR='./pkg/authz/enrichment/... ./plugins/claims-enrichment/... ./pkg/authz/validator ./pkg/authz ./internal/tag' COVERAGE_DIR='.coverage/claims-enrichment'
make test-automation
make linter
make ci-check
```

Root lint and struct-tag discovery include `plugins/`; default `./...` tests include
both parsers and the portable consumer fixture. Keep production core packages free
of reference-plugin imports. New backend integration does not authorize sibling
host changes.
