# Configuration Parser Shape

Sections: [package layout](#package-layout-and-ownership),
[constructor](#public-constructor), [grammar](#encoded-statements-and-grammar),
[validation](#validation-and-composition), and
[integration](#integration-and-migration).

Use this contract when adding or changing configuration. Every configuration
surface needs a public, reusable `parser` package. The parser covers all of the
feature's operator-configurable settings; cached values, runtime handles, and
derived fields remain the typed configuration/runtime owner's responsibility.
Nested configuration records belong to their feature's grammar and do not each
require a separate package. Request/response DTOs and runtime state are not
configuration surfaces merely because they are structs.

## Package Layout and Ownership

Use this schematic layout for a domain owning its configuration:

```text
pkg/<domain>/
    <subject>_config.go          public config type, defaults, validation
    <subject>_config_test.go     typed configuration and composition tests
    parser/
        <subject>.go            package parser; exported directive constructor
        <subject>_test.go       package parser_test; grammar and API tests
        <subject>_example_test.go
```

Examples may live in the corresponding test file. A single-subject package may
use `parser.go` and `parser_test.go`. Split related subjects into focused files
with private shared decoding helpers, as `pkg/oidc/parser` does for clients,
applications, and providers. Reuse an existing subject parser when adding a new
integration; do not duplicate its grammar in each embedding application.

When a shared domain owns several independent features, use
`pkg/<domain>/<feature>/parser`. The typed model may remain in the shared domain:
`pkg/authn/admin_api/parser` returns `authn.AdminAPIConfig`, and
`pkg/authn/token_refresh/parser` returns `authn.TokenRefreshConfig`.
Package paths identify the complete feature; preserve established names such as
`token_refresh`. Do not put reusable parsers under `internal`, a CLI command,
an HTTP handler, or an embedding server's package.

Dependencies flow from the embedding adapter to the parser, then to the public
typed configuration API. Runtime code consumes typed configuration without
importing a parser that depends on that runtime package. If a cycle appears,
separate the shared configuration/validation ownership before adding imports.
Keep one authoritative model; do not solve a cycle by copying structs.

## Public Constructor

The usual signature is
`New<Domain><Subject>ConfigFromDirectives(statements []string) (*Config, error)`.
Use the actual owning feature's public type in place of `Config`. Include the
complete domain/subject and Go initialisms in the constructor name even when
the import path already supplies that context. These existing APIs illustrate
the supported shapes:

| Package | Constructor arguments | Result |
| --- | --- | --- |
| `pkg/authn/admin_api/parser` | `NewAdminAPIConfigFromDirectives(statements []string)` | `*authn.AdminAPIConfig` |
| `pkg/authn/token_refresh/parser` | `NewTokenRefreshConfigFromDirectives(statements []string)` | `*authn.TokenRefreshConfig` |
| `pkg/oidc/parser` | `NewOIDCClientConfigFromDirectives(nickname string, statements []string)` | `*oidc.ClientConfig` |
| `pkg/oidc/parser` | `NewOIDCProviderConfigFromDirectives(statements []string, applications map[string]*oidc.ClientConfig)` | `*oidc.Config` |
| `pkg/oidc/parser` | `NewOAuthApplicationConfigFromDirectives(header string, statements []string, persisted *oidc.OAuthApplicationConfig)` | `*oidc.OAuthApplicationConfig` |

Every constructor also returns `error`. Additional arguments are explicit,
typed inputs required by that feature: a nickname, an encoded header, a
registration lookup, or persisted configuration. Prefer these to untyped
parameter bags or global lookups. A stateless parser uses functions; a parser
interface, builder, registry, or service is unnecessary unless the feature has
an actual need for it. No running portal, HTTP request, server-specific token
iterator, logger, or network client is required merely to parse settings.

The result represents the subject being parsed. In a shared package, introduce
or reuse its dedicated config type rather than return unrelated settings in a
larger aggregate. Use the same feature model for typed callers and directive
callers. A focused package may retain its established names such as
`oidc.Config`; do not rename working public types solely to copy an example.

## Encoded Statements and Grammar

Adapters tokenize their input, resolve host-specific placeholders, and call
`cfgutil.EncodeArgs` once per statement. The parser uses `cfgutil.DecodeArgs`;
do not substitute `strings.Fields`, join quoted values with spaces, or add
another quoting/escaping protocol. Decode one complete statement at a time.

Document whether the constructor accepts block bodies, complete directives, or
an explicitly separate header. Body parsers receive no enclosing braces or
header. A full-directive parser, such as the admin API parser, validates the
complete directive. Host adapters own block traversal and collect the entire
configuration subject before parsing so duplicates cannot escape detection
across individual calls.

New grammars use readable separate keywords such as `public origin` and
`private key export`. State choices use keywords such as `enabled`/`disabled`
or the established `enable`/`disable` directive form. Do not derive directive
spelling from snake_case JSON fields or introduce boolean literal arguments
for new settings. Preserve existing public grammar compatibility when extending
a parser unless a grammar change is part of the task; the existing OIDC client
parser's underscore fields and boolean spellings are an established contract.

Check exact keyword token boundaries, arity, empty values, unsupported settings,
and duplicates/conflicting states. Keep a setting identity independent of its
enable/disable spelling. Document cardinality for lists and intentionally
repeatable directives instead of accidentally accepting last-value-wins input.
Reject raw CR/LF because `DecodeArgs` reads only one CSV record. Adapters must
reject empty tokens before encoding: `EncodeArgs` can trim a trailing empty
field, which the parser cannot recover.

## Validation and Composition

Decode into a fresh local candidate, resolve any named references from explicit
caller inputs, and call the owning typed constructor or validator for defaults
and semantic checks. Resolve required references before final validation.
Typed configuration remains responsible for constraints such as lifetime
bounds, redirect rules, and cross-field dependencies. A config containing only
independent booleans needs no empty `Validate` method just to match a template.
Parsing must still enforce its complete grammar.

Return `nil, err` on failure. Errors may identify a statement number and known
setting, but must not echo raw statements, credentials, or untrusted values.
Do not mutate input slices, referenced registrations, or previously applied
configuration. Clone caller-owned data before passing it to mutating validators.
Keep parsing state local so independent calls do not share settings.

Document omitted versus empty configuration, defaults, opt-ins, and disabled
validation behavior. These semantics come from the feature, not a universal
default: an empty admin directive list disables both settings, while a token
refresh block opts in and must satisfy its required configuration. Preserve
independent authorization flags and the runtime's final authorization checks.

The caller applies a successful result through the public configuration API.
Direct assignment fits a dedicated field; use a typed application method when
merging into established aggregate configuration. For example,
`PortalConfig.ConfigureAdminAPI` preserves profile access and existing API
serialization fields. Such methods snapshot inputs, preserve unrelated
configuration, and reject invalid input before mutation. Do not add a second
stored copy of the same settings or silently change persisted field names.

Keep provisioning in the owning feature API and document any existing parser
entry point that invokes it. Ordinary adaptation and reload must not silently
regenerate client IDs, secrets, or signing keys. Use explicit provisioning and
persisted credentials as required by the feature; configuration parsing does
not start runtime workers, bind listeners, or make network requests.

## Integration and Migration

When adding or changing a configurable feature, implement or extend its parser
and corresponding unit, executable-example, and consumer E2E coverage in the
same change. Follow `testing-and-ci` for the required validation workflow. When
extracting legacy parsing, move the implementation and tests together, preserve
typed validation, update repository-local callers, and verify that configured
runtime behavior survives serialization where supported.

Update the owning feature skill with the exact config type, parser import path,
exported constructor, grammar/defaults, application method, and validation
commands. Keep this shared architecture contract here instead of duplicating it
in every feature skill. Older configuration without a parser is a gap; its
existence does not exempt new or changed configuration from this requirement.
Keep migrations within the authorized feature scope and this repository.
Embedding-server wiring and sibling-project changes are separate work.
