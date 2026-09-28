---
name: authorization-policy-acl
description: Maintain authorization ACL rules, typed custom claim fields, their reusable parser, policy integration, and signed-token or authenticated-user E2E coverage.
---

# Authorization Policy ACLs

## Ownership and public APIs

`pkg/acl` owns field definitions, condition compilation, matching and projection.
`pkg/authz` owns policy configuration and gatekeeper construction;
`pkg/authz/validator` supplies authenticated user claims and authoritative request
metadata to every guardian. Provider authentication and portal transformations
remain separate boundaries. Custom ACL aliases do not assign roles, change
headers, rewrite JWTs, or alter the user's normalized `GetData()` representation.

`acl.FieldConfig` has `Name`, `Claim`, and `Type`, with matching snake_case
JSON/XML/YAML tags. `Validate()` has no mutation or IO. Names are case-sensitive
ASCII identifiers: an initial letter or underscore, then letters, digits,
underscores or hyphens, at most 128 characters. Standard fields, standard aliases,
temporal/path-ACL internals, and conflicting matcher/shortcut keywords are reserved.
Claim keys are nonempty literal top-level keys, with no control characters or
surrounding whitespace. Dots, pipes, commas, spaces and URL punctuation are
literal; there is no nested lookup, network access, or placeholder expansion.

Types are `acl.FieldTypeString` (`string`) and `acl.FieldTypeStringList`
(`string_list`). There are no inferred types or implicit defaults.

`parser.NewACLFieldConfigFromDirectives(name, statements)` in `pkg/acl/parser`
accepts one named field's body, without header or braces:

```text
claim https://example.org/roles
type string list
```

Use `type string` for a scalar. Encode each statement with `cfgutil.EncodeArgs`,
preserving the entire claim key as one token; reject empty tokens before encoding.
Exactly one claim and one type are required, in either order. Repeated settings,
unsupported keywords/types, wrong arity, malformed encoding, and raw CR/LF/NUL
fail with nil results and redacted errors. Host block parsing stays outside the
library. Parse every declaration before applying the complete collection.

`PolicyConfig.ConfigureAccessListFields([]*acl.FieldConfig)` validates and
snapshots the complete collection into `AccessListFields`
(`access_list_fields`). Nil clears it. Duplicate names and invalid/null entries
fail atomically; rules and unrelated policy settings are preserved. Declare all
fields before calling policy validation or `Config.AddAuthorizationPolicy`, so
rule/declaration textual ordering is irrelevant. Typed JSON callers can populate
`AccessListFields` directly. Validation and runtime construction enforce the same
checks, including after an earlier validation and after JSON reload.

`acl.NewAccessListWithFields(fields)` snapshots declarations for direct library
consumers; `NewAccessList()` retains its existing behavior. Build all rules and
options before serving concurrently. Definitions never enter a process-global
registry, and `GetFieldDataType` remains the standard-field lookup used by portal
transformations. Do not change its meaning to support policy-local fields.

`AccessList.AddRule` rejects a null rule with a configuration error before
compilation, leaving existing rules unchanged. `AddRules` uses the same guard;
it applies rules sequentially, so valid earlier additions remain if a later
rule fails. Direct `authcrunch.NewServer` callers must receive configuration
errors for null rules or invalid declarations without relying on a host's JSON
shape validation.

## Evaluation contract

`AccessList.AllowWithClaims(ctx, normalized, claims)` starts with normalized
standard identity/request fields and projects only custom fields referenced by
rules from authenticated claims. It never mutates either input, and does not
itself authenticate anything. A preexisting alias cannot stand in for a missing
configured source. Original namespaced claims and canonical roles stay intact.

`AccessList.Allow(ctx, data)` remains available for callers already supplying ACL
field names. It applies the same custom-field type validation and list semantics.
Both APIs validate all referenced custom values before the first rule, including
before allow-stop and default-allow. A malformed deny input cannot become a
skipped condition followed by a successful allow.

- A scalar must be a string. An empty scalar is a valid string and can be matched
  explicitly, including with a regex.
- Lists accept `[]string` and JSON-shaped `[]any` only when every item is a string.
  Never stringify numbers, use reflection, drop invalid members, or split scalars.
- Absent fields remain absent. An ordinary positive or negative condition cannot
  match absence; explicit `field <alias> not exists` can.
- Null, typed nil slices, mixed arrays, objects and incompatible types deny the
  whole evaluation. Null does not count as an absent field.
- Empty nonnil lists exist, but never match a value condition, including negation.
  Existing standard-list empty behavior is preserved independently.
- Exact, partial, prefix, suffix, regex, negation and rule match-any/match-all reuse
  existing semantics. In particular, negative regex with condition-level
  `match any` accepts a nonmatching pair for a nonempty list.
- Malformed unreferenced custom claims are ignored. Do not project every raw
  claim: logged ACL input must not expand to unrelated metadata by default.

The validator uses this path for all eight method/path, source-address and
path-claim guardian combinations, including cached credentials and
`AuthorizeUser`. Method/path data comes from each current request interpretation;
custom claims cannot replace it. Cache hits still evaluate the current ACL and
request constraints. Caller-owned or cached users must remain unmodified.

The caller must authenticate the claim source and apply appropriate token trust
restrictions. A signed but user-editable profile attribute is not automatically
suitable for granting privileges. No new trust policy is implied by a field
binding.

## Generated code and verification

`assets/scripts/generate_acl.py` owns condition/rule source and generated tests.
Change its templates and regenerate together; keep feature regressions independent
in handwritten tests. Custom definitions enter compilation through per-list type
maps, with an empty-list guard limited to custom list comparisons. Preserve
standard matching behavior and all existing constructors.

Coverage belongs in:

- `pkg/acl/fields_test.go`: definitions, all matcher strategies and input shapes,
  missing/null/empty semantics, fail-closed rule ordering, logged-data projection,
  concurrent policy isolation, rejected null rules, and unchanged ACL inputs.
- `pkg/acl/parser/fields_test.go`: grammar, token preservation, redaction, independent
  results, and executable constructor example.
- `pkg/authz/access_list_fields_test.go`: atomic application, public typed validation,
  revalidation, and serialization.
- `pkg/authz/validator/access_list_fields_e2e_test.go`: real TLS authenticated-user
  and explicitly cached-identity workflows across every guardian variant.
- `server_access_list_fields_e2e_test.go`: public parser to serialized root config,
  real server/gatekeepers, independently signed JWTs, TLS protected resources,
  cache hits, malformed arrays, trust rejection, policy isolation and replacement,
  plus direct construction rejecting invalid declarations and null rules.

Run focused packages through `make test`, generator automation through
`make test-automation`, and `make ci-check` for the complete gate. New public
configuration structs need serialization-tag registration. Inspect all edited
code's diagnostics, including generated changes. Handwritten production code
uses explicit type switches, without the `reflect` package.
