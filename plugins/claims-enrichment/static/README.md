# Static claims enrichment

Add configured claims to AuthCrunch authorization decisions. Keys are configurable,
and values support every JSON type:

```json
{
  "claims": {
    "foo": "bar",
    "permissions": ["read", "write"],
    "enabled": true,
    "quota": 42,
    "settings": {"region": "west", "limits": [5, 10]},
    "optional": null
  }
}
```

Import `github.com/greenpau/go-authcrunch/plugins/claims-enrichment/static`.
Construct `static.New(&static.Config{Claims: ...})`, pass it to
`enrichment.New(binding, backend)`, and attach with
`Gatekeeper.SetClaimsEnricher` before serving requests. The binding declares
allowed output names/types and pins the authenticated identity sources and audience;
use source `static`, version `v1`, and a maximum age of at least one minute.

The dedicated parser accepts `claim <key> <string>` or
`claim <key> json <JSON value>`. Encode statements with `cfgutil.EncodeArgs`:

```go
statements := []string{
    cfgutil.EncodeArgs([]string{"claim", "foo", "bar"}),
    cfgutil.EncodeArgs([]string{"claim", "permissions", "json", `["read","write"]`}),
    cfgutil.EncodeArgs([]string{"claim", "settings", "json", `{"enabled":true}`}),
}
config, err := parser.NewStaticClaimsEnrichmentConfigFromDirectives(statements)
```

Values are literal and deeply copied. Plain keys add new custom claims; collisions
with authenticated claims fail. Identity and security claim names are protected.
Configuration is immutable: construct a new backend to change values. No external
service or cleanup is needed.

The hook applies claims to the current authorization decision. JWTs, identity
headers and cached identities retain their original claims. ACL fields can match
strings and string lists; other JSON values remain typed data without coercion.

See the [public TLS consumer example](consumer_e2e_test.go) for complete parser,
login, binding and gatekeeper wiring, and the
[owning skill](../../../.codex/skills/claims-enrichment/SKILL.md) for contracts and
limits. The same consumer example runs from an isolated external Go module.

```sh
make test TEST_DIR='./pkg/authz/enrichment/... ./plugins/claims-enrichment/...'
```
