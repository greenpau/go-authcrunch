# SQLite bound secrets

The root-module reference at `plugins/secrets/sqlite` stores JSON objects in a
private, local SQLite database using `modernc.org/sqlite`; production needs no
CGO. It implements bound-record retrieval and trusted provisioning, with no
network endpoint, secret encryption, plugin loader, or implicit key rotation.

Use `parser.NewSQLiteSecretsConfigFromDirectives([]string)` and pass its typed
result to `sqlite.New(ctx, config)`. The public grammar is exactly one value per
setting, each at most once: `name`, `path`, `record`, and optional `timeout`.
Name and record are required bounded identifiers; path is absolute. Timeout
defaults to `1s`, accepts `1ms` through `30s`, and bounds each database operation.
Parsing has no filesystem effects. Constructors snapshot caller configuration.

`Put(ctx, map[string]any)` atomically replaces the bound object. Empty objects,
invalid keys, non-JSON values, over 128 keys, or encoded objects over 64 KiB fail.
At most 1024 named records fit in a database. `Delete(ctx)` removes only the
bound record and is idempotent. These are trusted provisioning APIs: a host
must not expose them as anonymous endpoints.

`GetSecrets(ctx)` reads one fresh snapshot and returns a detached JSON graph.
Numbers are `json.Number`; strings, booleans, arrays, objects, and null retain
JSON types. `GetSecret(ctx, key)` uses exact top-level keys, including literal
dots. Present null is distinct from `ErrNotFound`. `GetString` rejects empty or
non-string values without coercion. `GetConfig` returns detached allowlisted
name/kind/record metadata, never payloads or database paths.

Resolve related fields with one object read into a private consumer candidate.
Validate that candidate and publish only after successful construction. Existing
consumers retain their previous snapshot until explicitly rebuilt; a failed
lookup or rebuild must not install a default credential. This library does not
add `authcrunch.Config.Secrets` or root-config dispatch.

Read the [shared SQLite contract](../../plugin-development/references/sqlite-backends.md)
when changing filesystem checks, schema validation, transactions, or lifecycle.
Each client owns `Close`; hosts drain requests before closing it. Missing files,
closed clients, invalid schemas, cancellation, and lock deadlines fail closed.
`ErrCommitUncertain` requires reconciliation before retrying a provisioning
mutation. Never log retrieved values or reflect them into errors.

Acceptance: unit tests cover detached values, exact numeric representation,
record binding, invalid inputs, cancellation, concurrent access, and reopen
persistence. `consumer_e2e_test.go` resolves a real signing key, serves protected
TLS requests through an AuthCrunch gatekeeper, rotates the backend value, and
proves explicit adoption and failure without fallback. The same fixture runs
from an isolated external module. Run:

```
make test TEST_DIR='./internal/sqlitedb ./plugins/secrets/sqlite/... ./internal/tag'
```

Also run the units and public consumer fixture with `CGO_ENABLED=0`, excluding
the external-module driver because that helper deliberately uses the Go race
detector. The race detector's toolchain requirement is separate from production.
