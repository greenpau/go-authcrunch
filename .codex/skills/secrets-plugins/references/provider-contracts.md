# Static and AWS Secrets Provider Contracts

## Source authority

These are independently usable Go libraries. Both declare `package secrets`
and Go 1.18 in the inspected module manifests; neither depends on go-authcrunch
or a host framework. Do not derive runtime behavior from their repository titles
or old README terminology. The old `go-authcrunch-creds-aws-secrets-manager` URL
redirects to the current `go-authcrunch-secrets-aws-secrets-manager` repository.

The following immutable revisions make these observations reproducible. Recheck
source, tests, and module metadata before documenting a newer revision.

| Module | Source | Tests and dependencies |
| --- | --- | --- |
| Static | [`secrets.go` at `c68974df1c544a1de39b8b2c99474043618083ea`](https://github.com/greenpau/go-authcrunch-secrets-static-secrets-manager/blob/c68974df1c544a1de39b8b2c99474043618083ea/secrets.go) | [`secrets_test.go`](https://github.com/greenpau/go-authcrunch-secrets-static-secrets-manager/blob/c68974df1c544a1de39b8b2c99474043618083ea/secrets_test.go), [`go.mod`](https://github.com/greenpau/go-authcrunch-secrets-static-secrets-manager/blob/c68974df1c544a1de39b8b2c99474043618083ea/go.mod) |
| AWS | [`secrets.go` at `9f35416c8e31afe86e86e85be5c2986b160c655a`](https://github.com/greenpau/go-authcrunch-secrets-aws-secrets-manager/blob/9f35416c8e31afe86e86e85be5c2986b160c655a/secrets.go) | [`secrets_test.go`](https://github.com/greenpau/go-authcrunch-secrets-aws-secrets-manager/blob/9f35416c8e31afe86e86e85be5c2986b160c655a/secrets_test.go), [`go.mod`](https://github.com/greenpau/go-authcrunch-secrets-aws-secrets-manager/blob/9f35416c8e31afe86e86e85be5c2986b160c655a/go.mod) |

The static module's only required module is its test comparison library. AWS
pins SDK v2 core `v1.17.3`, config `v1.18.8`, and Secrets Manager `v1.18.0`.
These versions identify the inspected implementation, not an upgrade
recommendation. Its `VERSION` file alone is not a dependency tag guarantee.

## Public API comparison

Use distinct aliases, for example `staticsecrets` and `awssecrets`. In the
signatures below, `Record` abbreviates `map[string]interface{}` and `Value`
abbreviates `interface{}`; they are not exported type aliases.

| Operation | Static | AWS |
| --- | --- | --- |
| Constructor | `NewClient(ctx, id string, secret Record) (Client, error)` | `NewClient(ctx, id string, region string) (Client, error)` |
| Read record | `GetSecret(ctx) (Record, error)` | `GetSecret(ctx, path string) (Record, error)` |
| Read field | `GetSecretByKey(ctx, key string) (Value, error)` | `GetSecretByKey(ctx, path string, key string) (Value, error)` |
| Metadata | `GetConfig(ctx) Record`: `id`, `provider` | `GetConfig(ctx) Record`: `id`, `region`, `provider` |
| Test hooks | None | `SetMockClient(aws.HTTPClient)`, `SetMockCredentialsProvider(aws.CredentialsProvider)` |

Every `ctx` parameter is `context.Context`. AWS additionally exports
`MockCredentialsProvider`; it returns synthetic credentials for tests. It is
not a deployment credential strategy. Hook methods are part of the published
AWS `Client` interface, but a consumer-owned reader interface need not expose them.

## Static behavior

Construction checks, in order: nil secret, empty secret, then empty ID. It
returns an error for each, but does not trim the ID or validate individual keys
or values. A map containing a nil or non-string value is accepted.

The client retains the original map. `GetSecret` returns that same map without
copying, I/O, or checking context cancellation. `GetSecretByKey` performs a
literal map lookup; dots or slashes in a key have no special meaning. An absent
key returns an empty string and an error; a present nil returns nil without an
error. Successful values retain their original Go types.

`GetConfig` creates a fresh map with the ID and `static_secrets_manager` label.
It omits the record entirely. Modifying that metadata map does not change the
client's config, but modifying a returned secret map changes subsequent reads.
Do not mutate shared maps concurrently. A shallow map copy isolates only
scalar values; nested maps and slices need their own ownership policy.

## AWS behavior

Construction stores the ID/region/provider and calls SDK
`config.LoadDefaultConfig` with the context and `config.WithRegion`. It does
not fetch a secret or prove backend access. It does not reject an empty ID.
For a nonempty region it tests the unanchored expression `\w{2}-\w+-\d`;
this is not an authoritative region validator. Empty region is permitted by
the library; actual region resolution is delegated to the pinned SDK. Supply
an explicit valid region for deterministic examples and enforce any stricter
requirements in the consumer.

The first `GetSecret` creates the SDK service client lazily. Each call sends
`GetSecretValue` with `SecretId` equal to the supplied path and `VersionStage`
set to `AWSCURRENT`. There is no library cache, background poller, explicit
retry loop, or request-timeout setting; SDK behavior and caller context apply.
A new retrieval can see a rotated version, but this does not update previously
returned maps or downstream runtime configuration.

The result must have `SecretString`. `SecretBinary` is unsupported by this
implementation. `SecretString` is decoded as a JSON object into a generic map:
strings remain strings, numbers become `float64`, and nested objects/arrays
remain generic values. Invalid JSON and non-object scalars/arrays fail decoding;
JSON `null` yields a nil map without an error, and `{}` is accepted. Consumers
must enforce required fields and reject empty/nil records when needed.

`GetSecretByKey` fetches the record on every invocation, checks presence, then
performs an unchecked `value.(string)` assertion. A present number, boolean,
object, array, or null can therefore panic despite the return type being
`interface{}`. Prefer `GetSecret` plus an explicit type check when consuming
untrusted or heterogeneous records; the [adapter example](consumer-example.md)
does this. An absent key or failed retrieval returns an empty string with an
error, not a usable fallback.

The lazily assigned service-client pointer has no synchronization. Concurrent
first use is not established as safe. The mock setters change configuration
used to create the client; once it exists, those changes do not reconfigure it.
Keep hooks before first use, never change them concurrently, and serialize or
initialize access before sharing a reference client.

## Payload and consumer semantics

The examples in the plugin repositories include these two record shapes:

```json
{"username":"example-user","password":"<consumer-supported password representation>","api_key":"<consumer-supported API-key representation>","email":"user@example.invalid","name":"Example User"}
```

```json
{"id":"0","usage":"sign-verify","value":"<newly generated signing material>"}
```

These are schematic shapes, not deployable credentials. Neither plugin enforces
the field names, hashes plaintext, validates a key's strength, or installs a user
or key. The actual destination decides its accepted representation. Preserve
precomputed password prefixes exactly; never reuse published example credentials
or signing values. Retrieving an API-key representation does not make its
format interchangeable with a password import.

For AWS, retrieve one record when several fields must come from the same secret
version. Separate `GetSecretByKey` calls each issue another request and can
straddle a rotation. The library does not return AWS version metadata, so a
version-aware cache or rollout protocol needs an explicit API extension.

The demonstrated read operation requires `secretsmanager:GetSecretValue` for
the intended resources. A customer-managed encryption key also requires
`kms:Decrypt` for that key. Do not treat the broader administrative policy in
the plugin README as the minimum runtime policy; derive permissions from the
operations actually used. See the official
[GetSecretValue API](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html).

## Validation evidence and remaining scenarios

The upstream tests exercise the real library with static data or a synthetic
AWS HTTP transport and credentials; they do not call a live AWS account.

| Existing test | Static coverage | AWS coverage |
| --- | --- | --- |
| `TestNewClient` | Valid metadata, missing ID, nil/empty map | Valid region/metadata, malformed region |
| `TestGetSecret` | Complete record retrieval | User/key records, missing `SecretString`, malformed AWS response envelope |
| `TestGetSecretByKey` | Existing and absent key | Existing string, absent key, AWS resource-not-found response |

Do not confuse a malformed AWS envelope test with validation of every malformed
inner `SecretString`. Existing tests do not establish concurrent first-use
safety, mutation isolation, cancellation/deadline behavior, wrong-type rejection,
IAM denial handling, rotation adoption, reusable directive parsing, or complete
AuthCrunch login integration. These are acceptance cases to add when developing
those behaviors, not a claim that the working plugins fail ordinary use.

For new implementations, prefer constructor-time dependency injection, safe
initialization, explicit payload validation, immutable snapshots, and typed
errors. Preserve existing public compatibility when adapting the reference
clients. Neither module currently supplies a public typed config or standalone
parser package; introducing those requires implementation and consumer tests.

## Researching integration

To determine whether a host supports either library, trace imports and wrapper
methods to the host's consumer interface, construction order, and final use of
the retrieved values. A wrapper may bind a path or cache a record even though
the underlying library does not. Record that distinction before making claims
about reload or rotation. Keep host-specific wiring and handoff notes in the
host project or this repository's ignored `tmp/`; do not make durable library
instructions depend on those temporary research files.
