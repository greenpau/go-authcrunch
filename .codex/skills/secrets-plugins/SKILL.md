---
name: secrets-plugins
description: Integrate and develop AuthCrunch secrets plugins using the SQLite, static, and AWS Secrets Manager implementations. Covers exact APIs, resource binding, payload types, safe metadata, lifecycle, parser gaps, and consumer validation; excludes identity-store authentication and host-specific module implementation.
---

# Secrets Plugins

## Own retrieval and adaptation

A secrets plugin retrieves values for a consumer to use in configuration. It
does not authenticate users, hash passwords, authorize requests, or install
signing keys by itself. Backend credential acquisition is also distinct from
the password, API key, or signing material contained in the retrieved record.

Read [SQLite bound secrets](references/sqlite.md) to maintain the pure-Go local
plugin, its public parser, provisioning API, and gatekeeper consumer tests.

The external reference modules are:

- [Static Secrets Manager](https://github.com/greenpau/go-authcrunch-secrets-static-secrets-manager),
  provider label `static_secrets_manager`.
- [AWS Secrets Manager](https://github.com/greenpau/go-authcrunch-secrets-aws-secrets-manager),
  provider label `aws_secrets_manager`.

Read [provider contracts](references/provider-contracts.md) when selecting,
calling, troubleshooting, or changing compatibility with either implementation.
It records exact signatures, source revisions, constructor behavior, payload
shape, tests, and support limits. Read the
[consumer example](references/consumer-example.md) when binding AWS paths,
sharing the existing client safely, or building a plain Go adapter.

For a new standalone secrets repository, the
[repository bootstrap workflow](../plugin-development/references/repository-workflow.md)
provides an `AGENTS.md` template that routes to AuthCrunch guidance and the new
repository's own implementation skill. A companion host plugin adds its host's
plugin-development guidance and local adapter contracts. In-repository synthetic
secrets plugins use `plugins/secrets/<name>` under the
[reference contract](../plugin-development/references/synthetic-reference.md);
the implemented SQLite reference is separate from the two external modules above.

## Essential compatibility rules

The static client binds one record at construction. Its reads take only context
and optionally a key. The AWS client takes a path on every read. They do **not**
implement one identical Go interface. A consumer can bind the AWS path in an
adapter and expose the same record-reader methods as the static client.

Keep these identities distinct:

| Identity | Meaning |
| --- | --- |
| Module path | Dependency imported by the consumer |
| Provider label | Backend kind reported by `GetConfig` |
| Instance ID | Consumer-local name selecting a configured client/record |
| Resource path | Backend object selected for AWS retrieval; not the instance ID |
| Field key | Exact top-level map key inside that object |

Both implementations use `map[string]interface{}`. Preserve values exactly and
check types at the consumer boundary. A retrieved bcrypt representation remains
a string until the password owner imports it; key IDs such as `"0"` should stay
strings when their consumer expects strings. Never stringify arbitrary values
with `fmt.Sprint`, treat a JSON number as a credential, or traverse dotted keys
as JSON paths without an explicitly implemented contract.

The reference clients expose metadata through `GetConfig`, not a serializable
copy of the secret. Preserve that separation in new implementations: metadata
is allowlisted identifiers/settings only. It can be logged by a consumer.
Locators and IDs must not themselves contain credentials; deployments may also
need to redact identifiers revealing account or tenant names.

## Construction, lookup, and lifetime

- Validate configuration and required consumer dependencies before publishing a
  client. Neither reference constructor proves the intended secret can be used
  by the final consumer; explicitly retrieve and validate required fields.
- Bind resource paths once when adapting a path-addressed client. Missing ID,
  locator, record, key, or wrong value type must fail the requested operation;
  an error's accompanying zero value is never a credential fallback.
- Retrieve a single record for a group of related fields that needs a coherent
  snapshot. Separate AWS field lookups can observe different secret versions.
- The static client shares its input/output map. Treat it as immutable or copy
  the allowed value graph at the boundary; concurrent mutation is unsupported.
- The AWS client lazily creates its SDK client without synchronization. Serialize
  access through a private adapter or complete initialization before concurrent
  publication. Configure test hooks before the first lookup and never mutate
  them during use. A mutex-free concurrent-start guarantee is not established.
- Pass deadlines to remote work. The static methods ignore context; AWS forwards
  it to SDK configuration loading and retrieval. Neither defines an independent
  request timeout or background refresh worker.
- The AWS library retrieves on each call and has no secret-value cache. A host
  adapter or the final AuthCrunch config can retain a snapshot. Determine
  freshness at the final consumer; `AWSCURRENT` is not automatic runtime rotation.
- Neither reference client has `Close`. New workers/caches need explicit lifetime
  ownership; root `Server.Close` does not own an arbitrary embedding client.

## Configuration support and future providers

Neither backend module exports a public typed configuration model or dedicated
`parser` package. Their constructor arguments are the current configuration API;
private `clientConfig` structs and `GetConfig` maps do not satisfy AuthCrunch's
reusable-parser contract. This is a documented migration gap, not permission to
invent a `secrets` directive or `authcrunch.Config.Secrets` field.

For new providers, use the
[development blueprint](../plugin-development/references/development-blueprint.md)
and the shared [parser contract](../coding-directives/references/configuration-parsers.md).
Specify typed configuration, pure parsing, validation, exact output types,
error behavior, transport limits, concurrency, and ownership. Keep old
constructors compatible if evolving a reference module. Add tests for the new
contract instead of copying legacy unchecked casts, mutable maps, mock-only
production exports, or weak validation into a template.

The final consumer owns secret-reference syntax and resolution. Resolve once
into a private configuration candidate before final validation and runtime
construction. For directive input, replace complete argument tokens before
encoding only when the resulting values satisfy that parser's grammar. Apply
multiline or structured values through the owning typed configuration API;
do not flatten PEM material or force raw CR/LF through single-line directives.
Keep secret contents out of diagnostic metadata and administrative configuration
snapshots. Reusable Go integration belongs here; host registration and host
grammar belong to their adapters.

Password import and revocation are owned by
[local-password-authentication](../local-password-authentication/SKILL.md);
key validation and issuance belong to the relevant KMS/portal consumer. Apply
those contracts after retrieval rather than claiming the plugin guarantees them.

## Acceptance scenarios

- Static construction rejects nil/empty records and missing IDs; valid reads
  preserve exact values; absent keys return an error.
- AWS sends the intended locator and current-version stage; a JSON object is
  decoded and a missing string payload, malformed payload, denied request,
  absent resource, timeout, and cancellation all prevent credential application.
- String consumers reject numbers, booleans, objects, arrays, null, and empty
  strings where credentials must be nonempty; no unchecked type assertion panics.
- A bound AWS reader and a static reader satisfy the same consumer interface;
  the direct AWS client does not. Metadata never includes retrieved values.
- Concurrent first use and mutation isolation match the promised adapter
  contract; a race-free sequential test alone does not prove shared-client safety.
- Rotation tests distinguish fresh backend retrieval from adoption by a cached
  adapter, runtime configuration, identity database, or signing-key store.
- A consumer fixture exercises parsing, retrieval, typed application, and an
  observable result, with synthetic data and no live AWS account. Scope claims
  to the layers actually exercised.
