---
name: logging
description: Maintain AuthCrunch authentication event attribution, logging skip rules, the reusable directive parser, immutable Zap filters, root logger wiring, and TLS log-output tests. Excludes host-specific access-log configuration and changes to authentication decisions.
---

# Logging and Authentication Events

`pkg/logging` owns diagnostic suppression; `pkg/logging/parser` owns the logging
block grammar. `authcrunch.Config.Logging` persists `*logging.Config`, and
`NewServer` wraps its supplied logger before constructing every component.
The caller's original logger remains unchanged. Filtering never changes returned
authentication errors, authorization flags, redirects, or HTTP responses.

## Authentication event attribution

Password, TOTP and backend WebAuthn failures in JSON and browser sandbox flows
emit WARN messages `password authentication failed`,
`totp passcode authentication failed`, and `u2f authentication failed`.
They include `portal_name`, canonical `realm` and `username`, `session_id`,
`request_id`, numeric `checkpoint_id`, `checkpoint_name`, `checkpoint_type`,
`src_ip` and `src_conn_ip`. The portal name comes from the selected portal config;
the realm comes from the server-held sandbox authenticator, paired with its
canonical backend account. Email aliases and transformed display/subject claims
must not replace that identity. Connected LDAP can move subsequent MFA into an
attached local account; its factor realm is that local realm, not necessarily
the originally submitted federation realm.

The INFO message `user was successfully authenticated` records final JSON
checkpoint login after token issuance and applicable session/OP admission
succeed. It includes the same portal/realm/account attribution, request/session
correlation, and `authentication_flow=api`. Incomplete factors and failed
issuance must not emit it. The call precedes HTTP serialization/write and cannot
prove network delivery. API-key, provider and refresh flows are separate; this
message is not a universal successful-authentication counter.

Preserve exact messages, levels and timing when adding fields. Browser
`user passed all authorization checkpoints` and `Successful login` describe
earlier boundaries, not final credential delivery. Rate limiting, invalid forms,
factor discovery, sandbox limits and malformed/origin-rejected WebAuthn can
fail before the three backend warnings. Assert actual HTTP outcomes separately;
some browser factor failures render an error page with HTTP 200.

The external-provider `Successful login` INFO event retains `session_id`,
`request_id`, `auth_method` and `auth_realm` after the provider accepts its
callback. It omits the arbitrary response payload: OAuth UserInfo enrichment can
contain nested credentials before snapshot sanitation. Preserve this omission
without adding a field-name redaction walker or changing provider claims.
The event still precedes portal authorization and issuance, including cases
where later claim validation fails. Other events with the same message have
different fields and boundaries; do not merge them into this event contract.
Explicit Debug diagnostics and other accepted structured diagnostics retain
their separate [logging policy](../threat-hunting/references/debug-logging.md).

Request and session IDs are correlation, not authenticated provenance. The
session ID is the portal correlation cookie value or a generated value, distinct
from sandbox secrets and refresh-family identity. Jar-free checkpoint requests
need not retain the same value. Embedding hosts own forwarded-address trust.
Never add passwords, passcodes, factor seeds, assertions, sandbox secrets,
private keys or issued credentials to these events.

Added realm and portal strings participate in existing textual field-value
filtering. A rule matches any equal textual value, not a named field key; use
distinct values when demonstrating selective suppression. Filtering a diagnostic
must leave failures, successful authorization and unrelated events unchanged.

## Configuration and Public APIs

`parser.NewLoggingConfigFromDirectives(statements []string) (*logging.Config, error)`
accepts the body of one logging section, without its header or braces:

```text
logging {
  skip partial text "auth provider returned error"
  skip partial text "reason: no token found"
}
```

Every statement has exactly four tokens:
`skip <exact|partial|prefix|suffix|regex> text <value>`.
The matcher is required. Adapters reject empty tokens, encode each tokenized
statement with `pkg/util/cfg.EncodeArgs`, and pass the complete body to the
parser. They own block traversal and reject unsupported nested blocks.
Do not split a quoted pattern with `strings.Fields` or join tokens by hand.
Assign the result directly to `Config.Logging` before `NewServer`.

The typed equivalent is:

```json
{"logging":{"skip":[
  {"match":"partial","text":"auth provider returned error"},
  {"match":"partial","text":"reason: no token found"}
]}}
```

`logging.Config.Skip` is `[]logging.SkipRule`, each containing `Match` and `Text`.
JSON, XML, and YAML use the same field names. `Config.Validate` owns semantic
validation and regexp compilation. Invalid matchers, empty/whitespace-only text,
invalid UTF-8, raw CR/LF, and invalid expressions fail without echoing values.
Parser errors return no partial result. Rules retain their order; any match skips
an entry. Repeated directives, including identical rules, are additive and valid.
Omitted configuration, an empty block, and an empty rule list suppress nothing.
There are no implicit skip rules or changes to log levels.

`logging.NewFilter(config) (*logging.Filter, error)` validates a detached snapshot;
nil configuration disables filtering. `Filter` is immutable and safe for concurrent
use, and its zero value is a no-op. Rebuild it on reload instead of mutating a live
configuration. Failed replacement construction cannot change an existing filter.
Root persistent-state bindings exclude `Logging`, so adding, changing, or removing
skip rules does not invalidate otherwise valid persisted sessions.

`Filter.WrapLogger(logger) (*zap.Logger, error)` clones a non-nil logger with the
filter; empty rules return the original logger. `Filter.WrapCore(zapcore.Core)`
can be supplied directly to `zap.WrapCore` or a host logging adapter.
`Filter.ShouldSkip(message string, fields ...zap.Field) bool` exposes the same
matching decision to hosts that own the actual log call.

## Matching Contract

Match the message and each textual field value independently, before output
encoding. Exact compares the complete value; partial searches for a substring;
prefix and suffix compare the corresponding edge. All are case-sensitive, with
no trimming or case folding. Regex uses Go `regexp` semantics, with substring
matching unless anchors are explicit. Whitespace, quotes, backslashes, and Unicode
in values survive argument encoding and configuration serialization.

Textual fields are Zap String, ByteString, Error, and Stringer types, including
`zap.Any` when Zap resolves its argument to one of these types. Use Zap's safe
encoder for error/Stringer conversion rather than calling potentially panicking
methods directly. Matching uses the primary value, not error verbose/causes
companions. Keys, logger names, caller/stack metadata, numbers, arrays, reflected
values, and nested object contents are outside this selector. Do not stringify
arbitrary objects or join independent fields into a synthetic log line.

Install the wrapper before `With`/`WithLazy` to match fields attached by those
operations. Fields already embedded in an opaque underlying core cannot be
recovered by the wrapper. Bound field matches affect only that child and its
descendants, not the parent or sibling loggers. Preserve the underlying encoder,
field values, namespaces, logger names, caller data, output destinations, dynamic
levels, error destination, and Sync ownership.

Full-entry filtering occurs before the underlying core's `Check`, so retained
entries traverse its sampler, tee selection, and registered hooks exactly once.
Calling the underlying core's `Write` directly in the checked logging path would
bypass these behaviors. Carry the outer checked entry's error destination into
the downstream checked entry, and never retain a pooled checked entry after Write.
`Logger.Check` may return non-nil before fields cause suppression or sampling.
Panic, development DPanic, and Fatal actions still run even for suppressed logs.
Hosts continue to own logger flushing and process lifecycle.

## Embedding Boundary

Wrapping the logger passed into `NewServer` covers AuthCrunch-created components.
It cannot suppress a message emitted by a different host middleware logger.
Hosts must apply this same filter at that logger's boundary, scoped to the
intended security components. Do not install process-global mutable filters or
change unrelated access/application loggers. Use fresh filters for replacements;
removing the section must restore ordinary logging.

A host deciding to skip a diagnostic must still preserve authentication failure
and its HTTP denial. Do not turn an error into success to silence another layer's
logger. Root TLS tests model a separate middleware logger; they do not certify
any external server's adapter.

## Validation

`pkg/logging/config_test.go` covers typed validation, snapshots, and JSON/XML/YAML.
Register exported logging types in `internal/tag/tag_test.go`; its inventory
check requires runtime structs as well as serialized configuration types.
`pkg/logging/parser/config_test.go` is an external-package parser matrix and
executable public-constructor example. `pkg/logging/filter_test.go` covers all
matchers, structured and bound fields, isolation, concurrency, sampler/tee/hooks,
dynamic levels, error output, flushing, and terminal actions.

Root `config_logging_test.go` verifies aggregate validation.
`server_logging_e2e_test.go` parses and persists configuration, constructs the real
runtime with a temporary identity database, uses a TLS portal and gatekeeper,
checks missing/malformed-token denial and successful login/authorization, and
reads actual JSON log files from component and host loggers. Keep all five
matchers and omitted/empty/combined cases in the default test suite.
The same file verifies persistent OAuth sessions across logging-only reloads.

`pkg/authn/authentication_event_logging_test.go` drives all six real local
factor-failure branches, including enrolled WebAuthn with a wrong-key signature
and a valid same-checkpoint control. It checks canonical attribution despite
aliases/transformed claims and conflicting request realm metadata. Existing
completion cancellation and bounded OP-capacity tests verify the final JSON
success boundary. `server_authentication_event_logging_e2e_test.go` uses public
root construction and TLS to distinguish one username across two realms and
portals, filter their field values independently, authorize actual issued tokens,
and scan captured diagnostics for passwords and returned login credentials.

`pkg/authn/external_login_logging_test.go` checks the provider-acceptance event's
four metadata fields for OAuth and SAML, including subsequent claim rejection,
redirects and provider failures. `TestE2EProviderLoginLogMetadata` in
`pkg/authn/external_login_logging_e2e_test.go` uses the public TLS provider-refresh
fixture with complete UserInfo enrichment, real callback/rotation/replay and
independent portal signature verification. It preserves benign nested claims
while checking INFO diagnostics for captured upstream and portal credentials.

```sh
make test TEST_DIR='./pkg/logging/... . ./internal/tag' TEST='Test.*Logging|ExampleNewLogging|TagCompliance' COVERAGE_DIR=.coverage/logging
make test TEST_DIR='./pkg/authn .' TEST='^(TestAuthenticationEvent.*|TestTokenRefreshJSONCompletionDiscard|TestTokenRefreshJSONOIDCCapacityRecovery|TestE2EServerAuthenticationEvents)$' COVERAGE_DIR=.coverage/authentication-events
make test TEST_DIR='./pkg/authn' TEST='^(TestExternalLoginEventMetadata|TestE2EProviderLoginLogMetadata)$' COVERAGE_DIR=.coverage/external-login-events
make ci-check
gopls check -severity=hint config.go server.go server_persistent_state.go config_logging_test.go server_logging_e2e_test.go pkg/logging/config.go pkg/logging/filter.go pkg/logging/config_test.go pkg/logging/filter_test.go pkg/logging/parser/config.go pkg/logging/parser/config_test.go
```
