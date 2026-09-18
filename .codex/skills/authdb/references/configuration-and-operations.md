# Configuration and Operations

The user-facing [authdb usage guide](../../../../cmd/authdb/README.md) owns
installation, the HTTPS quick start, bootstrap variables, JSON examples and
listener defaults, management-client setup, restart behavior, and
troubleshooting. Update that guide when command behavior changes; avoid a
second operator reference here.

## Go Host Integration

The executable decodes a JSON envelope with `http` as `*httpserver.Config` and
`security` as `*authcrunch.Config`. It does not translate Caddyfiles or a text
directive file. Go consumers can instead obtain the same HTTP config through
`pkg/httpserver/parser.NewHTTPServerConfigFromDirectives`, then pass it to
`httpserver.Serve` with their listener, root security configuration, context,
and logger. Keep feature-specific configuration in its existing owning types
and parsers.

Pass a fresh security graph to each runtime. `Serve` owns the listener even
when validation fails, constructs the runtime, and closes it after admitted
requests finish. Typed validation and directive parsing do not open files or
provision components. Runtime construction can provision a local database;
do not describe a construction-based check as side-effect-free validation.
File parsing and listener configuration validation happen before the CLI binds
its socket; runtime initialization follows and unwinds resources on failure.

Structural checks inspect only declared JSON objects and collections; opaque
provider `params` remain with their owning validators. The public error message
for failed initialization is redacted. Embedding code can inspect the wrapped
cause with `errors.Unwrap` for private diagnostics, but that cause may contain
configuration credentials and must not be copied to shared logs or responses.
