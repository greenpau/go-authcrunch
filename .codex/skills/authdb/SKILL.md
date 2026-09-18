---
name: authdb
description: Maintain the standalone cmd/authdb server, pkg/httpserver listener and portal routing, HTTP configuration parser, TLS, shutdown, executable tests, and deployment guidance. Use authdbctl for the management client.
---

# AuthDB Server

`cmd/authdb` runs AuthCrunch with Go's `net/http`, without Caddy. The user-facing
[`cmd/authdb/README.md`](../../../cmd/authdb/README.md) owns usage instructions,
the JSON envelope, bootstrap, listener settings, and operating guidance. Keep
its examples synchronized with the executable and the credential-free
[`cmd/authdb/config.json`](../../../cmd/authdb/config.json). Use
[configuration integration](references/configuration-and-operations.md) for
the reusable Go host boundary.

## Ownership

- `cmd/authdb/main.go` owns command flags, strict bounded JSON file loading,
  version metadata, production logging, TCP binding, and SIGINT/SIGTERM handling.
- `pkg/httpserver.Config` and `PortalRoute` own transport defaults and semantic
  validation. The CLI's `http` object is this public config; `security` is the
  existing root `authcrunch.Config`, not a new copy of its feature models.
- `pkg/httpserver/parser.NewHTTPServerConfigFromDirectives([]string)` returns
  `(*httpserver.Config, error)`. It parses encoded block-body statements and
  calls `Config.Validate`; no file access, listeners, or provisioning occur.
- `pkg/httpserver.Serve(ctx, listener, config, security, logger)` takes ownership
  of the listener immediately, including on error, and owns its constructed
  root runtime until all admitted requests have finished. Pass a fresh security
  graph and do not mutate it while serving.

The host checks serialized object collections before provisioning: optional
objects can be absent, but typed collections cannot contain null objects.
Keep this check limited to the declared JSON model; provider `params` values
remain owned by their validators. Guard incomplete raw crypto statements before
calling the legacy KMS decoder. Initialization errors expose a redacted message;
their wrapped causes are available to embedding code for private diagnostics
and may contain credentials. Do not print those causes from the executable.

Keep portal authentication, APIs, provider callbacks, cookies, MFA, refresh,
and OIDC behavior in their existing packages. The HTTP host supplies routing
and lifecycle, rather than copying endpoint logic. It does not provide an
application reverse proxy or a forward-auth endpoint; merely declaring root
`authorization_policies` does not publish a new HTTP resource.

## Configuration Parser

Host adapters encode each complete statement with `cfgutil.EncodeArgs` after
checking for empty tokens. The public parser uses `cfgutil.DecodeArgs`.

| Statement | Meaning/default |
| --- | --- |
| `listen <host:port>` | TCP address; omitted means `127.0.0.1:8443`; numeric port 0 selects an ephemeral port |
| `tls certificate <path>` | PEM certificate chain; required for HTTPS |
| `tls key <path>` | PEM private key; required for HTTPS |
| `insecure http enabled` / `insecure http disabled` | Explicit plaintext opt-in; disabled by default; cannot combine enabled with TLS files |
| `timeout read header <duration>` | Header deadline; `10s` |
| `timeout read <duration>` | Entire request read deadline; `30s` |
| `timeout write <duration>` | Response write deadline; `60s` |
| `timeout idle <duration>` | Keep-alive idle deadline; `120s` |
| `timeout shutdown <duration>` | Graceful drain window; `30s` |
| `max header bytes <number>` | Header limit; zero/omitted means `1048576`, otherwise 1024–16777216 |
| `portal <name> <path>` | Repeatable named portal mounts; at least one required |

Durations must be positive and at most 24 hours. Singleton directives cannot
repeat, including enabled/disabled spellings. Portal names are unique and paths
cannot overlap. Reject CR/LF, malformed quoting, wrong arity, empty values, and
unknown settings without echoing untrusted statement contents. Errors return a
nil result. Typed validation owns defaults and constraints; do not reproduce
them in CLI parsing. New settings need typed, parser, and consumer coverage.

## Routing and Lifecycle

Keep paths intact when delegating to `authn.Portal.ServeHTTP`. Mount roots
redirect temporarily to their own `/login`, preserving the query; nonmatching
paths return 404. Routes use segment boundaries, canonical paths, and reserved
portal namespace/prefix checks. Do not let `http.ServeMux` clean a malformed path into
a different namespace, and do not strip a mount before delegation. Refresh
base paths and OIDC issuer paths must match their portal mounts.

The direct listener discards `Forwarded`, all `X-Forwarded-*`, and `X-Real-IP`
headers before invoking AuthCrunch. TLS terminates locally; there is no trusted
proxy configuration. Preserve a cloned request so an embedding caller's headers
are not mutated. The portal retains responsibility for its own origin checks.

Load TLS keys before constructing the runtime, use TLS 1.2 or newer, and leave
HTTP/2 negotiation to `net/http`. Snapshot transport decisions before starting
Serve/ServeTLS: the standard library may initialize `Server.TLSConfig` while
starting even an HTTP listener. Reading it concurrently caused a race caught by
the executable test.

On shutdown, stop admitting requests, call `http.Server.Shutdown` with a fresh
bounded context, and keep accepted request contexts alive during the drain. At
the deadline, cancel them and close connections. Await handler completion before
`authcrunch.Server.Close`; a shutdown timeout remains an error. The deadline
bounds graceful HTTP draining, not arbitrary blocking code in a custom provider.
Unexpected accept failures also drain and dispose resources and return an error.
Normal signal-driven shutdown returns success.
The executable restores default signal handling after the first signal, so a
second SIGINT/SIGTERM can interrupt a blocked drain or provider initialization.

Track whether a portal committed its response: an unwritten handler error gets
500; a committed response must not receive another status/body. Never put raw
handler errors, requests, configuration objects, or credentials in host logs.
Log readiness using the actual listener address, including an ephemeral port.

## Command-Line Contract

Use `urfave/cli/v2`, as in `authdbctl`. `authdb run --config PATH` starts the
server; no command shows help. Preserve `help`, `help run`, `version`, and the
`--help`/`-h`, `--version`/`-v`, `--config`/`-c`, and `--debug` flags. Help and
version write to the app's stdout writer without loading configuration.
`main` owns process exit; built-in help errors must return through `run`.

Create fresh apps and flags for each invocation. Config/debug flag actions
apply root values first and explicit `run` values second, so options work on
both sides of the command. Only the root config flag reads `AUTHDB_CONFIG_PATH`;
otherwise a child flag's environment/default could overwrite an explicit global
option. Command flags take precedence over global flags, then environment, then
the existing working-directory `authdb.json` default. Honor `--debug=false`.
The version banner retains the repository's versioned build metadata.

Debug switches the structured JSON logger from info to debug, retaining real
portal logging and stderr output. Keep credential-redaction assertions active
in the executable TLS login journey with debug enabled. E2E subprocesses remove
ambient `AUTHDB_*` variables and add only their own configuration environment.

## Validation

`cmd/authdb/e2e_test.go` builds the real executable with the race detector and
uses private temporary JSON files, TLS certificates, and identity databases. It
covers root/nested mounts, HTTP/2 login and browser assets, native login,
authenticated/anonymous APIs, listener conflicts, bad configuration and redacted
startup failures, multiple portals, HTTP opt-in, persistence across restart,
clean process shutdown, and interruption by a second signal during a drain.
Keep failures bounded and reap subprocesses. Configure HTTP/2 on TLS fixture
clients before using or closing their fixture: transport protocol setup is lazy
and runs only once.

`pkg/httpserver/server_e2e_test.go` imports the public transport, refresh, and
OIDC parsers, serializes their results, and starts `httpserver.Serve`. It checks
OIDC discovery/keys, native refresh rotation/logout, and the actual TLS header
read deadline. `server_test.go` checks graceful drain, forced cancellation,
listener failure, routing, and initialization cleanup. Parser grammar tests and
its executable example stay in external `package parser_test`.

```sh
make test TEST_DIR='./cmd/authdb ./pkg/httpserver/...' COVERAGE_DIR=.coverage/authdb
make ci-check
```

`make build` builds both executables. Keep `VERSION` projections and isolated
release fixtures synchronized when changing server metadata; adding this binary
does not authorize a version bump or release. Packaging ownership remains with
[release-and-versioning](../release-and-versioning/SKILL.md).
