---
name: authdbctl
description: Maintain cmd/authdbctl commands, flags, configuration, terminal input, management retries, output, and executable E2E tests. Use authentication-client for the reusable portal login protocol.
---

# AuthDB Management CLI

## Ownership and Contracts

`cmd/authdbctl` owns application paths, configuration discovery, flags/env,
terminal input, management commands, retry decisions, and output. Use
`authentication-client` for the importable login protocol and token-file
contracts. Keep CLI and admin API dependencies out of `pkg/authclient`.
`connect` authenticates through `/login` even when the admin API is disabled.

Preserve `AUTHDBCTL_*` environment names and `~/.config/authdbctl` defaults.
Explicit flags override environment; YAML `token_path` overrides the path flag.
Freshly acquired credentials replace the in-memory cache only after a successful
file save. A failed login/save must preserve previously usable credentials.

Keep one buffered reader per wrapper for plain identity input; creating readers
for consecutive prompts can discard piped lines. Hidden prompts use a real
terminal, with terminal state owned by the caller and restored on completion,
error, or context timeout. The raw-mode line editor handles Ctrl-C/Ctrl-D as EOF.
A pending read must not change OS terminal settings after cancellation. Prompt
cancellation ends the command; do not start another prompt while that read is
pending. Do not move terminal IO into the reusable authentication package.

Management requests attach opaque credentials and reuse the cache. Access denial
may cause a fresh login only when another attempt remains. System messages have
token attachment disabled and must not trigger login. Validate management HTTP
200 bodies as JSON objects and reject `status: failure`; a failed mutation must
return an error without retrying. Malformed responses, including `null`, must
not produce a successful command exit. Preserve the original successful JSON
body for output, including generated credentials the command is meant to return.
Never put response bodies or configured secrets in error diagnostics.

Marshal realm/user fields as JSON rather than interpolating strings. A user
update selects exactly one operation; reject absent or conflicting selections
before configuration, login, or mutation. Hash generation may print the new hash
and intentionally generated API key, but must not print supplied password
fragments. Report encryption-key setup failures as errors.

## Test Boundaries

Keep corresponding tests for every Go change, including CLI helpers. The tests
are in the default suite, with no external accounts or services:

- `authentication_test.go`: authentication adapter, credential precedence,
  cache reuse, and login/retry behavior using scripted HTTP responses.
- `commands_test.go`: every management action, exact method/path/header/JSON
  payload, escaped realm names, response errors, configuration failures, and
  CSV/table output. Fresh flag sets prevent shared urfave flag state.
- `failures_test.go`: configuration and filesystem failures, failed credential
  saves, transport/read errors, malformed management responses, reauthentication
  failures, retry limits, and cancellation.
- `utility_commands_test.go`: bcrypt verification of generated hashes, password
  policy/cost errors, system-key permissions, and encrypted request/response
  round trips without access-token authentication.
- `terminal_test.go` and `testdata/terminal.py`: real pseudo-terminal input,
  hidden echo, MFA choice mapping, EOF/interruption, and timeout restoration.
  Python 3's standard library supplies the PTY on Unix; missing Python is a
  failure there. Only PTY-dependent cases skip on Windows. Close the broker
  before its slave descriptor so pending reads unblock during cleanup.
- `e2e_test.go`: build the real race-instrumented executable once, then run
  subprocesses with isolated homes and sanitized `AUTHDBCTL_*` environment.
  Use a real `authn.Portal` and temporary local identity database. Exercise
  configured password/TOTP/API keys, piped identity, interactive password/TOTP
  and combined MFA, rejected credentials and unsupported MFA choices, config
  routing, help/version, missing flags, cached authentication and re-login,
  and the complete management lifecycle. Assert on-disk identity changes,
  command exit status, token permissions, and authentication of saved tokens
  through `/whoami` using a separate client.

Executable E2E uses loopback HTTP with explicitly insecure fixture cookies;
`pkg/authclient` independently covers real TLS portal integration. Enable the
admin API only for management cases. Assert authentication-only cases issue
only login requests. Never use live credentials or a real user's config/cache.
WebAuthn rejection tests do not establish hardware assertion support.

Capture prompt output when testing functions directly. An unterminated prompt
can absorb Go's test event markers and make the structured report incomplete
even when the Go process exits successfully. Keep failure reports until the
corrected run has its own evidence.

## Validation

```sh
make test TEST_DIR='./cmd/authdbctl' COVERAGE_DIR='.coverage/authdbctl'
make test TEST_DIR='./cmd/authdbctl' TEST='^TestE2EAuthdbctl$' COVERAGE_DIR='.coverage/authdbctl-e2e'
make test TEST_DIR='./pkg/authclient' COVERAGE_DIR='.coverage/authclient' MINIMUM_COVERAGE=100
make ci-check
go vet ./...
```

Report measured CLI statement coverage separately from executable E2E results:
the subprocess binary is not included in the parent Go test coverage profile.
Do not claim the CLI is 100% covered because its executable passes E2E tests.
The reusable package retains its own explicit 100% gate. Inspect tested's final
outcome and incomplete-test count, not only the Go process status.
