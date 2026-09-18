# Accepted diagnostic logging

## Administrator debug logging

AuthCrunch intentionally exposes user claims and authentication diagnostics to
administrators troubleshooting a portal. Claims, identity payloads, session and
ACL decisions, and OAuth/OIDC token responses, tokens, authorization codes and
userinfo at explicit debug level are an accepted diagnostic behavior. Preserve
that visibility; do not redact it or report it as a vulnerability solely because
the payload contains sensitive information.

The exception assumes an administrator deliberately enables debug logging and
controls access to its destination. Report independently demonstrated exposure
to non-admins, default delivery to an untrusted destination, or sensitive output
returned in a user-visible response. Merely seeing a tainted value reach Debug
does not establish one of those conditions.

Inspect the actual call and data flow:

- `zap.Logger.Debug` and `zap.SugaredLogger.Debug`, `Debugf`, and `Debugw` are the
  explicit levels recognized by the CodeQL exception.
- Outside the structured realm, error, user, claims, and ACL rule exceptions
  below, Info, Warn, Error, DPanic, Panic, Fatal, standard-library logging and dynamic
  levels remain eligible for findings. A debug-enabled logger does not make an
  Info or Warn call a debug diagnostic.
- `With` and `WithOptions` attach fields that may outlive one debug call. They
  remain eligible even when followed by Debug; trace their later uses. A direct
  realm-name, typed-error, user-payload, or claims field may independently
  qualify for the exceptions below.
- Claims are accepted at the structured sinks described below, not globally
  sanitized data. Other loggers and unrelated fields remain analyzed. Keep
  other queries, including log injection at Debug calls, active.

Portal profile warnings require separate review. Historical alert line numbers
may refer to older code; inspect the alert revision before equating it with
the current checkout.

## Realm-name diagnostics

Realm names identify authentication routing and are accepted operational metadata
at ordinary logging levels as well as Debug. Suppress `go/clear-text-logging`
only for a direct `go.uber.org/zap.String` field with constant key `realm` or
`auth_realm` whose value directly reads a struct field named `Realm`.
Examples include `zap.String("realm", r.Realm)` and
`zap.String("auth_realm", rr.Upstream.Realm)` on a Zap Logger call. Direct
`Logger.With` fields also qualify. Resolve actual function/method targets rather
than matching source text; unrelated loggers do not qualify.

The exception applies to that individual field, never to every field in the same
log call. A neighboring password, token, or session identifier retains its
existing analysis. Error and user fields have their own exceptions below.
A string field merely labeled `realm` does not qualify when its value is a
password field, an arbitrary expression, or an aggregate object. Other keys,
dynamic keys, wrappers, sugared key/value
calls, and standard-library logging retain their existing checks.

Keep the accepted realm field as a sink filter in the custom query. Do not
globally sanitize `Realm` values, their containing request objects, or HTTP
headers. The same value logged elsewhere remains analyzed, and other queries
such as log injection continue to inspect realm diagnostics. This policy assumes
`Realm` contains a realm name; it does not authorize putting credentials there.

## Structured error diagnostics

Operational error diagnostics are accepted at ordinary Zap Logger levels as
well as Debug. Suppress `go/clear-text-logging` for direct
`zap.Any("error", err)`, `zap.NamedError("error", err)`, and `zap.Error(err)`
fields when the argument's static type implements Go's `error` interface.
This includes concrete error types and direct `Logger.With` fields. Resolve
actual Zap targets and require the constant `error` key for Any and NamedError.

Apply the exception to the individual error field, including when the same call
also logs realm metadata or user data. A password string, map, arbitrary object,
or value with static type `any` merely labeled `error` does not qualify.
Other keys, dynamic keys, wrappers, sugared key/value calls, `WithOptions`, and
unrelated loggers retain their existing checks. Neighboring payload, credential,
and session fields remain subject to their own logging policy.

This is an accepted diagnostic sink, not proof that an error cannot contain
sensitive data. Do not globally sanitize errors, their message text, or data
that flows into them. Log injection and other rules still inspect these fields.
The policy does not authorize adding credentials to error messages.

## Structured user payloads

User payloads deliberately logged as `zap.Any("user", payload)` are accepted
authentication diagnostics at ordinary Zap Logger levels as well as Debug.
This includes user claims, maps, and user objects, even when the upstream query
tracks sensitive data into the payload. Direct `Logger.With` fields also qualify.
Recognize the actual `go.uber.org/zap.Any` function and constant `user` key;
do not infer an exception from a variable name or the log message.

Suppress only that individual field for `go/clear-text-logging`. Separate
password, token, session, and other payload fields in the same call remain
analyzed unless they independently qualify for an accepted exception. Other
keys outside the claims exception below, constructors, dynamic keys, wrappers,
sugared calls, `WithOptions`, and unrelated loggers keep their existing analysis. Do not
globally sanitize claims or user objects; other destinations and queries,
including log injection, remain in scope. This policy preserves intentional
diagnostics and does not authorize adding new secrets to user payloads.

## Claims and individual claim fields

Claims and the fields inside them are accepted troubleshooting diagnostics at
ordinary Zap Logger levels as well as Debug. Suppress `go/clear-text-logging`
for `zap.Any("claims", payload)`, including claim maps, and for a direct Zap
field constructor with a constant key whose value is AuthCrunch's
`github.com/greenpau/go-authcrunch/pkg/user.Claims` or a direct read within it.
This includes `zap.String("jti", parsedUser.Claims.ID)`, whole claims under
other keys, nested struct fields, map/slice elements, slices, type assertions,
parentheses, and pointer operations. A typed claims variable retains this
recognition; arbitrary functions and expressions combining claims with other
values do not.

Recognize the qualified claims type and actual Zap targets, not a variable or
unrelated struct/type named `Claims`. A password string merely labeled `jti`
or `claims` does not qualify. Direct `Logger.With` fields qualify; dynamic
keys, wrappers, sugared calls, `WithOptions`, and other loggers retain their
existing analysis. As with user payloads, the explicit `zap.Any("claims", ...)`
form identifies the aggregate diagnostic by its constant key.

Apply the exception to each individual logging field. Neighboring request or
session identifiers, credentials, and other payloads remain analyzed unless
they independently qualify. Do not sanitize the claims source or remove it
from the upstream flow model. Log injection and other queries remain active.
Alert 1651's profile warning logs the JTI claim at Warn level and qualifies
under this policy; it does not require changing runtime logging or severity.

## ACL rule logging

Suppress all `go/clear-text-logging` findings whose logging sink is in exactly
`pkg/acl/rule.go`, at every logging level. This is an explicit accepted
diagnostic surface, including the Info/Warn/Error ACL rule variants; do not
restrict this file's exception to Debug or redact its payloads to clear those
alerts.

The exception applies only to that rule and exact repository-relative file.
Other rules still analyze the file. Adjacent files, similarly named files and
nested paths ending in `pkg/acl/rule.go` do not qualify. Data originating in
the exempt file and logged elsewhere remains subject to the destination's
normal checks. Implement this as a sink-location filter in the custom query,
never by omitting the file from extraction or marking its data sanitized.

## Scope and maintenance

This policy does not authorize adding passwords, private signing keys or
unrelated secrets to logs. Use the least diagnostic data needed, and review the
intent and destination: static analysis can recognize the method, not prove
the administrator-only deployment boundary. Synthetic CodeQL regression inputs
use password taint to exercise the upstream query, not real credentials.

For GitHub activation, the exact query replacement, local scans and regression
tests, use the [CodeQL workflow](../../scripts-and-automation/references/codeql.md).
Do not disable `go/clear-text-logging` globally or broaden the exact ACL
rule/file exception to other files or queries. Classify qualifying existing
alerts as accepted diagnostics; do not claim their data flow is absent or
that a hosted alert was dismissed without observing the remote result.
