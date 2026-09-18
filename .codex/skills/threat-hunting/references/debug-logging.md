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
- Outside the ACL rule exception below, Info, Warn, Error, DPanic, Panic,
  Fatal, standard-library logging and dynamic levels remain eligible for
  findings. A debug-enabled logger does not make an Info or Warn call a debug
  diagnostic.
- `With` and `WithOptions` attach fields that may outlive one debug call. They
  remain eligible even when followed by Debug; trace their later uses.
- Claims are not globally sanitized data. The same value may be accepted at a
  debug sink and reportable at a Warn sink. Keep other queries, including log
  injection at Debug calls, active.

Portal profile warnings require separate review. Historical alert line numbers
may refer to older code; inspect the alert revision before equating it with
the current checkout.

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
