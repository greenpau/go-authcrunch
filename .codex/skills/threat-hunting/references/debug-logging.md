# Administrator debug logging

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
- Info, Warn, Error, DPanic, Panic, Fatal, standard-library logging and dynamic
  levels remain eligible for findings. A debug-enabled logger does not make an
  Info or Warn call a debug diagnostic.
- `With` and `WithOptions` attach fields that may outlive one debug call. They
  remain eligible even when followed by Debug; trace their later uses.
- Claims are not globally sanitized data. The same value may be accepted at a
  debug sink and reportable at a Warn sink. Keep other queries, including log
  injection at Debug calls, active.

`pkg/acl/rule.go` contains explicit Debug/Info/Warn/Error variants. Never exempt
that whole file or infer the level from a type name. Portal profile warnings
also require separate review. Historical alert line numbers may refer to older
code; inspect the alert revision before equating it with the current checkout.

This policy does not authorize adding passwords, private signing keys or
unrelated secrets to logs. Use the least diagnostic data needed, and review the
intent and destination: static analysis can recognize the method, not prove
the administrator-only deployment boundary. Synthetic CodeQL regression inputs
use password taint to exercise the upstream query, not real credentials.

For GitHub activation, the exact query replacement, local scans and regression
tests, use the [CodeQL workflow](../../scripts-and-automation/references/codeql.md).
Do not disable `go/clear-text-logging` globally or add file/path-wide exclusions.
Classify qualifying existing alerts as accepted administrator diagnostics;
do not claim their data flow is absent or that a hosted alert was dismissed
without observing the remote result.
