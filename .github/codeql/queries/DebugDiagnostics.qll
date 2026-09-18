/** AuthCrunch's explicit administrator debug logging exception. */

import go

private predicate isDebugDiagnostic(LoggerCall logger) {
  exists(DataFlow::MethodCallNode call | call = logger |
    call.getTarget().hasQualifiedName("go.uber.org/zap", "Logger", "Debug")
    or
    call.getTarget()
        .hasQualifiedName("go.uber.org/zap", "SugaredLogger", ["Debug", "Debugf", "Debugw"])
  )
}

/**
 * Accept only a sink used exclusively by explicit Zap debug calls. In particular,
 * With/WithOptions, dynamic levels and other loggers remain reportable. Do not
 * turn the data itself into a sanitizer: it may also reach a non-debug sink.
 */
predicate isAdminDebugSink(DataFlow::Node node) {
  exists(LoggerCall logger | node = logger.getAValueFormattedMessageComponent()) and
  forall(LoggerCall logger | node = logger.getAValueFormattedMessageComponent() |
    isDebugDiagnostic(logger)
  )
}
