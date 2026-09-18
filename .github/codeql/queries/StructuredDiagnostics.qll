/** AuthCrunch's accepted structured realm-name, error, user and claims diagnostics. */

import go

private predicate isZapDiagnostic(LoggerCall logger) {
  exists(DataFlow::MethodCallNode call | call = logger |
    call.getTarget()
        .hasQualifiedName("go.uber.org/zap", "Logger",
          ["Debug", "Info", "Warn", "Error", "DPanic", "Panic", "Fatal", "With"])
  )
}

/** A component used exclusively by recognized structured Zap logging calls. */
private predicate isStructuredZapSink(DataFlow::Node node) {
  exists(LoggerCall logger | node = logger.getAValueFormattedMessageComponent()) and
  forall(LoggerCall logger | node = logger.getAValueFormattedMessageComponent() |
    isZapDiagnostic(logger)
  )
}

/**
 * A direct structured realm-name field, not an entire logging call or a global
 * sanitizer. Requiring both the key and a Realm field read avoids accepting
 * passwords, aggregate objects, or arbitrary expressions merely labeled realm.
 */
predicate isRealmDiagnosticSink(DataFlow::Node node) {
  exists(DataFlow::CallNode field |
    node = field.getResult() and
    field.getTarget().hasQualifiedName("go.uber.org/zap", "String") and
    field.getArgument(0).getStringValue() = ["realm", "auth_realm"] and
    field.getArgument(1).(DataFlow::FieldReadNode).getFieldName() = "Realm"
  ) and
  isStructuredZapSink(node)
}

/**
 * An individual error field. A value merely labeled error must not qualify
 * unless its static type implements Go's error interface. The idiomatic
 * zap.Error form uses the same field name and is accepted too.
 */
predicate isErrorDiagnosticSink(DataFlow::Node node) {
  exists(DataFlow::CallNode field |
    node = field.getResult() and
    (
      field.getTarget().hasQualifiedName("go.uber.org/zap", ["Any", "NamedError"]) and
      field.getArgument(0).getStringValue() = "error" and
      field.getArgument(1).getType() instanceof ErrorType
      or
      field.getTarget().hasQualifiedName("go.uber.org/zap", "Error") and
      field.getArgument(0).getType() instanceof ErrorType
    )
  ) and
  isStructuredZapSink(node)
}

/** An explicitly labeled user payload, scoped to its individual Zap field. */
predicate isUserDiagnosticSink(DataFlow::Node node) {
  exists(DataFlow::CallNode field |
    node = field.getResult() and
    field.getTarget().hasQualifiedName("go.uber.org/zap", "Any") and
    field.getArgument(0).getStringValue() = "user"
  ) and
  isStructuredZapSink(node)
}

/**
 * Claims themselves or direct reads within them, including nested fields and
 * map/slice elements. The qualified type identifies AuthCrunch claims, not a
 * variable, key or unrelated struct field that happens to be named Claims.
 * Do not propagate this policy through arbitrary calls or mixed expressions.
 */
private predicate isClaimsExpression(Expr value) {
  lookThroughPointerType(value.getType())
      .hasQualifiedName("github.com/greenpau/go-authcrunch/pkg/user", "Claims")
  or
  isClaimsExpression(value.(SelectorExpr).getBase())
  or
  isClaimsExpression(value.(IndexExpr).getBase())
  or
  isClaimsExpression(value.(SliceExpr).getBase())
  or
  isClaimsExpression(value.(TypeAssertExpr).getExpr())
  or
  isClaimsExpression(value.(ParenExpr).getExpr())
  or
  isClaimsExpression(value.(StarExpr).getBase())
  or
  isClaimsExpression(value.(AddressExpr).getOperand())
}

/** Accepted whole-claims payloads and individual typed claim fields. */
predicate isClaimsDiagnosticSink(DataFlow::Node node) {
  exists(DataFlow::CallNode field |
    node = field.getResult() and
    (
      field.getTarget().hasQualifiedName("go.uber.org/zap", "Any") and
      field.getArgument(0).getStringValue() = "claims"
      or
      field.getTarget().hasQualifiedName("go.uber.org/zap", _) and
      exists(field.getArgument(0).getStringValue()) and
      isClaimsExpression(field.getArgument(1).asExpr())
    )
  ) and
  isStructuredZapSink(node)
}
