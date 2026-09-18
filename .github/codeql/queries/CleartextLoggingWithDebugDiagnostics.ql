/**
 * @name Clear-text logging of sensitive information
 * @description Logging sensitive information outside accepted administrator debug,
 *              realm-name, error, user, claims and ACL rule diagnostics can expose it to an attacker.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id go/clear-text-logging
 * @tags security
 *       external/cwe/cwe-312
 *       external/cwe/cwe-315
 *       external/cwe/cwe-359
 */

import go
import semmle.go.security.CleartextLogging
import CleartextLogging::Flow::PathGraph
import DebugDiagnostics
import StructuredDiagnostics

// Retain the upstream flow model, rule ID, locations and message. Only the
// accepted debug, structured diagnostic and ACL rule sinks differ from the upstream query.
from CleartextLogging::Flow::PathNode source, CleartextLogging::Flow::PathNode sink
where
  CleartextLogging::Flow::flowPath(source, sink) and
  not isAdminDebugSink(sink.getNode()) and
  not isRealmDiagnosticSink(sink.getNode()) and
  not isErrorDiagnosticSink(sink.getNode()) and
  not isUserDiagnosticSink(sink.getNode()) and
  not isClaimsDiagnosticSink(sink.getNode()) and
  // This exact file is an accepted logging surface at every level. Other
  // queries and flows from this file to logging sinks elsewhere stay active.
  not sink.getNode().getLocation().getFile().getRelativePath() = "pkg/acl/rule.go"
select sink.getNode(), source, sink, "$@ flows to a logging call.", source.getNode(),
  "Sensitive data returned by " + source.getNode().(CleartextLogging::Source).describe()
