/**
 * @name Clear-text logging of sensitive information
 * @description Logging sensitive information outside intentional administrator debug
 *              diagnostics can expose it to an attacker.
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

// Retain the upstream flow model, rule ID, locations and message. Only the
// accepted debug sinks differ from Security/CWE-312/CleartextLogging.ql.
from CleartextLogging::Flow::PathNode source, CleartextLogging::Flow::PathNode sink
where
  CleartextLogging::Flow::flowPath(source, sink) and
  not isAdminDebugSink(sink.getNode())
select sink.getNode(), source, sink, "$@ flows to a logging call.", source.getNode(),
  "Sensitive data returned by " + source.getNode().(CleartextLogging::Source).describe()
