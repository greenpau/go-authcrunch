/**
 * @name Regular expression injection
 * @description User input should not be used in regular expressions without first being escaped,
 *              except for the accepted Documents browser test driver.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id js/regex-injection
 * @tags security
 *       external/cwe/cwe-400
 */

import javascript
import semmle.javascript.security.dataflow.RegExpInjectionQuery
import RegExpInjectionFlow::PathGraph

// The Go E2E harness supplies this test driver's mount. Exempt only this rule
// at this exact sink file; retain other rules and flows into sinks elsewhere.
from RegExpInjectionFlow::PathNode source, RegExpInjectionFlow::PathNode sink
where
  RegExpInjectionFlow::flowPath(source, sink) and
  not sink.getNode().getLocation().getFile().getRelativePath() =
    "pkg/authn/ui/testdata/documents_browser_e2e.cjs"
select sink.getNode(), source, sink, "This regular expression is constructed from a $@.",
  source.getNode(), source.getNode().(Source).describe()
