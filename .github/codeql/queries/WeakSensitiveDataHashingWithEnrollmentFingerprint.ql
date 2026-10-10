/**
 * @name Use of a broken or weak cryptographic hashing algorithm on sensitive data
 * @description Using broken or weak cryptographic hashing algorithms outside the accepted
 *              SQLite enrollment fingerprint can compromise security.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id go/weak-sensitive-data-hashing
 * @tags security
 *       external/cwe/cwe-327
 *       external/cwe/cwe-328
 *       external/cwe/cwe-916
 */

import go
import semmle.go.security.WeakSensitiveDataHashingCustomizations

/**
 * Provides a taint-tracking configuration for detecting use of a broken or weak
 * cryptographic hash function on sensitive data, that does NOT require a
 * computationally expensive hash function.
 */
module NormalHashFunctionFlow {
  import NormalHashFunction

  private module Config implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source instanceof Source }

    predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

    predicate isBarrier(DataFlow::Node node) { node instanceof Barrier }

    predicate isBarrierIn(DataFlow::Node node) {
      // Make sources barriers so that we only report the closest instance.
      isSource(node)
    }

    predicate isBarrierOut(DataFlow::Node node) {
      // Make sinks barriers so that we only report the closest instance.
      isSink(node)
    }

    predicate observeDiffInformedIncrementalMode() { any() }
  }

  import TaintTracking::Global<Config>
}

/**
 * Provides a taint-tracking configuration for detecting use of a broken or weak
 * cryptographic hashing algorithm on passwords.
 *
 * Passwords have stricter requirements on the hashing algorithm used (it must
 * be computationally expensive to prevent brute-force attacks).
 */
module ComputationallyExpensiveHashFunctionFlow {
  import ComputationallyExpensiveHashFunction

  private module Config implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source instanceof Source }

    predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

    predicate isBarrier(DataFlow::Node node) { node instanceof Barrier }

    predicate isBarrierIn(DataFlow::Node node) {
      // Make sources barriers so that we only report the closest instance.
      isSource(node)
    }

    predicate isBarrierOut(DataFlow::Node node) {
      // Make sinks barriers so that we only report the closest instance.
      isSink(node)
    }

    predicate observeDiffInformedIncrementalMode() { any() }
  }

  import TaintTracking::Global<Config>
}

/**
 * Global taint-tracking for both variants of weak hashing on sensitive data.
 * The configurations are merged to generate one combined path graph.
 */
module WeakSensitiveDataHashingFlow =
  DataFlow::MergePathGraph<NormalHashFunctionFlow::PathNode,
    ComputationallyExpensiveHashFunctionFlow::PathNode, NormalHashFunctionFlow::PathGraph,
    ComputationallyExpensiveHashFunctionFlow::PathGraph>;

import WeakSensitiveDataHashingFlow::PathGraph

/**
 * The SQLite account store uses SHA-256 only to create durable idempotency
 * evidence from canonical account metadata and an already validated bcrypt
 * hash. Match the complete expression and owner so another SHA-256 operation,
 * even in this file or method, remains reportable.
 */
private predicate isSQLiteEnrollmentFingerprintSink(DataFlow::Node node) {
  exists(CallExpr hashCall, CallExpr appendCall |
    node.asExpr() = appendCall and
    appendCall = hashCall.getArgument(0) and
    hashCall.getTarget().hasQualifiedName("crypto/sha256", "Sum256") and
    hashCall.getLocation().getFile().getRelativePath() =
      "plugins/identity-stores/sqlite/store.go" and
    hashCall.getEnclosingFunction().getName() = "CreateEnrollment" and
    appendCall.getCalleeName() = "append" and
    appendCall.getNumArgument() = 2 and
    appendCall.hasEllipsis() and
    appendCall.getArgument(0).(Ident).getName() = "canonical" and
    appendCall.getArgument(1).(Ident).getName() = "hash"
  )
}

from
  WeakSensitiveDataHashingFlow::PathNode source, WeakSensitiveDataHashingFlow::PathNode sink,
  string ending, string algorithmName, string classification
where
  (
    NormalHashFunctionFlow::flowPath(source.asPathNode1(), sink.asPathNode1()) and
    algorithmName = sink.getNode().(NormalHashFunction::Sink).getAlgorithmName() and
    classification = source.getNode().(NormalHashFunction::Source).getClassification() and
    ending = "."
    or
    ComputationallyExpensiveHashFunctionFlow::flowPath(source.asPathNode2(), sink.asPathNode2()) and
    algorithmName =
      sink.getNode().(ComputationallyExpensiveHashFunction::Sink).getAlgorithmName() and
    classification =
      source.getNode().(ComputationallyExpensiveHashFunction::Source).getClassification() and
    (
      sink.getNode().(ComputationallyExpensiveHashFunction::Sink).isComputationallyExpensive() and
      ending = "."
      or
      not sink.getNode().(ComputationallyExpensiveHashFunction::Sink).isComputationallyExpensive() and
      ending =
        " for " + classification +
          " hashing, since it is not a computationally expensive hash function."
    )
  ) and
  not isSQLiteEnrollmentFingerprintSink(sink.getNode())
select sink.getNode(), source, sink,
  "$@ is used in a hashing algorithm (" + algorithmName + ") that is insecure" + ending,
  source.getNode(), "Sensitive data (" + classification + ")"
