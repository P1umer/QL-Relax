/**
 * @id 5
 * @kind path-problem
 * @name NPD - New API
 */
import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.ir.IR


module MaybeNullToDerefConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    maybeNull(source.asExpr())
  }

  predicate isSink(DataFlow::Node sink) {
    dereferenced(sink.asExpr())
  }
  
    // Correct barrier implementation - directly corresponds to the negation condition of the original query
predicate isBarrier(DataFlow::Node node) {
  exists(IfStmt ifstmt, Variable v, DataFlow::Node source, DataFlow::Node sink |
    // Basic conditions
    node.asExpr() = v.getAnAccess() and
    ifstmt.getCondition().getAChild*() = v.getAnAccess()
  )
}
}

module MaybeNullToDerefFlow = DataFlow::Global<MaybeNullToDerefConfig>;

import MaybeNullToDerefFlow::PathGraph

from MaybeNullToDerefFlow::PathNode source, MaybeNullToDerefFlow::PathNode sink
where MaybeNullToDerefFlow::flowPath(source, sink)
 select
   // The first parameter is usually the location where the issue is reported (sink node)
   sink.getNode(),
   source, // source PathNode for the first placeholder in the message
   sink, // sink PathNode for the second placeholder in the message
   "Potential null pointer dereference vulnerability: variable is $@ and $@.", source.getNode().toString(),
   sink.getNode().toString()