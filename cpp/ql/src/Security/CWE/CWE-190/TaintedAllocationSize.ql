/**
 * @name Uncontrolled allocation size
 * @description Allocating memory with a size controlled by an external user can result in
 *              arbitrary amounts of memory being allocated.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision low
 * @id cpp/uncontrolled-allocation-size
 * @tags reliability
 *       security
 *       external/cwe/cwe-190
 *       external/cwe/cwe-789
 */

import cpp
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.ir.IR
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.security.FlowSources
import TaintedAllocationSize::PathGraph
import Bounded

/**
 * Holds if `alloc` is an allocation, and `tainted` is a child of it that is a
 * taint sink.
 */
predicate allocSink(Expr alloc, DataFlow::Node sink) {
  exists(Expr e | e = sink.asExpr() |
    (
      alloc instanceof AllocationExpr or
      alloc instanceof FunctionCall
    ) and
    e = alloc.getAChild()
  )
}

predicate readsVariable(LoadInstruction load, Variable var, IRBlock bb) {
  load.getSourceAddress().(VariableAddressInstruction).getAstVariable() = var and
  bb = load.getBlock()
}

predicate isFlowSource(FlowSource source, string sourceType) { 
  sourceType = source.getSourceType() or
  sourceType = "expanded-source"
}

<<<<<<< HEAD
predicate variableEqualityCheckedInBlock(Variable checkedVar, IRBlock bb) {
  exists(Operand access |
    readsVariable(access.getDef(), checkedVar, _) and
    any(IRGuardCondition guard).ensuresEq(access, _, _, bb, true)
  )
}

predicate nodeIsBarrierEquality(DataFlow::Node node) {
  exists(Variable checkedVar, Instruction instr, IRBlock bb |
    instr = node.asOperand().getDef() and
    readsVariable(instr, checkedVar, bb) and
    variableEqualityCheckedInBlock(checkedVar, bb)
  )
}

predicate isFlowSource(FlowSource source, string sourceType) { sourceType = source.getSourceType() }

=======
>>>>>>> f59589245a0 (Refactor: relax QL query logic)
module TaintedAllocationSizeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isFlowSource(source, _) }

  predicate isSink(DataFlow::Node sink) { allocSink(_, sink) }

  predicate isBarrier(DataFlow::Node node) {
    // Only keep the most basic barriers
    exists(Expr e | e = node.asExpr() |
      bounded(e)
    )
<<<<<<< HEAD
    or
    exists(Variable checkedVar, Instruction instr | instr = node.asOperand().getDef() |
      readsVariable(instr, checkedVar, _) and
      hasUpperBoundsCheck(checkedVar)
    )
    or
    nodeIsBarrierEquality(node)
    or
    // block flow to inside of identified allocation functions (this flow leads
    // to duplicate results)
    any(HeuristicAllocationFunction f).getAParameter() = node.asParameter()
=======
>>>>>>> f59589245a0 (Refactor: relax QL query logic)
  }
}

module TaintedAllocationSize = TaintTracking::Global<TaintedAllocationSizeConfig>;

// from
//   Expr alloc, TaintedAllocationSize::PathNode source, TaintedAllocationSize::PathNode sink,
//   string taintCause
// where
//   isFlowSource(source.getNode(), taintCause) and
//   TaintedAllocationSize::flowPath(source, sink) and
//   allocSink(alloc, sink.getNode())
//   // and sink.getNode().getFunction().toString().matches("%bad%")
// // select alloc, source, sink,
// //   "This allocation size is derived from $@ and could allocate arbitrary amounts of memory.",
// //   source.getNode(), "user input (" + taintCause + ")"
// select sink.getNode().getLocation().getFile().getAbsolutePath().toString()

from
  Expr alloc, TaintedAllocationSize::PathNode source, TaintedAllocationSize::PathNode sink,
  string taintCause
where
  isFlowSource(source.getNode(), taintCause) and
  TaintedAllocationSize::flowPath(source, sink) and
  allocSink(alloc, sink.getNode())
select alloc, source, sink,
  "This allocation size is derived from $@ and could allocate arbitrary amounts of memory.",
  source.getNode(), "user input (" + taintCause + ")"
