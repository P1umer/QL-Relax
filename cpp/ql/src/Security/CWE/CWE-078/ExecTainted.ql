/**
 * @name Uncontrolled data used in OS command
 * @description Using user-supplied data in an OS command, without
 *              neutralizing special elements, can make code vulnerable
 *              to command injection.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id cpp/command-line-injection
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import cpp
import semmle.code.cpp.security.CommandExecution
import semmle.code.cpp.security.Security
import semmle.code.cpp.valuenumbering.GlobalValueNumbering
import semmle.code.cpp.ir.IR
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.models.implementations.Strcat
import ExecTaint::PathGraph

/**
 * Holds if `incoming` is a string that is used in a format or concatenation function resulting
 * in `outgoing`. Removed position and format type restrictions.
 */
predicate interestingConcatenation(DataFlow::Node incoming, DataFlow::Node outgoing) {
  exists(FormattingFunctionCall call, int index |
    incoming.asIndirectArgument() = call.getConversionArgument(index) and
    outgoing.asDefiningArgument() = call.getOutputArgument(false)
  )
  or
  // strcat and friends
  exists(StrcatFunction strcatFunc, Call call |
    call.getTarget() = strcatFunc and
    incoming.asIndirectArgument() = call.getArgument(strcatFunc.getParamSrc()) and
    outgoing.asDefiningArgument() = call.getArgument(strcatFunc.getParamDest())
  )
  or
  exists(Call call, Operator op |
    call.getTarget() = op and
    op.hasQualifiedName("std", "operator+") and
    op.getType().(UserType).hasQualifiedName("std", "basic_string") and
<<<<<<< HEAD
    incoming.asIndirectArgument() = call.getArgument(1) and // right operand
=======
    (
      incoming.asIndirectArgument() = call.getArgument(0) or // left operand
      incoming.asIndirectArgument() = call.getArgument(1)    // right operand
    ) and
>>>>>>> f59589245a0 (Refactor: relax QL query logic)
    call = outgoing.asInstruction().getUnconvertedResultExpression()
  )
}

/**
 * A state will represent the most recent concatenation that occurred in the data flow.
 *  - `TConcatState` if the concetenation has not yet occurred.
 *  - `TExecState(incoming, outgoing)`, representing the concatenation of data from `incoming`
 *    into result `outgoing`.
 */
newtype TState =
  TConcatState() or
  TExecState(DataFlow::Node incoming, DataFlow::Node outgoing) {
    interestingConcatenation(pragma[only_bind_into](incoming), pragma[only_bind_into](outgoing))
  }

class ConcatState extends TConcatState {
  string toString() { result = "ConcatState" }
}

class ExecState extends TExecState {
  DataFlow::Node incoming;
  DataFlow::Node outgoing;

  ExecState() { this = TExecState(incoming, outgoing) }

  DataFlow::Node getIncomingNode() { result = incoming }

  DataFlow::Node getOutgoingNode() { result = outgoing }

  /**
   * Holds if this is a possible `ExecState` at `sink`, that is, if `outgoing` flows to `sink`.
   */
  predicate isFeasibleForSink(DataFlow::Node sink) { ExecState::flow(outgoing, sink) }

  string toString() { result = "ExecState" }
}

predicate isSinkImpl(DataFlow::Node sink, Expr command, string callChain) {
  command = sink.asIndirectArgument() and
  shellCommand(command, callChain)
}

predicate isBarrierImpl(DataFlow::Node node) {
  // Removed type-based barriers
  none()
}

/**
 * A `TaintTracking` configuration that's used to find the relevant `ExecState`s for a
 * given sink.
 */
module ExecStateConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { any(ExecState state).getOutgoingNode() = source }

  predicate isSink(DataFlow::Node sink) { isSinkImpl(sink, _, _) }

  predicate isBarrier(DataFlow::Node node) { isBarrierImpl(node) }

  predicate isBarrierOut(DataFlow::Node node) {
    // Removed duplicate prevention barrier
    none()
  }
}

module ExecState = TaintTracking::Global<ExecStateConfig>;

/**
 * A full `TaintTracking` configuration from source to concatenation to sink, using a flow
 * state to remember the concatenation. It's important that we track flow to the sink even though
 * as soon as we reach the concatenation we know it will get there (due to the check of
 * `isFeasibleForSink`), because this way we get a complete flow path.
 */
module ExecTaintConfig implements DataFlow::StateConfigSig {
  class FlowState = TState;

  predicate isSource(DataFlow::Node source, FlowState state) {
    source instanceof FlowSource and
    state instanceof ConcatState
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    ExecStateConfig::isSink(sink) and
    (
      state.(ExecState).isFeasibleForSink(sink) or
      state instanceof ConcatState  // Allow direct flow without requiring concatenation state
    )
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
  ) {
    (
      state1 instanceof ConcatState and
      state2.(ExecState).getIncomingNode() = node1 and
      state2.(ExecState).getOutgoingNode() = node2
    ) or
    (
      // Allow direct state transitions
      state1 instanceof ConcatState and
      state2 instanceof ConcatState and
      DataFlow::localFlowStep(node1, node2)
    )
  }

  predicate isBarrier(DataFlow::Node node) { isBarrierImpl(node) }

  predicate isBarrierOut(DataFlow::Node node) {
    // Removed duplicate prevention barrier
    none()
  }
}

module ExecTaint = TaintTracking::GlobalWithState<ExecTaintConfig>;

from
  ExecTaint::PathNode sourceNode, ExecTaint::PathNode sinkNode, string taintCause, string callChain,
  DataFlow::Node concatResult, Expr command
where
  ExecTaint::flowPath(sourceNode, sinkNode) and
  taintCause = sourceNode.getNode().(FlowSource).getSourceType() and
  isSinkImpl(sinkNode.getNode(), command, callChain) and
  (
    concatResult = sinkNode.getState().(ExecState).getOutgoingNode() or
    concatResult = sinkNode.getNode()  // Handle direct cases without concatenation
  )
select command, sourceNode, sinkNode,
  "This argument to an OS command is derived from $@, potentially concatenated into $@, and then passed to "
    + callChain + ".", sourceNode, "user input (" + taintCause + ")", concatResult,
  concatResult.toString()