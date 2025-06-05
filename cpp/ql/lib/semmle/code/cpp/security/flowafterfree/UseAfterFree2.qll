/**
 * A general library for tracking Use After Free (UAF) vulnerabilities.
 */

 import cpp
 private import semmle.code.cpp.security.flowafterfree.FlowAfterFree2
 private import semmle.code.cpp.ir.IR
 
 /**
  * Determines whether `e` is a use. A use is a pointer dereference or an argument to a call without a function definition.
  * Includes uses in free operations (e.g., free).
  */
 predicate isUse0(Expr e) {
   // The original code excluded uses in free operations, but we include them here
   // Removed the check for `isFree`
   (
     // Include various possible pointer usage patterns
     e = any(PointerDereferenceExpr pde).getOperand()
     or
     e = any(PointerFieldAccess pfa).getQualifier()
     or
     e = any(ArrayExpr ae).getArrayBase()
     or
     e = any(Call call).getQualifier()
     or
     any()
     or
     // Assume any function call will dereference pointers, including functions without bodies
     exists(int i, Call call |
       e = call.getArgument(i)
     )
   )
 }
 
 private module ParameterSinks {
   import semmle.code.cpp.ir.ValueNumbering
 
   private predicate flowsToUse(DataFlow::Node n) {
     isUse0(n.asExpr())
     or
     exists(DataFlow::Node succ |
       flowsToUse(succ) and
       DataFlow::localFlowStep(n, succ)
     )
   }
 
   private predicate flowsFromParam(DataFlow::Node n) {
     flowsToUse(n)
     or // Relax the condition to include any node that can flow to a use
     exists(DataFlow::Node prev |
       flowsFromParam(prev) and
       DataFlow::localFlowStep(prev, n)
     )
   }
 
   private predicate step(DataFlow::Node n1, DataFlow::Node n2) {
     DataFlow::localFlowStep(n1, n2)
   }
 
   private predicate paramToUse(DataFlow::Node n1, DataFlow::Node n2) = fastTC(step/2)(n1, n2)
 
   private predicate hasFlow(
     DataFlow::Node source, InitializeParameterInstruction init, DataFlow::Node sink
   ) {
     paramToUse(source, sink) and
     isUse0(sink.asExpr())
   }
 
   private InitializeParameterInstruction getAnAlwaysDereferencedParameter0() {
     exists(DataFlow::Node source, DataFlow::Node sink |
       hasFlow(source, result, sink)
     )
   }
 
   private CallInstruction getAnAlwaysReachedCallInstruction() {
     exists(CallInstruction call |
       result = call
     )
   }
 
   pragma[nomagic]
   private predicate callHasTargetAndArgument(Function f, int i, Instruction argument) {
     exists(CallInstruction call |
       call.getArgument(i) = argument
     )
   }
 
   pragma[nomagic]
   private predicate initializeParameterInFunction(Function f, int i) {
     exists(InitializeParameterInstruction init |
       init.getEnclosingFunction() = f and
       init.hasIndex(i)
     )
   }
 
   pragma[nomagic]
   private predicate alwaysDereferencedArgumentHasValueNumber(ValueNumber vn) {
     exists(int i, Function f, Instruction argument |
       callHasTargetAndArgument(f, i, argument) and
       initializeParameterInFunction(f, i) and
       vn.getAnInstruction() = argument
     )
   }
 
   InitializeParameterInstruction getAnAlwaysDereferencedParameter() {
     result = getAnAlwaysDereferencedParameter0()
     or
     exists(ValueNumber vn |
       alwaysDereferencedArgumentHasValueNumber(vn) and
       vn.getAnInstruction() = result
     )
   }
 }
 
 private import semmle.code.cpp.ir.dataflow.internal.DataFlowImplCommon
 private import semmle.code.cpp.ir.dataflow.internal.DataFlowPrivate
 
 /**
  * Determines whether `n` represents expression `e`, where `e` is a pointer and is dereferenced or used.
  */
 predicate isUse(DataFlow::Node n, Expr e) { 
   isUse0(e) and n.asExpr() = e
   or
   exists(DataFlowCall call, InitializeParameterInstruction init |
     n.asOperand().getDef().getUnconvertedResultExpression() = e and
     init = ParameterSinks::getAnAlwaysDereferencedParameter()
   )
 }
 