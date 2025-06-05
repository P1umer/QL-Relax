/**
 * @name Type confusion
 * @description Casting a value to an incompatible type can lead to undefined behavior.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 9.3
 * @precision medium
 * @id cpp/type-confusion
 * @tags security
 *       external/cwe/cwe-843
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import Flow::PathGraph

<<<<<<< HEAD
/** Holds if `f` is the last field of its declaring class. */
predicate lastField(Field f) {
  exists(Class c | c = f.getDeclaringType() |
    f =
      max(Field cand, int byteOffset |
        cand.getDeclaringType() = c and byteOffset = f.getByteOffset()
      |
        cand order by byteOffset
      )
=======
/**
 * Holds if `f` is a field located at byte offset `offset` in `c`.
 */
predicate hasAFieldWithOffset(Class c, Field f, int offset) {
  f = c.getAField() and
  offset = f.getByteOffset()
  or
  exists(Field g |
    g = c.getAField() and
    g =
      max(Field cand, int candOffset |
        cand = c.getAField() and
        candOffset = cand.getByteOffset() and
        offset >= candOffset
      |
        cand order by candOffset
      ) and
    hasAFieldWithOffset(g.getUnspecifiedType(), f, offset - g.getByteOffset())
>>>>>>> f59589245a0 (Refactor: relax QL query logic)
  )
}

/**
 * Holds if there exists a field in `c2` at offset `offset`.
 */
bindingset[offset, c2]
pragma[inline_late]
<<<<<<< HEAD
predicate hasCompatibleFieldAtOffset(Field f1, int offset, Class c2) {
  exists(Field f2 | offset = f2.getOffsetInClass(c2) |
    // Let's not deal with bit-fields for now.
    f2 instanceof BitField
    or
    f1.getUnspecifiedType().getSize() = f2.getUnspecifiedType().getSize()
    or
    lastField(f1) and
    f1.getUnspecifiedType().getSize() <= f2.getUnspecifiedType().getSize()
  )
}

/**
 * Holds if `c1` is a prefix of `c2`.
 */
bindingset[c1, c2]
pragma[inline_late]
predicate prefix(Class c1, Class c2) {
  not c1.isPolymorphic() and
  not c2.isPolymorphic() and
  if c1 instanceof Union
  then
    // If it's a union we just verify that one of it's variants is compatible with the other class
    exists(Field f1, int offset |
      // Let's not deal with bit-fields for now.
      not f1 instanceof BitField and
      offset = f1.getOffsetInClass(c1)
    |
      hasCompatibleFieldAtOffset(f1, offset, c2)
    )
  else
    forall(Field f1, int offset |
      // Let's not deal with bit-fields for now.
      not f1 instanceof BitField and
      offset = f1.getOffsetInClass(c1)
    |
      hasCompatibleFieldAtOffset(f1, offset, c2)
    )
}

/**
 * An unsafe cast is any explicit cast that is not
 * a `dynamic_cast`.
=======
predicate hasCompatibleFieldAtOffset(int offset, Class c2) {
  exists(Field f2 | hasAFieldWithOffset(c2, f2, offset))
}

/**
 * An unsafe cast is any explicit cast.
>>>>>>> f59589245a0 (Refactor: relax QL query logic)
 */
class UnsafeCast extends Cast {
  private Type toType;

  UnsafeCast() {
    (
      this instanceof CStyleCast
      or
      this instanceof StaticCast
      or
      this instanceof ReinterpretCast
      or
      this instanceof ConstCast
    ) and
    toType = this.getExplicitlyConverted().getUnspecifiedType().stripType()
  }

  Type getConvertedType() { result = toType }

  /**
   * Simplified compatibility check - only exact type matches are considered compatible
   */
  bindingset[this, t]
  pragma[inline_late]
  predicate compatibleWith(Type t) {
    t.stripType() = this.getConvertedType()
  }
}

/**
 * Holds if `source` is an allocation that allocates a value of type `type`.
 */
predicate isSourceImpl(DataFlow::Node source, Type type) {
  exists(AllocationExpr alloc |
    alloc = source.asExpr() and
    type = alloc.getAllocatedElementType().stripType()
  )
  or
  // Also include variable declarations as sources
  exists(Variable v |
    source.asExpr() = v.getAnAccess() and
    type = v.getType().stripType()
  )
  or
  // Include function parameters as sources
  exists(Parameter p |
    source.asParameter() = p and
    type = p.getType().stripType()
  )
}

/** A configuration describing flow from an allocation to a potentially unsafe cast. */
module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isSourceImpl(source, _) }

  predicate isBarrier(DataFlow::Node node) { none() }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() = any(UnsafeCast cast).getUnconverted() }

  int fieldFlowBranchLimit() { result = 1000 }
}

module Flow = DataFlow::Global<Config>;

predicate relevantType(DataFlow::Node sink, Type allocatedType) {
  exists(DataFlow::Node source |
    Flow::flow(source, sink) and
    isSourceImpl(source, allocatedType)
  )
}

predicate isSinkImpl(
  DataFlow::Node sink, Type allocatedType, Type convertedType, boolean compatible
) {
  exists(UnsafeCast cast |
    relevantType(sink, allocatedType) and
    sink.asExpr() = cast.getUnconverted() and
    convertedType = cast.getConvertedType()
  |
    if cast.compatibleWith(allocatedType) then compatible = true else compatible = false
  )
}

from
  Flow::PathNode source, Flow::PathNode sink, Type badSourceType, Type sinkType,
  DataFlow::Node sinkNode
where
  Flow::flowPath(source, sink) and
  sinkNode = sink.getNode() and
  isSourceImpl(source.getNode(), badSourceType) and
  isSinkImpl(sinkNode, badSourceType, sinkType, false)
select sinkNode, source, sink, "Conversion from $@ to $@ is invalid.", badSourceType,
  badSourceType.toString(), sinkType, sinkType.toString()