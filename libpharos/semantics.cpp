// Copyright 2015-2020 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/format.hpp>

#include <rose.h>
#include <BinarySymbolicExpr.h>
#include <integerOps.h>

#include "semantics.hpp"
#include "state.hpp"
#include "masm.hpp"
#include "util.hpp"
#include "enums.hpp"
#include "descriptors.hpp"
#include "limit.hpp"
#include "znode.hpp"
#include "matcher.hpp"

namespace pharos {

// This is where we construct the semantics logging facility.
Sawyer::Message::Facility slog;

// Used in a couple of places now that we're putting multiple values in an ITE expression.
using Rose::BinaryAnalysis::SymbolicExpr::OP_ITE;

// A naughty global variable for controlling the number of times we spew about discarded
// expressions.  Used in SymbolicValue::scopy().
unsigned int discarded_expressions = 0;

template<> char const* EnumStrings<MemoryType>::data[] = {
  "Stack Memory (Local Variables)",
  "Stack Memory (Return Address)",
  "Stack Memory (Parameter)",
  "Program Image Memory",
  "Heap Memory",
  "Unknown Memory",
};

//==============================================================================================
// Methods only ever invoked on the protoval.
//==============================================================================================

// Methods in this are are only ever invoked on the protoype value.  This means that the this
// pointer should not be used to access or update members in the current object because they
// are irrelevant.

BaseSValuePtr SymbolicValue::bottom_(size_t nbits) const {
  SymbolicValuePtr retval = SymbolicValuePtr(new SymbolicValue(nbits));
  TreeNodePtr tn = SymbolicExpr::makeIntegerVariable(nbits, "", TreeNode::BOTTOM);
  retval->set_expression(tn);
  return retval;
}

// This method is called when the emulation infrastructure needs a new variable.  This method
// must be implemented by our class to ensure that we return the correct SymbolicValuePtr type,
// and not simplay an instance of BaseSValuePtr.  Variables created by this method are
// different from those created by unspecified_() because these variables are those that we
// explicitly intend to reason about with greater confidence.
BaseSValuePtr SymbolicValue::undefined_(size_t nbits) const {
  //STRACE << "SymbolicValue::undefined_() nbits=" << nbits << LEND;
  return SymbolicValuePtr(new SymbolicValue(nbits));
}

BaseSValuePtr SymbolicValue::unspecified_(size_t nbits) const {
  SymbolicValuePtr retval = SymbolicValuePtr(new SymbolicValue(nbits));
  TreeNodePtr tn = SymbolicExpr::makeIntegerVariable(nbits, "", TreeNode::UNSPECIFIED);
  retval->set_expression(tn);
  return retval;
}

// This is the same idea as unspecified_, but supports our additional concept of being
// incomplete (and possibly even wrong) because of deficiencies in our code and reasoning.
// There's no point in trying to make it a virtual method, because until ROSE supports this on
// the BaseSValue, we can't call it from the protoval in the ROSE class anyway.
SymbolicValuePtr SymbolicValue::incomplete(size_t nbits) {
  SymbolicValuePtr retval = SymbolicValuePtr(new SymbolicValue(nbits));
  TreeNodePtr tn = SymbolicExpr::makeIntegerVariable(nbits, "", INCOMPLETE);
  retval->set_expression(tn);
  return retval;
}

// Another situation that warrants special treatment is values that are defined by the loader
// (primarily during import resolution).  When this flag is set, it prompts additional analysis
// to determine if the correct import can be determined.
SymbolicValuePtr SymbolicValue::loader_defined() {
  size_t nbits = global_arch_bytes * 8;
  SymbolicValuePtr retval = SymbolicValuePtr(new SymbolicValue(nbits));
  TreeNodePtr tn = SymbolicExpr::makeIntegerVariable(nbits, "", LOADER_DEFINED);
  retval->set_expression(tn);
  return retval;
}

//==============================================================================================

// This method tests for the ROSE defined TreeNode flag bit for unspecified behavior.
bool SymbolicValue::is_unspecified() const {
  return (get_expression()->flags() & TreeNode::UNSPECIFIED);
}

// This method tests for presence of the SEI defined bit signaling special import processing.
bool SymbolicValue::is_loader_defined() const {
  return (get_expression()->flags() & LOADER_DEFINED);
}

// This method tests for the presence of the SEI defined INCOMPLETE bit.
bool SymbolicValue::is_incomplete() const {
  return (get_expression()->flags() & INCOMPLETE);
}

#ifdef CUSTOM_ROSE
// This method requires a custom constructor that copies the immutable LeafNode object, and
// then set the flags on the copy and returns it.  This method then updates the expression in
// SymbolicValue to point to the new expression.  Perhaps we should test if the flag is already
// set, and not make another copy if it is?
void SymbolicValue::set_incomplete(bool i) {
  TreeNodePtr et = get_expression();
  unsigned flags = et->flags() ^ (i ? INCOMPLETE : 0);
  TreeNodePtr tn = et->copy_with_flags(flags);
  set_expression(tn);
}
#endif

// Non virtualized version returns a SymbolicValuePtr
SymbolicValuePtr SymbolicValue::scopy(size_t new_width) const {
  //STRACE << "SymbolicValue::scopy() this=" << *this << LEND;

  SymbolicValuePtr retval(new SymbolicValue(*this));

  // Cory thinks that this shouldn't be needed.  To make copy of a value and change it's width
  // ought to be verboten.  On the other hand, why did Robb provide a new_width parameter?
  if (new_width != 0 && new_width != retval->get_width())
    retval->set_width(new_width);

  // If the expression is too big, toss it.

  // Cory says: Now that we're in NEWWAY, we should revisit moving this someplace else.

  // Here's another horrible hackish workaround.  In certain cases, the symbolic expressions
  // grow exponentially in size. This results in us pushing around huge unintelligible
  // expressions that don't mean anything, and prevent us from running to completion in a
  // reasonable time.  So what we're going to do is bail wherever the expression gets too
  // big.  Right now this mostly seems to be happening on flag computations so it probably
  // won't be the end of the world anyway.

  // We're also trapped in a bad situation here.  This is the easiest and most logical place
  // to conduct the test.  But if we log here we get lots of spew, and if don't log here at
  // all we completely ignore a fairly critical and important error that we need to be
  // tracking.  The doubly horrible hackish workaround is to use a global variables to track
  // how many times we've recently logged this message. :-( Go look in solve_flow_equations()
  // for where we reset this on each new function. We declate it exeternal at the top of this
  // file, and declare the actual storage in semantics.cpp.
  retval->discard_oversized_expression();

  //STRACE << "SymbolicValue::scopy() retval=" << *retval << LEND;
  return retval;
}

void SymbolicValue::discard_oversized_expression() {
  size_t nnodes = get_expression()->nNodes();

  // With real conditions in ITEs there may very well be >500 nodes. A better approach is to
  // make this configurable so that the limits reflect the type of analysis being
  // performed. Some types of analysis just require more conditions (i.e. symbolic path
  // analysis)

  // This is JSG's logic to attempt to simplify large nodes using Z3. It is currently disabled
  // because results have not been validated and performance impact needs to be evaluated.

  // if (nnodes > get_global_limits().node_condition_limit) {
  //   PharosZ3Solver z3;
  //   TreeNodePtr simple_tn =
  //     z3.z3_to_treenode(z3.simplify(z3.treenode_to_z3(get_expression())));
  //   set_expression(simple_tn);
  //   nnodes = simple_tn->nNodes();
  // }


  if (get_global_limits().node_condition_limit
      && nnodes > get_global_limits().node_condition_limit)
  {
    // Almost/all of the discarded expressions are a single bit.  Situtations where the value
    // is larger than one bit might be worth investigating, but don't elevate the error past a
    // warning, because ordinary users don't care about this.
    if (get_width() != 1) {
      GTRACE << "Discarding non-boolean expression of " << get_width() << " bits." << LEND;
    }
    // This is unwise now that the limit is much higher.
    //SDEBUG << "Discarded expression was:" << *this << LEND;

    // Here's the important bit...  Replace the value with a new incomplete variable.
    size_t nbits = get_expression()->nBits();
    TreeNodePtr tn = SymbolicExpr::makeIntegerVariable(
      nbits, "", TreeNode::UNSPECIFIED | INCOMPLETE);
    set_expression(tn);

    // Only report this error once per function? :-(
    if (discarded_expressions < 1) {
      // Cory thinks that this should be an ERROR, but because it happens so frequently, he's
      // moving it warning importance until we can investigate further.
      SWARN << "Replaced excessively large expression with " << *get_expression() << LEND;
    }
    discarded_expressions++;
  }
}

bool operator==(const SymbolicValue& a, const SymbolicValue& b) {
  // Perhaps post NEWWAY is a good time to revisit eliminating this method because of the
  // ambiguity it creates about exactly which kind of equals we really mean.

  // semhash::Z3Solver solver;
  // YicesSolver *solver = new YicesSolver;
  // solver->set_linkage(YicesSolver::LM_EXECUTABLE);
  // return solver.equals(a.get_expression(),b.get_expression());
  return a.get_expression()->isEquivalentTo(b.get_expression());
}

// No longer used, but keeping in case we need this code in the future.  The correct
// implementation would presumably look something like this... (completely untested).
#define ULT_OP Rose::BinaryAnalysis::SymbolicExpr::OP_ULT
bool operator<(const SymbolicValue& a, const SymbolicValue& b) {
  GERROR << "Using untested SymbolicValue::operator<() code!" << LEND;
  TreeNodePtr aexpr = a.get_expression();
  TreeNodePtr bexpr = b.get_expression();
  STRACE << "SymbolicValue::operator< " << *aexpr << " < " << *bexpr << LEND;

  try {
    TreeNodePtr lt = InternalNode::instance(ULT_OP, aexpr, bexpr);
    if (lt->toUnsigned().isEqual(1)) return true;

    //using YicesSolver = Rose::BinaryAnalysis::YicesSolver;
    //YicesSolver solver;
    //solver.set_debug(stderr);
    //solver.set_linkage(YicesSolver::LM_EXECUTABLE);
    //if (solver.satisfiable(lt)) return true;
  }
  catch(...) {
    GERROR << "Caught unhandled while comparing symbolic values!" << LEND;
  }
  return false;
}

// Extract possible values from the TreeNode expression.  If the expression is an ITE
// expression, recursively call this routine on each of the values (but not the condition).
// Otherwise simply add the expression to this list of possible values.  This should function
// should probably be a method on the TreeNode class instead of here.
void extract_possible_values(const TreeNodePtr& tn, TreeNodePtrSet& s) {
  const InternalNodePtr in = tn->isInteriorNode();
  if (in && in->getOperator() == OP_ITE) {
    Rose::BinaryAnalysis::SymbolicExpr::Nodes children = in->children();
    extract_possible_values(children[1], s);
    extract_possible_values(children[2], s);
  }
  else {
    // Perhaps in a wittier version we would create a set of possible values each child of the
    // expression, then substitute to produce a possible value list.  For example, convert:
    // (add (ite c x y) 1) to possible values: [(add x 1), (add y 1)].  This gets tricky when
    // there's more than one ITE in the child list however.
    s.insert(tn);
  }
}

// A little syntactic sugar to make the recursive extract_possible_values() routine properly
// return a set of tree nodes.  This routine must return tree nodes and not symbolic values,
// because the symbolic value properties don't survive tree node simplification.
TreeNodePtrSet SymbolicValue::get_possible_values() const {
  TreeNodePtrSet possible_values;
  extract_possible_values(get_expression(), possible_values);
  return possible_values;
}

// A static helper that recurses through TreeNodes.  Perhaps it should be implemented as a
// visitor pattern, but this code is pretty simple as well.  The goal is find whether there's
// an ITE expression anywhere inside the expression, since this is a common cause of bugs in
// the new conversion to ITEs.
bool treenode_contains_ite(const TreeNodePtr& tn) {
  const InternalNodePtr in = tn->isInteriorNode();
  if (in) {
    if (in->getOperator() == OP_ITE) return true;
    else {
      for (const TreeNodePtr& cn : in->children()) {
        if (treenode_contains_ite(cn)) return true;
      }
    }
  }
  return false;
}

// A nicer API to the helper above that can be invoked as a method on a SymbolicValue.
bool SymbolicValue::contains_ite() const {
  return treenode_contains_ite(get_expression());
}

// Evaluate whether any of our possible expressions are equivalent to any of the posssible
// expressions of the other symbolic value.
bool SymbolicValue::can_be_equal(SymbolicValuePtr other) {
  // Handle the most common case first as a performance improvement?
  if (get_expression()->isEquivalentTo(other->get_expression())) return true;

  for (const TreeNodePtr& mv : get_possible_values()) {
    for (const TreeNodePtr& ov : other->get_possible_values()) {
      if (mv->isEquivalentTo(ov)) return true;
    }
  }
  return false;
}

// Wow...  An incredibly painful way to get a signed value. :-(
int64_t get_signed_value(LeafNodePtr lp) {
  int64_t num = 0;
  size_t nbits = lp->nBits();
  const Sawyer::Container::BitVector& bits = lp->bits();
  if (bits.size() <= 64) {
    uint64_t ival = bits.toInteger();
    if (IntegerOps::signBit2(ival, nbits)) {
      num = (int64_t)IntegerOps::signExtend2(ival, nbits, 64);
    } else {
      num = ival;
    }
  }
  return num;
}


// Examine the current symbolic value to decide whether it is of the form "esp_0+X+Y+Z".  If it
// is, return X+Y+Z.  If it is not, return boost::none.  If the expression contains complex
// sub-expressions or references to other variables, but it does contain esp_0 as one of the
// terms, return 0xFFFFFFFF.

// Increasingly, Cory suspects that this is the wrong way to do this... Instead we should:
// 1. Check if the expression is a constant.  Reject as a stack delta.
// 2. Check if the expression is a simple variable.  Accept as 0 if esp_0, else reject.
// 3. Substitute esp_0 with the value zero.
// 4. If the expression is different, it's the "stack delta".
boost::optional<int64_t> SymbolicValue::get_stack_const() const {
  // The constant delta from ESP.
  int64_t delta = 0;
  // Has something occurred that we don't fully understand?
  bool confused = false;
  // Did we find the ESP register reference?
  bool found = false;

  InternalNodePtr inode = get_expression()->isInteriorNode();
  if (!inode) {
    // If we're not a number, we should be variable, and the only variable we care about is the
    // initial value of ESP.  Per the latest change in ROSE, this should have the name esp_0.
    const std::string& cmt = get_comment();
    if (cmt.empty()) return boost::none;
    if (cmt.compare("esp_0") == 0) {
      SDEBUG << "Stack constant was: 0" << LEND;
      return (int64_t)0;
    }
    return boost::none;
  }
  else if (inode->getOperator() == Rose::BinaryAnalysis::SymbolicExpr::OP_ADD) {
    //SDEBUG << "Found add operator." << LEND;
    for (const TreeNodePtr tp : inode->children()) {
      LeafNodePtr lp = tp->isLeafNode();
      //if (lp) {
      //  SDEBUG << "Leaf Node in stack delta eval is: " << *lp << LEND;
      //}
      //else {
      //  SDEBUG << "Add operand is complex type: " << *tp << LEND;
      //}

      // Addition of complex terms is beyond our current ability to reason correctly about
      // them.  We might not even be correct about whether this is a stack memory reference if
      // the reference to ESP is buried within this complex term.  Perhaps we should ask for
      // all the variables in the term to make this decision.
      if (!lp) confused = true;
      // If this term is a constant, add it to our accumlating delta.
      else if (lp->isIntegerConstant()) {
        delta += get_signed_value(lp);
        //SDEBUG << "Increased delta to: " << delta << LEND;
      }
      else if (lp->isIntegerVariable() && (lp->flags() & UNKNOWN_STACK_DELTA)) {
        // Ignore unknown stack delta variables
        // do nothing
      } else {
        // Otherwise, check to see if this variable is the expected esp_0.
        const std::string& cmt = lp->comment();
        //SDEBUG << "Leaf node comment is: '" << cmt << "'" << LEND;
        if (cmt.empty()) confused = true;
        else if (cmt.compare("esp_0") == 0) found = true;
        else confused = true;
        //SDEBUG << "Register match: found=" << found << " confused=" << confused << LEND;
      }
    }
    //SDEBUG << "Almost there:" << delta << LEND;
    if (!found) return boost::none;
    // I think I'd prefer to return CONFUSED here...
    if (confused) return boost::none;
    //if (confused) return CONFUSED;
    SDEBUG << "Stack constant was: " << delta << LEND;
    return delta;
  }

  return boost::none;
}

MemoryType SymbolicValue::get_memory_type() const {
  boost::optional<int64_t> odelta = get_stack_const();
  if (odelta) {
    int64_t num = *odelta;

    // Negative deltas from the initial stack pointer are local variables.
    if (num < 0) return StackMemLocalVariable;

    // Positive deltas from the initial stack pointer are stack parameters.
    if (num > 0) return StackMemParameter;

    // Address [esp] contains the return address.
    return StackMemReturnAddress;
  }
  else {
    // Here, Cory would like to be reading the program memory image to determine whether the
    // address was already defined.  Unfortunately, that helper function is currently in
    // descriptors.hpp, and he's in no hurry to create an include dependency loop.  Hopefully
    // the next revision of the partitioner will have some better way to do this.
    // return ImageMem;

    // For right now, we only have one type of non-numeric address, and that's unknown.  In the
    // future, Cory would like to record whether the address was tracked to the return code
    // from a heap memory allocation routine, and which allocation it was.  (return HeapMem)
    return UnknownMem;
  }
}

// Merge two symbolic values.
Sawyer::Optional<BaseSValuePtr>
SymbolicValue::createOptionalMerge(const BaseSValuePtr& other,
                                   const BaseMergerPtr& merger,
#ifndef USE_ROSE_SYMVALUE_MERGE
                                   UNUSED
#endif
                                   const SmtSolverPtr & solver) const {

  SymbolicValuePtr sother;
  if (!other) {
    // Loader defined values "appear" suddenly in the middle of interpretation, but there's no
    // confusion caused by this.  We'll always return the same value, and it was really there
    // in the other block as well, it just hadn't been referenced yet (kind of like new memory
    // cell creations).  Perhaps this test really belong in equals(), or someplace else?
    if (is_loader_defined()) {
      return Sawyer::Nothing();
    }
    sother = SymbolicValue::incomplete(get_width());
  }
  else {
    sother = SymbolicValue::promote(other);
  }

  // The BaseMergerPtr is really a CERTMergerPtr.
  const CERTMergerPtr& cert_merger = merger.dynamicCast<CERTMerger>();
  // More unexpected differences between list memory and map memory.
  // If there's no CERT merger (because we're using the list memory model) call the standard merge routine.
  if (!cert_merger) {
    return ParentSValue::createOptionalMerge(other, merger, solver);
  }

  // This condition is currently set in SymbolicRegisterState::merge() and
  // SymbolicMemoryMapState::merge().  It should really be a single value, but there's two being
  // generated currently.  Also it should express the condition that lead to the current value
  // versus the other value, but right now it's just an newly created incomplete variable.
  SymbolicValuePtr condition = cert_merger->condition;

#if USE_ROSE_SYMVALUE_MERGE
  // But we should really be calling back into the ROSE infrastructure like this:
  Sawyer::Optional<BaseSValuePtr> oretval = ParentSValue::createOptionalMerge(other, merger, solver);

  // And then only if the expressions were different we would extend the behavior, perhaps like this:
  if (oretval) {
    BaseSValuePtr bretval = *oretval;
    SymbolicValuePtr sretval = SymbolicValue::promote(bretval);
    // Using our old routine...
    sretval->merge(sother, condition, cert_merger->inverted);
  }
  return oretval;
#else
  // Use our old symbolic merge approach.
  SymbolicValuePtr retval = scopy();
  retval->merge(sother, condition, cert_merger->inverted);
  return Sawyer::Optional<BaseSValuePtr>(retval);
#endif
}

void SymbolicValue::merge(const SymbolicValuePtr& other,
                          const SymbolicValuePtr& condition,
                          bool inverted) {
  STRACE << "SymbolicValue::merge() this=" << *this << LEND;
  STRACE << "SymbolicValue::merge() other=" << *other << LEND;

  this->defs.insert(other->defs.begin(), other->defs.end());

  // If my expression is already bottom, there's not much point in worrying about the other
  // value.  Switched to use ROSE bottom values.
  if (isBottom()) return;

  // If the other value is bottom, my value is now bottom as well after merging.
  if (other->isBottom()) {
    // Bottom is just bottom, so it's fine to use the other value.
    set_expression(other->get_expression());
    return;
  }

  // If neither of the values incomplete, the next question is: do they already match?
  TreeNodePtr my_expr = get_expression();
  TreeNodePtr other_expr = other->get_expression();
  // If they do, then we're done.  Robb remarks that the equivalent_to() method is a structural
  // comparison.  We should probably be calling must_equal() instead, since it will correctly
  // handle a wider variety of equivalent expressions.  Perhaps post-NEWWAY is the time to do this?
  if (my_expr->isEquivalentTo(other_expr)) return;

  // This logic is an absolute minimum, but it's a valid start...  One solution is to merge the
  // values by placing them inside an ITE based on an unknown conditional.  Unfortunately, this
  // does the wrong thing when we loop, because we keeping making bigger and bigger ITE
  // expressions.
  TreeNodePtr ctp = condition->get_expression();

  // Express the two possible values as an ITE expression.  Because create() calls simplifyTop,
  // there's theoretically a chance that ite_expr is not actually an ITE operator internal node
  // after the call to create.  There's no need to make the ITE expression as incomplete.  It
  // will autmatically be marked as such if the condition is incomplete (which it always is
  // right now).
  TreeNodePtr ite_expr;
  if (inverted) {
    ite_expr = InternalNode::instance(OP_ITE, ctp, other_expr, my_expr);
  }
  else {
    ite_expr = InternalNode::instance(OP_ITE, ctp, my_expr, other_expr);
  }
  // The only(?) place where we want to set the expression to a value not literally in sync
  // with the value set?
  ParentSValue::set_expression(ite_expr);
}

void SymbolicValue::print(std::ostream &o, RoseFormatter& fmt) const {
  // Call our parent print routine.
  ParentSValue::print(o, fmt);
}

//==============================================================================================
// Abstract Access
//==============================================================================================

AbstractAccess::AbstractAccess(
  DescriptorSet const & ds,
  bool b, SymbolicValuePtr ma, size_t s,
  SymbolicValuePtr v, SymbolicStatePtr state)
{
  isRead = b;
  isMemReference = true;
  memory_address = ma;
  size = s;
  value = v;
  set_latest_writers(ds, state);
}

AbstractAccess::AbstractAccess(
  DescriptorSet const & ds,
  bool b, RegisterDescriptor r,
  SymbolicValuePtr v, SymbolicStatePtr state)
{
  isRead = b;
  isMemReference = false;
  register_descriptor = r;
  size = r.get_nbits();
  value = v;
  set_latest_writers(ds, state);
}

std::string AbstractAccess::str() const {
  if (value) {
    std::string rw_flag = "W: ";
    if (isRead) rw_flag = "R: ";

    std::string v = value->str();
    if (is_reg()) {
      return rw_flag + reg_name() + " -> " + v;
    }
    else if (is_mem()) {
      std::string a = memory_address->str();
      return rw_flag + a + " -> " + v;
    }
  }
  return std::string("INVALID");
}

// This comparison operator was implemented to provide an ordering so that we could have a
// std::set of AbstractAccesses.  Abstract accesses aren't really greater or less than other
// abstract accesses.
bool AbstractAccess::operator<(const AbstractAccess& other) const {
  // Invalid before all others.
  if (is_invalid()) return true;
  // Other invalid before anything we might be.
  if (other.is_invalid()) return false;

  // If we're a register, and other is not, we come first (invalid case already handled).
  if (is_reg() && !other.is_reg()) return true;
  // If we're not a register and other is, we come last (invalid case already handled).
  if (!is_reg() && other.is_reg()) return false;

  // Same logic for only this OR other is a memory reference.
  if (is_mem() && !other.is_mem()) return true;
  if (!is_mem() && other.is_mem()) return false;

  // Order registers by their register descriptors.
  if (is_reg() && other.is_reg()) {
    return register_descriptor < other.register_descriptor;
  }
  // Order memory accesses by the hashes of their addresses.
  else if (is_mem() && other.is_mem()) {
    return memory_address->get_hash() < other.memory_address->get_hash();
  }
  else {
    OFATAL << "All abstract access cases were supposed to have been handled." << LEND;
    OFATAL << "AA this=" << *this << LEND;
    OFATAL << "AA other=" << other << LEND;
    throw std::logic_error("Internal logic error: unhandled abstract access case!");
  }
}

bool AbstractAccess::operator==(const AbstractAccess& other) const {
  // If both accesses are to the same register, and they both have the same read/write
  // boolean, then they're equivalent.  That they're the same size is probably implied by
  // being the same register, but there's little reason not to check that as well.
  if (is_reg() && other.is_reg() && isRead == other.isRead && size == other.size &&
      register_descriptor == other.register_descriptor) return true;

  // If both accesses are to the samememory address, they both have the same read/write
  // boolean, and they're both of the same size (which could differ for the same memory
  // address), then they're the same abstract access.
  if (is_mem() && other.is_mem() && isRead == other.isRead && size == other.size &&
      memory_address->get_hash() == other.memory_address->get_hash()) return true;

  // All invalid accesses are just a marker for being invalid (incompletely constructed or a
  // failure condition).  Thus one invalid access should be the same as another.
  if (is_invalid() && other.is_invalid()) return true;

  // All other acessses are different.
  return false;
}

bool AbstractAccess::exact_match(const AbstractAccess& other) const {
  if (*this == other &&
      value->get_expression()->isEquivalentTo(other.value->get_expression()) &&
      latest_writers.size() == other.latest_writers.size()) {
    // Now check whether the instructions in the list are actually the same...
    auto titer = latest_writers.begin();
    auto oiter = other.latest_writers.begin();
    while (titer != latest_writers.end()) {
      SgAsmInstruction* tinsn = *titer;
      SgAsmInstruction* oinsn = *oiter;
      if (tinsn->get_address() != oinsn->get_address()) {
        OINFO << "Insns addresses differed " << debug_instruction(tinsn)
              << " vs " << debug_instruction(oinsn) << LEND;
        return false;
      }
      titer++;
      oiter++;
    }

    return true;
  }
  return false;
}

void AbstractAccess::print(std::ostream &o) const {
  o << str();
}

void AbstractAccess::debug(std::ostream &o) const {
  o << str() << LEND;
  o << "Writers: " << LEND;
  for (const SgAsmInstruction* insn : latest_writers) {
    o << debug_instruction(insn) << LEND;
  }
}

void AbstractAccess::set_latest_writers(DescriptorSet const & ds, SymbolicStatePtr& state) {
  // Set the modifiers based on inspecting the current abstract access and the passed state.
  // We're converting from a Sawyer container of rose_addr_t to an InsnSet as well, because
  // that's more convenient in our code.

  // Hackish workaround for list based memory.   What should we really be doing?
  if (isMemReference && state->is_map_based()) {
    const SymbolicMemoryMapStatePtr& mstate = SymbolicMemoryMapState::promote(state->memoryState());
    MemoryCellPtr cell = mstate->findCell(memory_address);
    // This happens when the expression is an ITE or the program accesses unspecified
    // addresses.   The latter probably means that the analysis is bad, but we can't
    // complain too loudly here. :-(   More thought will probably be required.
    if (!cell) {
      GDEBUG << "No memory cell for address:" << *memory_address << LEND;
      return;
    }
    // Now get the writers for just this one cell.  There's been some recent email discussion
    // with Robb that this approach is defective, and there's a fix pending in ROSE.
    const MemoryCell::AddressSet& writers = cell->getWriters();
    for (rose_addr_t addr : writers.values()) {
      //OINFO << "Latest memory writer for " << str() << " was: " << addr_str(addr) << LEND;
      SgAsmInstruction* insn = ds.get_insn(addr);
      latest_writers.insert(insn);
    }
  }
  else {
    SymbolicRegisterStatePtr rstate = state->get_register_state();
    //OINFO << "Looking for latest register writer for " << str() << LEND;
    const RegisterStateGeneric::AddressSet& writers = rstate->getWritersUnion(register_descriptor);
    for(rose_addr_t addr : writers.values()) {
      //OINFO << "Latest register writer for " << str() << " was: " << addr_str(addr) << LEND;
      SgAsmInstruction* insn = ds.get_insn(addr);
      latest_writers.insert(insn);
    }
  }
}

boost::tribool
pharos_may_equal(
  const TreeNodePtr &n1,
  const TreeNodePtr &n2,
  UNUSED const SmtSolverPtr &solver)
{
  using Rose::BinaryAnalysis::SymbolicExpr::OP_ADD;

  boost::tribool result = boost::indeterminate;

  InternalNodePtr in1 = n1->isInteriorNode();

  // The CERT extension is a slightly more complicated version of the standard mayEquals,
  // except instead of using the ROSE matchAddVariableConstant class, we use our
  // AddConstantExtractor class with also supports ITEs.
  if (in1 && in1->getOperator() == OP_ADD) {
    LeafNodePtr ln2 = n2->isLeafNode();
    InternalNodePtr in2 = n2->isInteriorNode();
    // If other is a leaf variable or an interior add operation, we may be able to prove that
    // the expressions are NOT equal.
    if ((ln2 && ln2->isIntegerVariable()) || (in2 && in2->getOperator() == OP_ADD)) {
      // The constant extractor is smart enough to handle all TreeNode cases.
      AddConstantExtractor n1ace = AddConstantExtractor(n1);
      AddConstantExtractor n2ace = AddConstantExtractor(n2);
      //STRACE << "Comparing variables " << *n1ace.variable_portion()
      //       << " to " << *n2ace.variable_portion() << LEND;
      //STRACE << "Comparing constants " << n1ace.constant_portion()
      //       << " to " << n2ace.constant_portion() << LEND;
      if (n1ace.variable_portion() &&
          n1ace.variable_portion()->isEquivalentTo(n2ace.variable_portion()) &&
          n1ace.constant_portion() != n2ace.constant_portion()) {
        //STRACE << "Expressions may NOT alias!" << LEND;
        result = false;
      }
    }
  }

  return result;
}

void set_may_equal_callback() {
  //OINFO << "Setting may_equal callback!" << LEND;
  Rose::BinaryAnalysis::SymbolicExpr::Node::mayEqualCallback = pharos_may_equal;
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
