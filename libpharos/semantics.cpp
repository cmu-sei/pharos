// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

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

namespace pharos {

// This is where we construct the semantics logging facility.
Sawyer::Message::Facility slog("FSEM");

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
  TreeNodePtr tn = LeafNode::createVariable(nbits, "", TreeNode::BOTTOM);
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
  TreeNodePtr tn = LeafNode::createVariable(nbits, "", TreeNode::UNSPECIFIED);
  retval->set_expression(tn);
  return retval;
}

// This is the same idea as unspecified_, but supports our additional concept of being
// incomplete (and possibly even wrong) because of deficiencies in our code and reasoning.
// There's no point in trying to make it a virtual method, because until ROSE supports this on
// the BaseSValue, we can't call it from the protoval in the ROSE class anyway.
SymbolicValuePtr SymbolicValue::incomplete(size_t nbits) {
  SymbolicValuePtr retval = SymbolicValuePtr(new SymbolicValue(nbits));
  TreeNodePtr tn = LeafNode::createVariable(nbits, "", INCOMPLETE);
  retval->set_expression(tn);
  return retval;
}

// Another situation that warrants special treatment is values that are defined by the loader
// (primarily during import resolution).  When this flag is set, it prompts additional analysis
// to determine if the correct import can be determined.
SymbolicValuePtr SymbolicValue::loader_defined() {
  size_t nbits = global_descriptor_set->get_arch_bits();
  SymbolicValuePtr retval = SymbolicValuePtr(new SymbolicValue(nbits));
  TreeNodePtr tn = LeafNode::createVariable(nbits, "", LOADER_DEFINED);
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
  //if (nnodes > 5000) {
  //  GTRACE << "Very big expression has " << nnodes << " nodes." << LEND;
  //}

  // There's almost never expressions with more than 50,000 nodes. But when there are,
  // performance tanks horribly, taking 2-3 seconds to process a single instruction.  Since
  // expressions with more than about 500 nodes are of very questionable value anyway, let's
  // discard any that's larger than that low threshold.
  if (nnodes > 500) {
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
    TreeNodePtr tn = LeafNode::createVariable(nbits, "", TreeNode::UNSPECIFIED | INCOMPLETE);
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
  OERROR << "Using untested SymbolicValue::operator<() code!" << LEND;
  TreeNodePtr aexpr = a.get_expression();
  TreeNodePtr bexpr = b.get_expression();
  STRACE << "SymbolicValue::operator< " << *aexpr << " < " << *bexpr << LEND;

  try {
    TreeNodePtr lt = InternalNode::create(1, ULT_OP, aexpr, bexpr);
    if (lt->isNumber()) {
      if (lt->toInt() == 1) return true;
      else return false;
    }

    //typedef Rose::BinaryAnalysis::YicesSolver YicesSolver;
    //YicesSolver solver;
    //solver.set_debug(stderr);
    //solver.set_linkage(YicesSolver::LM_EXECUTABLE);
    //if (solver.satisfiable(lt)) return true;
  }
  catch(...) {
    OERROR << "Caught unhandled while comparing symbolic values!" << LEND;
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
      else if (lp->isNumber()) {
        delta += get_signed_value(lp);
        //SDEBUG << "Increased delta to: " << delta << LEND;
      }
      else if (lp->isVariable() && (lp->flags() & UNKNOWN_STACK_DELTA)) {
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
                                   SMTSolver* solver) const {

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
  // This condition is currently set in SymbolicRegisterState::merge() and
  // SymbolicMemoryState::merge().  It should really be a single value, but there's two being
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
    sretval->merge(sother, condition);
  }
  return oretval;
#else
  // Use our old symbolic merge approach.
  SymbolicValuePtr retval = scopy();
  retval->merge(sother, condition);
  return Sawyer::Optional<BaseSValuePtr>(retval);
#endif
}

void SymbolicValue::merge(const SymbolicValuePtr& other, const SymbolicValuePtr& condition) {
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
  TreeNodePtr ite_expr = InternalNode::create(get_width(), OP_ITE, ctp, my_expr, other_expr);
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

AbstractAccess::AbstractAccess(bool b, SymbolicValuePtr ma, size_t s,
                               SymbolicValuePtr v, SymbolicStatePtr state) {
  isRead = b;
  isMemReference = true;
  memory_address = ma;
  size = s;
  value = v;
  set_latest_writers(state);
}

AbstractAccess::AbstractAccess(bool b, RegisterDescriptor r,
                               SymbolicValuePtr v, SymbolicStatePtr state) {
  isRead = b;
  isMemReference = false;
  register_descriptor = r;
  size = r.get_nbits();
  value = v;
  set_latest_writers(state);
}

std::string AbstractAccess::str() const {
  if (is_reg()) return reg_name();
  else if (is_mem()) {
    std::string a = memory_address->str();
    return "[" + a + "]";
  }
  else return std::string("INVALID");
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

void AbstractAccess::set_latest_writers(SymbolicStatePtr& state) {
  // Set the modifiers based on inspecting the current abstract access and the passed state.
  // We're converting from a Sawyer container of rose_addr_t to an InsnSet as well, because
  // that's more convenient in our code.
  if (isMemReference) {
    SymbolicMemoryStatePtr mstate = state->get_memory_state();
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
      SgAsmInstruction* insn = global_descriptor_set->get_insn(addr);
      latest_writers.insert(insn);
    }
  }
  else {
    SymbolicRegisterStatePtr rstate = state->get_register_state();
    //OINFO << "Looking for latest register writer for " << str() << LEND;
    const RegisterStateGeneric::AddressSet& writers = rstate->getWritersUnion(register_descriptor);
    for(rose_addr_t addr : writers.values()) {
      //OINFO << "Latest register writer for " << str() << " was: " << addr_str(addr) << LEND;
      SgAsmInstruction* insn = global_descriptor_set->get_insn(addr);
      latest_writers.insert(insn);
    }
  }
}

} // namespace pharos

//==============================================================================================
//==============================================================================================

// This is a ghetto way to override these simplifiers.  I've talked to Robb about these, and
// they improved versions should show up in ROSE before too much longer.  Review again in NEWWAY.
namespace Rose {
namespace BinaryAnalysis {
namespace SymbolicExpr {

using namespace pharos;

  TreeNodePtr
  IteSimplifier::rewrite(InternalNode *inode) const
  {
    // Is the condition known?
    LeafNodePtr cond_node = inode->child(0)->isLeafNode();
    if (cond_node!=NULL && cond_node->isNumber()) {
      ASSERT_require(1==cond_node->nBits());
      return cond_node->toInt() ? inode->child(1) : inode->child(2);
    }

    // Are both operands the same? Then the condition doesn't matter
    if (inode->child(1)->isEquivalentTo(inode->child(2)))
      return inode->child(1);

    // Are they both extracts of the same offsets?
    SMTSolver *solver = NULL; // FIXME
    InternalNodePtr in1 = inode->child(1)->isInteriorNode();
    InternalNodePtr in2 = inode->child(2)->isInteriorNode();
    if (// Both nodes must be non-NULL (InternalNodes)
        in1 && in2 &&
        // Both nodes must be extract operators
        in1->getOperator() == OP_EXTRACT && in2->getOperator() == OP_EXTRACT &&
        // Both extract nodes must be of the same size
        in1->nBits() == in2->nBits() &&
        // They must have the same "from" bit offset
        in1->child(0)->mustEqual(in2->child(0), solver) &&
        // They must have the same "to" bit offset
        in1->child(1)->mustEqual(in2->child(1), solver) &&
        // The two values must have the same width.
        in1->child(2)->nBits() == in2->child(2)->nBits()) {
      //OINFO << "Rewriting: " << *inode << LEND;
      TreeNodePtr new_ite_expr = InternalNode::create(in1->child(2)->nBits(), OP_ITE, inode->child(0),
                                                      in1->child(2), in2->child(2));

      //OINFO << "New ITE is: " << *new_ite_expr << LEND;
      TreeNodePtr new_extract_expr = InternalNode::create(inode->nBits(), OP_EXTRACT,
                                                          in1->child(0), in1->child(1), new_ite_expr);

      //OINFO << "Rewritten: " << *new_extract_expr << LEND;
      return new_extract_expr;
    }
    return TreeNodePtr();
  }

  // This is the problem solved by our additional simplifier:
  //  expr=(concat[32]
  //     (ite[8] i133304[1] (extract[8] 0x00000018[32] 0x00000020[32] RC_of_0x41159F[32]) 0x00[8])
  //     (ite[8] i133304[1] (extract[8] 0x00000010[32] 0x00000018[32] RC_of_0x41159F[32]) 0x00[8])
  //     (ite[8] i133304[1] (extract[8] 0x00000008[32] 0x00000010[32] RC_of_0x41159F[32]) 0x00[8])
  //     (ite[8] i133304[1] (extract[8] 0x00000000[32] 0x00000008[32] RC_of_0x41159F[32]) 0x00[8]))}

  TreeNodePtr
  ConcatSimplifier::rewrite(InternalNode *inode) const
  {
    SMTSolver *solver = NULL; // FIXME

    Ptr condition;
    bool matches_ite = true;
    Nodes value1;
    Nodes value2;
    //for (size_t i=inode->nchildren(); i>0; --i) {
    for (size_t i=0; i != inode->nChildren(); i++) {
      InternalNodePtr ite = inode->child(i)->isInteriorNode();
      if (!ite || OP_ITE != ite->getOperator()) {
        matches_ite = false;
        break;
      }
      if (i == 0) {
        condition = ite->child(0);
      } else if (!ite->child(0)->mustEqual(condition, solver)) {
        matches_ite = false;
        break;
      }
      //OINFO << "Pushing value1: " << *ite->child(1) << LEND;
      value1.push_back(ite->child(1));
      //OINFO << "Pushing value2: " << *ite->child(2) << LEND;
      value2.push_back(ite->child(2));
    }
    if (matches_ite) {
      //OINFO << "Reordering: " << inode->get_nbits() << " inode=" << *inode << LEND;
      TreeNodePtr concat1 = InternalNode::create(inode->nBits(), OP_CONCAT, value1);
      //OINFO << "Concat1: " << *concat1 << LEND;
      TreeNodePtr concat2 = InternalNode::create(inode->nBits(), OP_CONCAT, value2);
      //OINFO << "Concat2: " << *concat2 << LEND;
      TreeNodePtr new_ite_expr = InternalNode::create(inode->nBits(),
                                                      OP_ITE, condition, concat1, concat2);

      //OINFO << "NewValue: " << *new_ite_expr << LEND;
      return new_ite_expr;
    }

    // This is the standard ROSE simplifier for concat...
    TreeNodePtr retval;
    size_t offset = 0;
    for (size_t i=inode->nChildren(); i>0; --i) { // process args in little endian order
      InternalNodePtr extract = inode->child(i-1)->isInteriorNode();
      if (!extract || OP_EXTRACT!=extract->getOperator())
        break;
      LeafNodePtr from_node = extract->child(0)->isLeafNode();
      ASSERT_require(from_node->nBits() <= 8*sizeof offset);
      if (!from_node || !from_node->isNumber() || from_node->toInt()!=offset ||
          extract->child(2)->nBits()!=inode->nBits())
        break;
      if (inode->nChildren()==i) {
        retval = extract->child(2);
      } else if (!extract->child(2)->mustEqual(retval, solver)) {
        break;
      }
      offset += extract->nBits();
    }
    if (offset==inode->nBits())
      return retval;
    return TreeNodePtr();
  }

  TreeNodePtr
  AddSimplifier::rewrite(InternalNode *inode) const
  {
    if (inode->nChildren() == 2) {
      InternalNodePtr ite1 = inode->child(0)->isInteriorNode();
      bool is_ite1 = (ite1 && OP_ITE == ite1->getOperator());
      InternalNodePtr ite2 = inode->child(1)->isInteriorNode();
      bool is_ite2 = (ite2 && OP_ITE == ite2->getOperator());

      InternalNodePtr ite;
      TreeNodePtr other;
      if (is_ite1 && !is_ite2) {
        ite = ite1;
        other = inode->child(1);
      }
      if (!is_ite1 && is_ite2) {
        ite = ite2;
        other = inode->child(0);
      }
      if (ite) {
        //OINFO << "Reordering: inode=" << *inode << LEND;

        TreeNodePtr add1 = InternalNode::create(inode->nBits(), OP_ADD, ite->child(1), other);
        //OINFO << "Add1: " << *add1 << LEND;

        TreeNodePtr add2 = InternalNode::create(inode->nBits(), OP_ADD, ite->child(2), other);
        //OINFO << "Add2: " << *add2 << LEND;

        TreeNodePtr new_ite_expr = InternalNode::create(inode->nBits(),
                                                        OP_ITE, ite->child(0), add1, add2);

        //OINFO << "NewValue: " << *new_ite_expr << LEND;
        return new_ite_expr;
      }
    }

    // From here on is the standard ROSE simplifier for the Add operation.

    // A and B are duals if they have one of the following forms:
    //    (1) A = x           AND  B = (negate x)
    //    (2) A = x           AND  B = (invert x)   [adjust constant]
    //    (3) A = (negate x)  AND  B = x
    //    (4) A = (invert x)  AND  B = x            [adjust constant]
    //
    // This makes use of the relationship:
    //   (add (negate x) -1) == (invert x)
    // by decrementing adjustment. The adjustment, whose width is the same as A and B, is allowed
    // to overflow.  For example, consider the expression, where all values are two bits wide:
    //   (add v1 (invert v1) v2 (invert v2) v3 (invert v3))            by substitution for invert:
    //   (add v1 (negate v1) -1 v2 (negate v2) -1 v3 (negate v3) -1)   canceling duals gives:
    //   (add -1 -1 -1)                                rewriting as 2's complement (2 bits wide):
    //   (add 3 3 3)                                                   constant folding modulo 4:
    //   1
    // compare with v1=0, v2=1, v3=2 (i.e., -2 in two's complement):
    //   (add 0 3 1 2 2 1) == 1 mod 4
    struct are_duals {

      bool operator()(TreeNodePtr a, TreeNodePtr b,
                      Sawyer::Container::BitVector &adjustment/*in,out*/) {
        ASSERT_not_null(a);
        ASSERT_not_null(b);
        ASSERT_require(a->nBits()==b->nBits());

        // swap A and B if necessary so we have form (1) or (2).
        if (b->isInteriorNode()==NULL)
          std::swap(a, b);
        if (b->isInteriorNode()==NULL)
          return false;

        InternalNodePtr bi = b->isInteriorNode();
        if (bi->getOperator()==OP_NEGATE) {
          // form (3)
          ASSERT_require(1==bi->nChildren());
          return a->isEquivalentTo(bi->child(0));
        } else if (bi->getOperator()==OP_INVERT) {
          // form (4) and ninverts is small enough
          if (a->isEquivalentTo(bi->child(0))) {
            adjustment.decrement();
            return true;
          }
        }
        return false;
      }
    };

    // Arguments that are negated cancel out similar arguments that are not negated
    bool had_duals = false;
    Sawyer::Container::BitVector adjustment(inode->nBits());
    Nodes children = inode->children();
    for (size_t i=0; i<children.size(); ++i) {
      if (children[i]!=NULL) {
        for (size_t j=i+1; j<children.size() && children[j]!=NULL; ++j) {
          if (children[j]!=NULL && are_duals()(children[i], children[j], adjustment/*in,out*/)) {
            children[i] = Sawyer::Nothing();
            children[j] = Sawyer::Nothing();
            had_duals = true;
            break;
          }
        }
      }
    }
    if (!had_duals)
      return TreeNodePtr();

    // Build the new expression
    children.erase(std::remove(children.begin(), children.end(), TreeNodePtr()), children.end());
    if (!adjustment.isEqualToZero())
      children.push_back(LeafNode::createConstant(adjustment));
    if (children.empty())
      return LeafNode::createInteger(inode->nBits(), 0, inode->comment());
    if (children.size()==1)
      return children[0];
    return InternalNode::create(inode->nBits(), OP_ADD, children, inode->comment());
  }

} // namespace SymbolicExpr
} // namespace BinaryAnalysis
} // namespace rose

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
