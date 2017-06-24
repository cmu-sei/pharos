// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/format.hpp>

#include <rose.h>

#include "misc.hpp"
#include "masm.hpp"
#include "pdg.hpp"
#include "usage.hpp"
#include "method.hpp"
#include "member.hpp"

namespace pharos {

// A global map of object uses.  Populated in analyze_functions_for_object_uses().
ObjectUseMap object_uses;

template<> char const* EnumStrings<AllocType>::data[] = {
  "Unknown",
  "Stack",
  "Heap",
  "Global",
  "Param",
};


using Rose::BinaryAnalysis::SymbolicExpr::OP_ITE;

// A hacked up routine to pick the correct object pointer from an ITE expression.  There's much
// better ways to implement this, but none that will be as easy for demonstrating that this is
// not a major architectural problem with the ITE expressions.  More NEWWAY fixes are required.
// Additionally, this function is currently only used in this file, but it might be useful
// elsewhere as well.
SymbolicValuePtr pick_this_ptr(SymbolicValuePtr& sv) {
  InternalNodePtr in = sv->get_expression()->isInteriorNode();
  if (in && in->getOperator() == OP_ITE) {
    // For right now, make a complete copy of the symbolic value, maintaining definers and so
    // forth.  Set the expression to just the half that we're interested in.
    SymbolicValuePtr newsv = sv->scopy();
    newsv->set_expression(in->child(1));
    return newsv;
  }
  else {
    return sv;
  }
}

ThisPtrUsage::ThisPtrUsage(FunctionDescriptor* f, SymbolicValuePtr tptr,
                           ThisCallMethod* tcm, SgAsmInstruction* call_insn) {
  assert(tptr);
  this_ptr = tptr;
  ctor = NULL;

  fd = f;
  assert(fd != NULL);

  // We don't know anything about our allocation yet.
  alloc_type = AllocUnknown;
  alloc_size = 0;
  alloc_insn = NULL;

  // New way of handling methods.  Use a set instead of a vector, but keep the first one
  // separately, so we can guess at constructors.
  first_method = tcm;
  add_method(tcm, call_insn);
  analyze_alloc();
}

// Report a unique identifier for this usage in a human readable way.
std::string ThisPtrUsage::identifier() const {
  // The this-pointer is a machine readable identifier (symbolic value), but it doesn't help
  // a human identify where the object instance is in the program.  The allocation address
  // would be the best human readable identifier, since it also identifies a specific object
  // instance, but sadly we haven't always identified an allocation instruction, so we'll
  // also report the function that the object occurs in.
  if (alloc_insn != NULL) {
    return boost::str(boost::format("allocated at 0x%08X") % alloc_insn->get_address());
  }
  else {
    return boost::str(boost::format("in function 0x%08X") % fd->get_address());
  }
}

// This verison is old.  It probably makes more sense to call through ObjectUse::debug() now.
void ThisPtrUsage::debug_methods() const {
  // There were several copies of this code, each a little different.  This seems to be the
  // combination of the best attributes.
  if (GDEBUG) {
    GDEBUG << "Methods sharing a this-pointer=" << *(this_ptr) << " :";
    for (const ThisCallMethod* tcm : methods) {
      GDEBUG << "  " << tcm->address_string();
    }
    GDEBUG << LEND;
  }
}

void ThisPtrUsage::debug() const {
  GDEBUG << " thisptr=" << *(this_ptr->get_expression());

  //GDEBUG << " alloc=" << Enum2Str(alloc_type) << " { ";
  GDEBUG << " { ";

  for (const ThisCallMethod* tcm : methods) {
    GDEBUG << tcm->address_string() << " ";
  }
  GDEBUG << "}";
}

void ThisPtrUsage::pick_ctor() {
  // A list of possible constructors in the this-pointer usage.
  ThisCallMethodSet ctors;

  // Try picking the constructor by looking at the methods set.
  for (ThisCallMethod* tcm : methods) {
    // If this one could be a constructor, add it to the set.
    if (tcm->is_constructor()) ctors.insert(tcm);
  }

  // One (and only one) constructor is what we expected.  Set the ctor to that method.
  if (ctors.size() == 1) {
    ThisCallMethod* new_ctor = *ctors.begin();
    // Jeff Gennari recommended this additional test, and it turns out that in every case
    // where it's true in the test suite, something else has gone wrong, so we're not going
    // to return a ctor in this case, since it seems to be more wrong than right.  Now that
    // there's a proper dominance rule, this is probably not needed (or correct).
    if (new_ctor != first_method) {
      GWARN << "The apparent constructor was not the first method called. ctor="
            << new_ctor->address_string() << " fm=" << first_method->address_string() << LEND;
    }
    else {
      ctor = new_ctor;
    }
  }
  // This is a pretty common condition when we've admitted many things that are not really
  // __thiscall to methods list.  Once we've tightened down the calling convention code some
  // more, we should probably turn this into a warning.  But right now, it's just annoying
  // with lots of spew about being unable to find constructors from __fastcall functions.
  else if (ctors.size() == 0) {
    if (GDEBUG) {
      GDEBUG << "Unable to choose constructor for ThisPtrUsage " << identifier() << ":" << LEND;
      for (ThisCallMethod* tcm : methods) {
        GDEBUG << "  Called method: " << tcm->address_string() << LEND;
      }
    }
  }
  // This is an uncommon condition in which we have multiple methods that return the object
  // pointer.  It appears to be encountered mostly in library IOstreams.  Cory hopes that
  // with better future handling of passed parameters, these warnings will eventually go
  // away.  Right now, pick the first method as passed to the ThisPtrUsage, which Cory would
  // like to remove entirely. :-(
  else {
    GWARN << "Conflicting data on which method is a constructor, choices were:" << LEND;
    for (ThisCallMethod* tcm : ctors) {
      // Hackishly pick the old style first_method if we can't decide.
      if (tcm == first_method) {
        ctor = tcm;
        GWARN << "  Chosen constructor: " << tcm->address_string() << LEND;
      }
      else {
        GWARN << "  Possible constructor: " << tcm->address_string() << LEND;
      }
    }
  }
}

// Object oriented methods which are dominated by other object oriented methods can not be
// constructors.  This should be a rigously sound rule, even if methods or constructors are
// inlined.  The only place where we have any doubts about this rule is highly optimized reuse
// of stack local objects where there's actually two object instances, but we can't tell
// because the compiler has gotten fancy and reused the memory from an earlier object instance
// in a way that results in the same symbolic value.  It's unclear if this is possible, but it
// should certainly be rare.
void ThisPtrUsage::apply_constructor_dominance_rule() {
  // We're going to need the CDG for this function to answer dominance questions.
  PDG* pdg = fd->get_pdg();
  if (pdg == NULL) return;

  // This is a poorly performing way to do this.  A better way would involve a work queue and
  // consider each pair only once, and remove a method on every dominance test.  But this is
  // easier, and will produce the same result, just with a longer run time.
  for (MethodEvidenceMap::value_type& opair : method_evidence) {
    SgAsmX86Instruction* outer_insn = isSgAsmX86Instruction(opair.first);
    if (outer_insn == NULL) continue;
    ThisCallMethod* otcm = *(opair.second.begin());
    for (MethodEvidenceMap::value_type& ipair : method_evidence) {
      SgAsmX86Instruction* inner_insn = isSgAsmX86Instruction(ipair.first);
      if (inner_insn == NULL) continue;

      // Don't ask if instructions dominate themselves...
      if (inner_insn == outer_insn) continue;

      // Does the outer instruction dominate the inner instruction?  If it does, then none of
      // the inner instructions methods can be constructors...  This should really call dominates()
      // once we're passing tests again...
      if (pdg->get_cdg().post_dominates(inner_insn, outer_insn)) {
        GDEBUG << "Insn: " << debug_instruction(outer_insn) << " dominates "
               << debug_instruction(inner_insn) << LEND;
        for (ThisCallMethod* tcm : ipair.second) {
          GDEBUG << "Method " << tcm->address_string()
                 << " cannot be a constructor because it is dominated by "
                 << otcm->address_string() << LEND;
          tcm->set_constructor(false, ConfidenceConfident);
        }
      }
    }
  }
}

// Analyze the allocation type and location of this-pointers.
void ThisPtrUsage::analyze_alloc() {
  // Set the allocation type to unknown by default.
  alloc_type = AllocUnknown;

  // Use the type returned from get_memory_type() to determine our allocation type.  Perhaps in
  // the future thse can be fully combined, but this was what was required to support non-zero
  // ESP initialization.
  MemoryType type = this_ptr->get_memory_type();
  if (type == StackMemLocalVariable) {
    alloc_type = AllocLocalStack;
  }
  else if (type == StackMemParameter) {
    alloc_type = AllocParameter;
  }
  else if (type == UnknownMem) {
    // This code is really a function of get_memory_type() still being broken.
    // If we're not a constant address (global), skip this function.
    if (!this_ptr->is_number()) return;
    // This is a bit hackish, but also reject obviously invalid constants.
    size_t num = this_ptr->get_number();
    if (num < 0x10000 || num > 0x7FFFFFFF) return;
    // Otherwise, we look like a legit global address?
    alloc_type = AllocGlobal;
  }
  else {
    return;
  }

  // It's not actually clear why we're looking for the allocation instruction.  Perhaps we
  // should quit doing this and just use the tests above.  At least for now though, looking for
  // the common pattern allows us to detect some unusual situations.  Wes' previous logic also
  // filtered by requiring LEA instructions, so we're preserving that limit.

  // This code previously relied on the first-creator-of-read feature of modifiers, which we're
  // retiring.  Even though it's not clear that this code is required, I've updated it to use
  // latest definers in place of modifiers, only we haven't switch to just using the _latest_
  // definers yet so it needed some additional filtering to determine which definer to use.
  PDG* pdg = fd->get_pdg();
  // Shouldn't happen.
  if (!pdg) return;
  const DUAnalysis& du = pdg->get_usedef();

  // This is hackish too.  We need it for debugging so that we have some way of reporting which
  // instructions are involved in the confusion.
  SgAsmInstruction* first_insn = NULL;
  for (SgAsmInstruction *ginsn : this_ptr->get_defining_instructions()) {
    // For debugging so that we have an address.
    if (first_insn == NULL) first_insn = ginsn;

    SgAsmX86Instruction *insn = isSgAsmX86Instruction(ginsn);
    if (insn == NULL) continue;

    // Since definers isn't the "latest" definer just yet, filter our subsequent analysis to
    // the one that wrote the this-ptr value.  This is hackish and wrong because we shouldn't
    // have to filter.  But maybe once we can upgrade , this code can go away...
    auto writes = du.get_writes(insn);
    bool found_write = false;
    for (const AbstractAccess& aa : writes) {
      if (aa.value->get_expression()->isEquivalentTo(this_ptr->get_expression())) {
        found_write = true;
        break;
      }
    }
    // If this instruction didn't write the this-ptr, it's not the one that we're looking for.
    if (!found_write) continue;
    // If we're here, this should be the instruction that defined the this-pointer.

    // If we're a local variable and we've found an LEA instruction, that's probably the one
    // we're looking for.
    if (alloc_type == AllocLocalStack && insn->get_kind() == x86_lea) {
      alloc_insn = ginsn;
      GDEBUG << "Stack allocated object: " << *(this_ptr->get_expression()) << " at "
             << debug_instruction(alloc_insn) << LEND;
      return;
    }
    // For global variables, the typical cases are move or push instructions.
    else if (alloc_type == AllocGlobal &&
             (insn->get_kind() == x86_mov || insn->get_kind() == x86_push)) {
      alloc_insn = ginsn;
      GDEBUG << "Global static object: " << *(this_ptr->get_expression()) << " at "
             << debug_instruction(alloc_insn) << LEND;
      return;
    }
    // For passed parameters, we should probably be looking for the instruction that reads the
    // undefined this-pointer value.  This code was sufficient at the time...
    else if (alloc_type == AllocParameter) {
      GDEBUG << "Passed object: " << *(this_ptr->get_expression()) << LEND;
      return;
    }
  }

  if (first_insn == NULL) {
    GDEBUG << "No allocation instruction found for " << *(this_ptr->get_expression())
           << " alloc_type=" << Enum2Str(alloc_type) << LEND;
  }
  else {
    GDEBUG << "No allocation instruction found for " << *(this_ptr->get_expression())
           << " alloc_type=" << Enum2Str(alloc_type) << " at " << debug_instruction(first_insn) << LEND;
  }

  // Based on evaluation of the test suite, if we've reached this point, something's gone
  // wrong, and it's very unclear if we're really the allocation type we thought we were.
  // Perhaps it's better to be cautious and retract our allocation type claims.  We could also
  // choose to return the best guess of our type here, by removing this line.
  //alloc_type = AllocUnknown;
  return;
}

ObjectUse::ObjectUse(FunctionDescriptor* f) {
  fd = f;
  assert(fd != NULL);
  analyze_object_uses();
}

void ObjectUse::apply_constructor_dominance_rule() {
  // For each reference, apply the constructor dominance rule to the this-pointer usage.
  // This must occur after we've analyzed all of the object uses in the function, because
  // it's comparing found calls against each other.

  // This method is very wrong, and completely unecessary in the Prolog version, so it needed
  // to be moved from the constructor into this method so it could be called after the prolog
  // exporting occurred.
  for (ThisPtrUsageMap::value_type& rpair : references) {
    rpair.second.apply_constructor_dominance_rule();
  }
}

void ObjectUse::debug() const {
  for (const ThisPtrUsageMap::value_type& rpair : references) {
    const ThisPtrUsage& tpu = rpair.second;
    GDEBUG << "OU: " << fd->address_string() << " ";
    tpu.debug();
    GDEBUG << LEND;
  }
}

// Analyze the function and populate the references member with information about each
// this-pointer use in the function.  The approach is to use our knowledge about which methods
// are object oriented, by calling follow_oo_thunks(), to identify the symbolic variables in
// the this-pointer location (ECX) at the time of the call.  Therefore this routine must follow
// the find_this_call_methods() analysis pass, and after this routine we should have a
// reasonable set of this-pointers in references.
void ObjectUse::analyze_object_uses() {
  for (CallDescriptor* cd : fd->get_outgoing_calls()) {
    // The the value in the this-pointer location (ECX) before the call.
    SymbolicValuePtr this_ptr = get_this_ptr_for_call(cd);
    GDEBUG << "This-Ptr for call at " << cd->address_string() <<  " is " << *this_ptr << LEND;
    // We're only interested in valid pointers.
    if (!(this_ptr->is_valid())) continue;
    // If the symbolic value is an ITE expression, pick the meaningful one.
    this_ptr = pick_this_ptr(this_ptr);
    GDEBUG << "Updated This-Ptr for call at " << cd->address_string()
           <<  " is " << *this_ptr << LEND;
    // Get the string representation of the this-pointer.
    SVHash hash = this_ptr->get_hash();

    // Go through each of the possible targets looking for OO methods.
    for (rose_addr_t target : cd->get_targets()) {
      // If we're not an OO method, we're not interested.
      ThisCallMethod* tcm = follow_oo_thunks(target);
      if (tcm == NULL) continue;

      // Do we already have any entry for this this-pointer?
      ThisPtrUsageMap::iterator finder = references.find(hash);
      // If we don't create a new entry for the this-pointer.
      if (finder == references.end()) {
        GDEBUG << "Adding ref this_ptr=" << *this_ptr << LEND;
        if (GDEBUG) tcm->debug();
        references.insert(ThisPtrUsageMap::value_type(hash,
          ThisPtrUsage(fd, this_ptr, tcm, cd->get_insn())));
      }
      // Otherwise, add this method to the existing list of methods.
      else {
        GDEBUG << "Adding method this_ptr=" << *this_ptr << LEND;
        finder->second.add_method(tcm, cd->get_insn());
      }
    }
  }
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
