// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include "member.hpp"
#include "descriptors.hpp"
#include "masm.hpp"
#include "method.hpp"

namespace pharos {

Member::Member(unsigned int o, unsigned int s, rose_addr_t ec,
               SgAsmx86Instruction* i, const VFTEvidence* v) {
  offset = o;
  size = s;
  object = NULL; // this should really be a type field.

  // It appears that it's possible to have a vtable and an embedded object simultaneously.
  // This happens when there's multple inheritance, and we feel entitled to overwrite the
  // vtable to the embedded object.

  // An non-zero address means we're an embedded object, so add it to the list of embedded
  // constructors.
  if (ec != 0) {
    embedded_ctors.insert(ec);
  }

  // Add the instruction to the list of using instructions.
  using_instructions.insert(i);

  // The evidence for the virtual function table pointer is allowed to be NULL.
  best_vftable = NULL;
  if (v != NULL) {
    // Add the evidence to the list.
    vftables.insert(*v);
    // Set the best vftable to point to the object in the set.
    pick_best_vftable();
  }
}

// There needs to be a better algorithm here to select the "best" virtual function table from
// the set of evidence provided.  To begin with we're implementing the simplest possible
// algorithm, which is that the write with the largest address is the best.  This should
// produce the correct answer in most cases, but there are some corner cases.
//
// The answer will incorrect when the instruction address order differs from the control flow
// order (we should use dominance relationships instead).  With this exception, we should
// produce the correct answer when all parent constructors have been inlined into the current
// function.  However, when we've merged multiple separate constructors into one evidence set,
// such as occurs when there's a non-inlined parent constructor, we will again choose
// incorrectly, and should incorporate the logic currently in
// ClassDescriptor::add_data_member() to correct this defect.
void Member::pick_best_vftable() {
  best_vftable = NULL;
  rose_addr_t baddr = 0;
  for (const VFTEvidence& e : vftables) {
    rose_addr_t eaddr = e.insn->get_address();
    if (eaddr > baddr) {
      if (e.vftable) best_vftable = e.vftable;
    }
  }
}

// Merge two members.  This method forms the core of our approach to consolidating multiple
// member accesses into a consistent whole.
void Member::merge(Member& m, rose_addr_t loc) {
  if (size != m.size) {

    // There might be a better place to do this conceptually, but this is where it's currently
    // the easiest.  If our current member is a virtual function table has the correct size,
    // and the new member is an embedded object, that conclusively makes the embedded object
    // our parent.  Report that now, but at the present time, we're not going to do much more
    // with that information.  Part of the goal here is to avoid generating the error massage
    // about overwriting the object size, since this behavior is expected.
    size_t arch_bytes = global_descriptor_set->get_arch_bytes();
    if (is_virtual() && size == arch_bytes && m.size == 0 && m.is_embedded_object()) {
      // Don't try to identify the constructor right now, just mention the inheritance
      // relationship.  We'll figure it out from the passed methods later.
      GINFO << "Member at offset " << m.offset << " in function " << addr_str(loc)
            << " is a parent class." << LEND;
      // Set the size to zero, because we don't know how large the embedded object is.
      size = 0;
    }
    // Jeff Gennari rightly proposed that the bigger member access should win.  This happens
    // a fair bit for expected reasons, so Cory considers it debugging.
    else if (m.size > size) {
      GDEBUG << "Overwrote data member size " << size << " with " << m.size
             << " at offset " << m.offset << " in function " << addr_str(loc) << LEND;
      size = m.size;
    }
    else {
      GDEBUG << "Refused to overwrite data member size " << size << " with " << m.size
             << " at offset " << m.offset << " in function " << addr_str(loc) << LEND;
    }
  }

  // Merge all evidence for virtual function tables into the existing member.  For a while
  // this was an ordered list, but complexities surrounding the merging of members eventually
  // prompted us to make this into an unordered set.
  vftables.insert(m.vftables.begin(), m.vftables.end());

  // Now that we've updated our merged virtual function table evidence set, we need to pick the
  // best virtual function table again.
  if (m.vftables.size() > 0) pick_best_vftable();

  // Always merge the embedded methods into the list.  Cory's not currently aware of any
  // situations where this is the incorrect thing to do.  Even in cases where there's a
  // virtual function table, which just confirms the inheritance relationship.
  embedded_ctors.insert(m.embedded_ctors.begin(), m.embedded_ctors.end());

  // Always merge the using instructions into the current list.  Presumably this is other
  // accesses of the same member discovered from another method on the class.  It's a little
  // unclear whether this should ever happen on the members referenced from a this-pointer
  // usage, or whether this behavior should be restricted to members referenced from a class
  // description, and how we might go about enforcing that restriction.
  using_instructions.insert(m.using_instructions.begin(), m.using_instructions.end());
}

// Print a member...  Moved here because it uses this_call_methods global for determination of
// whether the ctor is an OO method.  Is that really needed, or do we know it's an OO method?
void Member::debug() const {
  OINFO << boost::str(boost::format("Member: Offset: 0x%04X") % offset);
  OINFO << boost::str(boost::format(" Size: 0x%04X") % size);
  // Case 1: vftable and embedded object means parent class
  if (get_vftable() != NULL && is_embedded_object()) {
    OINFO << " [parent class]";
  }
  // Case 2: embedded object only means oridinary embedded object.
  else if (is_embedded_object()) {
    OINFO << " [embedded object]";
  }

  // Case 3: ordinary member (emit no special message).

  // Finally, we may have a vftable, either from a parent class, or for our own class.
  VirtualFunctionTable* vtable = get_vftable();
  if (vtable != NULL) {
    OINFO << boost::str(boost::format(" [vftable at 0x%08X]") % vtable->addr);
  }
  OINFO << LEND;

  // If we're an embedded object, say where we were constructed from.
  for (rose_addr_t ec : embedded_ctors) {
    OINFO << boost::str(boost::format("  Passed to method at 0x%08X") % ec) << LEND;
  }

  // List the instructions that use this member.
  for (SgAsmx86Instruction* i : using_instructions) {
    // It's help when debugging to see which function the instruction was in.
    FunctionDescriptor* ifd = global_descriptor_set->get_fd_from_insn(i);
    OINFO << "  Member used at: " << debug_instruction(i)
          << " in function " << ifd->address_string() << LEND;
  }

  // If we have a virtual function table, now print the entries.
  VirtualFunctionTable* vftable = get_vftable();
  if (vftable != NULL) {
    // Perhaps we should print the whole vtable here via vftable->print(o)...
    for (unsigned int e = 0; e < vftable->max_size; e++) {
      rose_addr_t fptr = vftable->read_entry(e);
      std::string ftype = "non-function";
      ThisCallMethod* tcm = follow_oo_thunks(fptr);
      if (tcm != NULL) {
        ftype = "method";
      }
      else if (global_descriptor_set->get_func(fptr) != NULL) {
        ftype = "function";
      }
      OINFO << "  VTable Entry: " << e << " points to " << ftype << " " << addr_str(fptr) << LEND;
    }
  }
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
