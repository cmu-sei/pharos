// Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "vcall.hpp"
#include "pdg.hpp"
#include "masm.hpp"

namespace pharos {

VirtualFunctionCallAnalyzer::VirtualFunctionCallAnalyzer(
  SgAsmX86Instruction *i, const PDG *p)
  : call_insn(i), pdg(p)
{}

VirtualFunctionCallAnalyzer::~VirtualFunctionCallAnalyzer() { /* Nothing to do here */ }

bool VirtualFunctionCallAnalyzer::resolve_object(const TreeNodePtr& object_expr,
                                                 const TreeNodePtr& vtable_ptr,
                                                 int64_t vtable_offset) {

  // Step 8.  Extract the variable and constant portions from the vtable abstract access
  // providing the vtable pointer and the offset into the vtable.
  AddConstantExtractor ooace = AddConstantExtractor(object_expr);

  // There must be a variable portion for this to be a virtual function call.
  const TreeNodePtr & object_ptr = ooace.variable_portion();
  if (object_ptr == NULL) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn)
           << " - no variable portion in object_expr=" << *object_expr << LEND;
    return false;
  }

  // Object offsets are not allowed to be negative.
  int64_t object_offset = ooace.constant_portion();
  if (object_offset < 0) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn)
           << " - negative object offset in object_expr=" << *object_expr << LEND;
    return false;
  }

  // We're arbitrarily enforcing a requirement that object pointers be leaf nodes.  This
  // probably isn't correct, but we'll need to think about it more.
  const LeafNodePtr & lobj_ptr = object_ptr->isLeafNode();
  if (!lobj_ptr) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn)
           << " - rejected non-leaf ptr=" << *object_ptr << LEND;
    return false;
  }

  // this is a virtual function call. Save the call information
  VirtualFunctionCallInformation vci;

  vci.vtable_ptr = vtable_ptr;
  vci.vtable_offset = object_offset;
  vci.vfunc_offset = vtable_offset;
  // In NEWWAY is anyone using vc->obj_ptr?
  vci.obj_ptr = SymbolicValue::treenode_instance(object_expr);
  vci.lobj_ptr = lobj_ptr;

  vcall_infos.push_back(vci);

  GINFO << "Virtual Call: vtoff=" << object_offset << " vfoff=" << vtable_offset
        << " thisptr=" << *(vci.lobj_ptr) << " insn=" << debug_instruction(call_insn) << LEND;
  return true;
}

// Typedef to eliminate long wrapping variables declarations below.
using AASet = std::set<const AbstractAccess*>;

// Find all memory accesses for the instruction that can be equal to the value.
AASet
find_accesses(SgAsmX86Instruction* insn,
              const DUAnalysis& du,
              const TreeNodePtr value)
{
  // Our return value.
  AASet result;

  // Because we've not handled ITE expressions in value (or aa.value for that matter) very
  // gracefully, we're going to at last permit anything remotely matching by using the
  // can_be_equal() comparison.  Our inability to add methods to TreeNodePtr means that we have
  // to do some sillyness here to convert the passed expression into a symbolic value so that
  // we can call can_be_equal() on our extended SymbolicValue class.
  SymbolicValuePtr sv = SymbolicValue::treenode_instance(value);

  // Go through each memory read looking for ones that match the value.
  for (const AbstractAccess& aa : du.get_reads(insn->get_address())) {
    //GDEBUG << "Considering AA=" << aa << LEND;
    // If the value in the access can be equal to the value supplied, add it to the set.
    if (sv->can_be_equal(aa.value)) {
      result.insert(&aa);
      GDEBUG << "Found AA: " << debug_instruction(insn) << " for value=" << *value << LEND;
    }
  }

  return result;
}

bool VirtualFunctionCallAnalyzer::analyze() {

  // Example code:
  //
  // A: mov edx, [ecx+4]
  // B: mov edi, [edx+8]
  // C: call edi
  //
  // Answer:
  //   Virtual, obj_ptr=X, vtable_ptr=Y, object_offet = 4, vtable_offset=8

  // 1. Find the abstract access for the vfunc pointer in the call instruction.
  // 2. Get the instruction that that defined the vfunc pointer.
  // 3. Find the abstract access that read the vfunc pointer.
  // 4. Extract the variable and constant portions from the vtable access.
  // 5. Find the abstract access that read the vtable pointer.
  // 6. Find the instruction that defined the vtable pointer.
  // 7. Find the abstract acccess that read the vtable pointer.
  // 8. Extract the variable and constant portions from the object access.

  GDEBUG << "Evaluating possible virtual call: " << debug_instruction(call_insn) << LEND;

  const DUAnalysis& du = pdg->get_usedef();

  // We're looking for the register or address that was read in the call insn
  auto reads = du.get_reads(call_insn->get_address());
  // If there were no reads in the call, something's really wrong.
  if (std::begin(reads) == std::end(reads)) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn) << " - no read of target." << LEND;
    return false;
  }

  // Step 1. Find the abstract access that obtained the virtual function pointer.  This is the
  // read that that was not the stack pointer register.
  const AbstractAccess* vfunc_aa = NULL;
  for (const AbstractAccess& aa : reads) {
    if (aa.is_mem()) {
      vfunc_aa = &aa;
    }
    else {
      // Reads of the ESP register don't count (because they're always present in call
      // instruction for the manipulation of the stack for the return address).
      if (aa.register_descriptor == du.ds.get_stack_reg()) continue;
      if (aa.register_descriptor.get_major() == x86_regclass_segment) continue;
      vfunc_aa = &aa;
    }
  }

  // If the virtual function pointer is still NULL, we're not a virtual call.
  if (vfunc_aa == NULL) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn) << " - no virtual func access." << LEND;
    return false;
  }

  // Step 2. Find the instructions that defined the virtual function pointer.  There are the
  // instructions that reference the virtual function table and the offset into it.  There
  // might be more than one such instruction based on slightly unusual control flow.
  InsnSet vftable_insns;

  // A little trick here supports calls of the form "call [reg+X]" more easily.  In this case,
  // the call instruction itself is the instruction with the vftable offset in it, and there's
  // only ever one vftable instruction.
  if (vfunc_aa->is_mem()) {
    vftable_insns.insert(call_insn);
  }
  // If the instruction was of the form "call reg", there are one or more different
  // instructions with the vftable offset in it.  These instructions are the latest writers to
  // the register in the call instruction.
  else {
    // Otherwise all of the latest writers are vftable instructions.

    vftable_insns = vfunc_aa->latest_writers;
    // If there are no latest writers at all, fail.  This should be a very unusual case,
    // because _someone_ should have written a call destination into the register.
    // destination.  It appears that this is triggering more often than expected, probably
    // because we don't appear to defining latest writers correctly for our CALL instructions.
    if (vftable_insns.size() == 0) {
      GDEBUG << "Non virtual: " << debug_instruction(call_insn)
             << " - no latest write for vfunc_aa=" << *vfunc_aa << LEND;
      return false;
    }
  }

  // The expression representing the destination of the virtual function call.
  TreeNodePtr vfunc_ptr = vfunc_aa->value->get_expression();

  // Step 3.  For each vftable instruction, find the abstract access that reads the virtual
  // function pointer from the memory address in the virtual function table.
  for (SgAsmInstruction* vftable_ginsn : vftable_insns) {
    SgAsmX86Instruction* vftable_xinsn = isSgAsmX86Instruction(vftable_ginsn);
    GDEBUG << "Possible vtable instruction: " << debug_instruction(vftable_xinsn) << LEND;

    // Find the abstract access (or accesses) that reads the virtual function pointer from the
    // memory address in the virtual function table.  This abstract access is found from the
    // vftable instruction, which might be the call itself, or one of several other
    // instructions depending on control flow.

    // Get the set and check the length, so that we can report more accurately.
    AASet vtable_aas = find_accesses(vftable_xinsn, du, vfunc_ptr);
    // If we didn't find any vtable abstract accesses, that's why this call is not virtual.
    if (vtable_aas.size() == 0) {
      GDEBUG << "Non virtual: " << debug_instruction(call_insn)
             << " - no vtable abstract access vfunc_ptr=" << *vfunc_ptr << LEND;
      continue;
    }

    // For each vtable abstract access, try to find the offset into the table.
    for (const AbstractAccess* vtable_aa : vtable_aas) {
      GDEBUG << "Vtable AA: " << debug_instruction(vftable_xinsn)
             << " vfunc_ptr=" << *vfunc_ptr << LEND;

      // All valid vtable accesses must be memory reads.
      if (!vtable_aa->is_mem()) {
        GDEBUG << "Non virtual: " << debug_instruction(call_insn)
               << " - vtable access was not a memory read" << *vtable_aa << LEND;
        return false;
      }

      // Step 4.  Extract the variable and constant portions from the vtable abstract access
      // providing the vtable pointer and the offset into the vtable.
      TreeNodePtr vtable_expr = vtable_aa->memory_address->get_expression();
      AddConstantExtractor foace = AddConstantExtractor(vtable_expr);

      // There must be a variable portion for this to be a virtual function call.
      const TreeNodePtr & vtable_ptr = foace.variable_portion();
      if (vtable_ptr == NULL) {
        GDEBUG << "Non virtual: " << debug_instruction(call_insn)
               << " - no variable portion in vtable_expr=" << *vtable_expr << LEND;
        continue;
      }

      // Virtual function table offsets are not allowed to be negative, but they can be zero.
      int64_t vtable_offset = foace.constant_portion();
      if (vtable_offset < 0) {
        GDEBUG << "Non virtual: " << debug_instruction(call_insn)
               << " - negative vtable offset in vtable_expr=" << *vtable_expr << LEND;
        continue;
      }

      // Report the likely virtual function table pointer and offset into the table.
      GDEBUG << "Possible virtual function table pointer: " << *vtable_ptr << LEND;
      GDEBUG << "Possible virtual function offset in vtable: " << vtable_offset << LEND;

      // Step 5.  Find the abstract access where the vtable pointer was read.

      // It's unclear what we should do when vtable_ptr is an ITE expression.  Currently,
      // find_accesses() uses can_be_equal() which isn't perfect.  Cory thought it was unlikely
      // that such a situation would arise in real virtual calls, but there are some examples
      // in Lite/poly.exe involving std::basic_char_streambuf.  More investigation and work is
      // required here, probably involving an approach that might result in multiple valid
      // resolutions of the call.  For now, this is good enough, and is close to what we did
      // previously.

      AASet vtable_ptr_aas = find_accesses(vftable_xinsn, du, vtable_ptr);

      for (const AbstractAccess* vtable_ptr_aa : vtable_ptr_aas) {

        // If the abstract access was NULL, then there's clearly no latest writer.
        if (vtable_ptr_aa == NULL) {
          GDEBUG << "Non virtual: " << debug_instruction(call_insn)
                 << " - no writer for vtable_ptr=" << *vtable_ptr << LEND;
          continue;
        }

        // Step 6.  Find the instruction that wrote the value into the vtable pointer.  This is
        // the instruction that references the object pointer and the offset into it.  Perhaps
        // we should be doing something will all of the writers, not just the first one?
        if (vtable_ptr_aa->latest_writers.size() == 0) {
          GDEBUG << "Non virtual: " << debug_instruction(call_insn)
                 << " - no latest write for vtable_aa=" << *vtable_ptr_aa << LEND;
          continue;
        }
        SgAsmX86Instruction* object_insn = isSgAsmX86Instruction(*(vtable_ptr_aa->latest_writers.begin()));
        if (object_insn == NULL) {
          GDEBUG << "Non virtual: " << debug_instruction(call_insn)
                 << " - no insn for vtable_ptr_aa=" << *vtable_ptr_aa << LEND;
          continue;
        }

        GDEBUG << "Possible object instruction:" << debug_instruction(object_insn) << LEND;

        // Step 7.  Find the abstract access that read the virtual function table pointer from
        // the memory address in the object.
        AASet object_aas = find_accesses(object_insn, du, vtable_ptr);

        for (const AbstractAccess* object_aa : object_aas) {
          // If we couldn't find where the object was written, fail.
          if (object_aa == NULL) {
            GDEBUG << "Non virtual: " << debug_instruction(call_insn)
                   << " - no object abstract access =" << debug_instruction(object_insn) << LEND;
            continue;
          }

          // All reads of the vtable pointer must be from memory (in the object).
          if (!(object_aa->is_mem())) {
            GDEBUG << "Non virtual: " << debug_instruction(call_insn)
                   << " - object access not to memory =" << *object_aa << LEND;
            continue;
          }

          // Step 8. We've now got the object pointer expression, but it might be a complicated
          // ITE expression.  To really conmplete step 8, we'll need to invoke the correct
          // logic on each of the possible values.
          SymbolicValuePtr object_sv = object_aa->memory_address;

          GDEBUG << "Possible multi-valued object pointer: " << *object_sv << LEND;

          // There are probably some major changes that can be made to this logic post-NEWWAY!
          if (object_sv->contains_ite()) {
            GDEBUG << "VCall ITE: " << *object_sv << LEND;
            bool matched = false;
            for (const TreeNodePtr& tn : object_sv->get_possible_values()) {
              GDEBUG << "VCall ITE this-ptr: " << *tn << LEND;
              // The most common non OO condition is the NULL pointer.
              if (tn->isIntegerConstant() && tn->isLeafNode()->bits().isAllClear()) {
                GDEBUG << "Skipping NULL pointer as possible object pointer." << LEND;
                continue;
              }

              if (resolve_object(tn, vtable_ptr, vtable_offset)) matched = true;
            }
            // We're still returning true on the _first_ matched entry, so results should be
            // fairly similar.
            if (matched) return true;
          }
          else {
            GDEBUG << "VCall Non-ITE:" << *object_sv << LEND;
            if (resolve_object(object_sv->get_expression(),
                               vtable_ptr, vtable_offset)) return true;
          }
        }
      }
    }
  }

  GDEBUG << "Non virtual: " << debug_instruction(call_insn)
         << " - couldn't find offsets in general." << LEND;
  return false;
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
