// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/foreach.hpp>

#include "vcall.hpp"
#include "pdg.hpp"

VirtualFunctionCallAnalyzer::VirtualFunctionCallAnalyzer(SgAsmx86Instruction *i, PDG *p) :
    call_insn(i) {
  pdg = p;
}

VirtualFunctionCallAnalyzer::~VirtualFunctionCallAnalyzer() { /* Nothing to do here */ }

#define VT_UNDEFINED 0xFFFFFFFF

bool VirtualFunctionCallAnalyzer::resolve_object(const TreeNodePtr& object_expr,
                                                 const TreeNodePtr& vtable_ptr,
                                                 int64_t vtable_offset,
                                                 CallInformationPtr &call_info) {

  // Step 8.  Extract the variable and constant portions from the vtable abstract access
  // providing the vtable pointer and the offset into the vtable.
  AddConstantExtractor ooace = AddConstantExtractor(object_expr);

  // There must be a variable portion for this to be a virtual function call.
  TreeNodePtr object_ptr = ooace.variable_portion;
  if (object_ptr == NULL) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn)
           << " - no variable portion in object_expr=" << *object_expr << LEND;
    return false;
  }

  // Object offsets are not allowed to be negative.
  int64_t object_offset = ooace.constant_portion;
  if (object_offset < 0) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn)
           << " - negative object offset in object_expr=" << *object_expr << LEND;
    return false;
  }

  // We're arbitrarily enforcing a requirement that object pointers be leaf nodes.  This
  // probably isn't correct, but we'll need to think about it more.
  LeafNodePtr lobj_ptr = object_ptr->isLeafNode();
  if (!lobj_ptr) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn)
           << " - rejected non-leaf ptr=" << *object_ptr << LEND;
    return false;
  }

  // this is a virtual function call. Save the call information
  VirtualFunctionCallInformationPtr vc(new VirtualFunctionCallInformation());

  vc->vtable_ptr = vtable_ptr;
  vc->vtable_offset = object_offset;
  vc->vfunc_offset = vtable_offset;
  // In NEWWAY is anyone using vc->obj_ptr?
  vc->obj_ptr = SymbolicValue::treenode_instance(object_expr);
  vc->lobj_ptr = lobj_ptr;

  call_info = vc;

  GINFO << "Virtual Call: vtoff=" << object_offset << " vfoff=" << vtable_offset
        << " thisptr=" << *(vc->lobj_ptr) << " insn=" << debug_instruction(call_insn) << LEND;
  return true;
}

const AbstractAccess* find_memory_access(SgAsmX86Instruction* insn,
                                         const DUAnalysis& du, const TreeNodePtr value) {
  // We're looking for a read in insn.
  const AbstractAccessVector* reads = du.get_reads(insn);
  // If there are none, return an invalid abstract access.  This probably shouldn't happen
  // because we ought to know that this instruction wrote a symbolic value that obviously came
  // from somewhere.  Return an invalid access if this occurs.
  if (reads == NULL) return NULL;

  // Because we've not handled ITE expressions in value (or aa.value for that matter) very
  // gracefully, we're going to at last permit anything remotely matching by using the
  // can_be_equal() comparison.  Our inability to add methods to TreeNodePtr means that we have
  // to do some sillyness here to convert the passed expression into a symbolic value so that
  // we can call can_be_equal() on our extended SymbolicValue class.
  SymbolicValuePtr sv = SymbolicValue::treenode_instance(value);

  // Go through each read looking for the right one.
  BOOST_FOREACH(const AbstractAccess& aa, *reads) {
    // The right one is the one that matches the requested value.  Or kindof-sortof matches.
    if (sv->can_be_equal(aa.value)) return &aa;
  }
  // We didn't find the value intended.  Return an invalid abstract access.
  return NULL;
}

bool VirtualFunctionCallAnalyzer::analyze(CallInformationPtr &call_info) {

  // Example code:
  //
  // A: mov edx, [ecx+4]
  // B: mod edi, [edx+8]
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

  // reset the CallInformationPtr???
  call_info.reset();

  const DUAnalysis& du = pdg->get_usedef();

  // We're looking for the register or address that was read in the call insn
  const AbstractAccessVector* reads = du.get_reads(call_insn);
  // If there were no reads in the call, something's really wrong.
  if (reads == NULL) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn) << " - no read of target." << LEND;
    return false;
  }

  // Step 1. Find the abstract access that obtained the virtual function pointer.  This is the
  // read that that was not the stack pointer register.
  const AbstractAccess* vfunc_aa = NULL;
  BOOST_FOREACH(const AbstractAccess& aa, *reads) {
     if (aa.is_mem()) {
        vfunc_aa = &aa;
     }
     else {
        // ESP should really be obtained from the architecture depdenent layer (e.g. RSP).
        // EIP and RIP are never in the reads/writes array (because they always are).
        if (aa.reg_name() == "esp") continue;
        vfunc_aa = &aa;
     }
  }

  if (vfunc_aa == NULL) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn) << " - no read of target." << LEND;
    return false;
  }

  // Step 2. Find the instruction that defined the virtual function call.  This is the
  // instruction that references the virtual function table, including the virtual function
  // table and the offset into it.  A little trick supports calls of the form "call [reg+X]".
  SgAsmX86Instruction* vtable_insn = NULL;
  // If the instruction was "call [reg+X]"
  if (vfunc_aa->is_mem()) {
    vtable_insn = call_insn;
  }
  // If the instruction was "call reg"
  else {
    // The vtable instruction will be the latest writer to the register in the call instruction.

    // If there are no latest writers at all, fail.
    if (vfunc_aa->latest_writers.size() == 0) {
      GDEBUG << "Non virtual: " << debug_instruction(call_insn)
             << " - no latest write for vfunc_aa=" << *vfunc_aa << LEND;
      return false;
    }
    vtable_insn = isSgAsmX86Instruction(*(vfunc_aa->latest_writers.begin()));
    if (vtable_insn == NULL) {
      GDEBUG << "Non virtual: " << debug_instruction(call_insn)
             << " - latest write not an X86 insn vfunc_aa=" << *vfunc_aa << LEND;
      return false;
    }
  }

  GDEBUG << "Possible vtable instruction: " << debug_instruction(vtable_insn) << LEND;

  // Step 3.  Find the abstract access that read the virtual function pointer from the memory
  // address in the virtual function table.
  TreeNodePtr vfunc_ptr = vfunc_aa->value->get_expression();
  const AbstractAccess* vtable_aa = find_memory_access(vtable_insn, du, vfunc_ptr);
  // If we couldn't find where the vtable was written, fail.
  if (vtable_aa == NULL) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn)
           << " - no vtable abstract access vfunc_ptr=" << *vfunc_ptr << LEND;
    return false;
  }

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
  TreeNodePtr vtable_ptr = foace.variable_portion;
  if (vtable_ptr == NULL) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn)
           << " - no variable portion in vtable_expr=" << *vtable_expr << LEND;
    return false;
  }

  // Virtual function table offsets are not allowed to be negative, but they can be zero.
  int64_t vtable_offset = foace.constant_portion;
  if (vtable_offset < 0) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn)
           << " - negative vtable offset in vtable_expr=" << *vtable_expr << LEND;
    return false;
  }

  // Report the likely virtual function table pointer and offset into the table.
  GDEBUG << "Possible virtual function table pointer: " << *vtable_ptr << LEND;
  GDEBUG << "Possible virtual function offset in vtable: " << vtable_offset << LEND;

  // Step 5.  Find the abstract access where the vtable pointer was read.

  // It's unclear what we should do when vtable_ptr is an ITE expression.  Currently,
  // find_memory_access() uses can_be_equal() which isn't perfect.  Cory thought it was
  // unlikely that such a situation would arise in real virtual calls, but there are some
  // examples in Lite/poly.exe involving std::basic_char_streambuf.  More investigation and
  // work is required here, probably involving an approach that might result in multiple valid
  // resolutions of the call.  For now, this is good enough, and is close to what we did
  // previously.
  const AbstractAccess* vtable_ptr_aa = find_memory_access(vtable_insn, du, vtable_ptr);
  // If the abstract access was NULL, then there's clearly no latest writer.
  if (vtable_ptr_aa == NULL) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn)
           << " - no writer for vtable_ptr=" << *vtable_ptr << LEND;
    return false;
  }

  // Step 6.  Find the instruction that wrote the value into the vtable pointer.  This is the
  // instruction that references the object pointer and the offset into it.  Perhaps we should
  // be doing something will all of the writers, not just the first one?
  if (vtable_ptr_aa->latest_writers.size() == 0) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn)
           << " - no latest write for vtable_aa=" << *vtable_ptr_aa << LEND;
    return false;
  }
  SgAsmX86Instruction* object_insn = isSgAsmX86Instruction(*(vtable_ptr_aa->latest_writers.begin()));
  if (object_insn == NULL) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn)
           << " - no insn for vtable_ptr_aa=" << *vtable_ptr_aa << LEND;
    return false;
  }

  GDEBUG << "Possible object instruction:" << debug_instruction(object_insn) << LEND;

  // Step 7.  Find the abstract access that read the virtual function table pointer from the
  // memory address in the object.
  const AbstractAccess* object_aa = find_memory_access(object_insn, du, vtable_ptr);
  // If we couldn't find where the object was written, fail.
  if (object_aa == NULL) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn)
           << " - no object abstract access =" << debug_instruction(object_insn) << LEND;
    return false;
  }

  // All reads of the vtable pointer must be from memory (in the object).
  if (!(object_aa->is_mem())) {
    GDEBUG << "Non virtual: " << debug_instruction(call_insn)
           << " - object access not to memory =" << *object_aa << LEND;
    return false;
  }

  // Step 8. We've now got the object pointer expression, but it might be a complicated ITE
  // expression.  To really conmplete step 8, we'll need to invoke the correct logic on each of
  // the possible values.
  SymbolicValuePtr object_sv = object_aa->memory_address;

  GDEBUG << "Possible multi-valued object pointer: " << *object_sv << LEND;

  // There are probably some major changes that can be made to this logic post-NEWWAY!
  if (object_sv->contains_ite()) {
    GDEBUG << "VCall ITE: " << *object_sv << LEND;
    bool matched = false;
    BOOST_FOREACH(const TreeNodePtr& tn, object_sv->get_possible_values()) {
      GDEBUG << "VCall ITE this-ptr: " << *tn << LEND;
      // The most common non OO condition is the NULL pointer.
      if (tn->isNumber() && tn->toInt() == 0) {
        GDEBUG << "Skipping NULL pointer as possible object pointer." << LEND;
        continue;
      }

      if (resolve_object(tn, vtable_ptr, vtable_offset, call_info)) matched = true;
    }
    if (matched) return true;
  }
  else {
    GDEBUG << "VCall Non-ITE:" << *object_sv << LEND;
    if (resolve_object(object_sv->get_expression(), vtable_ptr, vtable_offset, call_info)) return true;
  }

  GDEBUG << "Non virtual: " << debug_instruction(call_insn)
         << " - couldn't find offsets in general." << LEND;
  return false;
}
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
