// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Virtual_Function_Call_H
#define Pharos_Virtual_Function_Call_H

#include "util.hpp"
#include "defuse.hpp"
#include "calls.hpp"

namespace pharos {

// this is the call-specific information for virutal function calls.
class VirtualFunctionCallInformation : public CallInformation {
public:
  // the offset in the object of the virtual function table
  unsigned int vtable_offset;

  // the offset in the virtual function table for the call
  unsigned int vfunc_offset;

  // The expression pointing to the virtual function table.
  TreeNodePtr vtable_ptr;

  // the symbolic value for the object to which the virtual function belongs
  SymbolicValuePtr obj_ptr;

  // The leaf node of the this-pointer to which the virtual function belongs
  LeafNodePtr lobj_ptr;

  ~VirtualFunctionCallInformation() { /* Nothing to do here */ }
};

// This is a shared pointer for virtual function call information. It must be shared to avoid
// weird memory issues when it is stored in the CallDescriptorMap
typedef boost::shared_ptr<VirtualFunctionCallInformation> VirtualFunctionCallInformationPtr;


// This class analyzes a virtual function call. To be a virtual function call
// a Call must be register-based and have two code dereferences. Dereference #1
// fetches the virtual function from the virtual function table. Dereference #2
// fetches the virtual function table from the object
class VirtualFunctionCallAnalyzer {
private:

  // the instruction for the call invocation
  SgAsmx86Instruction *call_insn;

  PDG* pdg;

public:

  VirtualFunctionCallAnalyzer(SgAsmX86Instruction *i, PDG *p);

  ~VirtualFunctionCallAnalyzer();

  // Analyze the call to determine if it is a virtual function call
  // the call_info parameter is an output parameter or null;
  bool analyze(CallInformationPtr &call_info);

  // Resolves one of several object pointers to a virtual call.
  bool resolve_object(const TreeNodePtr& object_expr, const TreeNodePtr& vtable_ptr,
                      int64_t vtable_offset, CallInformationPtr &call_info);

};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
