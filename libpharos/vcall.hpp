// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Virtual_Function_Call_H
#define Pharos_Virtual_Function_Call_H

#include "misc.hpp" // For TreeNodePtr & LeafNodePtr
#include "semantics.hpp" // SymbolicValuePtr
#include "funcs.hpp"

namespace pharos {

class PDG; // Forward declaration to avoid include pdg.hpp

// this is the call-specific information for virutal function calls.
class VirtualFunctionCallInformation {
 public:
  // the offset in the object of the virtual function table
  unsigned int vtable_offset;

  // the offset in the virtual function table for the call
  unsigned int vfunc_offset;

  // the symbolic value for the object to which the virtual function belongs
  SymbolicValuePtr obj_ptr;

  // expanded version of obj_ptr
  TreeNodePtr expanded_obj_ptr;

};

// A vector of VirtualCallInformation objects.
using VirtualFunctionCallVector = std::vector<VirtualFunctionCallInformation>;

// This class analyzes a virtual function call.  The algorithm is rather complex, and is
// documented in the analyze method.
class VirtualFunctionCallAnalyzer {
 private:

  // the instruction for the call invocation
  SgAsmX86Instruction *call_insn;

  const FunctionDescriptor* fd;
  const PDG* pdg;

  // Resolves one of several object pointers to a virtual call.
  bool resolve_object(const TreeNodePtr& object_expr,
                      int64_t vtable_offset);

 public:

  // The results of the analysis.
  VirtualFunctionCallVector vcall_infos;

  VirtualFunctionCallAnalyzer(SgAsmX86Instruction *i, const FunctionDescriptor *fd);

  ~VirtualFunctionCallAnalyzer() = default;

  // Analyze the call to determine if it is a virtual function call
  // the call_info parameter is an output parameter or null;
  bool analyze();

};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
