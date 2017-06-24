// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Stkvar_H
#define Stkvar_H

#include <rose.h>

#include "semantics.hpp"


namespace pharos {

// Forward declaration to simplify include cycles.
class TypeDescriptor;
typedef boost::shared_ptr< TypeDescriptor > TypeDescriptorPtr;

class FunctionDescriptor;
class DUAnalysis;

// Data structure for a stack variable. A stack variable is a memory location on
// the stack that is accessed via one of the stack registers (frame or stack
// pointer).
class StackVariable {
 public:

  // Builds a new stack variable.
  StackVariable(SgAsmx86Instruction *insn, int64_t off, const AbstractAccess &aa);

  // Read properties for various stack variable elements

  int64_t offset() const;

  const InsnSet& usages();

  std::vector<std::reference_wrapper<const AbstractAccess>> accesses();

  void add_evidence(SgAsmx86Instruction *i, const AbstractAccess& aa);

  void add_usage(SgAsmx86Instruction *i);

  void add_access(const AbstractAccess& aa);

  TypeDescriptorPtr get_type_descriptor() const;

  // prints the major parts of a stack variable (offset, value, usage
  // instructions and size)
  std::string to_string() const;

 private:

  // the offset of this variable. Maintained for lookup purposes
  int64_t offset_;

  TypeDescriptorPtr type_descriptor_;

  // the AbstractAccesses associated with the StackVariable. This may be the same
  // for all variables ... in that case saving the expression is not necessary

  std::vector<std::reference_wrapper<const AbstractAccess>> abstract_accesses_;

  // The set of instructions that use the stack variable
  InsnSet usages_;

}; // end StackVariable


// return true if the instruction supplied is associated with a saved
// register. Return false otherwise.
bool uses_saved_register(const SgAsmx86Instruction *insn, FunctionDescriptor *fd);

// Return true if the instruction supplied is the one that passed the
// parameter (push it onto the stack or loaded it into a register). Returns false
// otherwise
bool uses_parameter(const SgAsmx86Instruction *insn, FunctionDescriptor *fd);

// Detect stack variables for a given function
void analyze_stack_variables(FunctionDescriptor *fd);

// the following function are helpers to gather information about stack
// variables. They are local to this function
void identify_stack_variables(FunctionDescriptor *fd);

const AbstractAccess* get_memory_access(SgAsmX86Instruction* insn,
                                        const DUAnalysis& du, const TreeNodePtr value);

void assign_stack_variable_types(FunctionDescriptor *fd);

void analyze_accesses_for_stack_variables(SgAsmX86Instruction* insn,
                                          const AbstractAccessVector* aavec, FunctionDescriptor *fd,
                                          const SymbolicValuePtr &initial_esp_sv);


// a list of stack variable pointers
typedef std::vector<StackVariable*> StackVariablePtrList;

} // namespace pharos

#endif

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
