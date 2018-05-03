// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Stkvar_H
#define Stkvar_H

#include <rose.h>
#include "semantics.hpp"

namespace pharos {

// Forward declaration to simplify include cycles.
class TypeDescriptor;
class ParameterDefinition;

typedef boost::shared_ptr< TypeDescriptor > TypeDescriptorPtr;

class FunctionDescriptor;
class DUAnalysis;

struct StackVariableEvidence {

  StackVariableEvidence(SgAsmX86Instruction *i, int64_t off, const AbstractAccess &a, bool p, bool l)
    : insn(i), offset(off), aa(a), uses_param(p), in_value(l) { }

  SgAsmX86Instruction* insn;
  int64_t offset;
  AbstractAccess aa;
  bool uses_param;
  bool in_value;
};

typedef std::vector<StackVariableEvidence*> StackVariableEvidencePtrList;

// Data structure for a stack variable. A stack variable is a memory location on
// the stack that is accessed via one of the stack registers (frame or stack
// pointer).
class StackVariable {
 public:

  // Builds a new stack variable based on initial evidence
  StackVariable(int64_t off);

  int64_t get_offset() const;

  const InsnSet& get_usages() const;

  std::vector<SymbolicValuePtr> get_values() const;

  void add_value(SymbolicValuePtr v);

  SymbolicValuePtr get_memory_address() const;

  void set_memory_address(SymbolicValuePtr m);

  const StackVariableEvidencePtrList& get_evidence() const;

  void add_evidence(StackVariableEvidence* e);

  void add_usage(SgAsmx86Instruction *i);

  // prints the major parts of a stack variable (offset, value, usage
  // instructions and size)
  std::string to_string() const;

 private:

  // the offset of this variable. Maintained for lookup purposes
  int64_t offset_;

  // the AbstractAccesses associated with the StackVariable. This may be the same
  // for all variables ... in that case saving the expression is not necessary
  StackVariableEvidencePtrList evidence_;

  // The value(s) associated with the stack variable. Note that there can be more than one
  // value, if the variable is reassigned. Each variable, however, only has one memory address
  std::vector<SymbolicValuePtr> values_;

  // The value associated wih the stack variable's address
  SymbolicValuePtr memory_address_;

  // The set of instructions that use the stack variable
  InsnSet usages_;

}; // end StackVariable

typedef StackVariable* StackVariablePtr;

// a list of stack variable pointers
typedef std::vector<StackVariablePtr> StackVariablePtrList;

// The StackVariableAnalyzer collects and processes evidence of stack variables
class StackVariableAnalyzer {

 private:

  // all evidence found indicating stack variable existence
  StackVariableEvidencePtrList evidence_;

  // The final list of stack variables
  StackVariablePtrList stkvars_;

  FunctionDescriptor *fd_;

  SymbolicValuePtr esp_value_;

  // return true if the instruction supplied is associated with a saved
  // register. Return false otherwise.
  bool uses_saved_register(const SgAsmx86Instruction *insn);

  // Return true if the instruction uses a parameter; false otherwise
  bool uses_parameter(const SgAsmx86Instruction *insn);

  bool uses_allocation_instruction(const SgAsmx86Instruction *insn);

  void accumulate_stkvar_evidence(SgAsmX86Instruction* insn, const AbstractAccess& aa);

  // This method selects the final set of stack variables
  void analyze_stkvar_evidence();

 public:

  StackVariableAnalyzer(FunctionDescriptor* fd);

  // Detect stack variables for a given function
  StackVariablePtrList analyze();
};


} // namespace pharos

#endif

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
