// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Stkvar_H
#define Stkvar_H

#include <rose.h>

#include "semantics.hpp"

// Forward declaration to simplify include cycles.

class FunctionDescriptor;

// Data structure for a stack variable. A stack variable is a memory location on
// the stack that is accessed via one of the stack registers (frame or stack
// pointer).
class StackVariable {
public:

   // Builds a new stack variable. Currently, the size is set to, and left at, 0
   StackVariable(int64_t off, TreeNodePtr tnp) : offset_(off), variable_(tnp), size_(0) {  }

   void add_usage(SgAsmx86Instruction *i);

   // getters for the various stack variable

   int64_t get_offset() const;

   TreeNodePtr get_variable();

   size_t get_size() const;

   InsnSet& get_usages();

   // prints the major parts of a stack variable (offset, value, usage
   // instructions and size)
   std::string to_string() const;

private:

   // the offset (to the stack pointer)
   int64_t offset_;

   // the expression associated with the StackVariable. This may be the same
   // for all variables ... in that case saving the expression is not necessary
   TreeNodePtr variable_;

   // The width of the variable
   size_t size_;

   // The set of instructions that use the stack variable
   InsnSet usages_;
};

// return true if the instruction supplied is associated with a saved
// register. Return false otherwise.
bool uses_saved_register(const SgAsmx86Instruction *insn, FunctionDescriptor *fd);

// Return true if the instruction supplied is the one that passed the
// parameter (push it onto the stack or loaded it into a register). Returns false
// otherwise
bool uses_parameter(const SgAsmx86Instruction *insn, FunctionDescriptor *fd);

// Detect stack variables for a given function
void analyze_stack_variables(FunctionDescriptor *fd);

// a list of stack variable pointers
typedef std::vector<StackVariable*> StackVariableList;

#endif
