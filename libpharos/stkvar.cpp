#include <rose.h>

#include "stkvar.hpp"
#include "misc.hpp"
#include "funcs.hpp"
#include "pdg.hpp"
#include "defuse.hpp"
#include "masm.hpp"
#include "convention.hpp"
#include "enums.hpp"

// Methods for the StackVariable class

std::string StackVariable::to_string() const {

   std::stringstream istr;

   istr << "Stack variable: Offset=" << offset_
   << ", Variable=" << *variable_
   << ", Size=" << size_
   << ", Usage instructions= {";

   for (InsnSet::iterator i = usages_.begin(); i != usages_.end(); i++) {

      SgAsmInstruction *insn = *i;
      istr << addr_str(insn->get_address());
      i++;
      if (i != usages_.end()) istr << ", ";
      i--;
   }
   istr << "}";

   return istr.str();
}

void StackVariable::add_usage(SgAsmx86Instruction *i) {
   usages_.insert(i);
}

// getters for the various stack variable

int64_t StackVariable::get_offset() const {
   return offset_;
}

TreeNodePtr StackVariable::get_variable() {
   return variable_;
}

size_t StackVariable::get_size() const {
   return size_;
}

InsnSet& StackVariable::get_usages() {
   return usages_;
}

// Return true if the instruction supplied is associated with a saved
// register. Return false otherwise.
bool uses_saved_register(const SgAsmx86Instruction *insn, FunctionDescriptor *fd) {

   if (insn == NULL) {
      return false;
   }

   SavedRegisterSet saved_registers = fd->get_register_usage().saved_registers;

   BOOST_FOREACH(auto sr, saved_registers) {
      if (sr.save != NULL) {
         if (sr.save->get_address() == insn->get_address()) {
            return true;
         }
      }
      if (sr.restore != NULL) {
         if (sr.restore->get_address() == insn->get_address())  {
            return true;
         }
      }
   }
   return false;
}

// Return true if the instruction supplied is the one that passed the
// parameter (push it onto the stack or loaded it into a register). Returns false
// otherwise
bool uses_parameter(const SgAsmx86Instruction *insn, FunctionDescriptor *fd) {
   if (insn == NULL) {
      return false;
   }

   const ParamVector& fd_params = fd->get_parameters().get_params();

   if (fd_params.empty()) {
      return false;
   }

   BOOST_FOREACH(const ParameterDefinition &pd, fd_params) {
      if (pd.insn == NULL) continue;
      if (insn->get_address() == pd.insn->get_address()) {
         return true;
      }
   }
   return false;
}

void analyze_stack_variables(FunctionDescriptor *fd) {

   // Get the PDG object...
   PDG *p = fd->get_pdg();

   const DUAnalysis& du = p->get_usedef();

   // I assume that this is the function input state
   const SymbolicStatePtr input_state = du.get_input_state();
   const RegisterDictionary* regdict = RegisterDictionary::dictionary_pentium4();
   const RegisterDescriptor* esp_rd = regdict->lookup("esp");

   // At this point we have the initial ESP value. This will be the base for
   // stack-based local variables
   const SymbolicValuePtr initial_esp_sv = input_state->read_register(*esp_rd);

   GDEBUG << "(function " << fd->address_string() << ")" << LEND;

   BOOST_FOREACH(SgAsmX86Instruction* insn, fd->get_insns_addr_order()) {

      if (insn == NULL) continue;

      // control flow instructions can't access local variables, right?
      if (insn_is_control_flow(insn) == true) {
         continue;
      }
      // Skip saved register instructions
      else if (uses_saved_register(insn,fd)) {
         GDEBUG << "   Insn " << addr_str(insn->get_address())
         << " uses a saved register and will be ignored" << LEND;
         continue;
      }
      // Skip stack parameters
      else if (uses_parameter(insn,fd)) {
         GDEBUG << "   Insn " << addr_str(insn->get_address())
         << " uses a parameter and will be ignored" << LEND;
         continue;
      }

      // Not a parameter or saved register, determine if it is a
      // read/write on the initial ESP symbolic value

      const AbstractAccessVector* reads = du.get_reads(insn);
      if (reads != NULL) {
         BOOST_FOREACH(AbstractAccess read_aa, *reads) {

            // only interested in memory accessess
            if (!read_aa.is_mem()) {
               continue;
            }

            TreeNodePtr stack_read_tnp = read_aa.memory_address->get_expression();
            AddConstantExtractor foace_read = AddConstantExtractor(stack_read_tnp);
            TreeNodePtr read_var_ptr = foace_read.variable_portion;
            int64_t read_var_offset = foace_read.constant_portion;

            if (read_var_ptr == initial_esp_sv->get_expression()) {

               if (read_var_ptr != NULL && read_var_offset < 0) {
                  GDEBUG << "   Stack variable portion read_var_ptr= " << *read_var_ptr << LEND;
                  GDEBUG << "   Variable read offset= " << read_var_offset << LEND;

                  // attempt to add the new variable if it does not exist.
                  // Interestingly, what should happen if there is a collison?

                  StackVariable *stk_var = fd->get_stack_variable(read_var_offset);
                  if (stk_var == NULL) {
                     // this is a new stack variable (one does not exist at the specified offset)
                     fd->add_stack_variable(insn, read_var_offset, read_var_ptr);
                     GDEBUG << "Adding new stack variable based on read" << LEND;
                  }
                  else {

                     // if the variable is already defined, then add an additional usage
                     // instruction
                     GDEBUG << "Adding new usage instruction for stack variable at offset "
                     << read_var_offset << LEND;

                     stk_var->add_usage(insn);
                  }
               }
            }
         }
      }

      // the same logic applies for writes. If the offset to the original stack
      // pointer is not used, then add them as stack variables

      const AbstractAccessVector* writes = du.get_writes(insn);
      if (writes != NULL) {
         BOOST_FOREACH(AbstractAccess write_aa, *writes) {

            // process the writes

            if (!write_aa.is_mem()) {
               continue;
            }

            TreeNodePtr stack_write_tnp = write_aa.memory_address->get_expression();
            AddConstantExtractor foace_write = AddConstantExtractor(stack_write_tnp);
            TreeNodePtr write_var_ptr = foace_write.variable_portion;
            int64_t write_var_offset = foace_write.constant_portion;

            // Special case where the detected variable offset is 0. This
            // only happens on a return, which pops the stack
            if (write_var_ptr != NULL && write_var_offset < 0) {
               GDEBUG << "   Stack variable portion write_var_ptr= " << *write_var_ptr << LEND;
               GDEBUG << "   Variable write offset= " << write_var_offset << LEND;

               // attempt to add the new variable

               StackVariable *stk_var = fd->get_stack_variable(write_var_offset);
               if (stk_var == NULL) {
                  // this is a new stack variable (one does not exist at the specified offset)
                  fd->add_stack_variable(insn, write_var_offset, write_var_ptr);
                  GDEBUG << "Adding new stack variable based on write" << LEND;
               }
               else {

                  // if the variable is already defined, then add an additional usage
                  // instruction
                  GDEBUG << "Adding new usage instruction for stack variable at offset "
                  << write_var_offset << LEND;

                  stk_var->add_usage(insn);
               }
            }
         }
      }
   }
}
