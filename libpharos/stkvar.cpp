#include <rose.h>

#include "stkvar.hpp"
#include "misc.hpp"
#include "funcs.hpp"
#include "pdg.hpp"
#include "defuse.hpp"
#include "masm.hpp"
#include "convention.hpp"
#include "enums.hpp"
#include "types.hpp"

namespace pharos {

// Methods for the StackVariable class

 // Builds a new stack variable.
StackVariable::StackVariable(SgAsmx86Instruction *insn, int64_t off, const AbstractAccess &aa)
  : offset_(off), type_descriptor_(NULL)
{
  add_evidence(insn, aa); // save the usage instruction for this variable
}

TypeDescriptorPtr StackVariable::get_type_descriptor() const {

  // if we have a type descriptor, then return it
  if (type_descriptor_ != NULL) {
    return type_descriptor_;
  }

  if (abstract_accesses_.empty()) {
    return NULL;
  }

  // TODO: something better than just taking the 0th abstract access
  const AbstractAccess& aa = abstract_accesses_.at(0);

  if (aa.value && aa.memory_address) {
    // The type of the stack variable is associated with the type, not the memory address
    try {
      TreeNodePtr valtnp = aa.value->get_expression();
      return boost::any_cast< TypeDescriptorPtr >(valtnp->userData());

    } catch (...) {
      OERROR << "Cannot find type descriptor " << LEND;
    }
  }
  return NULL;
}

int64_t
StackVariable::offset() const { return offset_; }

const InsnSet&
StackVariable::usages() { return usages_; }

std::vector<std::reference_wrapper<const AbstractAccess>>
StackVariable::accesses() { return abstract_accesses_; }

void
StackVariable::add_evidence(SgAsmx86Instruction *i, const AbstractAccess& aa) {

  if (aa.value && aa.memory_address) {
    TreeNodePtr valtnp = aa.value->get_expression();
    TreeNodePtr memtnp = aa.memory_address->get_expression();

    GDEBUG << "Adding StackVar evidence Insn: "
           << addr_str(i->get_address()) << " Val: "
           << " - " << *valtnp << ", Mem: "
           << *memtnp << LEND;

    add_usage(i);
    add_access(aa);
  }
}

void
StackVariable::add_usage(SgAsmx86Instruction *i) {
  if (i) {
    usages_.insert(i);
  }
}

void
StackVariable::add_access(const AbstractAccess& aa) {
  abstract_accesses_.push_back(std::cref(aa));
}

// return string representation of stack variable
std::string
StackVariable::to_string() const {

  std::stringstream istr;

  istr << "sd=" << offset_;

  TypeDescriptorPtr tdp = get_type_descriptor();

  if (tdp) {
    istr << " td=(" << tdp->to_string() << ")";
  }
  else {
    istr << " td=unknown";
  }

  if (!abstract_accesses_.empty()){

    // TODO: something better than just taking the 0th abstract access
    const AbstractAccess& aa = abstract_accesses_.at(0);
    if (aa.value) {
      SymbolicValuePtr val = aa.value;

      if (val) {
        istr << " value=" << *(val->get_expression());
      }
    }
  }

  istr << "\n    uses={";

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


// Is the purpose instruction to allocate stack space? If so it cannot
// be a stack variable. This covers the infamous "push REG" intruction
// without a corresponding pop to make room on the stack for
// DWORD-sized local variables.
bool uses_allocation_instruction(const SgAsmx86Instruction *insn, FunctionDescriptor *fd) {

  const InsnSet & alloc_insns = fd->get_register_usage().stack_allocation_insns;

  if (alloc_insns.empty()) return false;

  InsnSet::iterator ai = std::find_if(alloc_insns.begin(),
                                      alloc_insns.end(),
                                      [insn](SgAsmInstruction* i) {return insn->get_address() == i->get_address(); });

  bool result = (ai != alloc_insns.end());
  if (result) {
    GDEBUG << "Instruction " << addr_str(insn->get_address()) << " is a stack allocation instruction." << LEND;
  }
  return result;
}

// The following functions identify, extract, and analyze stack variables based
// on a function descriptor. The method analyze_stack_variables contains a
// series of analytical passes to idenitfy stack variables and then
// assign each found variable a type

// Return true if the instruction supplied is associated with a saved
// register. Return false otherwise.
bool uses_saved_register(const SgAsmx86Instruction *insn, FunctionDescriptor *fd) {

  GDEBUG << "Checking instruction '" << debug_instruction(insn)
         << "' for saved register use" << LEND;

  const SavedRegisterSet & saved_registers = fd->get_register_usage().saved_registers;

  for (auto & sr : saved_registers) {
    if (sr.save != NULL) {
      if (sr.save->get_address() == insn->get_address()) {
        return true;
        GDEBUG << "Uses saved register" << LEND;
      }
    }
    if (sr.restore != NULL) {
      if (sr.restore->get_address() == insn->get_address())  {
        return true;
        GDEBUG << "Uses saved register" << LEND;
      }
    }
  }
  GDEBUG << "Doesn't use saved register" << LEND;
  return false;
}

// Return true if the instruction supplied is the one that passed the
// parameter (push it onto the stack or loaded it into a register). Returns false
// otherwise
bool uses_parameter(const SgAsmx86Instruction *insn, FunctionDescriptor *fd) {
  if (insn == NULL) {
    return false;
  }

  GDEBUG << "Checking instruction '" << debug_instruction(insn)
         << "' for parameter use in funciton " << addr_str(fd->get_address()) << LEND;

  const ParamVector& fd_params = fd->get_parameters().get_params();

  if (fd_params.empty() == false) {

    // check the parameters associated with this function
    for (const ParameterDefinition &func_pd : fd_params) {
      if (func_pd.insn == NULL) continue;
      if (insn->get_address() == func_pd.insn->get_address()) {
        GDEBUG << "Uses FD parameter" << LEND;
        return true;
      }
    }
  }

  CallDescriptorSet outgoing_calls = fd->get_outgoing_calls();
  // Determine if this instruction is a parameter for an outgoing call

  if (outgoing_calls.size() == 0) return false;

  GDEBUG << "function " << addr_str(fd->get_address()) << " contains "
         << outgoing_calls.size() << " calls" << LEND;

  for (CallDescriptor *cd : outgoing_calls) {

    const ParamVector& cd_params = cd->get_parameters().get_params();

    if (cd_params.empty()) {
      // this call has no parameters
      continue;
    }

    for (const ParameterDefinition &call_pd : cd_params) {
      if (call_pd.insn == NULL) continue;
      if (insn->get_address() == call_pd.insn->get_address()) {
        GDEBUG << "Uses CD parameter" << LEND;
        return true;
      }
    }
  }

  GDEBUG << "Doesn't use parameter" << LEND;
  return false;
}

void analyze_stack_variables(FunctionDescriptor *fd) {

  // Identify stack variables based on the usage of stack frame registers
  // (notably ESP)

  GDEBUG << "Identifying stack variables" << LEND;

  identify_stack_variables(fd);

  GDEBUG << "... Done" << LEND;
}

const AbstractAccess* get_memory_access(SgAsmX86Instruction* insn,
                                        const DUAnalysis& du, const TreeNodePtr value) {
  // We're looking for a read in insn.
  auto reads = du.get_reads(insn);

  // Because we've not handled ITE expressions in value (or aa.value for that matter) very
  // gracefully, we're going to at last permit anything remotely matching by using the
  // can_be_equal() comparison.  Our inability to add methods to TreeNodePtr means that we have
  // to do some sillyness here to convert the passed expression into a symbolic value so that
  // we can call can_be_equal() on our extended SymbolicValue class.
  SymbolicValuePtr sv = SymbolicValue::treenode_instance(value);

  // Go through each read looking for the right one.
  for (const AbstractAccess& aa : reads) {
    // The right one is the one that matches the requested value.  Or kindof-sortof matches.
    if (sv->can_be_equal(aa.value)) return &aa;
  }
  // We didn't find the value intended.  Return an invalid abstract access.
  return NULL;
}

// Analyze the abstract access for evidence of using a stack variable
void analyze_accesses_for_stack_variables(
  SgAsmX86Instruction* insn,
  const AbstractAccess &aa,
  FunctionDescriptor *fd,
  const SymbolicValuePtr &initial_esp_sv,
  bool insn_uses_param)
{

  TreeNodePtr esp_tnp = initial_esp_sv->get_expression();

  if (insn_uses_param) {

    // Is the value used in the access itself a stack variable?
    AddConstantExtractor vfoace = AddConstantExtractor(aa.value->get_expression());
    int64_t val_offset = vfoace.constant_portion();
    TreeNodePtr val_tnp = vfoace.variable_portion();

    // Not guaranteed to have a variable portion in all cases, although
    // we do require one here.
    if (val_tnp) {

      // stack variables always have a negative offset
      if (val_offset < 0 && val_tnp->isEquivalentTo(esp_tnp)) {

        StackVariable *val_stkvar = fd->get_stack_variable(val_offset);
        if (val_stkvar == NULL) {

          // this is a new stack variable (one does not exist at the
          // specified offset)
          fd->add_stack_variable(new StackVariable(insn, val_offset, aa));

          GDEBUG << "Adding new stack variable based on read at offset " << val_offset << LEND;
        }
        else {
          // if the variable is already defined, then add an
          // additional usage instruction
          GDEBUG << "Adding new usage instruction for stack variable at offset "
                 << val_offset << LEND;

          val_stkvar->add_evidence(insn, aa);
        }
      }
    }
  }
  else {

    // We evaluate the memory access for stack activity. Negative
    // offsets to ESP indicate automatic stack variables.

    AddConstantExtractor foace = AddConstantExtractor(aa.memory_address->get_expression());
    int64_t mem_offset = foace.constant_portion();
    TreeNodePtr mem_tnp = foace.variable_portion();

    // Not guaranteed to have a variable portion in all cases, although we do require one here.
    if (!mem_tnp) return;

    // stack variables always have a negative offset to ESP
    if (mem_offset < 0 && mem_tnp->isEquivalentTo(esp_tnp)) {

      GDEBUG << "Offset < 0 "<< mem_offset << ", OK ..." << LEND;
      GDEBUG << "Value can be equal to initial ESP, OK ..." << LEND;
      GDEBUG << "   Stack variable read= "
             << *(aa.memory_address->get_expression()) << LEND;
      GDEBUG << "   Variable offset= "
             << mem_offset << LEND;

      // attempt to add the new variable if it does not exist.
      // Stack variables are (should be?) uniquely identified by
      // offset from ESP

      StackVariable *stk_var = fd->get_stack_variable(mem_offset);
      if (stk_var == NULL) {

        // this is a new stack variable (one does not exist at the
        // specified offset)
        fd->add_stack_variable(new StackVariable(insn, mem_offset, aa));

        GDEBUG << "Adding new stack variable based on read" << LEND;
      }
      else {
        // if the variable is already defined, then add an
        // additional usage instruction
        GDEBUG << "Adding new usage instruction for stack variable at offset "
               << mem_offset << LEND;

        stk_var->add_evidence(insn, aa);
      }
    }
    // else if LEA???
    else if (aa.memory_address->contains_ite() == true) {
      GDEBUG << "WARNING: Instruction "
             << addr_str(insn->get_address())
             << " involves ITEs ... cannot determine stack variables" << LEND;
      // TODO: Handle complicated case with ITEs
    }
  }
}

void identify_stack_variables(FunctionDescriptor *fd) {

  // Get the PDG object...
  PDG *p = fd->get_pdg();

  const DUAnalysis& du = p->get_usedef();

  // I assume that this is the function input state
  const SymbolicStatePtr input_state = du.get_input_state();
  if (!input_state) // to prevent a coredump
    return;

  const RegisterDescriptor& esp_rd = global_descriptor_set->get_stack_reg();

  // At this point we have the initial ESP value. This will be the base for
  // stack-based local variables
  const SymbolicValuePtr initial_esp_sv = input_state->read_register(esp_rd);

  GDEBUG << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-" << LEND;
  GDEBUG << "+- Beginning stack variable analysis -+" << LEND;
  GDEBUG << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-" << LEND;

  GDEBUG << "Analyzing stack varaibles in function "
         << addr_str(fd->get_address()) << LEND;

  // Now for every instruction in the function, check if that instruction
  //
  // a. is a control flow intruction (because they cannot use stack variables)
  // b. uses a saved register
  // c. uses a known stack parameter
  //
  // everything left can be evaluated for possible stack variable usage.

  for (SgAsmX86Instruction* insn : fd->get_insns_addr_order()) {

    bool is_param = false;

    if (insn == NULL) continue;

    // control flow instructions can't access local variables
    if (insn_is_control_flow(insn) == true) {
      GDEBUG << "   Insn " << addr_str(insn->get_address())
             << " is a control flow instruction" << LEND;

      continue;
    }

    else if (uses_allocation_instruction(insn,fd)) {
      GDEBUG << "   Insn " << addr_str(insn->get_address())
             << " is a stack allocation instruction" << LEND;
      continue;
    }

    // Skip saved register instructions
    else if (uses_saved_register(insn,fd)) {
      GDEBUG << "   Insn " << addr_str(insn->get_address())
             << " uses a saved register" << LEND;
      continue;
    }

    //  It is possible that the only use of a local variable is when
    //  it is supplied as a parameter to a call. Thus, we cannot
    //  simply skip these instructions.
    else if (uses_parameter(insn,fd)) {
      GDEBUG << "   Insn " << addr_str(insn->get_address())
             << " uses a parameter" << LEND;
      is_param = true;
    }

    // discard fake reads?

    // Not a parameter or saved register, determine if it is a
    // read/write on the initial ESP symbolic value
    //
    // The basic idea here is to cycle through each of the abstract reads and
    // writes for the instructions to determine if the access involves a local
    // variable

    access_filters::aa_range reads = du.get_mem_reads(insn);
    if (std::begin(reads) != std::end(reads)) {
      GDEBUG << "Checking reads for stack variables" << LEND;
      for (const AbstractAccess &aa : reads) {

        // The read is on a transient tree node
        if (du.fake_read(insn,aa)) continue;

        // if not real stack variable, doesn't count
        // is it a pop?
        // if yes, which register?
        // did anyone use that register after that? dependants_of() in DUAnalysis
        // get calling convenion and ask is scratch register
        //
        // Cory thinks that this requires a more whole program analysis
        // for every call in the program get the parameter list
        // export type descriptors for call parameters

        analyze_accesses_for_stack_variables(insn, aa, fd, initial_esp_sv, is_param);
      }
    }

    // the same logic applies for writes. If the offset to the original stack
    // pointer is not used, then add them as stack variables
    access_filters::aa_range writes = du.get_mem_writes(insn);
    if (std::begin(writes) != std::end(writes)) {
      GDEBUG << "Checking writes for stack variables" << LEND;
      for (const AbstractAccess &aa : writes) {
        analyze_accesses_for_stack_variables(insn, aa, fd, initial_esp_sv, is_param);
      }
    }
  }
}

} // namespace pharos
