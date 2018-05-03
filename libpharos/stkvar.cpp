#include <rose.h>

#include "stkvar.hpp"
#include "misc.hpp"
#include "funcs.hpp"
#include "pdg.hpp"
#include "defuse.hpp"
#include "masm.hpp"
#include "enums.hpp"
#include "types.hpp"

namespace pharos {

// Methods for the StackVariable class
StackVariable::StackVariable(int64_t off) : offset_(off)
{ }

int64_t
StackVariable::get_offset() const
{ return offset_; }

std::vector<SymbolicValuePtr>
StackVariable::get_values() const
{ return values_; }

void
StackVariable::add_value(SymbolicValuePtr v)
{ values_.push_back(v); }

void
StackVariable::set_memory_address(SymbolicValuePtr m) {
  memory_address_ = m;
}

SymbolicValuePtr
StackVariable::get_memory_address() const
{ return memory_address_; }

const InsnSet&
StackVariable::get_usages() const
{ return usages_; }

void
StackVariable::add_evidence(StackVariableEvidence* e) {

  evidence_.push_back(e);
  add_usage(e->insn);

  if (e->aa.value && e->aa.memory_address) {
    TreeNodePtr valtnp = e->aa.value->get_expression();
    TreeNodePtr memtnp = e->aa.memory_address->get_expression();

    GDEBUG << "Adding StackVar evidence Insn: "
           << addr_str(e->insn->get_address()) << " Val: "
           << " - " << *valtnp << ", Mem: "
           << *memtnp << LEND;
  }
}

const StackVariableEvidencePtrList&
StackVariable::get_evidence() const {
  return evidence_;
}

void
StackVariable::add_usage(SgAsmx86Instruction *i) {
  if (i) {
    usages_.insert(i);
  }
}
// return string representation of stack variable
std::string
StackVariable::to_string() const {

  std::stringstream istr;

  istr << "sd=" << offset_;

  istr << " ida-name=var_" << std::noshowbase << std::hex << -(offset_+4);

  if (memory_address_) {
    TreeNodePtr addr_tnp = memory_address_->get_expression();
    istr << " address-exp=(";
    if (addr_tnp) {
      istr << *addr_tnp;
    }
    else {
      istr << "<unknown>";
    }
    istr << ")";


    TypeDescriptorPtr addr_tdp = fetch_type_descriptor(memory_address_);
    // TODO: This is useful for this when done debugging
    // int64_t addr_raw = reinterpret_cast<int64_t>(&*addr_tnp);
    // istr << ", " << "raw=(" << addr_str(addr_raw) << ")";
    istr << " td=(";

    if (addr_tdp) {
      istr << addr_tdp->to_string();
    }
    else {
      istr << "<unknown>";
    }
    istr << ")";
  }
  else {
    istr << " address-exp=(invalid)";
  }

  if (!values_.empty()) {
    istr << " values=({";
    size_t i=0;
    for (auto v : values_) {
      TreeNodePtr val_tnp = v->get_expression();
      if (val_tnp) {
        istr << "(exp=(" << *val_tnp << ")";
      }
      else {
        istr << "(<unknown>)";
      }

      TypeDescriptorPtr value_tdp = fetch_type_descriptor(v);

      // TODO: This is useful for debugging
      // int64_t val_raw = reinterpret_cast<int64_t>(&*val_tnp);
      // istr << ", " << "raw=(" << addr_str(val_raw) << ")";

      istr << " td=(";
      if (value_tdp) {
        istr << value_tdp->to_string() << ")";
      }
      else {
        istr << "(<unknown>)";
      }
      if (i+1 < values_.size()) istr << "), ";
      ++i;
    }
    istr << "})";
  }
  else {
    istr << " values=(invalid)";
  }

  istr << " uses={";
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
bool
StackVariableAnalyzer::uses_allocation_instruction(const SgAsmx86Instruction *insn) {

  const InsnSet & alloc_insns = fd_->get_register_usage().stack_allocation_insns;

  if (alloc_insns.empty()) return false;

  InsnSet::iterator ai = std::find_if(alloc_insns.begin(),
                                      alloc_insns.end(),
                                      [insn](SgAsmInstruction* i)
                                      { return insn->get_address() == i->get_address(); });

  bool result = (ai != alloc_insns.end());
  if (result) {
    GDEBUG << "Instruction " << addr_str(insn->get_address())
           << " is a stack allocation instruction." << LEND;
  }
  return result;
}

// The following functions identify, extract, and analyze stack variables based
// on a function descriptor. The method analyze_stack_variables contains a
// series of analytical passes to idenitfy stack variables and then
// assign each found variable a type

// Return true if the instruction supplied is associated with a saved
// register. Return false otherwise.
bool
StackVariableAnalyzer::uses_saved_register(const SgAsmx86Instruction *insn) {

  GDEBUG << "Checking instruction '" << debug_instruction(insn)
         << "' for saved register use" << LEND;

  const SavedRegisterSet & saved_registers = fd_->get_register_usage().saved_registers;

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
bool
StackVariableAnalyzer::uses_parameter(const SgAsmx86Instruction *insn) {

  if (insn == NULL) {
    return false;
  }

  GDEBUG << "Checking instruction '" << debug_instruction(insn)
         << "' for parameter use in function " << addr_str(fd_->get_address()) << LEND;

  const ParamVector& fd_params = fd_->get_parameters().get_params();

  if (fd_params.size() > 0) {
    // check the parameters associated with this function
    for (const ParameterDefinition &func_pd : fd_params) {
      if (func_pd.insn == NULL) continue;
      if (insn->get_address() == func_pd.insn->get_address()) {
        GDEBUG << "Uses FD parameter" << LEND;
        return true;
      }
    }
  }

  //  Now check outgoing calls

  CallDescriptorSet outgoing_calls = fd_->get_outgoing_calls();
  // Determine if this instruction is a parameter for an outgoing call

  if (outgoing_calls.size() > 0) {

    GDEBUG << "Function " << addr_str(fd_->get_address()) << " contains "
           << outgoing_calls.size() << " calls" << LEND;

    for (CallDescriptor *cd : outgoing_calls) {

      const ParamVector& cd_params = cd->get_parameters().get_params();

      if (cd_params.empty()) {
        // this call has no parameters
        GDEBUG << "There are no parameters" << LEND;
        continue;
      }

      GDEBUG << "Evaluating out going call " << addr_str(cd->get_address()) << LEND;

      for (const ParameterDefinition &call_pd : cd_params) {
        if (call_pd.insn == NULL) continue;
        if (insn->get_address() == call_pd.insn->get_address()) {
          GDEBUG << "Uses CD parameter" << LEND;
          return true;
        }
      }
    }
  }

  GDEBUG << "Doesn't use parameter" << LEND;

  return false;
}


StackVariableAnalyzer::StackVariableAnalyzer(FunctionDescriptor* fd) {

  fd_ = fd;

  if (fd_ == NULL) return;

  // Get the PDG object...

  const DUAnalysis& du = fd_->get_pdg()->get_usedef();

  // I assume that this is the function input state
  const SymbolicStatePtr input_state = du.get_input_state();
  if (!input_state) // to prevent a coredump
    return;

  RegisterDescriptor esp_rd = global_descriptor_set->get_stack_reg();

  // At this point we have the initial ESP value. This will be the base for
  // stack-based local variables
  esp_value_ = input_state->read_register(esp_rd);
}

// Analyze the abstract access for evidence of using a stack variable
void StackVariableAnalyzer::accumulate_stkvar_evidence(
  SgAsmX86Instruction* insn,
  const AbstractAccess& aa)
{

  if (!insn) return;

  TreeNodePtr esp_tnp = esp_value_->get_expression();
  if (!esp_tnp) return;

  //  It is possible that the only use of a local variable is when
  //  it is supplied as a parameter to a call. Thus, we cannot
  //  simply skip these instructions.
  bool uses_param = uses_parameter(insn); ;

  SymbolicValuePtr aa_val = aa.value;
  if (aa_val) {
    // Is the value used in the access itself a stack variable?

    AddConstantExtractor vfoace = AddConstantExtractor(aa_val->get_expression());
    int64_t voffset = vfoace.constant_portion();
    TreeNodePtr val_tnp = vfoace.variable_portion();
    if (val_tnp) {
      // stack variables always have a negative offset starting below -4
      if (voffset < -4 && val_tnp->isEquivalentTo(esp_tnp)) {
        evidence_.push_back(new StackVariableEvidence(insn, voffset, aa, uses_param, true));
      }
    }
  }

  SymbolicValuePtr aa_mem = aa.memory_address;
  if (aa_mem) {
    // Is the value used in the access itself a stack variable?

    AddConstantExtractor mfoace = AddConstantExtractor(aa_mem->get_expression());
    int64_t moffset = mfoace.constant_portion();
    TreeNodePtr mem_tnp = mfoace.variable_portion();
    if (mem_tnp) {
      // stack variables always have a negative offset starting below -4
      if (moffset < -4 && mem_tnp->isEquivalentTo(esp_tnp)) {
        evidence_.push_back(new StackVariableEvidence(insn, moffset, aa, uses_param, false));

      }
    }
  }
}

StackVariablePtrList
StackVariableAnalyzer::analyze() {

  GDEBUG << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-" << LEND;
  GDEBUG << "+- Beginning stack variable analysis -+" << LEND;
  GDEBUG << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-" << LEND;

  GDEBUG << "Analyzing stack varaibles in function "
         << addr_str(fd_->get_address()) << LEND;

  // Now for every instruction in the function, check if that instruction
  //
  // a. is a control flow intruction (because they cannot use stack variables)
  // b. uses a saved register
  // c. uses a known stack parameter
  //
  // everything left can be evaluated for possible stack variable usage.

  for (SgAsmX86Instruction* insn : fd_->get_insns_addr_order()) {

    if (insn == NULL) continue;

    // control flow instructions can't access local variables
    if (insn_is_control_flow(insn) == true) {
      GDEBUG << "   Insn " << addr_str(insn->get_address())
             << " is a control flow instruction" << LEND;

      continue;
    }

    else if (uses_allocation_instruction(insn)) {
      GDEBUG << "   Insn " << addr_str(insn->get_address())
             << " is a stack allocation instruction" << LEND;
      continue;
    }

    // Skip saved register instructions
    else if (uses_saved_register(insn)) {
      GDEBUG << "   Insn " << addr_str(insn->get_address())
             << " uses a saved register" << LEND;
      continue;
    }

    // Not a parameter or saved register, determine if it is a
    // read/write on the initial ESP symbolic value
    //
    // The basic idea here is to cycle through each of the abstract reads and
    // writes for the instructions to determine if the access involves a local
    // variable

    GDEBUG << "AA on instruction " << debug_instruction(insn) << LEND;

    // Get the DUAnalysis object to check accesses for stack var
    // evidence
    const DUAnalysis& du = fd_->get_pdg()->get_usedef();

    access_filters::aa_range reg_reads = du.get_reg_reads(insn);
    if (std::begin(reg_reads) != std::end(reg_reads)) {
      GDEBUG << "Checking reg reads for stack variables" << LEND;
      for (const AbstractAccess &rraa : reg_reads) {
        // The read is on a transient tree node
        if (du.fake_read(insn, rraa)) continue;
        accumulate_stkvar_evidence(insn, rraa);
      }
    }
    access_filters::aa_range mem_reads = du.get_mem_reads(insn);
    if (std::begin(mem_reads) != std::end(mem_reads)) {
      GDEBUG << "Checking mem reads for stack variables" << LEND;
      for (const AbstractAccess &mraa : mem_reads) {
        // The read is on a transient tree node
        if (du.fake_read(insn, mraa)) continue;
        accumulate_stkvar_evidence(insn, mraa);
      }
    }

    // the same logic applies for writes. If the offset to the original stack
    // pointer is not used, then add them as stack variables

    access_filters::aa_range reg_writes = du.get_reg_writes(insn);
    if (std::begin(reg_writes) != std::end(reg_writes)) {
      GDEBUG << "Checking reg writes for stack variables" << LEND;
      for (const AbstractAccess &rwaa : reg_writes) {
        accumulate_stkvar_evidence(insn, rwaa);
      }
    }
    access_filters::aa_range mem_writes = du.get_mem_writes(insn);
    if (std::begin(mem_writes) != std::end(mem_writes)) {
      GDEBUG << "Checking writes for stack variables" << LEND;
      for (const AbstractAccess &mwaa : mem_writes) {
        accumulate_stkvar_evidence(insn, mwaa);
      }
    }
  }

  // All of the stack variable evidence has been accumulated. Now
  // analyze it for the actual, final set of stack variables
  analyze_stkvar_evidence();

  return stkvars_;
}

void
StackVariableAnalyzer::analyze_stkvar_evidence() {

  // Step 0. Sort evidence in offset order
  std::sort(evidence_.begin(), evidence_.end(),
            [](const StackVariableEvidence* a, const StackVariableEvidence *b) -> bool {
              return a->offset > b->offset;
            });

  StackVariablePtrList candidate_vars;

  // first we accumulate evidence into a set of candidate stack
  // variables
  for (StackVariableEvidence* evidence : evidence_) {

    GDEBUG << "Offset: " << evidence->offset << LEND;
    GDEBUG << "  Insn: " << addr_str(evidence->insn->get_address()) << LEND;
    GDEBUG << "  Uses param: " << ((evidence->uses_param) ? "true" : "false") << LEND;
    GDEBUG << "  Evidence location: "
          << ((evidence->in_value) ? "value" : "memory") << LEND;
    GDEBUG << "  Accesses: " << evidence->aa.str() << LEND;
    GDEBUG << "  AA mem/reg: " << ((evidence->aa.is_mem()) ? "mem" : "reg") << LEND;
    GDEBUG << "---"  << LEND;

    // is there an existing stackvariable baed on this evidence?
    auto find_pred = [&evidence](const StackVariable* v) {
      return v->get_offset() == evidence->offset;
    };

    auto stkvar_iter = std::find_if(candidate_vars.begin(), candidate_vars.end(), find_pred);
    StackVariable *var = NULL;
    if (stkvar_iter != candidate_vars.end()) {
      // variable exists, add the evidence if it is a me
      var = *stkvar_iter;
      var->add_evidence(evidence);
    }
    else {
      // Otherwise this is a potentially new variable, so examine the evidence
      var = new StackVariable(evidence->offset);
      // Should the evidence be saved

      GDEBUG << "Adding evidence to " << evidence->offset << ": "
             << addr_str(evidence->insn->get_address()) << LEND;

      var->add_evidence(evidence);
      candidate_vars.push_back(var);
    }
  }

  // Now assess each candidate to determine if it is a true stack variable

  for (StackVariable* candidate : candidate_vars) {

    GDEBUG << "Candidate variable offset: " << candidate->get_offset() << LEND;

    bool is_new_var = false;
    for (StackVariableEvidence* evidence : candidate->get_evidence()) {

      if (true == evidence->uses_param) {

        GDEBUG << "Evaluating evidence at instruction "
          << addr_str(evidence->insn->get_address()) << LEND;

        // In the case of parameters, we care about the value that is,
        // stack variable evidence in parameters is typically seen in
        // the value portion of the access

        // Parameter based evidence in reg accesses is discarded, for now
        if (false == evidence->aa.is_mem()) {
          GDEBUG << "Parameter is a register access, ignoring" << LEND;
          continue;
        }

        // If the evidence is associated with a parameter, then we
        // must check the value of the access. One caveat is that
        // pushing literals (e.g. push 0) may happen and should be
        // handled
        if (true == evidence->in_value && evidence->aa.value) {
          TreeNodePtr tnp = evidence->aa.value->get_expression();

          GDEBUG << "Checking parameter value for literal: " << *tnp << LEND;

          // Detect and discard things like "push 0"
          if (!tnp->isNumber()) {
            candidate->set_memory_address(evidence->aa.value);
            is_new_var = true;
          }
        }
      }
      // Evidence does not use a parameter
      else {

        // If this does not use a param, consult the address of the
        // abstract access
        if (true == evidence->aa.is_mem()) {
          if (evidence->aa.memory_address) {
            TreeNodePtr tnp = evidence->aa.memory_address->get_expression();

            if (!tnp->isNumber()) {
              candidate->set_memory_address(evidence->aa.memory_address);
              is_new_var = true;
            }
          }
        }
        // If the access is a register access, then only info in
        // the value, not the memory address can be relevant
        else if (true == evidence->aa.is_reg()) {

          // Ignore stack adjustments; for example, in the case of
          // cdecl calling convention discarding all references to ESP
          // may inadvertantly discard things we don't yet
          // understand. If things break, start looking here
          if (evidence->aa.reg_name() == "esp") {
            GDEBUG << ">>> The register accessed is ESP <<<" << LEND;
            continue;
          }
          if (evidence->aa.value) {
             GDEBUG << "Evidence not param and is_reg insn: " << addr_str(evidence->insn->get_address()) << LEND;
            candidate->set_memory_address(evidence->aa.value);
            is_new_var = true;
          }
        }

        // For non-param instructions the value of the stack variable
        // can be found. When params are in play the value can only be
        // the stack variable

        // Beware that values may not exist. JSG wonders if they
        // should be created?
        if (evidence->aa.value) {

          // If the evidence value is the candidate address, then
          // something is off ... one cannot set a variable address to
          // itself, right?

          SymbolicValuePtr ma = candidate->get_memory_address();

          // It may be possible to discover the value first
          if (ma && ma->can_be_equal(evidence->aa.value)) continue;

          bool known_val = false;
          for (auto val : candidate->get_values()) {
            if (evidence->aa.value->can_be_equal(val)) {
              known_val = true;
              break;
            }
          }
          if (!known_val) {
            candidate->add_value(evidence->aa.value);
          }
        }
      }
      // You can't set a value without setting the memory address,
      // so no need to set the flag here

      if (is_new_var) {
        GDEBUG << "  New Var Insn: " << addr_str(evidence->insn->get_address()) << LEND;
        GDEBUG << "  Uses param: " << ((evidence->uses_param) ? "true" : "false") << LEND;
        GDEBUG << "  Evidence location: "
               << ((evidence->in_value) ? "value" : "memory") << LEND;
        GDEBUG << "  Access: " << evidence->aa.str() << LEND;
        GDEBUG << "  Access isRead: " << ((evidence->aa.isRead) ? "yes" : "no") << LEND;
        GDEBUG << "  Access mem/reg: " << ((evidence->aa.is_mem()) ? "mem" : "reg") << LEND;
        GDEBUG << "-" << LEND;
      }
    }

    if (is_new_var) {

      GDEBUG << "The evidence suggests that a stack variable exists at offset "
            << candidate->get_offset() << LEND;

      // Add the stack variable in offset order
      StackVariablePtrList::iterator pos =
        std::lower_bound(stkvars_.begin(), stkvars_.end(), candidate,
                         [](StackVariable* s1, StackVariable* s2) {
                           return s1->get_offset() > s2->get_offset();
                         });

      stkvars_.insert(pos, candidate);
    }
    GDEBUG << "---"  << LEND;
  }

  GDEBUG << "Found " << stkvars_.size() << " stack variables based on "
         << evidence_.size() << " elements of evidence" << LEND;
}

} // namespace pharos
