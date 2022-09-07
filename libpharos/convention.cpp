// Copyright 2015-2022 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/optional.hpp>

#include "rose.hpp"
#include <sageInterfaceAsm.h> // For isNOP().

#include "misc.hpp"
#include "funcs.hpp"
#include "pdg.hpp"
#include "defuse.hpp"
#include "masm.hpp"
#include "convention.hpp"
#include "enums.hpp"

namespace pharos {

// Constructor for the description of a saved register.
SavedRegister::SavedRegister(RegisterDescriptor r, SgAsmInstruction* push, SgAsmInstruction* pop) {
  reg = r;
  save = push;
  assert(save != NULL);
  restore = pop;
  assert(restore != NULL);
}

// Order saved registers by the address of the instruction that does the saving.  In practice
// this should mean that they're in the order in which they were saved.
bool SavedRegisterCompare::operator()(const SavedRegister& x, const SavedRegister& y) const {
  return (x.save->get_address() < y.save->get_address());
}

// A helper function to find saved and restored registers.  Maybe this should be in misc.cpp.
// Test whether the function is a push or a move that "saves" a register.  If the next
// dependent writes the saved value back into the passed register descriptor, then that looks
// like a "restore" instruction.  Finally, the restore instruction should have no dependents on
// the restore register...

// Chuck advocated for a "set of rules" here, and so here's a start.  Our primary goal is to
// return true in the stereotypical prolog/epilog scenario and false in most other cases.
// That's why we currently restrict ourselves to stack memory addreses and not arbitrary
// abstract locations.  We did permit mixtures of moves, pushes, and pops by not rigorously
// enforcing the requirement that the save be a push instruction and the restore be a pop
// instruction.  We currently believe that NO accesses after the restore are allowed, reads
// being forbidden beacuse they would result in the register being a parameter, and writes
// being forbidden because it would appear that the value is NOT restored.  While there are
// comeotehr approaches to this problem (e.g. is the starting value use anywhere in the output
// state, those approaches have other problems)...

// It's currently unclear to Cory what this code will do in the case of one push instruction
// that has multiple matching pops.  It appears that it will only add the first one to the
// saved registers list.  Perhaps the return should be replaced with a counter and the other
// depdendencies of the push should be considered as well.
bool RegisterUsage::check_saved_register(SgAsmX86Instruction *insn, RegisterDescriptor reg) {

  SDEBUG << "Checking saved register: " << debug_instruction(insn) << LEND;

  // If the instruction is not a push or a mov, we currently don't handle it, so it can't be a
  // saved and restored register instruction.
  if (insn->get_kind() != x86_push && insn->get_kind() != x86_mov) return false;

  const PDG* p = fd->get_pdg();
  if (p == NULL) return false;
  const DUAnalysis& du = p->get_usedef();

  rose_addr_t iaddr = insn->get_address();
  // Which stack address did the instruction write to?
  const AbstractAccess* wa = du.get_first_mem_write(iaddr);
  // If there's no memory write, we can't be a saved and restored register.
  if (wa == NULL) return false;

  const SymbolicValuePtr stack_addr = wa->memory_address;
  TreeNodePtr stack_node = stack_addr->get_expression();
  boost::optional<int64_t> opt_stack_delta = stack_addr->get_stack_const();
  int64_t stack_foo = 0;
  if (opt_stack_delta) {
    stack_foo = *opt_stack_delta;
  }
  else {
    SDEBUG << "Push or move to non-stack address at:" << debug_instruction(insn) << LEND;
    return false;
  }

  SDEBUG << "Checking for save/restore: " << debug_instruction(insn)
         << " for: " << reg << " writes to: " << *stack_node << " (" << stack_foo << ")" << LEND;

  const DUChain* deps = du.get_dependents(iaddr);
  if (deps == NULL) {
    // This test is an attempt to work around the optimization where the compiler pushes a
    // register _just_ to allocate four bytes for the lcoal stack frame.  That doesn't happen
    // with MOV instructions, because they're less efficient than SUB and PUSH.  In the cases
    // where there's an unused MOV, it usually means that the register really is a parameter,
    // and just isn't used in the function, but that low levels of optimization didn't remove
    // the reference completely.
    if (insn->get_kind() == x86_push) {
      SDEBUG << "Instruction at " << addr_str(iaddr)
             << " had no dependents so it's not a parameter." << LEND;
      // Returning true here doesn't mean that this instruction is a saved register, just that
      // it's not parameter.  Since we don't update the saved register list until later in this
      // function, it seems that this is ok.  The scenario that we're interested in is kind of
      // like a special case of saved and restored...
      return true;
    }
    // For MOV instructions, just treat the register as an ordinary parameter.
    else {
      return false;
    }
  }

  SgAsmX86Instruction *restore_insn = nullptr;

  // Get the dependents of the push/mov instruction.
  for (const Definition& sdef : *deps) {
    STRACE << "  For each dependency: " << sdef.access << LEND;

    // We're only interested in dependents that read from the same memory address.
    if (!(sdef.access.isRead)) continue;
    if (!(sdef.access.is_mem())) continue;

    // Further it must read the stack address that we're interested in...
    SymbolicValuePtr read_addr = sdef.access.memory_address;
    TreeNodePtr read_node = read_addr->get_expression();

    STRACE << "  Dependency is a memory access of: " << *read_node << LEND;

    boost::optional<int64_t> opt_read_delta = read_addr->get_stack_const();
    int64_t read_foo = 0;
    if (opt_read_delta) {
      read_foo = *opt_read_delta;
    }
    else {
      // We used to warn about unexpectedly non-stack values here, but there are some cases
      // that trigger this message in places where a warning isn't appropriate.  Specifically,
      // if there have been stack delta analysis failures, the memory read expression might be
      // an ITE expression, which won't match a single stack delta.  Additionally, this test is
      // before the pop/move test which needs to return false (instead of continuing), but the
      // error is really only meaningful if we've met that expectation as well.  The solution
      // was to downgrade the message to a debugging severity.
      SDEBUG << "Saved register depends on non-stack address at:" << debug_instruction(insn) << LEND;
    }

    // If the memory adresses don't match, then we're looking at some other poorly understood
    // coincidental dependency, and not something that coule be the restore instruction.
    if (read_foo != stack_foo) continue;

    // We've found a read of the value that was pushed.  From this point on, we're going to
    // return a value rather than loop to another dependency.
    // SDEBUG << "  Dependency is a memory read of the relevant stack address!" << LEND;

    // This is the instruction that appears to restore the value.  From this point forward in
    // the logic if we encounter anything unexpected, we should return false, and not simply
    // continue.  The reason for this is that it helps ensure that we don't incorrectly label
    // things as saved and restored registers when it gets complicated, and having extra
    // bogus parameters is a better failure scenario than ignoring actual parameters.
    SgAsmX86Instruction *candidate_restore_insn = sdef.definer;

    SDEBUG << "The dependent insn is: " << debug_instruction(candidate_restore_insn)
           << " for: " << *read_node << " (" << read_foo << ")" << LEND;

    // This test is required because otherwise, we'll accept call instructions that read pushed
    // parameters, and label them as saved registers.
    if (candidate_restore_insn->get_kind() != x86_pop &&
        candidate_restore_insn->get_kind() != x86_mov &&
        // Perhaps leave should only be a valid restoration instruction when register == ebp?
        candidate_restore_insn->get_kind() != x86_leave) return false;

    // Now confirm that the restore instruction writes the value back into the passed register
    // descriptor.
    bool restored_correctly = false;
    rose_addr_t raddr = candidate_restore_insn->get_address();
    auto rwrites = du.get_writes(raddr);
    if (std::begin(rwrites) == std::end(rwrites)) return false;
    for (const AbstractAccess& rw : rwrites) {
      if (rw.is_reg(reg)) {
        restored_correctly = true;
        break;
      }
    }
    if (restored_correctly == false) {
      SDEBUG << "The dependent insn: " << debug_instruction(candidate_restore_insn)
             << " did not restore the value properly!" << LEND;
      // Chuck and Cory concluded that we should NOT be a saved and restored register here.
      // The example is that an instruction like this: "mov some_other_reg, [saved_stack_addr]"
      // puts some_other_reg in our list of places we need to analyze to see if the saved
      // register was used as a parameter.
      return false;
    }

    // Finally, confirm that no one else reads the restored value.
    bool restore_used = false;
    const DUChain* user_deps = du.get_dependents(raddr);
    if (user_deps != NULL) {
      for (const Definition& udef : *user_deps) {
        STRACE << "Considering possible user: " << debug_instruction(udef.definer) << LEND;
        if (udef.access.is_reg(reg)) {
          SDEBUG << "Restored value used by: " << debug_instruction(udef.definer) << LEND;
          restore_used = true;
          // One case where the value is used after restoration is sufficient evidence that
          // this is not a saved and restored register.  For a while we only worried about
          // extra reads here, which was required for parameter detection, but the we're also
          // not truly a restored register if there are subsequent writes.
          return false;
        }
      }
    }

    if (!restore_used) {
      // Just because this instruction looks like a valid restore instruction doesn't mean that
      // there's not another dependent of the save that would prove otherwise.  Specifically,
      // we found instances where the register was saved with a move and then restored with a
      // move (because of a complete lack of optimization) then there was no dependency on the
      // second move because the call that really used the register was not correctly detected.
      // By moving on to the next instruction we can have another shot at figuring out that
      // this register is really being used, and it only takes one use to prove that the
      // register is not a parameter.
      restore_insn = candidate_restore_insn;
      continue;
    }

    // Following our earlier edict about conservative failures, don't simply continue, instead
    // report that this is NOT a properly saved and restored register.
    return false;
  }

  // Now that we've considered _all_ of the dependents of the save instruction, if we found one
  // that qualified as a save/restore pair and no evidence to the contrary (e..g having return
  // false already), then it's time to make the instructions as a save/restore pair.
  if (restore_insn) {
    GTRACE << "Saved register: reg=" << unparseX86Register(reg, {})
           << " save=" << debug_instruction(insn)
           << " restore=" << debug_instruction(restore_insn) << LEND;
    saved_registers.insert(SavedRegister(reg, insn, restore_insn));
    return true;
  }

  // Is this reachable now?  Did we handle this case differntly now with the changes above?
  stack_allocation_insns.insert(insn);

  // If we've reached this point in the code, we're not really a saved register because we
  // never found the instruction that restored the original value.  But, we never found any
  // read of the value at _all_, so while we're not technically a saved register, we're not a
  // parameter register to the function either, and it's easiest to return true here to cause
  // that result.
  return true;
}

void RegisterUsage::analyze(FunctionDescriptor const *f) {
  // If we don't know which function to analyze, complain.  This shouldn't happen.
  if (f == NULL) {
    OFATAL << "RegisterUsage::analyze() called on NULL function." << LEND;
    assert (f != NULL);
  }

  // Cory wishes we could have passed this to the constructor, but he
  // couldn't get that to work...
  fd = f;

  // Find saved & restore registers, and which were parameters to the function.
  analyze_parameters();

  analyze_changed();

}

// Determine the registers used by the function.  The way this is currently implemented is
// probably not the right way to accomplish related goals long term.  Cory would prefer to use
// the Simplify/FX approach of comparing the complete input state to the complete output state,
// and any values that were unchanged were "saved and restored".  But it's very unclear whether
// our symbolic execution is up to that task presently, so we're going to do it this way for
// now.
void RegisterUsage::analyze_parameters() {
  // Save some effort by skipping thunks.  Perhaps we should transfer the calling convention
  // information from the target to here, but Cory's not sure about that yet.
  if (fd->is_thunk()) {
    GTRACE << "Function " << fd->address_string() << " has parameters from thunk." << LEND;
    return;
  }

  // Get the PDG if we haven't already...
  PDG const *p = fd->get_pdg();

  // If we're an excluded function, we don't know what the calling convention is.
  if (p == NULL) return;
  const Addr2DUChainMap& dd = p->get_usedef().get_dependencies();

  // Get a handle to the stack pointer register, because it's special.
  RegisterDictionaryPtrArg regdict = fd->ds.get_regdict();
  RegisterDescriptor esp = regdict->find("esp");

  // This is for keeping track of which stack parameter deltas we've actually used, and which
  // which haven't.  This might be duplicated work, and we've not saved this anywhere.  Here is
  // a good candidate for where to do it.
  std::set<int64_t> stack_params;

  // For each instruction...
  for (SgAsmStatement* bs : fd->get_func()->get_statementList()) {
    SgAsmBlock *bb = isSgAsmBlock(bs);
    if (!bb) continue;
    for (SgAsmStatement* is : bb->get_statementList()) {
      SgAsmX86Instruction *insn = isSgAsmX86Instruction(is);
      if (!insn) continue;

      // If there's no use-def chain for the instruction, give up.
      if (dd.find(insn->get_address()) == dd.end()) {
        // Cory used to have this at WARN, but it turns out that instructions which have no
        // semantics have no use-def chain, so let's not double report that right now.
        SDEBUG << "No use-def chain for instruction: " << debug_instruction(insn) << LEND;
        continue;
      }

      // NOP instructions cannot lead to saved registers or register parameters.  Failure to
      // tes for NOPs here breaks thiscall detection of 0x411585 in 2008/Debug/ooex0.
      if (insn_is_nop(insn)) {
        SDEBUG << "NOP instruction isn't a parameter: " << debug_instruction(insn) << LEND;
        continue;
      }

      // Exclude special cases (xor reg, reg; sub reg, reg) that clear registers, but do not
      // imply real dependencies.  Also include "mov reg, reg" NOPs while the NOP code above is
      // broken.
      if (insn->get_kind() == x86_xor || insn->get_kind() == x86_sub || insn->get_kind() == x86_mov) {
        SgAsmExpressionPtrList &ops = insn->get_operandList()->get_operands();
        if (ops.size() >= 2) {
          SgAsmRegisterReferenceExpression* rop0 = isSgAsmRegisterReferenceExpression(ops[0]);
          SgAsmRegisterReferenceExpression* rop1 = isSgAsmRegisterReferenceExpression(ops[1]);

          if (rop0 && rop1 && rop0->get_descriptor().get_minor() == rop1->get_descriptor().get_minor()) {
            SDEBUG << "Clear register instruction isn't a parameter: "
                   << debug_instruction(insn) << LEND;
            continue;
          }
        }
      }

      for (const Definition& def : dd.at(insn->get_address())) {
        // This is the access that had the NULL definer.
        const AbstractAccess& aa = def.access;
        SDEBUG << "Evaluating " << debug_instruction(insn) << " which uses value "
               << *(aa.value) << " for parameter in " << fd->address_string() << LEND;

        // We're only interested in instructions with NULL definers.
        if (def.definer != NULL) continue;
        // No invalid accesses should have survived this long.
        assert(aa.is_valid());

        // We're only interested in reads for parameters.  Eventually we should confirm that
        // the function also does not overwrite any of the registers unexpectedly.
        if (!(aa.isRead)) continue;

        // We're only sort-of interested in memory accesses right now.
        if (aa.is_mem()) {
          MemoryType type = aa.memory_address->get_memory_type();
          if (type == StackMemParameter) {
            boost::optional<int64_t> opt_stack_delta = aa.memory_address->get_stack_const();
            int64_t delta = *opt_stack_delta;
            stack_params.insert(delta);
          }
          else {
            STRACE << "Function " << fd->address_string() << " accesses complex memory in "
                   << debug_instruction(insn) << " aa=" << aa << LEND;
          }

          // Go to the next definition regardless.  Cory observes that with the recent change
          // below to use the register name from the comment and not the abstract access, it
          // might not be correct to continue here anymore.
          continue;
        }

        // We must be a register access from this point on.

        // Cory's a little unsure if this logic truly required, or whether there's a problem
        // somewhere else.  The scenario is "xor ecx,ecx", "mov eax, ecx", "ret".  We correctly
        // exclude the xor in the special cases above, but we end up marking the move as a
        // parameter use, which is compeletely incorrect.  At least one way to have detected
        // this is that the value under consideration is not the "starting" value of any register.
        const std::string& cmt = aa.value->comment();
        size_t clen = cmt.size();
        // If there's no comment at all, we're not a starting value, and thus not a parameter.
        // Also, if the comment doesn't look like a starting value comment, then we're also not
        // a return value.  This probably isn't a very good way fo doing this, but Cory's not
        // sure what the alternatives are presently.  This at least produces correct results.
        if (clen < 2 || cmt.substr(clen - 2, 2) != "_0") {
          STRACE << "Possible parameter register use at " << debug_instruction(insn)
                 << " is not a starting register, and so can't be a parameter." << LEND;
          continue;
        }

        // If we're pushing a register, and the access is for ESP, that's normal.  Just record
        // that the function uses the stack as a parameter.
        if (insn->get_kind() == x86_push && aa.is_reg(esp)) {
          parameter_registers[aa.register_descriptor] = insn;
          STRACE << "Function " << fd->address_string() << " uses ESP at "
                 << debug_instruction(insn) << LEND;
          continue;
        }

        bool sr = check_saved_register(insn, aa.register_descriptor);

        if (!sr) {
          // We're a register parameter.  But the parameter is not necessarily the register in
          // aa.register descriptor.  Consider the instructions: "mov eax,ecx; mov [eax],34".
          // The second instruction reads a value from a register (eax), and that value no
          // definer, but the value is ecx_0, not eax_0.  Thus the parameter register is ECX.
          // Strictly speaking, I think this means that skipping memory reads earlier could be
          // incorrect as well... :-(

          RegisterDescriptor initial_reg = regdict->find(cmt.substr(0, clen - 2));

          parameter_registers[initial_reg] = insn;
          GTRACE << "Function " << fd->address_string() << " uses register "
                 << unparseX86Register(initial_reg, {})
                 << " as parameter in " << debug_instruction(insn) << LEND;
          break;
        }
      }
    }
  }

  // Display for debugging, should probably be a function of it's own.
  GTRACE << "Function " << fd->address_string() << " has parameters: ";
  for (const RegisterEvidenceMap::value_type& rpair : parameter_registers) {
    RegisterDescriptor reg = rpair.first;
    GTRACE << " " << unparseX86Register(reg, {});
  }
  GTRACE << LEND;
}

void RegisterUsage::analyze_changed() {
  // Get the PDG if we haven't already...
  const PDG* pdg = fd->get_pdg();
  // If we're an excluded function, we don't know what the calling convention is.
  if (pdg == NULL) return;

  const DUAnalysis& du = pdg->get_usedef();
  // If the output state was not valid, we had no normal return blocks.  If there were no
  // normal return blocks, we don't return, and the normal meaning of changed registers doesn't
  // really mean anything, because we're not returning anyway.  Instead of polluting upstream
  // analysis, just return.  An example of this is _invalid_parameter at 0x409D95 in
  // 2010/Lite/oo.exe, which polluted calling conventions all the way up into STL OO methods.
  if (!du.get_output_valid()) return;

  const SymbolicStatePtr input_state = du.get_input_state();
  if (!input_state) return;
  SymbolicRegisterStatePtr rinput = input_state->get_register_state();
  const SymbolicStatePtr output_state = du.get_output_state();
  if (!output_state) return;
  SymbolicRegisterStatePtr routput = output_state->get_register_state();

  RegisterSet all_changed_registers = routput->diff(rinput);

  RegisterDictionaryPtrArg regdict = fd->ds.get_regdict();
  RegisterDescriptor esp = regdict->find("esp");
  RegisterDescriptor ebp = regdict->find("ebp");
  RegisterDescriptor esi = regdict->find("esi");
  RegisterDescriptor edi = regdict->find("edi");
  RegisterDescriptor ebx = regdict->find("ebx");

  // It turns out that we can't enable this code properly because our system is just too
  // fragile.  If we're incorrect in any low-level function, this propogates that failure
  // throughout the entire call-chain leading to that function.  Specifically, claiming that a
  // function overwrites a register when it fact it does not, leads to the loss of important
  // local state that results in incorrect analysis.

  // Cory has found two common cases.  The first case is functions with two possible execution
  // paths, on path returns and does not modify the register, and the other path does not
  // return and does modify the register.  This this might be fixed with better does not return
  // analysis.  The second case is even more difficult to handle correctly, and is best
  // demonstrated by __SEH_prolog4().  This function is not stack neutral, and handles saving
  // the registers for it's caller.  When paired with __SEH_epilog4, it results in saved and
  // restored registers that are not correctly detected, leading to the conclusion that the
  // calling function modifies those registers in violation of the calling convention.

  // We'll need to do a lot more work to get this functioning properly, but in the meantime,
  // lets do what we can without breaking anything, which is to accept changed registers that
  // are not unusual according to the standard calling conventions.  The actual overwriting of
  // the registers occurs in make_call_dependencies() in defuse.cpp.

  for (RegisterDescriptor rd : all_changed_registers) {
    // Silently reject changes to ESP, we'll handle those through stack delta analysis code.
    if (rd == esp) continue;
    // Warn about cases where we reject register changes based on calling convention assumptions.
    if (rd == ebp or rd == esi or rd == edi or rd == ebx) {
      GDEBUG << "Function " << fd->address_string() << " overwrites "
             << unparseX86Register(rd, {})
             << " violating all known calling conventions." << LEND;
    }
    else {
      changed_registers.insert(rd);
    }
  }

  GDEBUG << "Function " << fd->address_string() << " changed registers: ";
  for (RegisterDescriptor rd : changed_registers) {
    GDEBUG << " " << unparseX86Register(rd, {});
  }
  GDEBUG << LEND;
}

template<> char const* EnumStrings<CallingConvention::ParameterOrder>::data[] = {
  "left-to-right",
  "right-to-left",
  "unknown",
};

template<> char const* EnumStrings<CallingConvention::ThisPointerLocation>::data[] = {
  "first-stack-parameter",
  "register",
  "not-applicable",
  "unknown",
};

template<> char const* EnumStrings<CallingConvention::ReturnValueLocation>::data[] = {
  "returned-on-stack",
  "returned-in-register",
  "not-applicable",
  "unknown",
};

template<> char const* EnumStrings<CallingConvention::StackCleanup>::data[] = {
  "caller-cleanup",
  "callee-cleanup",
  "not-appplicable",
  "unknown",
};

CallingConvention::CallingConvention(size_t word_size_, const std::string &name_,
                                     const std::string &compiler_) {
  word_size = word_size_;
  name = name_;
  compiler = compiler_;
  param_order = ORDER_UNKNOWN;
  this_location = THIS_UNKNOWN;
  retval_location = RETVAL_UNKNOWN;
  stack_alignment = 0;
  // We must have a name and a size.
  assert(word_size > 0);
  assert(!name.empty());
}

void CallingConvention::add_nonvolatile(RegisterDictionaryPtrArg dict, std::string rname) {
  RegisterDescriptor rd = dict->find(rname);
  if (!rd.is_valid()) {
    GFATAL << "Unable to find non-volatile register '" << rname << "'." << LEND;
    assert(rd.is_valid());
  }
  nonvolatile.insert(rd);
}

void CallingConvention::add_nonvolatile(RegisterDescriptor rd) {
  if (!rd.is_valid()) {
    GFATAL << "Invalid register with adding non-volatile." << LEND;
    assert(rd.is_valid());
  }
  nonvolatile.insert(rd);
}

void CallingConvention::add_nonvolatile(const RegisterSet& regs) {
  for (RegisterDescriptor rd : regs) {
    if (!rd.is_valid()) {
      GFATAL << "Invalid register with adding non-volatile." << LEND;
      assert(rd.is_valid());
    }
    nonvolatile.insert(rd);
  }
}

void CallingConvention::report() const {
  if (!(GTRACE)) return;
  GTRACE << "Calling convention:  " << name << LEND;
  GTRACE << "  Architecture size: " << word_size << LEND;
  GTRACE << "  Compiler:          " << compiler << LEND;
  GTRACE << "  Comment:           " << comment << LEND;
  GTRACE << "  Parameter order:   " << Enum2Str(param_order) << LEND;
  GTRACE << "  Stack cleanup:     " << Enum2Str(stack_cleanup) << LEND;
  GTRACE << "  Return value loc:  " << Enum2Str(retval_location) << LEND;
  GTRACE << "  This pointer loc:  " << Enum2Str(this_location) << LEND;
  GTRACE << "  Stack alignment:   " << stack_alignment << LEND;

  GTRACE << "  Parameter regs:   ";
  for (RegisterDescriptor rd : reg_params) {
    GTRACE << " " << unparseX86Register(rd, {});
  }
  GTRACE << LEND;

  GTRACE << "  Nonvolatile regs: ";
  for (RegisterDescriptor rd : nonvolatile) {
    GTRACE << " " << unparseX86Register(rd, {});
  }
  GTRACE << LEND;
}

// The stack parameter form.
ParameterDefinition::ParameterDefinition(
  size_t c, const SymbolicValuePtr& v, std::string n,
  std::string t, const SgAsmInstruction* i,
  const SymbolicValuePtr& a, size_t delta)
{
  // The parameter number.
  d.num = c;

  // If the caller didn't provide a name, make up a "generic" one.
  if (n != "") {
    d.name = n;
  }
  else {
    d.name = boost::str(boost::format("p%d") % c);
  }

  if (t != "") {
    d.type = t;
  }
  else {
    d.type = "unknown";
  }

  d.value = v;
  // Smart pointer for value_pointed_to is constructed with a "NULL" value.
  d.stack_delta = delta;
  d.address = a;
  d.insn = i;
  d.direction = DIRECTION_NONE;
}

// The register parameter form.
ParameterDefinition::ParameterDefinition(
  size_t c, const SymbolicValuePtr& v, std::string n,
  std::string t, const SgAsmInstruction* i,
  RegisterDescriptor r)
{

  // The parameter number.
  d.num = c;

  // If the caller didn't provide a name, make up a "generic" one.
  if (n != "") {
    d.name = n;
  }
  else {
    d.name = boost::str(boost::format("r%d") % c);
  }

  if (t != "") {
    d.type = t;
  }
  else {
    d.type = "unknown";
  }

  d.value = v;
  // Smart pointer for value_pointed_to is constructed with a "NULL" value.
  d.reg = r;
  d.insn = i;
  d.stack_delta = 0;
  d.address = SymbolicValuePtr();
}

// Called as we dynamically discover these attributes for a parameter.
void ParameterDefinition::set_stack_attributes(
  const SymbolicValuePtr& v, const SymbolicValuePtr& a,
  SgAsmInstruction* i, const SymbolicValuePtr& p)
{
  write_guard<decltype(mutex)> guard{mutex};
  d.value = v;
  d.value_pointed_to = p;
  d.address = a;
  d.insn = i;
}

void ParameterDefinition::set_reg_attributes(
  const SymbolicValuePtr& v, const SgAsmInstruction* i,
  const SymbolicValuePtr& p)
{
  write_guard<decltype(mutex)> guard{mutex};
  d.value = v;
  d.value_pointed_to = p;
  d.insn = i;
}

void ParameterDefinition::copy_parameter_description(ParameterDefinition const & other)
{
  if (this == &other) { return; }
  write_guard<decltype(mutex)> guard{mutex};
  read_guard<decltype(other.mutex)> oguard{other.mutex};
  d.name = other.d.name;
  d.type = other.d.type;
  d.direction = other.d.direction;
}

void ParameterDefinition::copy_parameter_description(APIParam const & ap)
{
  write_guard<decltype(mutex)> guard{mutex};
  if (!ap.name.empty()) {
    d.name = ap.name;
  }
  if (!ap.type.empty()) {
    d.type = ap.type;
  }
  d.direction = DirectionEnum(ap.direction);
}

void ParameterDefinition::set_parameter_description(
  std::string n, std::string t, ParameterDefinition::DirectionEnum dir)
{
  write_guard<decltype(mutex)> guard{mutex};
  d.name = std::move(n);
  d.type = std::move(t);
  d.direction = dir;
}

//void ParameterList::add_parameter(SymbolicValuePtr local_value) {
//  parameters.push_back(CallParameter(0, local_value));
//}

template<> char const* EnumStrings<ParameterDefinition::DirectionEnum>::data[] = {
  "none",
  "in",
  "out",
  "inout"
};

// JSG thinks having the logging baked deep into library code (aka debug) seems like a bad
// idea. Having a general to_string method that can be used to fetch a string representation
// seems better.
std::string ParameterDefinition::to_string() const {
  read_guard<decltype(mutex)> guard{mutex};

  std::stringstream out;
  out << "  num=" << d.num;
  if (is_reg()) {
    out << " reg=" << unparseX86Register(d.reg, {});
  }
  else {
    out << " sd=" << d.stack_delta;
  }

  out << " name=" << d.name;
  // if (type.compare("unknown") != 0) {
  //   out << " type=" << type;
  // }
  if (d.value && d.value->is_valid()) {

    TreeNodePtr param_tnp = d.value->get_expression();

    // This is useful for debugging
    // uint64_t raw_param_id = reinterpret_cast<uint64_t>(&*param_tnp);
    // out << " raw=(" << addr_str(raw_param_id) << ")";

    out << " value=" << *(param_tnp);

    try {

      TypeDescriptorPtr tdp = boost::any_cast< TypeDescriptorPtr >(
        d.value->get_expression()->userData());
      if (tdp) {
        out << " td=(" << tdp->to_string() << ")";
      } else
        OINFO << " td=unknown";
    } catch (...) {
      out << " td=missing";
    }
  }
  else {
    GWARN << "Invalid paramater value used, reasoning may be incomplete" << LEND;
  }
  if (d.value_pointed_to && d.value_pointed_to->is_valid()) {
    out << " *value=" << *(d.value_pointed_to->get_expression());
  }
  else {
    GWARN << "Invalid paramater value_pointed_to used, reasoning may be incomplete" << LEND;
  }
  if (d.insn != NULL) {
    out << " insn=" << debug_instruction(d.insn);
  }
  if (is_stack() && d.address && d.address->is_valid()) {
    out << " addr=" << *(d.address->get_expression());
  }
  if (d.direction != ParameterDefinition::DIRECTION_NONE) {
    out << " dir=" << Enum2Str(d.direction);
  }

  return out.str();
}

void ParameterDefinition::debug() const {
  read_guard<decltype(mutex)> guard{mutex};

  OINFO << "  num=" << d.num;
  if (is_reg()) {
    OINFO << " reg=" << unparseX86Register(d.reg, {});
  }
  else {
    OINFO << " sd=" << d.stack_delta;
  }

  OINFO << " name=" << d.name;
  if (d.type.compare("unknown") != 0) {
    OINFO << " type=" << d.type;
  }
  if (d.value && d.value->is_valid()) {
    OINFO << " value=" << *(d.value->get_expression());

    try {

      TypeDescriptorPtr tdp = boost::any_cast< TypeDescriptorPtr >(
        d.value->get_expression()->userData());
      if (tdp) {
        OINFO << " type descriptor=[" << tdp->to_string() << "]";
      } else
        OINFO << " type descriptor=INVALID";
    } catch (...) {
      OINFO << " type descriptor=MISSING";
    }
  }
  if (d.value_pointed_to && d.value_pointed_to->is_valid()) {
    OINFO << " *value=" << *(d.value_pointed_to->get_expression());
  }
  if (d.insn != NULL) {
    OINFO << " insn=" << debug_instruction(d.insn);
  }
  if (is_stack() && d.address && d.address->is_valid()) {
    OINFO << " addr=" << *(d.address->get_expression());
  }
  if (d.direction != ParameterDefinition::DIRECTION_NONE) {
    OINFO << " dir=" << Enum2Str(d.direction);
  }

  OINFO << LEND;
}

// Find the parameter definition that matches a specific stack delta, or return NULL if it does
// not exist.
const ParameterDefinition* ParameterList::get_stack_parameter(size_t delta) const {
  read_guard<decltype(mutex)> guard{mutex};
  for (ParameterDefinition const & p : d.params) {
    if (p.is_stack() && p.get_stack_delta() == delta) {
      return &p;
    }
  }
  return nullptr;
}

ParameterDefinition* ParameterList::get_rw_stack_parameter(size_t delta) {
  return const_cast<ParameterDefinition *>(
    const_cast<const ParameterList *>(this)->get_stack_parameter(delta));
}

// Find the parameter definition that corresponds to a specific regsiter descriptior, or return
// NULL if it does not exist.
const ParameterDefinition* ParameterList::get_reg_parameter(RegisterDescriptor rd) const {
  read_guard<decltype(mutex)> guard{mutex};
  for (ParameterDefinition const & p : d.params) {
    if (p.get_register() == rd) {
      return &p;
    }
  }
  return nullptr;
}

ParameterDefinition* ParameterList::get_rw_reg_parameter(RegisterDescriptor rd) {
  return const_cast<ParameterDefinition *>(
    const_cast<const ParameterList *>(this)->get_reg_parameter(rd));
}

const ParameterDefinition* ParameterList::get_return_reg(RegisterDescriptor rd) const {
  read_guard<decltype(mutex)> guard{mutex};
  for (ParameterDefinition const & p : d.returns) {
    if (p.get_register() == rd) {
      return &p;
    }
  }
  return nullptr;
}

ParameterDefinition* ParameterList::get_rw_return_reg(RegisterDescriptor rd) {
  return const_cast<ParameterDefinition *>(
    const_cast<const ParameterList *>(this)->get_return_reg(rd));
}

// Get the stack parameter at a specific delta. Create it if it does not exist.  Further,
// create all of the parameters between the highest existing parameter and the newly requested
// one, since those must at least be unused parameters, and are quite likely just parameter
// usages that we don't understand properly or haven't processed yet.
ParameterDefinition* ParameterList::create_stack_parameter(size_t delta) {
  ParameterDefinition* retval;

  // The easiest case is that the parameter already exists.  If so, return it.
  retval = get_rw_stack_parameter(delta);
  if (retval != NULL) return retval;

  // This serves two purposes, to prevent the consumption of excessive memory and CPU time when
  // something has gone wrong, and to make the type casting interaction between int64_t and
  // size_t a little safer.
  if (delta > 10000) {
    GWARN << "Ignoring grossly unreasonable stack parameter delta of " << delta << "." << LEND;
    return NULL;
  }
  // We only support dword stack deltas currently.  Surprisingly there were a lot of deltas
  // that were not multiples of four in some binary samples we found.  Moved to warning.
  if ((delta % 4) != 0) {
    GWARN << "Stack parameter delta " << delta << " was not a multiple of 4." << LEND;
    return NULL;
  }

  write_guard<decltype(mutex)> guard{mutex};

  // How many existing parameters are there?
  size_t psize = d.params.size();
  // By default, assume that there are no existing parameters.
  int64_t existing_delta = -4;
  int64_t existing_num = -1;
  // If there are some existing parameters, what's the last one?
  if (psize > 0) {
    ParameterDefinition& last_param = d.params[psize - 1];
    // BUG?  This assumes that parameters are always passed registers first, and stack
    // parameters last, and that the source code ordering matches the stack delta ordering,
    // which is true in every (x86) case that Cory knows of.
    existing_num = last_param.get_num();
    // The stack delta field is only populated if the parameter is a stack parameter.
    if (!last_param.is_reg()) {
      existing_delta = last_param.get_stack_delta();
    }
  }

  // More sanity checking, no reason for this to occur.
  if (existing_delta >= (int64_t)delta) {
    GFATAL << "Unable to find stack parameter " << delta << " when we should have." << LEND;
  }

  // This will presumably be popluated later.
  SymbolicValuePtr invalid;

  // Create each parameter from existing_num to num (existing_delta to delta).
  size_t num = existing_num + 1;
  for (size_t sd = existing_delta + 4; sd <= delta; sd += 4) {
    // OINFO << "Creating parameter " << num << " at delta " << sd << " of " << delta << LEND;
    d.params.emplace_back(num, invalid, "", "", nullptr, invalid, sd);
    num++;
  }

  // Finally, go find the parameter that we just created and return it.
  return &d.params.back();
}

//
ParameterDefinition &
ParameterList::create_reg_parameter(RegisterDescriptor r, const SymbolicValuePtr v,
                                    const SgAsmInstruction* i, const SymbolicValuePtr p) {
  ParameterDefinition* retval;
  // Find and return an existing parameter.
  retval = get_rw_reg_parameter(r);
  // If we found an existing register parameter definition.
  if (retval != NULL) {
    // Set the newly updates attributes in the existing parameter definition.
    retval->set_reg_attributes(v, i, p);
    return *retval;
  }

  write_guard<decltype(mutex)> guard{mutex};

  // How many existing parameters are there?
  size_t psize = d.params.size();
  // By default, assume that there are no existing parameters.
  int64_t existing_num = -1;
  // If there are some existing parameters, what's the last one?
  if (psize > 0) {
    ParameterDefinition& last_param = d.params[psize - 1];
    existing_num = last_param.get_num();
  }

  size_t num = existing_num + 1;

  // The default behavior is to make up a name of right now...
  std::string pname = "";
  // If there's no instruction, that also marks the special case of an unused parameter.
  // Cory's not currently aware of any reason why the lack of an instruction would imply
  // anything else, but it's not immediately obvious that it _must_ be true in all cases.
  if (i == NULL) {
    pname = boost::str(boost::format("unused%d") % num);
  }

  d.params.emplace_back(num, v, pname, "", i, r);
  return d.params.back();
}

// Cory is beginning to realize that there's a lot of code duplication going on here.
// Unfortunately, there needs to be to enforce a consistent API.  I want to ensure that the
// parameter/return numbers are consistent, and to keep the params and returns vectors private,
// so I'm not sure that there's a cleaner way to do this.  Perhaps we should revisit this to
// clean up the code a bit more.
ParameterDefinition &
ParameterList::create_return_reg(RegisterDescriptor r, const SymbolicValuePtr v) {
  ParameterDefinition* retval;

  // Find and return an existing return value.
  retval = get_rw_return_reg(r);
  if (retval != NULL) return *retval;

  write_guard<decltype(mutex)> guard{mutex};

  // How many existing return values are there?
  size_t psize = d.returns.size();
  // By default, assume that there are no existing return values.
  int64_t existing_num = -1;
  // If there are some existing return values, what's the last one?
  if (psize > 0) {
    ParameterDefinition& last_param = d.params[psize - 1];
    existing_num = last_param.get_num();
  }
  size_t num = existing_num + 1;

  // In the case of return values, we can get the evidence instruction (or more correctly one
  // of the evidence instructions) from the modifiers on the symbolic value.  In this case,
  // we're closer to a better design where the evidence is a list of instructions rather than
  // just one.  But for now, we're only able to hold one evidence instruction in the parameter
  // definition.  This code was broken when we removed modifiers, and rather than adding it
  // back with a single evidence instruction I should talk to JSG and decide how to proceed.
  const SgAsmInstruction* i = nullptr;
  // Effectively, the previous code was: i = *(g->get_modifiers().begin());
  // Now we'll need to pass the instruction because writers don't follow the SymbolicValue. :-(

  // Create the parameter definition and put it in the list.
  d.returns.emplace_back(num, v, "", "", i, r);

  // Then return it.
  return d.returns.back();
}

void ParameterList::debug() const {
  read_guard<decltype(mutex)> guard{mutex};

  if (d.params.size() == 0) {
    OINFO << "none" << LEND;
    return;
  }
  else {
    OINFO << LEND;
  }
  for (const ParameterDefinition& p : d.params) {
    p.debug();
  }
}

void CallingConventionMatcher::report() const {
  if (!(GTRACE)) return;
  for (const CallingConvention& cc : conventions) {
    cc.report();
  }
}

const CallingConvention* CallingConventionMatcher::find(size_t word_size, const std::string &name) const {
  for (const CallingConvention& cc : conventions) {
    if (cc.get_word_size() == word_size && cc.get_name() == name) return &cc;
  }
  return NULL;
}

CallingConventionPtrVector
CallingConventionMatcher::match(const FunctionDescriptor* fd,
                                bool allow_unused_parameters) const {
  CallingConventionPtrVector matches;
  if (fd == NULL) {
    GERROR << "Calling convention matcher invoked on a NULL function descriptor." << LEND;
    return matches;
  }

  // Thunks get their calling convention from the target function.
  if (fd->is_thunk()) {
    const FunctionDescriptor* tfd = fd->follow_thunks_fd();
    if (tfd == NULL) {
      // I think this scenario should be handled gracefully someplace else.
      rose_addr_t ta = fd->follow_thunks();
      const ImportDescriptor* id = fd->ds.get_import(ta);
      if (id != NULL) {
        GDEBUG << "Function " << fd->address_string()
               << " is a thunk to " << id->get_long_name() << LEND;
        size_t arch_bits = fd->ds.get_arch_bits();
        const CallingConvention* stdcall = find(arch_bits, "__stdcall");
        if (stdcall != NULL) matches.push_back(stdcall);
        return matches;
      }
      else {
        GWARN << "Function " << fd->address_string()
              << " is an unrecognized thunk to address " << addr_str(ta) << LEND;
      }
      return matches;
    }
    // We can't recurse here because we'll recurse endlessly in thunk loops.  Instead, just
    // pretend that we passed the correct function descriptor.  We're not actually writing to
    // fd at all, so it doesn't matter which one we point to.
    else {
      fd = tfd;
    }
  }

  fd->get_pdg();
  const RegisterUsage& ru = fd->get_register_usage();

  // Get the stack delta (once)...
  StackDelta sd = fd->get_stack_delta();
  GDEBUG << "Function " << fd->address_string() << " stack delta is: " << sd << LEND;

  for (const CallingConvention& cc : conventions) {
    // Only register usage patterns of the correct architecture size can match.
    size_t arch_bits = fd->ds.get_arch_bits();
    if (arch_bits != cc.get_word_size()) continue;

    // If the function changes a non-volatile register, then it can't match.
    bool follows_nonvolatile_rule = true;
    for (RegisterDescriptor rd : cc.get_nonvolatile()) {
      if (ru.changed_registers.find(rd) != ru.changed_registers.end()) {
        GDEBUG << "Function " << fd->address_string() << " can't match "
               << cc.get_name() << " because non-volatile register "
               << unparseX86Register(rd, {}) << " was changed." << LEND;
        follows_nonvolatile_rule = false;
        break;
      }
    }
    if (!follows_nonvolatile_rule) continue;

    // Don't place too much stock in faulty stack delta analysis?
    if (sd.confidence >= ConfidenceGuess) {
      // If the function modified the stack (callee cleanup) then we can't be any calling
      // convention that is caller cleanup.  We can't conduct the inverse test (requiring a
      // stack delta), because functions without stack parameters could have a zero delta
      // and still be callee cleanup.
      if (sd.delta != 0) {
        if (cc.get_stack_cleanup() == CallingConvention::CLEANUP_CALLER) {
          GDEBUG << "Function " << fd->address_string() << " can't match " << cc.get_name()
                 << " because it has a stack delta for caller cleanup convention." << LEND;
          continue;
        }
      }
    }

    // Did we use at least one of the parameter registers?
    bool used_a_parameter_register = false;
    // Make a copy of the parameter registers, so that we can remove them as we process them.
    RegisterEvidenceMap temp_params = ru.parameter_registers;

    // A list of registers that functions are allowed to use without being considered
    // parameters
    static char const * allowed_registers[] =
      {"esp", "df", "cs", "ds", "ss", "es", "gs", "fs", nullptr};
    for (char const ** regname = allowed_registers; *regname; ++regname) {
      RegisterDescriptor rd = regdict->find(*regname);
      if (temp_params.find(rd) != temp_params.end()) temp_params.erase(rd);
    }

    // The calling convention doesn't have register parameters, and the function does, then it
    // can't match the calling convention.
    if (cc.get_reg_params().size() == 0 && temp_params.size() > 0) {
      GDEBUG << "Function " << fd->address_string() << " can't match " << cc.get_name()
             << " because it passes parameters in registers." << LEND;
      continue;
    }

    // For each parameter in the calling convention (in order), remove it from the set of
    // parameters passed to the function.  When you get to a register that was not passed, stop
    // processing parameters.  The intention is to ensure that the parameters were passed in
    // the correct order, but how does this interact with code that accepts unused parameters?
    // Do we end up denying the existence of the register passed parameter?
    for (RegisterDescriptor rd : cc.get_reg_params()) {
      if (temp_params.find(rd) != temp_params.end()) {
        used_a_parameter_register = true;
        temp_params.erase(rd);
      }
      else {
        GTRACE << "Function " << fd->address_string() << " does not use parameter register "
               << unparseX86Register(rd, {}) << LEND;
        // If there are function parameters that are passed in registers, but not actually
        // used, then breaking here causes a premature end to the consideration of the
        // remaining parameters in the calling convention, leaving any additional parameters
        // that were used in temp_params, and ultimately rejecting this calling convention.
        if (allow_unused_parameters == false) {
          GTRACE << "Skipping remaining parameters in calling convention." << LEND;
          break;
        }
      }
    }

    // Under no circumstances can we match if we're using parameters that are recognized.
    if (temp_params.size() > 0) {
      GTRACE << "Unmatched parameter registers: ";
      for (const RegisterEvidenceMap::value_type& rpair : temp_params) {
        RegisterDescriptor rd = rpair.first;
        GTRACE << " " << unparseX86Register(rd, {});
      }
      GTRACE << LEND;
      continue;
    }

    // If this calling convention has register parameters and the function didn't use at least
    // one of them, then it can't match the calling convention (excepting unused parameters).
    // We're presuming (correctly?) that all calling conventions prefer to pass parameters in
    // the registers rather than the stack, and that if there were any parameters, the first
    // would have been in the register.
    if (allow_unused_parameters == false &&
        cc.get_reg_params().size() > 0 && !used_a_parameter_register) {
      GDEBUG << "Function " << fd->address_string() << " can't match "
             << cc.get_name() << " because it doesn't use "
             << "any registers (and unused parameters are disallowed)." << LEND;
      continue;
    }

    // We've not found any reason to disqualify this calling convention, so it's a possibility.
    matches.push_back(&cc);
  }

  return matches;
}

// Create a set of calling conventions used in real compilers.
CallingConventionMatcher::CallingConventionMatcher()
  // It is presumes that the amd64 register dictionary is a superset of the 32-bit and 16-bit
  // dictionaries
#if PHAROS_ROSE_REGISTERDICTIONARY_PTR_HACK
  : regdict(Rose::BinaryAnalysis::RegisterDictionary::instanceAmd64())
#else
  : regdict(Rose::BinaryAnalysis::RegisterDictionary::dictionary_amd64())
#endif
{
  // ================================================================================
  // 16-bit calling conventions...
  // ================================================================================
  // Agner says 16-bit DOS and windows has SI, DI, BP and DS as nonvolatile.

  RegisterDescriptor eax = regdict->find("eax");
  RegisterDescriptor ecx = regdict->find("ecx");
  RegisterDescriptor edx = regdict->find("edx");
  //RegisterDescriptor st0 = regdict->find("st0");

  // Agner says this list is correct for Windows & Unix
  CallingConvention nonvol = CallingConvention(32, "__fake", "Fake");
  nonvol.add_nonvolatile(regdict, "ebx");
  nonvol.add_nonvolatile(regdict, "esi");
  nonvol.add_nonvolatile(regdict, "edi");
  nonvol.add_nonvolatile(regdict, "ebp");
  nonvol.add_nonvolatile(regdict, "cs");
  nonvol.add_nonvolatile(regdict, "ds");
  nonvol.add_nonvolatile(regdict, "ss");
  nonvol.add_nonvolatile(regdict, "es");
  nonvol.add_nonvolatile(regdict, "fs");
  nonvol.add_nonvolatile(regdict, "gs");

  // Agner's commentary points out that this is strictly not non-volatile, since it's always
  // supposed to be cleared by default.  Thus clearing it is allowed (double-safe), but setting
  // it is not.
  nonvol.add_nonvolatile(regdict, "df");

  // ESP/RSP volatility depends on caller/callee cleanup.
  // EIP/RIP volatility depends on handling of call.
  // EFLAGS is pretty clearly volatile.
  // Other registers are less clear, but are probably volatile.

  // ================================================================================
  // 32-bit calling conventions...
  // ================================================================================

  // C declaration
  // http://msdn.microsoft.com/en-us/library/zkwh89ks.aspx
  CallingConvention cc = CallingConvention(32, "__cdecl", "Microsoft Visual Studio");
  cc.set_stack_alignment(32);
  cc.set_stack_cleanup(CallingConvention::CLEANUP_CALLER);
  cc.set_retval_register(eax);
  cc.set_param_order(CallingConvention::ORDER_RTL);
  cc.add_nonvolatile(nonvol.get_nonvolatile());
  conventions.push_back(cc);

  // Standard call
  // http://msdn.microsoft.com/en-us/library/zxk0tw93.aspx
  cc = CallingConvention(32, "__stdcall", "Microsoft Visual Studio");
  cc.set_stack_alignment(32);
  cc.set_stack_cleanup(CallingConvention::CLEANUP_CALLEE);
  cc.set_retval_register(eax);
  cc.set_param_order(CallingConvention::ORDER_RTL);
  cc.add_nonvolatile(nonvol.get_nonvolatile());
  conventions.push_back(cc);

  // This call
  // http://msdn.microsoft.com/en-us/library/ek8tkfbw.aspx
  cc = CallingConvention(32, "__thiscall", "Microsoft Visual Studio");
  cc.set_stack_alignment(32);
  cc.set_stack_cleanup(CallingConvention::CLEANUP_CALLEE);
  cc.set_retval_register(eax);
  cc.set_param_order(CallingConvention::ORDER_RTL);
  cc.add_reg_param(ecx);
  cc.set_this_register(ecx);
  cc.add_nonvolatile(nonvol.get_nonvolatile());
  conventions.push_back(cc);

  // Fast call
  // http://msdn.microsoft.com/en-us/library/6xa169sk.aspx
  cc = CallingConvention(32, "__fastcall", "Microsoft Visual Studio");
  cc.set_stack_alignment(32);
  cc.set_stack_cleanup(CallingConvention::CLEANUP_CALLEE);
  cc.set_retval_register(eax);
  cc.set_param_order(CallingConvention::ORDER_RTL);
  cc.add_reg_param(ecx);
  cc.add_reg_param(edx);
  cc.add_nonvolatile(nonvol.get_nonvolatile());
  conventions.push_back(cc);

#if 0
  // Common Language Runtime (CLR) call
  // http://msdn.microsoft.com/en-us/library/ec7sfckb.aspx
  // This calling convention cannot be used for functions that are called from native code.
  cc = CallingConvention(32, "__clrcall", "Microsoft Visual Studio");
  cc.set_stack_alignment(32);
  cc.set_stack_cleanup(CallingConvention::CLEANUP_CALLEE);
  cc.set_retval_register(eax);
  cc.set_param_order(CallingConvention::ORDER_LTR);
  cc.add_nonvolatile(nonvol.get_nonvolatile());
  conventions.push_back(cc);
#endif

  // Vector call
  // http://msdn.microsoft.com/en-us/library/dn375768.aspx
  cc = CallingConvention(32, "__vectorcall", "Microsoft Visual Studio");
  cc.set_stack_alignment(32);
  cc.set_stack_cleanup(CallingConvention::CLEANUP_CALLEE);
  cc.set_retval_register(eax);
  cc.set_param_order(CallingConvention::ORDER_RTL);
  // Vector call parameter order is complicated...
  cc.add_reg_param(ecx); // Might also be a this pointer...
  cc.add_reg_param(edx);
  cc.add_nonvolatile(nonvol.get_nonvolatile());
  conventions.push_back(cc);

  // Obsolete calling conventions
  // __pascal, __fortran, and __syscall

  // ================================================================================
  // 64-bit calling conventions
  // ================================================================================

  // Volatile versus non-volatile register usage:
  // http://msdn.microsoft.com/en-us/library/9z1stfyw.aspx
  nonvol = CallingConvention(64, "__fake", "Fake");
  nonvol.add_nonvolatile(regdict, "rbx");
  nonvol.add_nonvolatile(regdict, "rbp");
  nonvol.add_nonvolatile(regdict, "r12");
  nonvol.add_nonvolatile(regdict, "r13");
  nonvol.add_nonvolatile(regdict, "r14");
  nonvol.add_nonvolatile(regdict, "r15");
  // See earlier comment on clearing df being allowed.
  nonvol.add_nonvolatile(regdict, "df");

  RegisterDescriptor rax = regdict->find("rax");
  RegisterDescriptor rdi = regdict->find("rdi");
  RegisterDescriptor rsi = regdict->find("rsi");
  RegisterDescriptor rcx = regdict->find("rcx");
  RegisterDescriptor rdx = regdict->find("rdx");
  RegisterDescriptor r8 = regdict->find("r8");
  RegisterDescriptor r9 = regdict->find("r9");

  RegisterDescriptor xmm0 = regdict->find("xmm0");
  RegisterDescriptor xmm1 = regdict->find("xmm1");
  RegisterDescriptor xmm2 = regdict->find("xmm2");
  RegisterDescriptor xmm3 = regdict->find("xmm3");

  cc = CallingConvention(64, "__x64call", "GNU C Compiler");
  cc.set_stack_alignment(64);
  cc.set_stack_cleanup(CallingConvention::CLEANUP_CALLEE);
  cc.set_retval_register(rax);
  cc.set_param_order(CallingConvention::ORDER_RTL);
  cc.add_reg_param(rdi);
  cc.add_reg_param(rsi);
  cc.add_reg_param(rdx);
  cc.add_reg_param(rcx);
  cc.add_reg_param(r8);
  cc.add_reg_param(r9);
  cc.add_reg_param(xmm0);
  cc.add_reg_param(xmm1);
  cc.add_reg_param(xmm2);
  cc.add_reg_param(xmm3);
  cc.add_nonvolatile(nonvol.get_nonvolatile());
  conventions.push_back(cc);

  // 64-bit Application Binary Interface
  // http://msdn.microsoft.com/en-us/library/ms235286.aspx

  // In addition to the Unix non-volatile registers, Microsoft adds rsi, rdi, and xmm6-xmm15
  nonvol.add_nonvolatile(regdict, "rsi");
  nonvol.add_nonvolatile(regdict, "rdi");
  // The Microsoft standard on this had changed over time.  xmm6-xmm15 are now non-volative,
  // although the new AVX extended ymm?? registers (bits 65-128) and zmm?? registers (bits
  // 129-256) are not officially non-volatile.
  nonvol.add_nonvolatile(regdict, "xmm6");
  nonvol.add_nonvolatile(regdict, "xmm7");
  nonvol.add_nonvolatile(regdict, "xmm8");
  nonvol.add_nonvolatile(regdict, "xmm9");
  nonvol.add_nonvolatile(regdict, "xmm10");
  nonvol.add_nonvolatile(regdict, "xmm11");
  nonvol.add_nonvolatile(regdict, "xmm12");
  nonvol.add_nonvolatile(regdict, "xmm13");
  nonvol.add_nonvolatile(regdict, "xmm14");
  nonvol.add_nonvolatile(regdict, "xmm15");

  cc = CallingConvention(64, "__x64call", "Microsoft Visual Studio");
  cc.set_stack_alignment(64);
  cc.set_stack_cleanup(CallingConvention::CLEANUP_CALLEE);
  cc.set_retval_register(rax);
  cc.set_param_order(CallingConvention::ORDER_RTL);
  cc.add_reg_param(rcx);
  cc.add_reg_param(rdx);
  cc.add_reg_param(r8);
  cc.add_reg_param(r9);
  cc.add_reg_param(xmm0);
  cc.add_reg_param(xmm1);
  cc.add_reg_param(xmm2);
  cc.add_reg_param(xmm3);
  cc.add_nonvolatile(nonvol.get_nonvolatile());
  conventions.push_back(cc);

}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
