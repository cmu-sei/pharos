// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/algorithm/string.hpp>
#include <boost/tokenizer.hpp>
#include <boost/foreach.hpp>

#include "defuse.hpp"
#include "sptrack.hpp"
#include "badcode.hpp"
#include "limit.hpp"
#include "riscops.hpp"
#include "misc.hpp"
#include "options.hpp"

// In practice five iterations was all that was needed for the worst of the functions that
// actually produced results (ever) in the Objdigger test suite.  This limit might become
// optional if we can find and fix the remaining convergence bugs.
#define MAX_LOOP 5

// Updated in objdigger.cpp and program options.
bool global_timing = false;

// This is not a method in DUAnalysis, because I don't want to have to have a handle to the
// Analysis object to dump the definitions.  It would be nicer if the DUChain map had a method
// on it do this, but a global function will do for now.
void print_definitions(DUChain duc) {
  BOOST_FOREACH(Definition d, duc) {
    // Some arbitrary indentation.
    OINFO << "      ";

    std::cout.width(30);
    OINFO << std::left << d.access.str();
    OINFO << " <=== ";
    if (d.definer == NULL) OINFO << "[no defining instruction]" << LEND;
    else OINFO << debug_instruction(d.definer) << LEND;
  }
}

DUAnalysis::DUAnalysis(FunctionDescriptor* f, spTracker* s) {
  // We've always got a real function to analyze.
  current_function = f;
  assert(current_function != NULL);

  // The primary function to analyze.
  primary_function = current_function->get_func();
  assert(primary_function != NULL);

  // A stack pointer tracker object to advise us on stack deltas for calls.
  sp_tracker = s;

  // Now go do the analysis.
  status = solve_flow_equation_iteratively();
}

void DUAnalysis::print_dependencies() const {
  OINFO << "Dependencies (Inst I, value read by I <=== instruction that defined value):" << LEND;
  BOOST_FOREACH(const Insn2DUChainMap::value_type &p, depends_on) {
    OINFO << debug_instruction(p.first) << LEND;
    print_definitions(p.second);
  }
}

void DUAnalysis::print_dependents() const {
  OINFO << "Dependents (Inst I, value defined by I <=== instruction that read value):" << LEND;
  BOOST_FOREACH(const Insn2DUChainMap::value_type &p, dependents_of) {
    OINFO << debug_instruction(p.first) << LEND;
    print_definitions(p.second);
  }
}

const AbstractAccess* DUAnalysis::get_the_write(SgAsmX86Instruction* insn) const {
  const AbstractAccessVector* aav = get_writes(insn);
  if (aav == NULL) return NULL;
  if (aav->size() != 1) {
    SERROR << "Instruction: " << debug_instruction(insn)
           << " had more than the expected single write." << LEND;
  }
  if (aav->size() < 1) return NULL;
  //AbstractAccessVector::iterator first = aav->begin();
  return &(*(aav->begin()));
}

const AbstractAccess* DUAnalysis::get_first_mem_write(SgAsmX86Instruction* insn) const {
  // Get the writes for this instruction.
  const AbstractAccessVector* aav = get_writes(insn);
  // If there were non, return NULL.
  if (aav == NULL) return NULL;
  // Walk the writes, looking for memory writes.
  BOOST_FOREACH(const AbstractAccess& aa, *aav) {
    // Return the first memory write we encounter.
    if (aa.is_mem()) return &aa;
  }
  // If we didn't find a memory write, then return NULL.
  return NULL;
}

// Safely make a matching pair of dependency links.  Hopefully this doesn't perform too poorly.
// If it does, there are probably some optimizations that can be made using iterators that
// would help.
void DUAnalysis::add_dependency_pair(SgAsmX86Instruction *i1, SgAsmX86Instruction *i2, AbstractAccess access) {
  // Make new DUChains if needed.
  if (i1 != NULL && depends_on.find(i1) == depends_on.end()) depends_on[i1] = DUChain();
  if (i2 != NULL && dependents_of.find(i2) == dependents_of.end()) dependents_of[i2] = DUChain();
  // Add the matching entries.
  // i1 reads the aloc defined by i2.  i2 defines the aloc read by i1.
  if (i1 != NULL) depends_on[i1].insert(Definition(i2, access));
  if (i2 != NULL) dependents_of[i2].insert(Definition(i1, access));
}

// Has our emulation of the instructions leading up to this call revealed where it calls to?
// Specifically the pattern "mov esi, [import]" and "call esi" requires this code to determine
// that ESI contains the address of an import table entry.
void DUAnalysis::update_call_targets(SgAsmX86Instruction* insn, SymbolicRiscOperatorsPtr& rops) {
  SgAsmExpressionPtrList &ops = insn->get_operandList()->get_operands();
  assert(ops.size() > 0);

  // Are we a call to register instruction?
  SgAsmDirectRegisterExpression *ref = isSgAsmDirectRegisterExpression(ops[0]);
  if (ref != NULL) {
    RegisterDescriptor rd = ref->get_descriptor();
    // Read the current value out of the register.
    SymbolicValuePtr regval = SymbolicValue::promote(rops->readRegister(rd));
    SDEBUG << "Call instruction: " << debug_instruction(insn) << " calls to: " << *regval << LEND;

    // If the outermost value has the loader defined bit then either itself or one of its
    // children has the loader defined bit set.  Check all possible values to figure out which
    // one(s) have the bit.
    if (regval->is_loader_defined()) {
      SDEBUG << "Call is to loader defined value: " << *regval << LEND;
      BOOST_FOREACH(const TreeNodePtr& tn, regval->get_possible_values()) {
        // It's a annoying that we have to convert back to a SymbolicValue here, but we can't
        // currently define methods on tree node pointers, and I'm not sure that I want to
        // reference the LOADER_DEFINED constant from here either.  We'd also have to change
        // the API to get_import_by_variable(), but at least it's only ever used from here.
        // Perhaps more NEWWAY fixups are needed?
        SymbolicValuePtr v = SymbolicValue::treenode_instance(tn);
        if (v->is_loader_defined()) {
          SDEBUG << "Call target is to loader defined value: " << *v << LEND;
          ImportDescriptor* id = global_descriptor_set->get_import_by_variable(v);
          // Yes, it's a call to an import.  Update the call target list with a new target.
          if (id != NULL) {
            SDEBUG << "The call " << debug_instruction(insn)
                   << " was to import " << id->get_long_name() << LEND;
            CallDescriptor* cd = global_descriptor_set->get_call(insn->get_address());
            cd->add_import_target(id);
          }
          else {
            SDEBUG << "The constant call target was not resolved." << LEND;
          }
        }
      }
    }
  }
}

// A horrible hackish workaround to various bugs in ROSE. :-( Basically because ROSE doesn't
// update the instruction succesors correctly we need to call bb_get_successors for lst
// instruction in each basic block, and insn->get_sucessors for all others.  This is indepedent
// of whether the instruction is a call or not and other logic that we need...  This code can
// be eliminated once we have a consistent interface.
bool is_last_insn_in_bb(SgAsmBlock *bb, SgAsmX86Instruction* insn) {
  SgAsmStatementPtrList & insns = bb->get_statementList();
  SgAsmX86Instruction *last_insn = isSgAsmX86Instruction(insns[insns.size() - 1]);

  if (insn == last_insn) return true;
  return false;
}

AddrSet get_hinky_successors(SgAsmBlock *bb, SgAsmX86Instruction* insn, bool last) {
  AddrSet result;
  bool complete;
  if (last)
    BOOST_FOREACH(rose_addr_t succ, bb_get_successors(bb)) {
      result.insert(succ);
    }
  else
    BOOST_FOREACH(rose_addr_t succ, insn->getSuccessors(&complete)) {
      result.insert(succ);
    }
  return result;
}

void DUAnalysis::handle_stack_delta(SgAsmBlock *bb, SgAsmX86Instruction* insn, CustomDispatcherPtr& dispatcher,
                                    SymbolicStatePtr& before_state, int initial_delta) {
  rose_addr_t iaddr = insn->get_address();

  SymbolicRiscOperatorsPtr rops = dispatcher->get_operators();
  SymbolicStatePtr after_state = rops->get_sstate();

  // We'll need to know the delta for this instruction.
  StackDelta olddelta = sp_tracker->get_delta(iaddr);
  SDEBUG << "Stack delta=" << olddelta << " insn=" << debug_instruction(insn) << LEND;

  // By default, we have wrong knowledge of the stack pointer.
  StackDelta newdelta(0, ConfidenceWrong);
  // Get the ESP register descriptor.
  const RegisterDescriptor& esprd = dispatcher->findRegister("esp", 32);
  // Are confident in our current knowledge of the stack pointer based on emulation?  With
  // value sets and the current flawed merging algorithm based on defining instructions,
  // I'm not sure that this test is really sufficient, but that fix will have to wait.

  SymbolicValuePtr before_esp = before_state->read_register(esprd);
  SymbolicValuePtr after_esp = after_state->read_register(esprd);
  //SDEBUG << "Before state ESP:" << *before_esp << LEND;
  //SDEBUG << "After state ESP:" << *after_esp << LEND;
  boost::optional<int64_t> opt_before_const = before_esp->get_stack_const();
  boost::optional<int64_t> opt_after_const = after_esp->get_stack_const();

  if (opt_after_const && *opt_after_const != CONFUSED) {
    // What was the change in the emulator state from before this instruction to after this
    // instruction?
    int adjdelta = -(*opt_after_const) + initial_delta;
    // We can only be as confident as our previous delta, and never more.  I'm still a
    // little unclear about whether it's correct to assume a "certain" confidence and allow
    // the solve flow equation iteratively code to downgrade that confidence, or whether we
    // somehow need to be working our way up from guesses to certain.
    newdelta = StackDelta(adjdelta, olddelta.confidence);

    // Something strange happened here.  When reviewing this code, BOTH conditions were found
    // to perform the same computaion, with the only difference being that this condition also
    // printed a warning.  This code is equaivalent, but I'm unsure if it's correct anymore.
    if (!opt_before_const) {
      SINFO << "Regained confidence in stack value at " << addr_str(insn->get_address())
            << " new delta=" << newdelta << LEND;
    }
  }
  // If the stack pointer was known going into this instruction, and is not now, we've
  // just lost track of it, and that's noteworthy.  Warn about it.
  else {
    if (opt_before_const) {
      SWARN << "Lost track of stack pointer: " << debug_instruction(insn) << LEND;
    }
  }

  // Start by figuring out what the fall thru address is.
  rose_addr_t fallthru = insn_get_fallthru(insn);

  // Now that we've established our delta and confidence following this instruction, that
  // becomes the stack delta for each of the succesors for this instruction (not counting the
  // external target of a call).  We don't really care if the list of sucessors is complete,
  // only that the addreses listed really are successors.

  bool last = is_last_insn_in_bb(bb, insn);
  BOOST_FOREACH(rose_addr_t target, get_hinky_successors(bb, insn, last)) {
    if (last) {
      // Here we need to interate over the basic block successors instead of the instruction
      // successors due to some inconsisntency in the way they're handled.  In particular, the
      // sucessors on the call instruction are not updated correctly when a partitioner config is
      // used.
      SDEBUG << "Successor for last instruction in basic block is: " << addr_str(target) << LEND;

      // This is the "normal" call handling, which sets the stack delta for the fall thru
      // instruction after the call.  We want to run this code when the instruction is a call,
      // the target we're considering is not the fallthru address, and the target is not in the
      // current function.  The fallthru ought to b...????
      // contains_addr().

      // This might still be a little broken for cases in which the finally handler has a
      // non-zero delta, which we haven't computed yet, and can't set correctly.
      if (insn_is_call(insn)) {
        if (target == fallthru) {
          // Ask the stack tracker what the delta for this call was.
          StackDelta calldelta = sp_tracker->get_call_delta(iaddr);
          GenericConfidence newconfidence = calldelta.confidence;
          // Downgrade confidence if required.
          if (newdelta.confidence < newconfidence) newconfidence = newdelta.confidence;

          // The additional minus 4 is to compensate for the pushed return adddress which is
          // already changed in the state, but is not included in the call delta.
          StackDelta fallthrudelta = StackDelta(newdelta.delta - calldelta.delta - 4, newconfidence);
          SDEBUG << "New fall thru delta is: " << fallthrudelta << LEND;

          // Update the state to account for the return instruction that we did not emulate.
          // Exactly the best way to accomplish this is a little unclear.  We'd like something
          // that is clear and does not produce any unintended side effects related to definers
          // and modifiers.

          // Cory's not really sure if a COPY is needed here, but it seems safer than not.
          SymbolicValuePtr oldesp = after_state->read_register(esprd)->scopy();
          SymbolicValuePtr dvalue = SymbolicValue::constant_instance(32, calldelta.delta + 4);
          SymbolicValuePtr newesp = SymbolicValue::promote(rops->add(oldesp, dvalue));
          newesp->set_modifiers(oldesp->get_modifiers()); // copying esp in handle_stack_delta()

          SDEBUG << "Adding oldesp=" << *oldesp << " to dvalue=" << *dvalue << LEND;
          SDEBUG << "Yielding newesp=" << *newesp << LEND;
          rops->writeRegister(esprd, newesp);
          // Update the stack tracker and report on our actions.
          sp_tracker->update_delta(fallthru, fallthrudelta);
          SDEBUG << "Setting stack delta following call to " << fallthrudelta
                 << " insnaddr=" << addr_str(fallthru) << LEND;
          // We're handled this case.
          continue;
        }

        // If it's a call to an external address, we don't need to do anything at all.  We'll
        // handle initialize the delta to zero when we process that function.
        if (!current_function->contains_addr(target)) continue;
      }
    }

    // In all other cases, we want to propagate our new "after" delta to all of our sucessors.

    // The most common case is that the instruction is in the middle of a basic block (e.g. not
    // the last instruction in the block).  Another fairly common case is a jump table that
    // jumps to multiple addresses within the function, and all of the successors should start
    // with our stack delta.

    // An unusual case is when a function "calls" to a basic block contained within itself.
    // Normal ROSE processing for CALL/RET pairs would have put the call in the middle of a
    // basic block if it was obvious that the return address was popped off the stack.  The
    // situation we're talking about is slightly more complex, where the function is calling to
    // itself and actually returning, but for some reason we've figured out that it is NOT a
    // real function.  The common example is finally handlers in C++ code.  The behavior is
    // still the same though, which is to propagate our stack delta.
    STRACE << "Setting stack delta=" << newdelta << " insnaddr=" << addr_str(target) << LEND;
    sp_tracker->update_delta(target, newdelta);
  }
}

SymbolicValuePtr create_return_value(SgAsmX86Instruction* insn,
                                     size_t bits, bool return_code) {

  // Decide how to label the return value.  Maybe we shouldn't do this anymore, but Cory knows
  // that we're currently checking this comment in other places in the code, and it's not
  // harmful, so he's currently leaving the functionality in place.
  std::string cmt = "";

  // We should probably be deciding whether this is a "return value" by inspecting the calling
  // convention rather than taking an explicit parameter from the caller.
  if (return_code) {
    // A standard return code (aka EAX).  This should be expanded to include ST0 and EDX in
    // some cases.
    cmt = str(boost::format("RC_of_0x%X") % insn->get_address());
  }
  else {
    // Non-standard return code (aka an overwritten scratch register).
    cmt = str(boost::format("NSRC_of_0x%X") % insn->get_address());
  }

  // What happens when rd is not a 32-bit register as expected?  At least we're getting the
  // size off the register, which would prevent us from crashing, but it's unclear whether
  // we've been thinking correctly through the scenarios that involve small register return
  // values.
  SymbolicValuePtr value = SymbolicValue::variable_instance(bits);
  value->set_comment(cmt);
  // This call instruction is now the only definer and modifier.
  value->defined_by(insn);
  // mwd: defined_by() no longer sets the modifiers
  value->add_modifier(insn);

  return value;
}

void create_overwritten_register(SymbolicRiscOperatorsPtr rops,
                                 const RegisterDescriptor* rd,
                                 bool return_code,
                                 SymbolicValuePtr value,
                                 CallDescriptor* cd) {

  // Update the value of the register in the current state...
  rops->writeRegister(*rd, value);
  // Record the write, since it didn't happen during semantics.
  rops->writes.push_back(AbstractAccess(false, *rd, value, rops->get_sstate()));

  // Set the return value in the call descriptor.  Return values are more complicated than
  // our design permits.  For now, there's just one, which is essentially EAX.
  if (return_code) {
    cd->set_return_value(value);
    // Add the return register to the "returns" parameter list as well.
    ParameterList& params = cd->get_rw_parameters();
    SDEBUG << "Creating return register parameter " << unparseX86Register(*rd, NULL)
           << " with value " << *value << LEND;
    params.create_return_reg(rd, value);
  }
}

void DUAnalysis::make_call_dependencies(SgAsmX86Instruction* insn, CustomDispatcherPtr& dispatcher,
                                        SymbolicStatePtr& cstate) {
  SymbolicRiscOperatorsPtr rops = dispatcher->get_operators();

  // This might not be correct.  I'm still a little muddled on how we're handling thunks.
  if (!insn_is_call(insn)) return;
  SDEBUG << "Creating parameter dependencies for " << debug_instruction(insn) << LEND;

  // Get the call descriptor for this call.  Should we do this externally?
  CallDescriptor* cd = global_descriptor_set->get_call(insn->get_address());
  if (cd == NULL) {
    SERROR << "No call descriptor for " << debug_instruction(insn) << LEND;
    return;
  }

  // This where we'll be storing the new value of EAX, get a handle to the state now.
  SymbolicStatePtr state = rops->get_sstate();

  // We really should be doing this based on the calling convention.
  // Have we marked the function as being this call?
  FunctionDescriptor* cfd = cd->get_function_descriptor();

  // Cory downgraded this to a debug message, because it generates a lot of spew that's not
  // meaningful, and certainly not worthy of a warning reported as an error.  I thought I had
  // rewritten this once already to do something more intelligent, but that code appears to
  // have been lost somehow. :-(
  if (!cfd || !cfd->get_func()) {
    SDEBUG << "WARNING cfd is null @" << debug_instruction(insn) << LEND;
  }

  if (cfd) {
    SDEBUG << "Adding caller " << debug_instruction(insn) << " to call targets for "
           << cfd->address_string() << LEND;
    cfd->add_caller(insn->get_address());

    // We used to follow thunks here to get the correct value from get_returns_this_pointer(),
    // but now analyze_return_code() is doing the right thing for us, so this value will be
    // correct even if we're a thunk to another function.
  }

  // =========================================================================================
  // Start of register analysis...
  // =========================================================================================

  const RegisterDescriptor& eaxrd = dispatcher->findRegister("eax", 32);
  const RegisterDescriptor& esprd = dispatcher->findRegister("esp", 32);
  const RegisterDescriptor& ecxrd = dispatcher->findRegister("ecx", 32);

  // The prefered situation is that we've already analyzed the call target and we know
  // whether it returned a value or not, and so we simply ask that function what it did.
  const FunctionDescriptor* dethunked_cfd = NULL;
  if (cfd != NULL) dethunked_cfd = cfd->follow_thunks_fd();

  if (dethunked_cfd != NULL) {
    const RegisterUsage& ru = dethunked_cfd->get_register_usage();
    SDEBUG << "Call at " <<  addr_str(insn->get_address())
           << " returns-eax:" << cfd->get_returns_eax()
           << " returns-ecx: " << cfd->get_returns_this_pointer() << LEND;

    BOOST_FOREACH(const RegisterDescriptor* rd, ru.changed_registers) {
      if (*rd != eaxrd) {
        // It turns out that we can't enable this code properly because our system is just too
        // fragile.  If we're incorrect in any low-level function, this propogates that failure
        // throughout the entire call-chain leading to that function.  Specifically, claiming
        // that a function overwrites a register when it fact it does not, leads to the loss of
        // important local state that results in incorrect analysis.  In most of the cases that
        // Cory has found so far, this is caused by functions with two possible execution
        // paths, one: returns and does not modify the register, and two: does not return and
        // does modify the register.  Thus this might be fixed with better does not return analysis.
        SymbolicValuePtr rv = create_return_value(insn, rd->get_nbits(), false);
        create_overwritten_register(rops, rd, false, rv, cd);
        SDEBUG << "Setting changed register " << unparseX86Register(*rd, NULL)
               << " for insn " << addr_str(insn->get_address())
               << " to value=" << *(rops->read_register(*rd)) << LEND;
        // And we're done with this register...
        continue;
      }

      // EAX special cases...
      if (dethunked_cfd->get_returns_this_pointer()) {
        // Assign to EAX in the current state, the value of ECX from the previous state.
        //const RegisterDescriptor& ecxrd = dispatcher->findRegister("ecx", 32);

        // Read the value of ecx from the current state at the time of the call.
        SymbolicValuePtr ecx_value = cstate->read_register(ecxrd);
        create_overwritten_register(rops, &eaxrd, true, ecx_value, cd);
        SDEBUG << "Setting return value for " << addr_str(insn->get_address())
               << " to ECX prior to call, value=" << *(rops->read_register(eaxrd)) << LEND;
      }
      else if (dethunked_cfd->get_returns_eax()) {
        SymbolicValuePtr eax = create_return_value(insn, get_arch_bits(), true);
        create_overwritten_register(rops, &eaxrd, true, eax, cd);
        SDEBUG << "Setting standard return value for " << addr_str(insn->get_address())
               << " to " << *(rops->read_register(eaxrd)) << LEND;
      }
    }
  }
  // Otherwise...
  else {
    //GINFO << "Call at " <<  addr_str(insn->get_address()) << " dethunk=NULL"
    //      << " returns-eax:" << cfd->get_returns_eax()
    //      << " returns-ecx: " << cfd->get_returns_this_pointer() << LEND;

    // If we're not a call to an internal function, we're probably a call to an external
    // API. The logic is messy here.  Perhaps this case should be immediately after
    // determining that cfd was NULL?
    ImportDescriptor* id = cd->get_import_descriptor();
    if (id == NULL && cfd != NULL) {
      rose_addr_t iaddr = cfd->follow_thunks();
      id = global_descriptor_set->get_import(iaddr);
    }

    if (id != NULL) {
      // If we really are a call to an external import, just assume that we return a value.
      // Cory does't think that there are any external APIs that don't follow the standard
      // calling conventions, and none of them permit true returns void calls.  In the
      // future, this code branch can become more sophisticated, asking the import
      // configuration what the type of return value is and so on.
      SDEBUG << "Creating return code for import " << id->get_long_name()
             << " at " << debug_instruction(insn) << LEND;
      SymbolicValuePtr eax = create_return_value(insn, get_arch_bits(), true);
      create_overwritten_register(rops, &eaxrd, true, eax, cd);
      SDEBUG << "Setting standard return value for " << addr_str(insn->get_address())
             << " to " << *(rops->read_register(eaxrd)) << LEND;

      // The parameter list that we want in a moment should be in the import descriptor's
      // built-in function descriptor.  That's where we're supposed to have loaded the
      // details from the JSON file about the import parameter names, types, etc.
      dethunked_cfd = id->get_function_descriptor();
      // The parameter definitions for the function that we're calling.
      const ParameterList& fparams = dethunked_cfd->get_parameters();
      if (GDEBUG) {
        GDEBUG << "Parameters for import at " << id->address_string() << " named "
               << id->get_long_name() << " for call at: " << debug_instruction(insn) << " are: ";
        fparams.debug();
      }
    }
    else {
      // Long ago, Wes wrote code that executed here that went to the basic block where the
      // call originated and looked for instructions that read the eax register.  If the value
      // had no definers, it was deemed that this function created a return value regardless of
      // the logic above.  At revision 1549 this code was no longer required to pass tests, and
      // Cory removed it.
      GDEBUG << "Call at: " << debug_instruction(insn) << "appears to not return a value." << LEND;
    }
  }

  // =========================================================================================
  // Stack dependency analysis.  Move to separate function?
  // =========================================================================================

  // What was our stack delta going into the call instruction?
  StackDelta sd = sp_tracker->get_delta(insn->get_address());

  // How many parameters does the call have?
  StackDelta params = cd->get_stack_parameters();
  SDEBUG << "The call: " << debug_instruction(insn) << " appears to have "
         << params.delta << " bytes of parameters." << LEND;

  // If our confidence in the stack delta is too bad, don't make it worse by creating crazy
  // depdencies that are incorrect.
  if (sd.confidence < ConfidenceGuess && params.delta != 0) {
    // This is a pretty common error once our stack deltas are wrong, and so in order to reduce
    // spew, Cory moved this error to DEBUG, and incremented the failures counter.
    SWARN << "Skipping creation of " << params.delta << " bytes of parameter dependencies"
          << " due to low confidence of stack delta." << LEND;
    SWARN << "Stack delta was: " << sd << " at instruction: " << debug_instruction(insn) << LEND;
    // This wrongness was a consequence of earlier wrongness, but there's more wrong now.
    sp_tracker->add_failure();
    return;
  }

  // Also don't make the situation worse by creating a crazy number of dependencies if the
  // number of call parameters is unrealistically large.
  if (params.delta > ARBITRARY_PARAM_LIMIT) {
    SERROR << "Skipping creation of " << params.delta << " bytes of parameter dependencies"
           << " due to high parameter count for call: " << debug_instruction(insn) << LEND;
    // We know we didn't do the right thing, so let's tick failures.
    sp_tracker->add_failure();
    return;
  }

  // Dump the memory state
  //SDEBUG << "Memory state:" << state << LEND;

  SDEBUG << "Call: " << debug_instruction(insn) << " params=" << params.delta << LEND;

  // There's nothing more we can do in the current system if we couldn't figure out where we
  // were calling to...
  if (dethunked_cfd == NULL) {
    SWARN << "Unknown call target at: " << debug_instruction(insn)
          << ", parameter analysis failed." << LEND;
    return;
  }

  // The parameter definitions for the function that we're calling.
  const ParameterList& fparams = dethunked_cfd->get_parameters();

  // Report the parameters that we expect to find...
  if (GDEBUG) {
    GDEBUG << "Parameters for call at: " << debug_instruction(insn) << " are: " << LEND;
    fparams.debug();
  }

  // We'll be creating new parameter defintions on the call, so let's get a handle to the
  // parameter list object right now.
  ParameterList& call_params = cd->get_rw_parameters();

  // Go through each parameter to the call, and create an appropriate dependency.
  BOOST_FOREACH(const ParameterDefinition& pd, fparams.get_params()) {
    // Cory says, this code used to assume that only stack parameters were in the parameter
    // list. Now that we're also creating parameter definitions for register values, this code
    // needs to be a little more complicated.  The very first iteration is to simply ignore
    // register parameters.
    if (pd.reg != NULL) {
      // =====================================================================================
      // Register parameter definitions and instruction dependencies (move to a new function?)
      // =====================================================================================

      SDEBUG << "Found register parameter: " << unparseX86Register(*(pd.reg), NULL)
             << " for call " << cd->address_string() << LEND;

      // Create a dependency between the instructions that last modifier the value of the
      // register, and the call instruction that uses the value (or the memory at the value?)

      // Read the value out of the current states
      SymbolicValuePtr rv = state->read_register(*(pd.reg));
      // The call reads the register value.
      AbstractAccess aa = AbstractAccess(true, *(pd.reg), rv, state);
      SgAsmX86Instruction *modifier = NULL;

      // For the stack adresses below, Cory (mistakenly?) thought that only one modifier was
      // expected.  For register modifiers, it seems more obvious that we should create
      // dependencies between all modifers and the call.  So let's do that here.
      BOOST_FOREACH(SgAsmInstruction* gm, rv->get_modifiers()) { // adding dep pairs to call
        SDEBUG << "Adding call dependency for " << debug_instruction(insn) << " to "
               << debug_instruction(gm) << LEND;
        // Convert from a generic instruction to an X86 instruction (and save last one).
        modifier = isSgAsmX86Instruction(gm);
        // Now create the actual dependency.
        add_dependency_pair(insn, modifier, aa);
      }

      // Also we need to find (or create) a parameter for this register on the calling side.
      // This routine will create the register definition if it doesn't exist and return the
      // existing parameter if it does.  In a departure from the API I used on the stack side,
      // I just had the create_reg_parameter() interface update the symbolic value and modified
      // instruction as well.  Maybe we should change the stack parameter interface to match?
      SymbolicValuePtr pointed_to = state->read_memory(rv, get_arch_bits());
      call_params.create_reg_parameter(pd.reg, rv, modifier, pointed_to);

      // We're done handling the register parameter.  The rest of the code after here is for
      // stack parameters.
      continue;
    }

    // From the old code for doing this...
    size_t p = pd.stack_delta;

    // The parameter will be found on the stack at [offset].  The sd.delta component is to
    // convert to stack deltas relative to the call.  And p is the variable part (the parameter
    // offset in the called function).  The outer sign is because we've been working with
    // positive deltas, and the hardware really does negative stack addresses.
    int64_t offset = -(sd.delta - p);

    SDEBUG << "Creating parameter read of stack offset: [" << offset << "]" << LEND;

    // Turn the offset into a SymbolicValue and find the memory cell for that address.
    // const RegisterDescriptor& esprd = dispatcher->findRegister("esp", 32);
    SymbolicValuePtr esp_0 = cstate->read_register(esprd);
    //SDEBUG << "Initial ESP is supposedly:" << *esp_0 << LEND;
    SymbolicValuePtr mem_addr = SymbolicValue::promote(rops->add(esp_0, rops->number_(32, p)));
    //SymbolicValuePtr mem_addr = SymbolicValuePtr(new SymbolicValue(32, offset));
    //SDEBUG << "Constructed memory address:" << *mem_addr << LEND;

    const MemoryCellPtr memcell = state->get_memory_state()->findCell(mem_addr);
    if (memcell == NULL) {
      SWARN << "No definer for parameter at [" << offset
            << "] for call: " << debug_instruction(insn) << LEND;
      continue;
    }

    // Who last modified this address?  This will typically be the push instruction that pushed
    // the parameter onto the stack before the call.  This code is a little bit incorrect in
    // that we're assuming that all four bytes have still been modified by the same instruction
    // as the first byte was.
    SymbolicValuePtr mca = SymbolicValue::promote(memcell->get_address());

    // Use rops->readMemory to read four bytes.  This is wrong because the size isn't always
    // four bytes.  The segment register and the condition are literally unused, and the
    // default value shouldn't be used (but might be).  We used to read directly out of the
    // memory map, but we need proper reassembly of multiple bytes so now we call readMemory.
    const RegisterDescriptor& csrd = dispatcher->findRegister("cs", 16);
    SymbolicValuePtr dflt = SymbolicValue::promote(rops->undefined_(32));
    SymbolicValuePtr cond = SymbolicValue::promote(rops->undefined_(1));
    BaseSValuePtr bmcv = rops->readMemory(csrd, mca, dflt, cond);
    SymbolicValuePtr mcv = SymbolicValue::promote(bmcv);

    InsnSet modifiers = mca->get_modifiers(); // memory parameter dependency creation

    SDEBUG << "Parameter memory address:" << *mca << LEND;
    SDEBUG << "Parameter memory value:" << *mcv << LEND;

    // We only expect one modifier.  If there's more, I'd like to investigate.
    if (modifiers.size() != 1) {
      // Not having any modifiers is fairly common in at least one binary file we looked at.
      // It's probably caused by stack delta analysis failures, so let's make that a warning.
      if (modifiers.size() == 0) {
        SWARN << "No modifiers for call parameter " << offset << " addr= " << *mca
              << "value=" << *mcv << " at: " << debug_instruction(insn) << LEND;
      }
      else {
        SERROR << "Unexpected number of modifiers (" << modifiers.size()
               << ") for call parameter at: " << debug_instruction(insn) << LEND;
        SERROR << "On parameter " << offset << " addr=" << *mca << " value=" << *mcv << LEND;
        BOOST_FOREACH(SgAsmInstruction* mod, modifiers) {
          SERROR << "  Modifier: " << debug_instruction(mod) << LEND;
        }
      }
      continue;
    }

    // Recast the first (only) entry in the modifiers list as an X86 instruction.
    SgAsmX86Instruction *modifier = isSgAsmX86Instruction(*modifiers.begin());

    // The call instruction reads this address, and gets the current value.  We're assuming
    // that we read four bytes of memory, which is incorrect, and we should probably get around
    // to fixing this, but we'll need proper protoypes to know the type and size of the
    // parameter on the stack, which we presently don't have.
    AbstractAccess aa = AbstractAccess(true, mca, 4, mcv, state);

    SDEBUG << "Adding call dependency for " << debug_instruction(insn) << " to "
           << debug_instruction(modifier) << LEND;

    // Now create the actual dependency.
    add_dependency_pair(insn, modifier, aa);

    ParameterDefinition* cpd = call_params.create_stack_parameter(p);
    if (cpd == NULL) {
      GFATAL << "Unable to create stack parameter for delta " << (p)
             << " for call: " << debug_instruction(insn) << LEND;
    }
    else {
      SymbolicValuePtr pointed_to = state->read_memory(mcv, get_arch_bits());
      cpd->set_stack_attributes(mcv, mca, modifier, pointed_to);
      //OINFO << " CPD:";
      //cpd->debug();
      //OINFO << " CPD:";
      //fpd->debug();
    }

    SDEBUG << "Last modifier for [" << offset << "] instruction was: "
           << debug_instruction(modifier) << LEND;
  }
}

LimitCode DUAnalysis::evaluate_bblock(SgAsmBlock *bblock, CustomDispatcherPtr& dispatcher,
                                      int initial_delta) {
  // This limit is not well tested.  But I know that we've encountered huge basic blocks of
  // thousands of instructions that made this function not perform well.
  ResourceLimit block_limit;
  get_global_limits().set_limits(block_limit, PharosLimits::limit_type::BASE);

  LimitCode rstatus = block_limit.check();

  SymbolicRiscOperatorsPtr rops = dispatcher->get_operators();
  const RegisterDescriptor& eiprd = dispatcher->findRegister("eip", 32);
  const RegisterDescriptor& esprd = dispatcher->findRegister("esp", 32);

  const SgAsmStatementPtrList &insns = bblock->get_statementList();

  for (size_t i=0; i<insns.size(); ++i) {
    SgAsmX86Instruction *insn = isSgAsmX86Instruction(insns[i]);
    if (insn == NULL) continue;
    block_limit.increment_counter();
    rose_addr_t iaddr = insn->get_address();
    STRACE << "eval bblock insn addr " << iaddr << " => " << debug_instruction(insn, 5, NULL) << LEND;
    // Get the state just before evaluating the instruction
    SymbolicStatePtr cstate = rops->get_sstate()->sclone();
    if (insn_is_call(insn)) {
      SDEBUG << "Stack value before call is " <<  *rops->read_register(esprd) << LEND;
      CallDescriptor* cd = global_descriptor_set->get_call(insn->get_address());
      assert(cd != NULL);
      cd->set_state(cstate);
    }

    // The scope of this try should probably be narrowed.  In particular, just because we gave
    // up on emulating the instruction doesn't mean that we should do _nothing_ with respect to
    // the stack.
    try {
      // Evaluate the instruction
      SymbolicValuePtr iaddrptr = SymbolicValue::constant_instance(32, iaddr);
      // Another forced EIP hack.  Possibly not needed in ROSE2 port?
      rops->writeRegister(eiprd, iaddrptr);
      SDEBUG << "Insn: " << debug_instruction(insn) << LEND;
      dispatcher->processInstruction(insn);
      address_map[iaddr] = insn;
      SymbolicStatePtr pstate = rops->get_sstate();

      //if (iaddr == 0x00402f7e) SDEBUG << "Mystery state" << LEND << pstate << LEND;

      // Test for a jump to a packed section
      // Cory notes that Wes made copies of this code back in doPostCall as well...
      if (((insn->get_kind() >= x86_ja && insn->get_kind() <= x86_js) ||
           insn->get_kind() == x86_call) && i < insns.size()-1) {
        SgAsmStatementPtrList ri;
        for (size_t qq = i+1; qq < insns.size(); qq++) ri.push_back(insns[qq]);
        BadCodeMetrics bc;
        size_t repeated = 0, deadstores = 0, badjmps = 0, unusualInsns = 0;

        SDEBUG << "Testing possible jmp to packed section " << debug_instruction(insn) << LEND;

        if (branchesToPackedSections.find(insn) != branchesToPackedSections.end() ||
            bc.isBadCode(ri,&repeated,&unusualInsns,&deadstores,&badjmps)) {

          branchesToPackedSections.insert(insn);
          SWARN << "Skipping " << debug_instruction(insn)
                << " - Dead Stores: " <<  deadstores << " Repeated Insns: " << repeated
                << " Bad Cond Jumps: " << badjmps << " Unusual Insns: " << unusualInsns << LEND;

          handle_stack_delta(bblock, insn, dispatcher, cstate, initial_delta);
          // Forcibly downgrade the confidence to guess since we didn't emulate correctly.  This
          // should probably be handled as a minimum confidence parameter to handle stack delta or
          // something like that.
          StackDelta osd = sp_tracker->get_delta(iaddr);
          if (osd.confidence > ConfidenceGuess) {
            osd.confidence = ConfidenceGuess;
            sp_tracker->update_delta(iaddr, osd);
          }
          break;
        }
      }

      if (insn_is_call(insn)) update_call_targets(insn, rops);
      handle_stack_delta(bblock, insn, dispatcher, cstate, initial_delta);
      make_call_dependencies(insn, dispatcher, cstate);

      SDEBUG << "reads size=" << rops->reads.size() << " writes size=" << rops->writes.size() << LEND;
      // Get the list of registers read
      AbstractAccessVector all_regs;
      for (size_t x = 0; x < rops->reads.size(); x++) {
        AbstractAccess aa = rops->reads[x];
        if (!aa.is_reg()) continue;
        SDEBUG << debug_instruction(insn) << " reads "
               << aa.reg_name() << " = " << *(aa.value) << LEND;
        all_regs.push_back(aa);

        if (reads.find(insn) == reads.end())
          reads[insn] = AbstractAccessVector();
        reads[insn].push_back(aa);
      }

      // Register writes.
      for (size_t x = 0; x < rops->writes.size(); x++) {
        AbstractAccess aa = rops->writes[x];
        if (!aa.is_reg()) continue;
        SDEBUG << debug_instruction(insn) << " writes "
               << aa.reg_name() << " = " << *(aa.value) << LEND;
        if (writes.find(insn) == writes.end())
          writes[insn] = AbstractAccessVector();
        writes[insn].push_back(aa);
      }

      if (depends_on.find(insn) == depends_on.end()) depends_on[insn] = DUChain();

      // Build the def-use chains
      BOOST_FOREACH(AbstractAccess &aa, all_regs) {
        const RegisterDescriptor& rd = aa.register_descriptor;
        std::string regname = unparseX86Register(rd, NULL);

        if (regname == "eip") continue;
        // std::cout << "Reads register " << regname << " defined by ";
        SymbolicValuePtr sv = cstate->read_register(rd);
        InsnSet modifiers = sv->get_modifiers(); // abstract access creation

        if (modifiers.begin() == modifiers.end()) {
          SDEBUG << "Warning: Use of uninitialized register "
                 << regname << " by " << debug_instruction(insn) << LEND;
          Definition reg_def(NULL, aa);
          depends_on[insn].insert(reg_def);
          // Should probably be add_dependency_pair(insn, NULL, aa);

        }

        for (InsnSet::iterator it = modifiers.begin(); it != modifiers.end(); it++) {
          // Create a use-chain entry
          SgAsmX86Instruction *definer = isSgAsmX86Instruction(*it);
          add_dependency_pair(insn, definer, aa);
        }
      }

      // Get the list of addresses written
      for (size_t y = 0; y < rops->writes.size(); y++) {
        AbstractAccess aa = rops->writes[y];
        if (!aa.is_mem()) continue;

        // We're looking for global fixed memory writes here...
        if (aa.memory_address->is_number()) {
          rose_addr_t known_addr = aa.memory_address->get_number();
          // We're only interested in constants that are likely to be memory addresses.
          if (possible_global_address(known_addr)) {
            ImportDescriptor *id = global_descriptor_set->get_import(known_addr);
            if (id == NULL) {
              GlobalMemoryDescriptor* gmd = global_descriptor_set->get_global(known_addr);
              if (gmd == NULL) {
                // This message is really debugging for a case that Cory is interested in, not
                // something that's useful to general users, so he moved it back to SDEBUG. :-(
                SDEBUG << "Unexpected global memory write to address " << addr_str(known_addr)
                       << " at " << debug_instruction(insn) << LEND;
              }
              else {
                gmd->add_write(insn, aa.size);
                SDEBUG << "Added global memory write: " << gmd->address_string() << LEND;
              }
            }
            // This is where we used to test for overwrites of imports, that's now more clearly
            // (but perhaps less cleanly) in RiscOps::readMemory().
          }
        }

#if 0
        // Long ago, Cory believed that there should not be any cases where there was a write
        // to an address that wasn't in the memory map (or at least if there were, he wanted to
        // know more about them).  As a more careful review of situations involving loops and
        // incomplete values ocurred, it became obvious that this was no longer a meaningful
        // test because sometimes the addresses were incomplete, and so it's not surprising
        // that there are writes to addreses not actually in the map.  The existing code didn't
        // do anything other than generate an ERROR, and (probably incorrectly) prevented the
        // write from being logged in the writes map.  This is unlikely to be the correct place
        // to handle this error.  To transition to the complete removal of this code, I've
        // disabled it and revised this comment.
        const SymbolicMemoryCellPtr memcell = pstate->get_memory_state()->get_cell(aa.memory_address);
        if (memcell == NULL) {
          SINFO << "Memory write to " << *(aa.memory_address->get_expression())
                << " not found in cell list for insn " << debug_instruction(insn) << LEND;
        }
#endif

        SDEBUG << "--> Memory write at: " << debug_instruction(insn)
               << " addr=" << *(aa.memory_address) << " value=" << *(aa.value) << LEND;

        // Update the mem writes history
        if (writes.find(insn) == writes.end())
          writes[insn] = AbstractAccessVector();

        // Does this push back cause writes to grows as we solve_flow_equation_iteratively()?
        writes[insn].push_back(aa);
      }

      // Get the list of addresses read
      for (size_t y = 0; y < rops->reads.size(); y++) {
        AbstractAccess aa = rops->reads[y];
        if (!aa.is_mem()) continue;

        // Find the corresponding data value for this address
        InsnSet modifiers;
        SDEBUG << "--> Memory read at " << *(aa.memory_address) << LEND;

        // We're looking for global fixed memory reads here...
        if (aa.memory_address->is_number() && !insn_is_control_flow(insn)) {
          rose_addr_t known_addr = aa.memory_address->get_number();
          // We're only interested in constants that are likely to be memory addresses.
          if (possible_global_address(known_addr)) {
            ImportDescriptor *id = global_descriptor_set->get_import(known_addr);
            if (id == NULL) {
              GlobalMemoryDescriptor* gmd = global_descriptor_set->get_global(known_addr);
              if (gmd == NULL) {
                SDEBUG << "Unexpected global memory read from address " << addr_str(known_addr)
                       << " at " << debug_instruction(insn) << LEND;
              }
              else {
                gmd->add_read(insn, aa.size);
                SDEBUG << "Added global memory read: " << gmd->address_string() << LEND;
              }
            }
            else {
              // It's not really all that curious after all...  It mostly turns out to be that
              // situation where an import is moved into a register, and then the call is made
              // to the value in the register several times.
              SDEBUG << "Curious read of import address 0x" << addr_str(known_addr)
                     << " at instruction " << debug_instruction(insn) << LEND;
            }
          }
        }

        // Ensure that we have an entry in the map.
        if (reads.find(insn) == reads.end()) reads[insn] = AbstractAccessVector();

        reads[insn].push_back(aa);

#if 0
        // See the more detailed comment above where a similar message is generated for writes
        // not found in the cell list.  In summary, this test is no longer really useful.
        const SymbolicMemoryCellPtr memcell = pstate->get_memory_state()->get_cell(aa.memory_address);
        if (memcell == NULL) {
          SINFO << "Memory read of " << *(aa.memory_address->get_expression())
                << " not found in cell list for insn " << debug_instruction(insn) << LEND;
        }
#endif

        modifiers = aa.value->get_modifiers(); // abstract access creation
        // If there are no modifiers for this address, add a NULL definer.
        if (modifiers.size() == 0) {
          add_dependency_pair(insn, NULL, aa);
          SDEBUG << "--> Memory read at " << *(aa.memory_address)
                 << " of " <<  *(aa.value) << " from NULL definer." << LEND;
        }
        else {
          BOOST_FOREACH(SgAsmInstruction *minsn, modifiers) {
            SgAsmX86Instruction *definer = isSgAsmX86Instruction(minsn);
            add_dependency_pair(insn, definer, aa);
            SDEBUG << "--> Memory read at " << *(aa.memory_address)
                   << " of " << *(aa.value) << " definer is "
                   << debug_instruction(definer) << LEND;
          }
        }
      }

      rstatus = block_limit.check();
      if (rstatus != LimitSuccess) {
        SERROR << "Basic block " << addr_str(bblock->get_address())
               << " " << block_limit.get_message() << LEND;
        // Break out of the loop of basic blocks.
        break;
      }
    }
    catch (const SemanticsException &e) {
      // This is a hackish kludge to make the exception readable.  There are different kinds of
      // exception generated, but they're so long that they're pretty much unreadable.  They've
      // also go two copies of the offending instruction in an unpleasant format.  It's a mess,
      // and Cory should talk with Robb Matzke about it...
#if 1
      // First transform the exception into a string.
      std::stringstream ss;
      ss << e;
      std::string newerror = ss.str();
      // Then chop off: "rose::BinaryAnalysis::InstructionSemantics::BaseSemantics::Exception: "
      if (newerror.size() > 70) {
        newerror = newerror.substr(70);
      }
      // Then remove eveything after the first occurence of "0x"
      size_t pos = newerror.find(" 0x", 0);
      if (pos != std::string::npos) {
        newerror = newerror.substr(0, pos);
      }

      // Then emit a more reasonable error.  This message should really be at log level
      // "error", but in an effort to reduce the amount of spew for general users, Cory
      // downgraded it to log level "warning" until we're able to reduce the frequency of the
      // message.
      SWARN << "Semantics exception: " << newerror << " " << debug_instruction(insn) << LEND;
#else
      // This produces unreasonably ugly messages.
      SWARN << e << LEND;
#endif

      // This is sort of out of place here.
      handle_stack_delta(bblock, insn, dispatcher, cstate, initial_delta);
      // Forcibly downgrade the confidence to guess since we didn't emulate correctly.  This
      // should probably be handled as a minimum confidence parameter to handle stack delta or
      // something like that.
      StackDelta osd = sp_tracker->get_delta(iaddr);
      if (osd.confidence > ConfidenceGuess) {
        osd.confidence = ConfidenceGuess;
        sp_tracker->update_delta(iaddr, osd);
      }
    }
  }

  SDEBUG << "Evaluation of basic block at " << addr_str(bblock->get_address())
         << " complete." << LEND;
  if (global_timing) {
    SDEBUG << block_limit.get_relative_clock() << " seconds elapsed." << LEND;
  }
  return rstatus;
}

// Wow, this definately should have been done a long time ago, but I don't know exactly where
// yet, so we'll just do it here.  Basically, this code makes "jmp [import]" have a non-NULL
// successor list.  I have no idea what to do with this broken code now that I see that there's
// no add successsor.  I guess I'll have to create a ThunkDescriptor or something.
void update_jump_targets(SgAsmInstruction* insn) {
  rose_addr_t target = insn_get_jump_deref(insn);
  if (target != 0) {
    ImportDescriptor* id = global_descriptor_set->get_import(target);
    if (id != NULL) {
      // There's NO add_successor()!!!
    }
  }
}

void DUAnalysis::update_function_delta(FunctionDescriptor* fd) {
  // Our unified stack delta across all return instructions.
  StackDelta unified = StackDelta(0, ConfidenceNone);
  bool first = true;
  // This is the number on the RETN instruction and is also our expected stack delta.
  int64_t retn_size = 0;

  BOOST_FOREACH(SgAsmBlock *block, fd->get_return_blocks()) {
    // Find the return instruction.
    const SgAsmStatementPtrList &insns = block->get_statementList();
    assert(insns.size() > 0);
    SgAsmX86Instruction *last = isSgAsmX86Instruction(insns[insns.size() - 1]);
    SDEBUG << "Last instruction in ret-block:" << debug_instruction(last) << LEND;
    StackDelta ld = sp_tracker->get_delta(last->get_address());
    SDEBUG << "Stack delta going into last instruction: " << ld << LEND;
    // Not all blocks returned by get_return_blocks() end with return instructions.  It also
    // includes blocks that jump (jmp or jcc) outside the current function.  We'll start by
    // handling the more common case, blocks that end with a return.
    if (last->get_kind() == x86_ret) {
      // Get the number of bytes popped off the stack by the return instruction (not counting the
      // return address).
      SgAsmExpressionPtrList &ops = last->get_operandList()->get_operands();
      if (ops.size() > 0) {
        SgAsmIntegerValueExpression *val = isSgAsmIntegerValueExpression(ops[0]);
        if (val != NULL) retn_size = val->get_absoluteValue();
      }
      SDEBUG << "RET instruction pops " << retn_size << " additional bytes off the stack." << LEND;
      // Add the return size to the delta going into the return instruction.
      ld.delta += retn_size;
    }
    // This case is still confusing to me.  Why would calls be return blocks in ANY case?
    else if (insn_is_call(last)) {
      // This workaround simply causes the merge code to do nothing.
      SWARN << "Block is a 'return' block, ending with a CALL instruction:"
            << debug_instruction(last) << LEND;
      ld.delta = unified.delta;
      ld.confidence = unified.confidence;
    }
    // This is the less obvious case.  Blocks that end with an external jump.  The right answer
    // here is to take the block delta at the jump instruction and add the delta that would have
    // occured if you had called to the target.
    else if (last->get_kind() == x86_jmp) {
      SDEBUG << "JMP instruction:" << debug_instruction(last) << LEND;


      // If we are a thunk, let our target function update our delta for us
      if (fd->is_thunk()) {
        SDEBUG << "Processing a thunk deferring stack update to thunk target" << LEND;
        return;
      }

      // Start by checking to see if this is a jump to a dereference of an address in the
      // import table.
      rose_addr_t target = insn_get_jump_deref(last);
      StackDelta td;
      if (target != 0) {
        ImportDescriptor* id = global_descriptor_set->get_import(target);
        if (id != NULL) {
          td = id->get_stack_delta();
          SDEBUG << "Branch target is to " << *id << LEND;
        }
      }
      // If that failed, maybe we're just a branch directly to some other function.
      else {
        target = insn_get_branch_target(last);
        td = sp_tracker->get_delta(target);
      }

      SDEBUG << "Branch target is: 0x" << std::hex << target << std::dec
             << " which has stack delta: " << td << LEND;
      // We can only be as confident as the delta we're branching to.
      if (td.confidence < ld.confidence)
        ld.confidence = td.confidence;
      ld.delta += td.delta;

      // And there's one more fix-up that's needed.  A common case is thunks that jump to a
      // callee cleanup function.  In this case, we've set retn_size to zero for the jump,
      // and yet our stack delta will be non-zero.  This generates a warning later that is
      // incorrect.  Although it may not be the perfect solution, we can prevent that by
      // setting retn_size here.  We may need to check explicitly for thunks for this to
      // be more correct, or it may be fine like it is.
      if (retn_size == 0) retn_size = ld.delta;
    }
    else {
      // This message used to be at log level "error", but most of them are really just
      // warnings about "int3" instructions.  We should probably fix that at the disassembly
      // level and then move this message back to "error" level.
      SWARN << "Unexpected instruction at end of basic block: " << debug_instruction(last) << LEND;
      ld.delta = 0;
      ld.confidence = ConfidenceNone;
    }

    // Merge the updated last instruction delta with the unified delta.
    if (first) {
      unified.delta = ld.delta;
      unified.confidence = ld.confidence;
      first = false;
    }
    else {
      if (ld.delta != unified.delta) {
        // Here's another case that should really be log level "error", but it's too common to
        // subject general users to at the present time.
        SWARN << "Function " << fd->address_string()
              << " has inconsistent return stack deltas: delta1="
              << unified << " delta2=" << ld << LEND;
        unified.delta = 0;
        unified.confidence = ConfidenceNone;
        break;
      }
      else {
        if (ld.confidence < unified.confidence)
          unified.confidence = ld.confidence;
      }
    }
  }

  SDEBUG << "Final unified stack delta for function " << fd->address_string()
         << " is: " << unified << LEND;
  if (unified.delta != retn_size) {
    SWARN << "Unified stack delta for function " << fd->address_string()
          << " does not match RETN size of: " << retn_size
          << " unified stack delta was: " << unified << LEND;
    // We used to charge ahead, knowing that we were wrong...  It seems wiser to use the RETN
    // size, at least until we have a better guessing algorithm, and a more reliable stack
    // delta system in general.
    unified.delta = retn_size;
    unified.confidence = ConfidenceGuess;
  }
  if (unified.confidence > ConfidenceNone) {
    fd->update_stack_delta(unified);
  }
  SDEBUG << "Final unified stack delta (reread) for function " << fd->address_string()
         << " is: " << fd->get_stack_delta() << LEND;
}

// DUPLICATIVE OF FunctionDescriptor::check_saved_register. :-( WRONG! WRONG! WRONG!
// Is this a sterotypical case of a saved register?  E.g. does this instruction only read the
// value of a register so that we can subsequently restore it for the caller?
bool DUAnalysis::saved_register(SgAsmX86Instruction* insn, const Definition& def) {
  // We're typically looking for the situation in which insn is a push instruction, and the
  // only other dependent is a pop instruction.  The passed definition will be the register
  // that's being "saved", and the defining instructon should be NULL.

  // We might have already tested this, but testing it again will make this function useful in
  // more contexts.
  if (def.definer != NULL) return false;

  // This isn't really required, since we could be saving the register with a pair of moves,
  // but it'll be easier to debug I think if I start with push/pop pairs.
  if (insn->get_kind() != x86_push) return false;

  SDEBUG << "Checking for saved register for:" << debug_instruction(insn) << LEND;

  // We need a register descriptor for ESP, because it's special.
  const RegisterDictionary* regdict = RegisterDictionary::dictionary_pentium4();
  const RegisterDescriptor* resp = regdict->lookup("esp");

  AbstractAccess* saveloc = NULL;

  AccessMap::iterator finder = writes.find(insn);
  if (finder != writes.end()) {
    BOOST_FOREACH(AbstractAccess& aa, finder->second) {
      // Of course the push updated ESP.  We're not intersted in that.
      if (aa.is_reg(*resp)) continue;
      if (saveloc == NULL && aa.is_mem()) {
        saveloc = &aa;
        continue;
      }
      SDEBUG << "Unexpected write to: " << aa.str() << " while checking for saved register"
             << debug_instruction(insn) << LEND;
    }
  }

  // If we couldn't find a memory address that we wrote to, we've not a register save.
  if (saveloc == NULL) return false;
  SDEBUG << " --- Looking for write to" << saveloc->str() << LEND;

  const DUChain* deps = get_dependents(insn);
  if (deps == NULL) {
    SDEBUG << "No dependents_of entry for instruction: " << debug_instruction(insn) << LEND;
    return false;
  }

  BOOST_FOREACH(const Definition& dx, *deps) {
    if (dx.access.same_location(*saveloc)) {
      // The definer field is the instruction that used the saved location on the stack.
      // Typically this is a pop instruction in the epilog.
      SDEBUG << " --- Found instruction using saveloc" << dx.access.str() << " | "
             << debug_instruction(dx.definer) << LEND;
    }
  }

  return false;
}

void fixupCFGEdges(CFG &cfg) {
  std::map<rose_addr_t, CFGVertex> addr2vmap;

  // Build a mapping between basic block addresses to CFG vertexes
  boost::graph_traits<ControlFlowGraph>::vertex_iterator vi, vi_end;
  for (boost::tie(vi, vi_end)=vertices(cfg); vi!=vi_end; ++vi) {
    SgAsmBlock *source = boost::get(boost::vertex_name, cfg, *vi);

    if (source) {
      STRACE << "Found basic block vertex " << addr_str(source->get_address()) << LEND;
      addr2vmap[source->get_address()] = *vi;
    }
  }

  for (boost::tie(vi, vi_end)=vertices(cfg); vi!=vi_end; ++vi) {
    SgAsmBlock *source = boost::get(boost::vertex_name, cfg, *vi);

    // Get the out edges of the CFG
    std::set<rose_addr_t> existing_edges;
    boost::graph_traits<ControlFlowGraph>::out_edge_iterator oei, oei_end;
    for (boost::tie(oei, oei_end)=out_edges(*vi, cfg); oei != oei_end; ++oei) {
      CFGVertex successor = target(*oei, cfg);
      SgAsmBlock *sblock = get(boost::vertex_name, cfg, successor);
      if (!sblock) continue;
      rose_addr_t saddr = sblock->get_address();
      existing_edges.insert(saddr);
    }

    // Ensure that each successor has a corresponding edge if it is in the CFG
    const SgAsmIntegerValuePtrList &succs = source->get_successors();
    for (SgAsmIntegerValuePtrList::const_iterator si=succs.begin(); si!=succs.end(); ++si) {
      if (addr2vmap.find((*si)->get_absoluteValue()) != addr2vmap.end() &&
          existing_edges.find((*si)->get_absoluteValue()) == existing_edges.end()) {
        add_edge(*vi,addr2vmap[(*si)->get_absoluteValue()],cfg);
        STRACE << "Inserting edge from " << addr_str(source->get_address())
               << " to " << (*si)->get_absoluteValue() << LEND;
      }
    }
  }
}

// why is fd passed in if there is the internal current_function, which I assume the internal
// function_summary is also referring to?
void DUAnalysis::analyze_return_code(FunctionDescriptor* fd, CustomDispatcherPtr dispatcher) {
  // If we're a thunk, then we should use whatever values our target has.
  if (fd->is_thunk()) {
    fd->propagate_thunk_info();
    return;
  }

  // It is possible for input_state and output_state to be NULL if the function encountered
  // analysis failures that prevented the computation of a reasonably correct state.  In those
  // cases, we're unable to analyze the return code, and should just return.
  if (output_state == NULL) {
    SDEBUG << "Function " << fd->address_string() << " has no output state.  "
           << "Unable to analyze return code." << LEND;
    return;
  }
  if (input_state == NULL) {
    SDEBUG << "Function " << fd->address_string() << " has no input state.  "
           << "Unable to analyze return code." << LEND;
    return;
  }

  // Otherwise we should analyze our own behavior to decide what we return.

  // Check to see whether we're returning the initial value of EAX in ECX.  This is basically a
  // hack to make up for a lack of real calling convention detection.
  const RegisterDescriptor& eaxrd = dispatcher->findRegister("eax", 32);
  const RegisterDescriptor& ecxrd = dispatcher->findRegister("ecx", 32);

  SymbolicValuePtr retvalue = output_state->read_register(eaxrd);
  SymbolicValuePtr initial_ecx = input_state->read_register(ecxrd);
  SymbolicValuePtr initial_eax = input_state->read_register(eaxrd);

  // If EAX at the end of the function contains the same value as ECX at the beginning of the
  // function, then we're return ECX in EAX...
  bool returns_ecx = (*retvalue == *initial_ecx);
  STRACE << "Checking return values for function " << fd->address_string() << LEND;
  STRACE << "Returns ECX=" << returns_ecx
         << " EAX=" << retvalue->get_hash() << " ECX=" << initial_ecx->str() << LEND;
  fd->set_returns_this_pointer(returns_ecx);

  // The test for whether the function returns a value at all is inverted.  It tests whether
  // EAX is the same as it was when we started.  If it is, then we did NOT return a value.
  bool unchanged_eax = (*retvalue == *initial_eax);
  STRACE << "Returns EAX=" << !unchanged_eax
         << " EAX=" << retvalue->get_hash() << " EAX=" << initial_eax->str() << LEND;
  fd->set_returns_eax(!unchanged_eax);

  // Emitted once per function...
  SDEBUG << "Returns eax=" << fd->get_returns_eax()
         << " thisptr=" << fd->get_returns_this_pointer()
         << " function=" << fd->address_string() << LEND;
}

// Create a symbolic emulation environment
CustomDispatcherPtr make_emulation_environment() {
  SymbolicRiscOperatorsPtr rops = make_risc_ops();
  CustomDispatcherPtr dispatcher = CustomDispatcher::instance(rops);
  // We used to initialize the segment registers to zero here.  Given the bad experience with
  // initializing ESP and EBP to zero, it seemed unwise to do this unless it was needed, and
  // even if it is, an explicit choice to substitute the constant into the expression later is
  // probably a wiser choice.
  // rops->writeRegister(dispatcher->findRegister("es", 16), rops->number_(16, 0));
  return dispatcher;
}

// Decide which blocks in the flowlist are "bad".  The API for this function has changed, it
// used to take a third (output) parameter, but we changed to updating the DUAnalysis member
// variable bad_blocks with the addresses of the bad blocks.
void DUAnalysis::find_bad_blocks(std::vector<CFGVertex>& flowlist, ControlFlowGraph& cfg) {
  // For every vertex in in the flow list.
  for (size_t i=0; i<flowlist.size(); ++i) {
    // Convert the vertex to a basic block.
    CFGVertex vertex = flowlist[i];
    SgAsmBlock *bblock = get(boost::vertex_name, cfg, vertex);
    assert(bblock!=NULL);
    rose_addr_t baddr = bblock->get_address();

    // This logic was from Wes.  If the block is less than 80% likely to be code, call the
    // isBadCode analyzer.
    if (bblock->get_code_likelihood() <= 0.8) {
      SgAsmStatementPtrList il = bblock->get_statementList();
      BadCodeMetrics bc;
      if (bc.isBadCode(il)) {
        // If the analyze decided that the code is "bad", then add it to the bad block set.
        // So Cory found an instance of this in the SHA256 beginning a21de440ac315d92390a...
        // In that case the determination that the code was "bad" was incorrect.
        GWARN << "The code at " << addr_str(baddr) << " has been deemed bad by the oracle." << LEND;
        GWARN << "If you see this message, please let Cory know this feature is being used." << LEND;
        bad_blocks.insert(baddr);
      }
    }
  }
}

typedef std::vector<SgAsmBlock*> BlockVector;

// This function attempts to assign a value to the function summary output state variable.  In
// theory, it does this by merging all return blocks into a single consistent result.  Wes'
// original code appeared to have multiple problems, and there used to be a horrible
// hodge-podge set of parameters passed, but apparently the function got cleaned up quite a lot
// because now it only needs the state histories.  Cory has not reviewed this function
// carefully to see if it's actually correct yet, but it's certainly on the road to being
// reasonable now.
void DUAnalysis::update_output_state(StateHistoryMap& state_histories) {

  // Until we reach the end of this function, assume that we're malformed with respect to
  // having a well formed set of return blocks.
  valid_returns = false;

  // Because it's shorter than current_function...
  FunctionDescriptor* fd = current_function;

  // This list isn't really the return blocks, but rather all "out" edges in the control flow
  // graph which can contain jumps, and other strange things as a result of bad partitioning.
  BlockSet out_blocks = fd->get_return_blocks();

  // Create an empty output state when we don't know what else to do...  In this case because
  // there are no out edges from the function...  For example a jump to itself...
  if (out_blocks.size() == 0) {
    SDEBUG << "Function " << fd->address_string() << " has no out edges." << LEND;
    output_state = SymbolicState::instance();
    return;
  }

  // Make a list of real return blocks that are worth merging into the outout state.
  BlockVector ret_blocks;
  BOOST_FOREACH(SgAsmBlock* block, out_blocks) {
    rose_addr_t addr = block->get_address();

    // Blocks that we've previously identified as "bad" are not valid return blocks.
    if (bad_blocks.find(addr) != bad_blocks.end()) continue;

    // The block also needs to have an entry in the state history to be useful.
    if (state_histories.find(addr) == state_histories.end()) continue;

    // Find the last instruction, and check to see if it's a return.
    const SgAsmStatementPtrList &insns = block->get_statementList();
    if (insns.size() == 0) continue;

    SgAsmX86Instruction *last = isSgAsmX86Instruction(insns[insns.size() - 1]);
    SDEBUG << "Last instruction in ret-block:" << debug_instruction(last) << LEND;

    // Cory originally through that we should be ensuring stack delta concensus in this routine
    // around here, but it appears that is already implemented in update_function_delta().

    // There's also some ambiguity here about what we should be doing for blocks that don't end
    // in return.  The simple approach is to say that we should check valid_returns before
    // placing too much stock in the output_state, but a more robust approach would be to merge
    // external function states into our state, especially in cases where this function eitehr
    // returns a value or passes control to anotehr complete and well formed function.

    // If the block ends in a return instruction, add it to ret_blocks.
    if (last->get_kind() == x86_ret) {
      ret_blocks.push_back(block);
    }
  }

  // If no blocks ended with return instructions, return an empty output_state.
  if (ret_blocks.size() == 0) {
    SDEBUG << "Function " << fd->address_string() << " has no valid return blocks." << LEND;
    output_state = SymbolicState::instance();
    return;
  }

  // If not all of the blocks got copied into the return blocks set, then we must have
  // discarded one or more for being bad code, or lacking return statements.  That means that
  // there's something a wrong with the function, and we should only indicate that it has a
  // well formed return block structure if every block ended with a return.
  if (ret_blocks.size() == out_blocks.size()) valid_returns = true;

  // Regardless of whether all or just some of the blocks ended in returns, we can still create
  // an output state.  Do that now by beginning with the first state, and merging into it all
  // of the other states.  There's no need to confirm that each address is in state histories,
  // because w did that when filtering the blocks earlier.
  rose_addr_t addr = ret_blocks[0]->get_address();
  output_state = state_histories[addr];
  for (size_t q = 1; q < ret_blocks.size(); q++) {
    SgAsmBlock* block = ret_blocks[q];
    addr = block->get_address();
    output_state->merge(state_histories[addr], global_rops.get());
  }
}

typedef std::map<rose_addr_t, unsigned int> IterationCounterMap;

LimitCode DUAnalysis::solve_flow_equation_iteratively() {
  // The intention is to have some easier way of initializing these from command parmeters.
  ResourceLimit func_limit;
  get_global_limits().set_limits(func_limit, PharosLimits::limit_type::BASE);

  // Start by checking absolute limits.
  LimitCode rstatus = func_limit.check();

  // Get the ROSE function from the descriptor.
  FunctionDescriptor* fd = current_function;
  SgAsmFunction *func = fd->get_func();

  // Management structures for solve_flow_equations
  // CFG Vertices refer to vertices of the original function
  // Mapping from rose_addr_t (the beginning of the basic block) to the RiscOperators that
  // contains the state history for the latest iteration over the basic block when solving the
  // flow equation.
  StateHistoryMap state_histories;
  // The number of times we've interated over the flow equation for a given address.
  IterationCounterMap iterations;
  // The addreses that are still pending?
  std::map<rose_addr_t, bool> pending;
  // This limits the number of times we complain about discarded expressions.  It's a naughty
  // global variable.   Go read about it in SymbolicValue::scopy().
  discarded_expressions = 0;

  // We used to call sp_tracker->analyzeFunc(func); to guess at stack deltas here...

  // We can't just call fd->get_cfg() here because we need the anlayzer too...
  rose::BinaryAnalysis::ControlFlow cfg_analyzer;
  ControlFlowGraph cfg = cfg_analyzer.build_block_cfg_from_ast<ControlFlowGraph>(func);
  CFGVertex entry_vertex = 0;
  assert(get(boost::vertex_name, cfg, entry_vertex)==func->get_entry_block());
  std::vector<CFGVertex> flowlist = cfg_analyzer.flow_order(cfg, entry_vertex);
  if (flowlist.size() < num_vertices(cfg)) {
    fixupCFGEdges(cfg);
    flowlist = cfg_analyzer.flow_order(cfg, entry_vertex);
  }
  STRACE << "# of CFG vertices " << num_vertices(cfg) << LEND;

  CustomDispatcherPtr dispatcher = make_emulation_environment();
  SymbolicRiscOperatorsPtr rops = dispatcher->get_operators();
  SymbolicStatePtr initial_state = rops->get_sstate();

  const RegisterDescriptor& esprd = dispatcher->findRegister("esp", 32);
  SymbolicValuePtr initial_sp = rops->read_register(esprd);
  boost::optional<int64_t> opt_stack_delta = initial_sp->get_stack_const();
  int64_t initial_delta = 0;
  if (opt_stack_delta) {
    initial_delta = *opt_stack_delta;
    if (initial_delta != 0) {
      SDEBUG << "Non-zero initial stack delta of " << initial_delta << " in function "
             << fd->address_string() << LEND;
    }
  }

  input_state = rops->get_sstate()->sclone();

  // Set the stack delta of the first instruction to zero, with confidence Certain (by definition).
  SDEBUG << "Setting initial stack delta to " << StackDelta(0, ConfidenceCertain) << " in function "
         << fd->address_string() << " at " << addr_str(func->get_entry_va()) << LEND;
  sp_tracker->update_delta(func->get_entry_va(), StackDelta(0, ConfidenceCertain));

  // Solve the flow equation iteratively to find out what's defined at the end of every basic
  // block.  The policies[] stores this info for each vertex.
  STRACE << "Size of the flow list: " << flowlist.size() << LEND;
  bool changed;

  // Decide which blocks are bad.  By doing this before starting the main emulation, we could
  // choose to skip full analysis if the function doesn't look right.
  find_bad_blocks(flowlist, cfg);

  do {
    changed = false;
    func_limit.increment_counter();

    SDEBUG << "loop try #" << func_limit.get_counter() << LEND;
    for (size_t i=0; i<flowlist.size(); ++i) {
      CFGVertex vertex = flowlist[i];
      SgAsmBlock *bblock = get(boost::vertex_name, cfg, vertex);
      assert(bblock!=NULL);
      rose_addr_t baddr = bblock->get_address();

      // If the block is a "bad" block, then skip it.
      if (bad_blocks.find(baddr) != bad_blocks.end()) continue;

      // If this block is in the processed list (meaning we've processed it before) and it it
      // is no longer pending then continue with the next basic block.  This is a very common
      // case and we could probably simplify the logic some by adding and removing entries
      // from a worklist that would prevent us from being in this loop in the first place.
      if ((pending.find(baddr) != pending.end() && !pending[baddr])) continue;

      // If we're really pending, but we've visited this block more than max iteration times,
      // then we should give up even though it produces incorrect answers.  Report the condition
      // as an error so that the user knows something went wrong.
      if ((iterations.find(baddr) != iterations.end() && iterations[baddr] >= MAX_LOOP)) {
        // Cory thinks that this should really be an error, but it's still too common to be
        // considered a true error, and so he moved it to warning importance.
        SWARN << "Maximum iterations (" << MAX_LOOP << ") exceeded for block "
              << addr_str(baddr) << " in function " << fd->address_string() << LEND;
        // Setting the block so that it is not pending should help prevent the error message
        // from being generated repeatedly for the same block.
        pending[baddr] = false;
        continue;
      }

      // We're processing the block now, so it's no longer pending (and we've interated once more).
      pending[baddr] = false;
      iterations[baddr]++;

      // Debugging from Wes' version...
      //SgAsmIntegerValuePtrList &s = bblock->getSuccessors();
      //for (size_t x = 0; x < s.size(); x++) {
      //  SDEBUG << "Successor: "  << addr_str(s[x]->get_absolute_value()) << LEND;
      //}

// Enable convergence algorithm debugging, but not full state debugging.
//#define CONVERGE_DEBUG
// Enable full state debugging (for merge logic etc).
//#define STATE_DEBUG

#ifdef CONVERGE_DEBUG
#define DSTREAM OINFO
      global_timing = true;
#else
#define DSTREAM SDEBUG
#endif

      ResourceLimit block_limit;
      DSTREAM << "Starting iteration " << iterations[baddr] << " for block " << addr_str(baddr)
              << " Reason " << bblock->reason_str("",bblock->get_reason()) << LEND;

      // Incoming rops for the block.  This is the merge of all out policies of predecessor
      // vertices, with special consideration for the function entry block.
      SymbolicStatePtr cstate;

      size_t merge_cnt = 0;
      ResourceLimit merge_limit;
      boost::graph_traits<ControlFlowGraph>::in_edge_iterator iei, iei_end;
      for (boost::tie(iei, iei_end)=in_edges(vertex, cfg); iei != iei_end; ++iei) {
        CFGVertex predecessor = source(*iei, cfg);
        SgAsmBlock *pblock = get(boost::vertex_name, cfg, predecessor);
        rose_addr_t paddr = pblock->get_address();
        DSTREAM << "Merging states for predecessor " << addr_str(paddr)
                << " into block " << addr_str(baddr) << LEND;

        if (state_histories.find(paddr) != state_histories.end()) {
          merge_cnt++;
#ifdef STATE_DEBUG
          if (cstate) {
            OINFO << "================= STATE BEFORE MERGE ================" << LEND;
            cstate->type_recovery_test();
          }
          else {
            OINFO << "============= STATE BEFORE MERGE (NONE) =============" << LEND;
          }
          OINFO << "================= STATE BEING MERGED ================" << LEND;
          state_histories[paddr]->type_recovery_test();
#endif
          if (cstate) {
            cstate->merge(state_histories[paddr], rops.get());
          }
          else {
            cstate = state_histories[paddr]->sclone();
          }
#ifdef STATE_DEBUG
          OINFO << "================= STATE AFTER MERGE ================" << LEND;
          cstate->type_recovery_test();
#endif
        }
      }

      if (!cstate) {
        if (bblock != func->get_entry_block()) {
          GERROR << "Block " << addr_str(baddr) << " has no predecessors." << LEND;
        }
        cstate = initial_state;
      }
      rops->set_sstate(cstate);

      DSTREAM << "Merged " << merge_cnt << " predecessors for block " << addr_str(baddr)
              << " in function " << fd->address_string()
              << " (loop #" << func_limit.get_counter() << ") complete." << LEND;
      if (global_timing) {
        SDEBUG << merge_limit.get_relative_clock() << " seconds elapsed." << LEND;
      }
      //else SDEBUG << "States match" << LEND;
      // STRACE << "Merged stated" << LEND;
      // STRACE << rops->get_sstate() << LEND;
      // Compute output rops of this block.
      // rops->get_rdundef_state().clear();

      DSTREAM << "Emulating block " << addr_str(baddr) << LEND;
      evaluate_bblock(bblock, dispatcher, initial_delta);

      // If output of this block changed from what we previously calculated, then mark all its
      // children as pending.
      if (state_histories.find(baddr) == state_histories.end() ||
          !(rops->get_sstate()->equals(state_histories[baddr]))) {
        changed = true;

        // This debugging is completely disabled because it's multi-line without prefixes.
#ifdef STATE_DEBUG
        OINFO << "================= STATE AFTER EXECUTION ================" << LEND;
        rops->get_sstate()->type_recovery_test();
#ifdef REPLACED_STATE
        StateHistoryMap::iterator finder = state_histories.find(baddr);
        if (finder == state_histories.end()) {
          OINFO << "============ STATE BEING REPLACED (NONE) ===============" << LEND;
        }
        else {
          OINFO << "================ STATE BEING REPLACED ==================" << LEND;
          cstate->type_recovery_test();
        }
#endif
#endif

        DSTREAM << "Updating state history for " << addr_str(baddr) << LEND;
        // Since cstate should be newly allocated, is this clone duplicative (or almost
        // duplicative?)
        state_histories[baddr] = rops->get_sstate()->sclone();
#ifdef STATE_DEBUG
        OINFO << "================= STATE AFTER UPDATE ================" << LEND;
        state_histories[baddr]->type_recovery_test();
#endif

        boost::graph_traits<ControlFlowGraph>::out_edge_iterator oei, oei_end;
        for (boost::tie(oei, oei_end)=out_edges(vertex, cfg); oei != oei_end; ++oei) {
          CFGVertex successor = target(*oei, cfg);
          SgAsmBlock *sblock = get(boost::vertex_name, cfg, successor);
          rose_addr_t saddr = sblock->get_address();
          DSTREAM << "Marking successor block " << addr_str(saddr) << " for revisting." << LEND;
          pending[saddr] = true;
        }
      }

      DSTREAM << "Basic block analysis at " << addr_str(baddr)
              << " in function " << fd->address_string()
              << " (loop #" << func_limit.get_counter() << ") complete." << LEND;
      if (global_timing) {
        DSTREAM << block_limit.get_relative_clock() << " seconds elapsed." << LEND;
      }
      DSTREAM << "========================================================================" << LEND;

      rstatus = func_limit.check();
      // The intention is that rstatus and changed would be the only clauses on the while condition.
      if (rstatus != LimitSuccess) {
        SERROR << "Function " << fd->address_string()
               << " " << func_limit.get_message() << LEND;
        // Break out of the loop of basic blocks.
        break;
      }
    } // foreach block in flow list...

    SDEBUG << "Flow equation loop #" << func_limit.get_counter()
           << " for " << fd->address_string() << " complete." << LEND;
    // Cory would like for this to become: func_limit.report("Func X took: ");
    if (global_timing) {
      SDEBUG << func_limit.get_relative_clock() << " seconds elapsed." << LEND;
    }

  } while (changed && rstatus == LimitSuccess);

  if (rstatus != LimitSuccess) {
    OINFO << "Function analysis convergence failed for: " << fd->address_string() << LEND;
  }

  if (GDEBUG) {
    BOOST_FOREACH(IterationCounterMap::value_type& ip, iterations) {
      OINFO << " Basic block: " << addr_str(ip.first) << " in function " << fd->address_string()
            << " took " << ip.second << " iterations." << LEND;
    }
  }

  // Look at all of the return blocks, and bring them together into a unified stack delta.
  update_function_delta(fd);

  // Merge all states at each return block into a single unified output state.  This routine
  // definitely need to be called from here because the state histories are local.
  update_output_state(state_histories);

  // Determine whether we return a value at all, and if it's the initial value of ECX.  This
  // routine should probably continue to be part of the DUAnalysis class because it uses
  // input_state and output_state to do it's work.
  analyze_return_code(fd, dispatcher);

  return rstatus;
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
