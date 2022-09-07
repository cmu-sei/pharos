// Copyright 2015-2022 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/algorithm/string.hpp>
#include <boost/tokenizer.hpp>
#include <boost/range/adaptor/map.hpp>
// #include <boost/property_map/property_map.hpp>
// #include <boost/graph/properties.hpp>
// #include <boost/graph/copy.hpp>

#include "defuse.hpp"
#include "sptrack.hpp"
#include "badcode.hpp"
#include "limit.hpp"
#include "riscops.hpp"
#include "misc.hpp"
#include "util.hpp"
#include "options.hpp"
#include "cdg.hpp"
#include "masm.hpp"

namespace pharos {

// In practice five iterations was all that was needed for the worst of the functions that
// actually produced results (ever) in the Objdigger test suite.  This limit might become
// optional if we can find and fix the remaining convergence bugs.
#define MAX_LOOP 5

// Enable convergence algorithm debugging, but not full state debugging.
// #define CONVERGE_DEBUG
// Enable full state debugging (for merge logic etc).
// #define STATE_DEBUG

#ifdef CONVERGE_DEBUG
#define DSTREAM OINFO
#else
#define DSTREAM SDEBUG
#endif

// =========================================================================================
// Basic Block Analysis methods
// =========================================================================================

BlockAnalysis::BlockAnalysis(DUAnalysis & _du, const ControlFlowGraph& cfg,
                             CFGVertex _vertex, bool _entry)
  : du(_du), vertex(_vertex), entry(_entry)
{
  block = get(boost::vertex_name, cfg, vertex);
  address = block->get_address();
  iterations = 0;
  pending = true;

  // The meaning of this boolean has evolved gradually. It used to include blocks that were bad
  // because they had no proper control flow predecessors, but that's not handled by which CFG
  // we're using for the analysis (with certain blocks excluded completely).  This boolean
  // still marks blocks that don't appear to be legitimate code.  It's unclear whether we
  // really want this however.  In the less rigorous analysis, we already checked this when we
  // filtered the pharos CFG, and perhaps we don't want to filter at all for the more rigorous
  // analysis?  The next commit may attempt to remove this boolean entirely.
  bad = check_for_bad_code(du.ds, block);

  // Create entry condition variables for this block.  Pre-computing this is a bit problematic
  // because it kind of prevents us from adding additional predecessors as we analyze.  Perhaps
  // we should create these as we ask for them?  Or as we add predecessors?  The number of
  // these conditions is one less than the number of incoming edges.
  size_t degree = boost::in_degree(vertex, cfg);
  size_t num_conds = degree ? degree - 1 : 0;
  conditions.reserve(num_conds);

  // assume every block can be entered
  entry_condition = SymbolicValue::treenode_instance(SymbolicExpr::makeBooleanConstant(true));
  exit_condition =  SymbolicValue::treenode_instance(SymbolicExpr::makeBooleanConstant(true));

  size_t i = 0;
  for (const SgAsmBlock *pblock : cfg_in_bblocks(cfg, vertex)) {
    if (i == num_conds) {
      break;
    }
    ++i;

    // Create the incomplete variable
    auto cv = SymbolicValue::incomplete(1);

    // Generate a name for the variable.  This tries to give it a name based on the address of
    // the instruction that branched to this block.
    auto & bstmts = pblock->get_statementList();
    rose_addr_t addr;
    if (bstmts.empty()) {
      addr = pblock->get_address();
    } else {
      auto & last_statement = bstmts.back();
      assert(last_statement);
      addr = last_statement->get_address();
    }
    cv->comment("Cond_from_" + addr_str(addr));

    // Add the variable to the list
    conditions.push_back(cv);
  }
}

// New algorithm discussed with Duggan merges all instruction acceses into the DUAnalysis
// accesses map in one pass, utilizing move semantics and other optimizations.
void
DUAnalysis::update_accesses(
  SgAsmX86Instruction *insn,
  SymbolicRiscOperatorsPtr& rops)
{
  rose_addr_t iaddr = insn->get_address();
  auto it = accesses.find(iaddr);
  if (it == accesses.end()) {
    accesses[iaddr] = std::move(rops->insn_accesses);
    // Clear vector to avoid accessing moved elements.
  }
  else {
    for (auto && aa : rops->insn_accesses) {
      auto ait = std::find(it->second.begin(), it->second.end(), aa);
#if 1
      // This code if order does matter (it may still).
      if (ait != it->second.end()) {

#if 0
        // Enable some debugging about the cases that we are discarding.
        AbstractAccess& oaa = *ait;
        if (!aa.exact_match(oaa)) {
          OINFO << "Insn " << debug_instruction(insn) << " accesses:" << LEND;
          if (!(aa.value->get_expression()->isEquivalentTo(oaa.value->get_expression()))) {
            OINFO << "  Value1: " << aa << LEND;
            OINFO << "  Value2: " << oaa << LEND;
          }
          else {
            OINFO << "  Instruction counts " << aa.latest_writers.size()
                  << " vs " << oaa.latest_writers.size() << LEND;
            for (auto writer : aa.latest_writers) {
              OINFO << "  LW1: " << debug_instruction(writer) << LEND;
            }
            for (auto writer : oaa.latest_writers) {
              OINFO << "  LW2: " << debug_instruction(writer) << LEND;
            }
          }
        }
#endif

        // Remove the existing access with a similar "key", because it should be older in terms
        // of the iteration algorithm.  We'll add the new access to replace it before returning.
        it->second.erase(ait);
      }
      it->second.push_back(std::move(aa));
#else
      // This code if order doesn't matter (it may still).
      if (ait == it->second.end()) {
        it->second.push_back(std::move(aa));
      } else {
        *ait = std::move(aa);
      }
#endif
    }
  }

  // Clear vector to avoid accessing moved elements.
  rops->insn_accesses.clear();
}

// Record the reads and writes performed by each instruction in the form of a list of abstract
// accesses for each instruction.  Create and update the depends_on map for each instruction.
// Finally, record reads and writes for all global variables.
//
// This method updates all_regs, du.accesses, du.depends_on, and du.dependents_of.
void
BlockAnalysis::record_dependencies(
  SgAsmX86Instruction *insn,
  const SymbolicStatePtr& cstate)
{
  SymbolicRiscOperatorsPtr rops = SymbolicRiscOperators::promote(du.dispatcher->operators());

  du.update_accesses(insn, rops);
  //du.print_accesses(insn); // Debugging

  rose_addr_t iaddr = insn->get_address();
  // Ensure that there's always an entry in the depends_on map for this instruction.
  if (du.depends_on.find(iaddr) == du.depends_on.end()) {
    du.depends_on[iaddr] = DUChain();
  }

  AbstractAccessVector all_regs;
  SDEBUG << "insn accesses size=" << du.accesses[iaddr].size() << LEND;
  for (const AbstractAccess & aa : du.accesses[iaddr]) {
    // Reads
    if (aa.isRead) {
      // ----------------------------------------------------------------------------------
      // Register reads
      // ----------------------------------------------------------------------------------
      if (aa.is_reg()) {
        // Update list of all registers.
        all_regs.push_back(aa);

        // Build the def-use chains
        RegisterDescriptor rd = aa.register_descriptor;
        // Skip the instruction pointer, since every instruction reads it.
        // The writes to EIP are kept now so that they can be inspected for branch conditions.
        if (rd == du.ds.get_ip_reg()) continue;
        SymbolicValuePtr sv = cstate->read_register(rd);

        if (aa.latest_writers.size() == 0) {
          std::string regname = unparseX86Register(rd, {});
          SDEBUG << "Warning: Use of uninitialized register "
                 << regname << " by " << debug_instruction(insn) << LEND;
          Definition reg_def(NULL, aa);
          du.depends_on[iaddr].insert(reg_def);
          // Should probably be add_dependency_pair(insn, NULL, aa);
        }
        else {
          for (SgAsmInstruction* winsn : aa.latest_writers) {
            // Create a use-chain entry
            SgAsmX86Instruction *definer = isSgAsmX86Instruction(winsn);
            du.add_dependency_pair(insn, definer, aa);
          }
        }
      }
      // ----------------------------------------------------------------------------------
      // Memory reads
      // ----------------------------------------------------------------------------------
      else {
        // Find the corresponding data value for this address
        // InsnSet modifiers;

        // We're looking for global fixed memory reads here...
        if (aa.memory_address->isConcrete() &&
            aa.memory_address->get_width() <= 64 &&
            !insn_is_control_flow(insn)) {
          rose_addr_t known_addr = *aa.memory_address->toUnsigned();
          // We're only interested in constants that are likely to be memory addresses.
          if (possible_global_address(known_addr)) {
            const ImportDescriptor *id = du.ds.get_import(known_addr);
            if (id == NULL) {
              GlobalMemoryDescriptor* gmd = du.ds.get_rw_global(known_addr); // add_read()
              if (gmd == NULL) {
                SDEBUG << "Unexpected global memory read from address " << addr_str(known_addr)
                       << " at " << debug_instruction(insn) << LEND;
              }
              else {
                gmd->add_read(insn, aa.size);
              }
            }
            // When we read memory in the import table, it's often the because we've loaded the
            // address of the import into a register, and then called the value pointed to by
            // the register.
          }
        }

        // If there are no latest writers for this address, add a NULL definer.
        if (aa.latest_writers.size() == 0) {
          du.add_dependency_pair(insn, NULL, aa);
          SDEBUG << "--> Memory read at " << *(aa.memory_address)
                 << " of " <<  *(aa.value) << " from NULL definer." << LEND;
        }
        else {
          for (SgAsmInstruction *winsn : aa.latest_writers) {
            SgAsmX86Instruction *definer = isSgAsmX86Instruction(winsn);
            du.add_dependency_pair(insn, definer, aa);
            SDEBUG << "--> Memory read at " << *(aa.memory_address) << " of " << *(aa.value)
                   << " definer is " << debug_instruction(definer) << LEND;
          }
        }
      }
    }
    // Writes
    else {
      // ----------------------------------------------------------------------------------
      // Memory writes
      // ----------------------------------------------------------------------------------
      if (!aa.is_reg()) {
        // We're looking for global fixed memory writes here...

        if (aa.memory_address->isConcrete() && aa.memory_address->get_width() <= 64) {
          rose_addr_t known_addr = *aa.memory_address->toUnsigned();
          // We're only interested in constants that are likely to be memory addresses.
          if (possible_global_address(known_addr)) {
            const ImportDescriptor *id = du.ds.get_import(known_addr);
            if (id == NULL) {
              GlobalMemoryDescriptor* gmd = du.ds.get_rw_global(known_addr); // add_write()
              if (gmd == NULL) {
                // This message is really debugging for a case that Cory is interested in, not
                // something that's useful to general users, so he moved it back to SDEBUG. :-(
                SDEBUG << "Unexpected global memory write to address " << addr_str(known_addr)
                       << " at " << debug_instruction(insn) << LEND;
              }
              else {
                // Always record that there was a write to the global variable.
                gmd->add_write(insn, aa.size);
                // Record the possible value (which will only be saved if it's a new value).
                gmd->add_value(aa.value);
              }
            }
            // This is where we used to test for overwrites of imports, that's now more clearly
            // (but perhaps less cleanly) in RiscOps::readMemory().
          }
        }
      }
    }
  }
}

// Reformat the exception to make it more readable, and then emit it as a warning.
void
handle_semantics_exception(SgAsmX86Instruction *insn, const SemanticsException &e)
{
  // This is a hackish kludge to make the exception readable.  There are different kinds of
  // exception generated, but they're so long that they're pretty much unreadable.  They've
  // also go two copies of the offending instruction in an unpleasant format.  It's a mess,
  // and Cory should talk with Robb Matzke about it...
#if 1
  // First transform the exception into a string.
  std::stringstream ss;
  ss << e;
  std::string newerror = ss.str();
  // Then chop off: "Rose::BinaryAnalysis::InstructionSemantics::BaseSemantics::Exception: "
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
}

// Check to see whether the call or jump instruction goes to some invalid code (e.g. because
// the target of the jump have been obfuscated).  This happens fairly frequently in malware, so
// we should avoid doing stupid things when it occurs.  This is some seriously ancient code
// written by Wes.  It's still useful, but it definitely needs some attention and improvements.
bool
BlockAnalysis::check_for_invalid_code(SgAsmX86Instruction *insn, size_t i)
{
  // Get the instruction list (again).  This is a little messy, but then again, so is this
  // whole method.
  const SgAsmStatementPtrList &insns = block->get_statementList();

  // This should really be insn_is_branch(insn)..
  if (((insn->get_kind() >= x86_ja && insn->get_kind() <= x86_js) ||
       insn->get_kind() == x86_call) && i < insns.size()-1) {
    SgAsmStatementPtrList ri;
    // The size_t i, is the current instruction in the basic block being analyzed.
    for (size_t qq = i+1; qq < insns.size(); qq++) ri.push_back(insns[qq]);
    BadCodeMetrics bc(du.ds);
    size_t repeated = 0, deadstores = 0, badjmps = 0, unusualInsns = 0;

    SDEBUG << "Testing possible jmp to packed section " << debug_instruction(insn) << LEND;

    auto & branchesToPackedSections = du.getJmps2UnpackedCode();
    if (branchesToPackedSections.find(insn) != branchesToPackedSections.end() ||
        bc.isBadCode(ri, &repeated, &unusualInsns, &deadstores, &badjmps)) {

      branchesToPackedSections.insert(insn);
      OINFO << "Skipping " << debug_instruction(insn)
            << " - Dead Stores: " <<  deadstores << " Repeated Insns: " << repeated
            << " Bad Cond Jumps: " << badjmps << " Unusual Insns: " << unusualInsns << LEND;

      return true;
    }
  }
  return false;
}

LimitCode
BlockAnalysis::analyze(bool with_context)
{
  // This limit is not well tested.  But I know that we've encountered huge basic blocks of
  // thousands of instructions that made this function not perform well.
  ResourceLimit block_limit;
  get_global_limits().set_limits(block_limit, PharosLimits::limit_type::BASE);

  LimitCode rstatus = block_limit.check();

  DSTREAM << "Emulating block " << addr_str(address) << LEND;

  SymbolicRiscOperatorsPtr rops = SymbolicRiscOperators::promote(
    du.dispatcher->operators());
  size_t arch_bits = du.ds.get_arch_bits();
  RegisterDescriptor eiprd = du.ds.get_ip_reg();
  RegisterDescriptor esprd = du.ds.get_stack_reg();

  const SgAsmStatementPtrList &insns = block->get_statementList();

  for (size_t i=0; i<insns.size(); ++i) {
    SgAsmX86Instruction *insn = isSgAsmX86Instruction(insns[i]);
    if (insn == NULL) continue;
    block_limit.increment_counter();
    rose_addr_t iaddr = insn->get_address();
    STRACE << "eval bblock insn addr " << iaddr << " => "
           << debug_instruction(insn, 5, NULL) << LEND;
    // Get the state just before evaluating the instruction
    SymbolicStatePtr cstate = rops->get_sstate()->sclone();
    if (with_context && insn_is_call(insn)) {
      SDEBUG << "Stack value before call is " <<  *rops->read_register(esprd) << LEND;
      CallDescriptor* cd = du.ds.get_rw_call(insn->get_address()); // set_state()
      assert(cd != NULL);
      cd->set_state(cstate);
    }

    try {
      // Evaluate the instruction
      SymbolicValuePtr iaddrptr = SymbolicValue::constant_instance(arch_bits, iaddr);
      // Another forced EIP hack.  Possibly not needed in ROSE2 port?
      rops->writeRegister(eiprd, iaddrptr);
      SDEBUG << "Insn: " << debug_instruction(insn) << LEND;
      du.dispatcher->processInstruction(insn);
      SymbolicStatePtr pstate = rops->get_sstate();

      if (with_context) {
        if (check_for_invalid_code(insn, i)) {
          handle_stack_delta(block, insn, cstate, true);
          // A jump/call to invalid code should be the last instruction in the block anayway.
          break;
        }

        if (insn_is_call(insn)) du.update_call_targets(insn, rops);
        handle_stack_delta(block, insn, cstate, false);
        du.make_call_dependencies(insn, cstate);
        record_dependencies(insn, cstate);
      }

      rstatus = block_limit.check();
      // If we've reached our limit, stop processing instructions.
      if (rstatus != LimitSuccess) {
        SERROR << "Basic block " << addr_str(address)
               << " " << block_limit.get_message() << LEND;
        break;
      }
    }
    catch (const SemanticsException &e) {
      handle_semantics_exception(insn, e);
      if (with_context) handle_stack_delta(block, insn, cstate, true);
    }
  }

  DSTREAM << "Evaluation of basic block at " << addr_str(address) << " took "
          << block_limit.get_relative_clock().count() << " seconds." << LEND;
  return rstatus;
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
  if (last) {
    for (auto expr_value : bb->get_successors()) {
      result.insert(rose_addr_t(expr_value->get_value()));
    }
  }
  else {
    auto succesors = insn->getSuccessors(complete);
    for (auto succ : succesors.values()) {
      result.insert(succ);
    }
  }
  return result;
}

void
BlockAnalysis::handle_stack_delta(SgAsmBlock *bb, SgAsmX86Instruction* insn,
                                  SymbolicStatePtr& before_state, bool downgrade)
{
  rose_addr_t iaddr = insn->get_address();
  const CallDescriptor* cd = du.ds.get_call(iaddr);

  SymbolicRiscOperatorsPtr rops = SymbolicRiscOperators::promote(
    du.dispatcher->operators());
  SymbolicStatePtr after_state = rops->get_sstate();

  // We'll need to know the delta for this instruction.
  StackDelta olddelta = du.sp_tracker.get_delta(iaddr);
  SDEBUG << "Stack delta=" << olddelta << " insn=" << debug_instruction(insn) << LEND;

  // By default, we have wrong knowledge of the stack pointer.
  StackDelta newdelta(0, ConfidenceWrong);
  // Get the stack register descriptor.
  size_t arch_bytes = du.ds.get_arch_bytes();
  RegisterDescriptor esprd = du.ds.get_stack_reg();
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
    int adjdelta = -(*opt_after_const);
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


  // Duggan sugegsts that this loop shouldn't be over successors at all, but rather our current
  // best understanding of the call targets (from Parititioner 2 or perhaps our call descriptors).
  bool last = is_last_insn_in_bb(bb, insn);
  for (rose_addr_t target : get_hinky_successors(bb, insn, last)) {
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
      // contains_insn_at().

      // This might still be a little broken for cases in which the finally handler has a
      // non-zero delta, which we haven't computed yet, and can't set correctly.
      if (insn_is_call(insn)) {
        if (target == fallthru) {
          // Ask the stack tracker what the delta for this call was.
          StackDelta calldelta = du.get_call_delta(iaddr);
          GenericConfidence newconfidence = calldelta.confidence;
          // Downgrade confidence if required.
          if (newdelta.confidence < newconfidence) newconfidence = newdelta.confidence;

          // The additional minus 4 is to compensate for the pushed return adddress which is
          // already changed in the state, but is not included in the call delta.
          StackDelta fallthrudelta = StackDelta(newdelta.delta - calldelta.delta - arch_bytes, newconfidence);
          SDEBUG << "New fall thru delta is: " << fallthrudelta << LEND;

          // Update the state to account for the return instruction that we did not emulate.
          // Exactly the best way to accomplish this is a little unclear.  We'd like something
          // that is clear and does not produce any unintended side effects related to definers
          // and modifiers.

          // Cory's not really sure if a COPY is needed here, but it seems safer than not.
          SymbolicValuePtr oldesp = after_state->read_register(esprd)->scopy();
          auto dvalue = calldelta.delta + arch_bytes;
          TreeNodePtr sum = oldesp->get_expression() + dvalue;
          if (cd && calldelta.confidence == ConfidenceMissing) {
            auto sdv = cd->get_stack_delta_variable();
            if (sdv) {
              using Rose::BinaryAnalysis::SymbolicExpr::OP_ADD;
              sum = InternalNode::instance(OP_ADD, sum, sdv,
                                           Rose::BinaryAnalysis::SmtSolverPtr());
            }
          }
          SymbolicValuePtr newesp = SymbolicValue::promote(oldesp->copy());
          newesp->set_expression(sum);

          SDEBUG << "Adding oldesp=" << *oldesp << " to dvalue=" << dvalue << LEND;
          SDEBUG << "Yielding newesp=" << *newesp << LEND;
          rops->writeRegister(esprd, newesp);
          // Update the stack tracker and report on our actions.
          du.update_delta(fallthru, fallthrudelta);
          SDEBUG << "Setting stack delta following call to " << fallthrudelta
                 << " insnaddr=" << addr_str(fallthru) << LEND;
          // We're handled this case.
          continue;
        }

        // If it's a call to an external address, we don't need to do anything at all.  We'll
        // handle initialize the delta to zero when we process that function.
        if (!du.current_function->contains_insn_at(target)) continue;
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
    du.update_delta(target, newdelta);
  }

  // In cases where we've failed to process the instructio correctly, we now want to downgrade
  // the confidence to guess.  Historically, this logic has been called after the normal
  // processing above, but it appears that this might just simply overwrite all of the work
  // we've done previously.  We should probably investigate this case a little more carefully,
  // and move this code to the _top_ of this function if that's really true.
  if (downgrade) {
    // Forcibly downgrade the confidence to guess since we didn't emulate correctly.  This
    // should probably be handled as a minimum confidence parameter to handle stack delta or
    // something like that.
    StackDelta osd = du.sp_tracker.get_delta(iaddr);
    if (osd.confidence > ConfidenceGuess) {
      osd.confidence = ConfidenceGuess;
      du.update_delta(iaddr, osd);
    }
  }
}


// =========================================================================================
// =========================================================================================

// This is not a method in DUAnalysis, because I don't want to have to have a handle to the
// Analysis object to dump the definitions.  It would be nicer if the DUChain map had a method
// on it do this, but a global function will do for now.
void print_definitions(DUChain duc) {
  for (const Definition & d : duc) {
    // Some arbitrary indentation.
    OINFO << "      ";

    std::cout.width(30);
    OINFO << std::left << d.access.str();
    OINFO << " <=== ";
    if (d.definer == NULL) OINFO << "[no defining instruction]" << LEND;
    else OINFO << debug_instruction(d.definer) << LEND;
  }
}

// =========================================================================================
// Definition and Usage Analysis
// =========================================================================================

DUAnalysis::DUAnalysis(DescriptorSet& ds_, FunctionDescriptor & f)
  : sp_tracker(ds_), rops_callbacks(ds_), ds(ds_)
{
  // We've always got a real function to analyze.

  const ProgOptVarMap& vm = ds.get_arguments();

  propagate_conditions = (vm.count("propagate-conditions") > 0);

  current_function = &f;
  output_valid = false;
  all_returns = false;

  // Currently hard coded to do the traditional style of analysis.
  rigor = false;

  // The RiscOps can be obtained from the dispatcher once it's created.
  SymbolicRiscOperatorsPtr rops;

  SymbolicValuePtr proto = SymbolicValue::instance();
  RegisterDictionaryPtrArg regdict = ds.get_regdict();
  if (rigor) {
    // This is the new bit that instantiates the list-based memory state instead of the map based state.
    SymbolicRegisterStatePtr rstate = SymbolicRegisterState::instance(proto, regdict);
    SymbolicMemoryListStatePtr mstate = SymbolicMemoryListState::instance();
    SymbolicStatePtr state = SymbolicState::instance(rstate, mstate);
    rops = SymbolicRiscOperators::instance(ds, state, &rops_callbacks);
  }
  else {
    SymbolicRegisterStatePtr rstate = SymbolicRegisterState::instance(proto, regdict);
    SymbolicMemoryMapStatePtr mstate = SymbolicMemoryMapState::instance();
    SymbolicStatePtr state = SymbolicState::instance(rstate, mstate);
    rops = SymbolicRiscOperators::instance(ds, state, &rops_callbacks);
  }

  size_t arch_bits = ds.get_arch_bits();
  dispatcher = RoseDispatcherX86::instance(rops, arch_bits, {});

  // Configure the limit analysis.  The func_limit instance is local, but we still need to
  // configure the global limits of the analysis of all functions as well.
  get_global_limits().set_limits(func_limit, PharosLimits::limit_type::FUNC);

  // Now go do the analysis.
  if (rigor) {
    status = analyze_basic_blocks_independently();
  }
  else {
    status = solve_flow_equation_iteratively();
  }

  GDEBUG << "Analysis of function " << current_function->address_string() << " took "
         << func_limit.get_relative_clock().count() << " seconds." << LEND;

  if (status != LimitSuccess) {
    SERROR << "Analysis of function " << current_function->address_string () << " failed: " << func_limit.get_message() << LEND;
  }

}

// For debugging accessess
void DUAnalysis::print_accesses(rose_addr_t addr) const {
  SgAsmInstruction* insn = ds.get_insn(addr);
  OINFO << "Instruction accesses for: " << debug_instruction(insn) << LEND;
  auto iter = accesses.find(addr);
  if (iter == accesses.end()) {
    OERROR << "Instruction " << addr_str(addr) << " has no accesses!" << LEND;
  }
  else {
    for (const AbstractAccess & aa : iter->second) {
      OINFO << "  " << aa.str() << LEND;
    }
  }
}

// For debugging dependencies
void DUAnalysis::print_dependencies() const {
  OINFO << "Dependencies (Inst I, value read by I <=== instruction that defined value):" << LEND;
  for (const Addr2DUChainMap::value_type &p : depends_on) {
    SgAsmInstruction* insn = ds.get_insn(p.first);
    OINFO << debug_instruction(insn) << LEND;
    print_definitions(p.second);
  }
}

// For debugging dependents
void DUAnalysis::print_dependents() const {
  OINFO << "Dependents (Inst I, value defined by I <=== instruction that read value):" << LEND;
  for (const Addr2DUChainMap::value_type &p : dependents_of) {
    SgAsmInstruction* insn = ds.get_insn(p.first);
    OINFO << debug_instruction(insn) << LEND;
    print_definitions(p.second);
  }
}

const AbstractAccess* DUAnalysis::get_the_write(rose_addr_t addr) const {
  auto writes = get_writes(addr);
  auto i = std::begin(writes);
  if (i == std::end(writes)) return NULL;
  const AbstractAccess *aa = &*i;
  if (++i != std::end(writes)) {
    SgAsmInstruction* insn = ds.get_insn(addr);
    SERROR << "Instruction: " << debug_instruction(insn)
           << " had more than the expected single write." << LEND;
  }
  return aa;
}

const AbstractAccess* DUAnalysis::get_first_mem_write(rose_addr_t addr) const {
  auto mem_writes = get_mem_writes(addr);
  auto i = std::begin(mem_writes);
  if (i == std::end(mem_writes)) return NULL;
  return &*i;
}

// Is the abstract access in the provided instruction truly an uninitialized read?  Some
// operations, such as "AND X, 0" read X, but not in the sense intended.  This code attempts to
// detect that condition by also confirming that the value read was not used in a write expression
// in the same instruction.  If it was a fake read then there won't be a reference to the read value.
//
// In the case that this code was written for, the solution turned out to also require reading
// our hybrid definers/writers out of the latest_writers field on the abstract access.
bool
DUAnalysis::fake_read(SgAsmX86Instruction* insn, const AbstractAccess& aa) const
{

  // And here's why this algorithm got a function of it's own.  There's the mildly complex case
  // of "AND X, 0" and other simplification identities that don't really result in true reads.
  // We're going to test for that case now by also confirming that there are no writes (for
  // this instruction) which include the value read.  There would have to be a write involving
  // the read value or it wasn't really used.

  // This approach is a little lazy but I didn't want to have to write my own visitor class to
  // look for a specific subexpression.

  TreeNodePtr read_tn = aa.value->get_expression();

  for (const AbstractAccess& waa : get_writes(insn->get_address())) {
    TreeNodePtr write_tn = waa.value->get_expression();

    // search if this write includes the read. If it does, then it is not fake
    if (has_subexp (write_tn, read_tn)) {
      // The read was somewhere in the write, so the value was _truly_ read, and we've already
      // established that it was initialized by someone else, so it's not a truly uninitialized
      // read.
      return false;
    }
  }

  // read read value was not there
  GTRACE << " The read in " << debug_instruction(insn)
         << " was a fake read of: " << *(aa.value) << LEND;
  return true;
}

// Safely make a matching pair of dependency links.  Hopefully this doesn't perform too poorly.
// If it does, there are probably some optimizations that can be made using iterators that
// would help.
void DUAnalysis::add_dependency_pair(SgAsmX86Instruction *i1, SgAsmX86Instruction *i2, AbstractAccess access) {
  rose_addr_t a1 = 0;
  if (i1 != NULL) {
    a1 = i1->get_address();
    if (depends_on.find(a1) == depends_on.end()) depends_on[a1] = DUChain();
    depends_on[a1].insert(Definition(i2, access));
  }
  rose_addr_t a2 = 0;
  if (i2 != NULL) {
    a2 = i2->get_address();
    if (dependents_of.find(a2) == dependents_of.end()) dependents_of[a2] = DUChain();
    dependents_of[a2].insert(Definition(i1, access));
  }

  //OTRACE << "Creating instruction dependency pair: " << addr_str(a1) << " " << addr_str(a2) << LEND;
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
      for (const TreeNodePtr& tn : regval->get_possible_values()) {
        SymbolicValuePtr v = SymbolicValue::treenode_instance(tn);
        if (v->is_loader_defined()) {
          ds.update_import_target(v, insn);
        }
      }
    }
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
  value->comment(cmt);
  // This call instruction is now the only definer.
  value->defined_by(insn);

  return value;
}

void create_overwritten_register(SymbolicRiscOperatorsPtr rops,
                                 DescriptorSet const & ds,
                                 RegisterDescriptor rd,
                                 bool return_code,
                                 SymbolicValuePtr value,
                                 CallDescriptor* cd,
                                 const ParameterList& pl) {

  // Update the value of the register in the current state...
  rops->writeRegister(rd, value);
  // Record the write, since it didn't happen during semantics.
  rops->insn_accesses.push_back(AbstractAccess(ds, false, rd, value, rops->get_sstate()));

  // Set the return value in the call descriptor.  Return values are more complicated than our
  // current design permits.  For now, there's just one, which is essentially EAX.
  if (return_code) {
    cd->set_return_value(value);
    // Add the return register to the "returns" parameter list as well.
    ParameterList& params = cd->get_rw_parameters();
    SDEBUG << "Creating return register parameter " << unparseX86Register(rd, {})
           << " with value " << *value << LEND;
    ParameterDefinition & rpd = params.create_return_reg(rd, value);
    // If the upstream parameters list has only a single return value, assume that this is it,
    // and transfer the type.
    if (pl.get_returns().size() == 1) {
      const ParameterDefinition& upstream_pd = *pl.get_returns().begin();
      rpd.set_type(upstream_pd.get_type());
    }
  }
}

void
DUAnalysis::make_call_dependencies(SgAsmX86Instruction* insn, SymbolicStatePtr& cstate)
{
  SymbolicRiscOperatorsPtr rops = SymbolicRiscOperators::promote(dispatcher->operators());

  // This might not be correct.  I'm still a little muddled on how we're handling thunks.
  if (!insn_is_call(insn)) return;
  SDEBUG << "Creating parameter dependencies for " << debug_instruction(insn) << LEND;

  // Get the call descriptor for this call.  Should we do this externally?
  CallDescriptor* cd = ds.get_rw_call(insn->get_address()); // multiple
  if (cd == NULL) {
    SERROR << "No call descriptor for " << debug_instruction(insn) << LEND;
    return;
  }

  // Record that this function has a call involving the call descriptor.
  current_function->add_outgoing_call(cd);

  // This is the function descriptor that contains our parameters.  It might come from the
  // function descriptor in the call descriptor, or it might come from the import descriptor
  // (which must be const).
  const FunctionDescriptor* param_fd = NULL;

  // Get the function descriptor that describes the function that we're calling.  There's a
  // nasty bit of confusion here that still needs some additional cleanup.  This value can be
  // non-NULL even when the call is to an import descriptor, and so until we can figure out
  // where the bogus values are coming from (id == NULL) should be checked first.
  FunctionDescriptor* cfd = cd->get_rw_function_descriptor(); // Adds caller

  // But the call can also be to an import.   If it is, this will be the import descriptor.
  const ImportDescriptor* id = cd->get_import_descriptor();

  // If the call is to an import, the parameters will come from the function descriptor in the
  // import descriptor.  This description may contain useful types, etc. from the API database.
  if (id != NULL) {
    param_fd = id->get_function_descriptor();
  }
  // There's some nasty thunk logic here that I'd like to be elsewhere.
  else if (cfd != NULL) {
    const FunctionDescriptor* dethunked_cfd = cfd->follow_thunks_fd();
    // If we successfully followed thunks, it's easy.
    if (dethunked_cfd != NULL) {
      param_fd = dethunked_cfd;
      // A little hackish code to work around some ongoing const design issues.
      FunctionDescriptor* non_const_cfd = ds.get_rw_func(dethunked_cfd->get_address()); // for call updates
      cfd = non_const_cfd;
    }
    // But there might have been thunks to addresses that are imports.  This is a corner
    // condition that we're still hacking for in places like this. :-(
    else {
      // The worst this can do is set ID to NULL (again).
      rose_addr_t iaddr = cfd->follow_thunks();
      id = ds.get_import(iaddr);
      if (id != NULL) {
        GDEBUG << "Got parameters for " << debug_instruction(insn) << " from thunked import." << LEND;
        param_fd = id->get_function_descriptor();
      }
    }
  }

  // If we've failed to figure out which function we're calling to, it's pretty hopeless.  Just
  // give up and return to the caller.  This is done after the return code check, because it
  // allows us to preseume that all imports return a value without knowing any of the details
  // about the import (e.g. there's no function descriptor for the import).
  if (param_fd == NULL) {
    SWARN << "Unknown call target at: " << debug_instruction(insn)
          << ", parameter analysis failed." << LEND;
    return;
  }

  // If this is a function that we've explictly been asked to ignore because of a tag on the
  // called function, do that now.  To ignore the function means to treat the call to the
  // function as if it had no impact on the machine state at all (skip the rest of this
  // function).  One reason that the function might need to be ignored, is that it has two
  // modes of behavior -- one that really does nothing and another that substantially violates
  // calling convention standards but never returns.  One very common example of this, which
  // motivated this feature is the _RTC_CheckESP() function.  Because the function descriptor
  // was obtained from a call descriptor, it's possible for the function pointer to be NULL,
  // meaning that we can't actually compute the hash, so don't try if that will fail.
  if (param_fd->get_func()) {
    std::string sig = param_fd->get_pic_hash();
    if (ds.tags().check_hash(sig, "ignore")) {
      GDEBUG << "Call at " << cd->address_string() << " to function "
             << param_fd->address_string() << " was ignored." << LEND;
      return;
    }
  }

  // The parameter definitions for the function that we're calling (including the return code
  // type which we'll need before the other parameter analysis).
  const ParameterList& fparams = param_fd->get_parameters();

  // We'll be creating new parameter defintions on the call, so let's get a handle to the
  // parameter list object right now.
  ParameterList& call_params = cd->get_rw_parameters();

  // =========================================================================================
  // Register return code analysis...
  // =========================================================================================

  size_t arch_bits = ds.get_arch_bits();

  // This where we'll be storing the new value of EAX, get a handle to the state now.
  SymbolicStatePtr state = rops->get_sstate();

  RegisterDescriptor esprd = ds.get_stack_reg();
  RegisterDescriptor eaxrd = ds.get_arch_reg("eax");
  RegisterDescriptor ecxrd = ds.get_arch_reg("ecx");

  if (id != NULL) {
    // If we really are a call to an external import, just assume that we return a value.
    // Cory does't think that there are any external APIs that don't follow the standard
    // calling conventions, and none of them permit true returns void calls.  In the
    // future, this code branch can become more sophisticated, asking the import
    // configuration what the type of return value is and so on.
    SDEBUG << "Creating return code for import " << id->get_long_name()
           << " at " << debug_instruction(insn) << LEND;
    // We don't handle situations involving more than one return value from an import at all
    // right now.  That's probably ok, since it probably never happens.
    if (fparams.get_returns().size() > 1) {
      GFATAL << "Multiple return values not analyzed correctly." << LEND;
    }
    // We're going to overwrite EAX in all cases, since all external calling conventions
    // declare EAX as a scrtahc register, even if the function doesn't return a value.  Whether
    // the return code is a "real" return code involving an intentional return of a value, is
    // determined by whether our parameter returns list contains any values.  We should
    // probably work towards getting this register out of the calling convention data so that
    // we don't have to make architecture specific calls here.
    bool real_return_value = (fparams.get_returns().size() > 0);
    // This call simply creates the symbolic value that the return code is set to.
    SymbolicValuePtr rv = create_return_value(insn, arch_bits, real_return_value);
    // This call propogates the performs the actual write, creates the abstract access, sets
    // the return value in the call descriptor, propogates the parameter definition, etc.
    create_overwritten_register(rops, ds, eaxrd, real_return_value, rv, cd, fparams);
    SDEBUG << "Setting standard return value for " << addr_str(insn->get_address())
           << " to " << *(rops->read_register(eaxrd)) << LEND;
  }
  // There Otherwise (if cfd == NULL), check for an import.
  else if (cfd != NULL) {
    SDEBUG << "Adding caller " << debug_instruction(insn) << " to call targets for "
           << cfd->address_string() << LEND;
    cfd->add_caller(insn->get_address());

    const RegisterUsage& ru = cfd->get_register_usage();
    SDEBUG << "Call at " <<  addr_str(insn->get_address())
           << " returns-ecx: " << cfd->get_returns_this_pointer() << LEND;

    for (RegisterDescriptor rd : ru.changed_registers) {
      if (rd != eaxrd) {
        // Mark the register as overwritten.
        SymbolicValuePtr rv = create_return_value(insn, rd.get_nbits(), false);
        create_overwritten_register(rops, ds, rd, false, rv, cd, fparams);
        GTRACE << "Setting changed register " << unparseX86Register(rd, {})
               << " for insn " << addr_str(insn->get_address())
               << " to value=" << *(rops->read_register(rd)) << LEND;
        // And we're done with this register...
        continue;
      }

      // EAX special cases...
      if (cfd->get_returns_this_pointer()) {
        // Assign to EAX in the current state, the value of ECX from the previous state.
        // Read the value of ecx from the current state at the time of the call.
        SymbolicValuePtr ecx_value = cstate->read_register(ecxrd);
        create_overwritten_register(rops, ds, eaxrd, true, ecx_value, cd, fparams);
        GTRACE << "Setting return value for " << addr_str(insn->get_address())
               << " to ECX prior to call, value=" << *(rops->read_register(eaxrd)) << LEND;
      }
      else {
        // Create a new symbolic value to represent the modified return code value.
        SymbolicValuePtr eax_value = create_return_value(insn, arch_bits, true);
        create_overwritten_register(rops, ds, eaxrd, true, eax_value, cd, fparams);
        GTRACE << "Setting standard return value for " << addr_str(insn->get_address())
               << " to " << *(rops->read_register(eaxrd)) << LEND;
      }
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

  // =========================================================================================
  // Handle creation of register parameters first because it's not really dependent on whether
  // we had stack failures or not.
  // =========================================================================================

  // Go through each parameter to the call, and create an appropriate dependency for register
  // parameters.
  for (const ParameterDefinition& pd : fparams.get_params()) {
    // We'll handled non-register (memory) parameters a bit later (maybe).
    if (not pd.is_reg()) continue;

    SDEBUG << "Found register parameter: " << unparseX86Register(pd.get_register(), {})
           << " for call " << cd->address_string() << LEND;

    // Create a dependency between the instructions that last modifier the value of the
    // register, and the call instruction that uses the value (or the memory at the value?)

    // Read the value out of the current states
    SymbolicValuePtr rv = cstate->read_register(pd.get_register());
    // The call reads the register value.
    AbstractAccess aa = AbstractAccess(ds, true, pd.get_register(), rv, cstate);
    SgAsmX86Instruction *latest_writer = NULL;

    // Create dependencies between all latest writers and the call instruction.  Converting
    // this code to use latest writers instead of the modifiers resulted in dependencies,
    // where the previous approach was producing none (at least at the time).
    for (SgAsmInstruction* gm : aa.latest_writers) {
      SDEBUG << "Adding call dependency for " << debug_instruction(insn) << " to "
             << debug_instruction(gm) << LEND;
      // Convert from a generic instruction to an X86 instruction (and save last one).
      latest_writer = isSgAsmX86Instruction(gm);
      // Now create the actual dependency.
      add_dependency_pair(insn, latest_writer, aa);
    }

    // Also we need to find (or create) a parameter for this register on the calling side.
    // This routine will create the register definition if it doesn't exist and return the
    // existing parameter if it does.  In a departure from the API I used on the stack side,
    // I just had the create_reg_parameter() interface update the symbolic value and modified
    // instruction as well.  Maybe we should change the stack parameter interface to match?
    SymbolicValuePtr pointed_to = cstate->read_memory(rv, arch_bits);
    call_params.create_reg_parameter(pd.get_register(), rv, latest_writer, pointed_to);
  }

  // =========================================================================================
  // Stack dependency analysis.  Move to separate function?
  //
  // This code is mostly about deciding whether our understanding of the stack delta is correct
  // enough to apply the knowledge about the call target to the local environment.
  // =========================================================================================

  // What was our stack delta going into the call instruction?
  StackDelta sd = sp_tracker.get_delta(insn->get_address());

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
    ++sd_failures;
    return;
  }

  // Also don't make the situation worse by creating a crazy number of dependencies if the
  // number of call parameters is unrealistically large.
  if (params.delta > ARBITRARY_PARAM_LIMIT) {
    SERROR << "Skipping creation of " << params.delta << " bytes of parameter dependencies"
           << " due to high parameter count for call: " << debug_instruction(insn) << LEND;
    // We know we didn't do the right thing, so let's tick failures.
    ++sd_failures;
    return;
  }

  // Dump the memory state
  //SDEBUG << "Memory state:" << state << LEND;

  SDEBUG << "Call: " << debug_instruction(insn) << " params=" << params.delta << LEND;

  // =========================================================================================
  // Parameter definition analysis, creation, etc.
  // =========================================================================================

  // Report the parameters that we expect to find...
  if (GTRACE) {
    GTRACE << "Parameters for call at: " << debug_instruction(insn) << " are: " << LEND;
    fparams.debug();
  }

  // Go through each parameter to the call, and create an appropriate dependency.
  for (const ParameterDefinition& pd : fparams.get_params()) {
    // We've already handled register parameters earlier.
    if (pd.is_reg()) continue;

    // From the old code for doing this...
    size_t p = pd.get_stack_delta();

    // The parameter will be found on the stack at [offset].  The sd.delta component is to
    // convert to stack deltas relative to the call.  And p is the variable part (the parameter
    // offset in the called function).  The outer sign is because we've been working with
    // positive deltas, and the hardware really does negative stack addresses.
    int64_t offset = -(sd.delta - p);
    // Non-negative offsets for parameters are unexpected, and produce ugly error messages
    // later.  Additionally, it's not immediately obviously from the error message that the
    // sign is wrong (probably indicating a stack delta analysis failure).  Let's generate an
    // error message specific to this situation, and the continue.
    if (offset > -4 || (offset % 4 != 0)) {
      SWARN << "Unexpected parameter offset (" << offset << ") at call: "
            << debug_instruction(insn) << LEND;
      continue;
    }

    SDEBUG << "Creating read of parameter " << p << " at stack offset: [esp" << offset << "]" << LEND;

    // Turn the offset into a SymbolicValue and find the memory cell for that address.
    // RegisterDescriptor esprd = dispatcher->findRegister("esp", arch_bits);
    SymbolicValuePtr esp_0 = cstate->read_register(esprd);
    //SDEBUG << "Initial ESP is supposedly:" << *esp_0 << LEND;
    SymbolicValuePtr mem_addr = SymbolicValue::promote(rops->add(esp_0, rops->number_(arch_bits, p)));
    //SymbolicValuePtr mem_addr = SymbolicValuePtr(new SymbolicValue(arch_bits, offset));
    //SDEBUG << "Constructed memory address:" << *mem_addr << LEND;

    const SymbolicMemoryMapStatePtr& mstate =
      SymbolicMemoryMapState::promote(state->memoryState());
    const MemoryCellPtr memcell = mstate->findCell(mem_addr);
    if (memcell == NULL) {
      SWARN << "No definer for parameter " << p << " at [esp" << offset
            << "] for call: " << debug_instruction(insn) << LEND;
      continue;
    }

    // Who last modified this address?  This will typically be the push instruction that pushed
    // the parameter onto the stack before the call.  This code is a little bit incorrect in
    // that we're assuming that all four bytes have still been modified by the same instruction
    // as the first byte was.
    SymbolicValuePtr mca = SymbolicValue::promote(memcell->address());

    // Use rops->readMemory to read memory to read either 32 or 64 bits depending on the
    // architecture.  In truth, we have no idea how large the object being pointed to is and
    // this choice is arbitary.  For now I've made it the archtecture size since that seems the
    // least likely to cause problems.  The segment register and the condition are literally
    // unused, and the default value shouldn't be used but might be to create a deafult value
    // during the read.  We used to read directly out of the memory map, but we need proper
    // reassembly of multiple bytes so now we call readMemory.
    RegisterDescriptor csrd = dispatcher->findRegister("cs", 16);
    SymbolicValuePtr dflt = SymbolicValue::promote(rops->undefined_(arch_bits));
    SymbolicValuePtr cond = SymbolicValue::promote(rops->undefined_(1));
    BaseSValuePtr bmcv = rops->readMemory(csrd, mca, dflt, cond);
    SymbolicValuePtr mcv = SymbolicValue::promote(bmcv);

    SDEBUG << "Parameter memory address:" << *mca << LEND;
    SDEBUG << "Parameter memory value:" << *mcv << LEND;

    const auto & writers = memcell->getWriters();
    // Not having any modifiers is fairly common in at least one binary file we looked at.
    // It's probably caused by stack delta analysis failures, so let's make that a warning.
    if (writers.size() == 0) {
      SWARN << "No latest writer for call parameter " << p << " at [esp" << offset << "] addr= "
            << *mca << "value=" << *mcv << " at: " << debug_instruction(insn) << LEND;
      continue;
    }

    // The call instruction reads this address, and gets the current value.  We're assuming
    // that we read four bytes of memory, which is incorrect, and we should probably get around
    // to fixing this, but we'll need proper protoypes to know the type and size of the
    // parameter on the stack, which we presently don't have.
    AbstractAccess aa = AbstractAccess(ds, true, mca, 4, mcv, state);

    // The most common case is for there to be only one writer.  This is the typical scenario
    // where the arguments all pushed onto the stack immediately before the call.  If any of
    // the parameters are computed conditionally however, there may be more than one push
    // instruction responsible for writing the parameter.  The value of the parameter should
    // already be an ITE expression, but we need to create multiple dependencies here as well.

    // Save the last of the latest writers for adding to the parameter definition.
    SgAsmX86Instruction *writer = NULL;
    // Now get the writers for just this one cell.  There's been some recent email discussion
    // with Robb that this approach is defective, and there's a fix pending in ROSE.
    for (rose_addr_t waddr : writers.values()) {
      SgAsmInstruction* winsn = ds.get_insn(waddr);
      assert(winsn);
      writer = isSgAsmX86Instruction(winsn);
      assert(writer);

      SDEBUG << "Adding call dependency for " << debug_instruction(insn) << " to "
             << debug_instruction(writer) << LEND;

      // Now create the actual dependency.
      add_dependency_pair(insn, writer, aa);
    }
    ParameterDefinition* cpd = call_params.create_stack_parameter(p);
    if (cpd == NULL) {
      GFATAL << "Unable to create stack parameter " << p << " for offset [esp" << offset
             << "] for call: " << debug_instruction(insn) << LEND;
    }
    else {
      SymbolicValuePtr pointed_to = state->read_memory(mcv, arch_bits);
      // The writer variable is only _one_ of the writers.  The parameter definition can't
      // currently store more than one evidence instruction, so I'm not sure it really matters,
      // but we should fix this by enhancing parameter definitions to have complete lists.
      cpd->set_stack_attributes(mcv, mca, writer, pointed_to);
      // Copy names, types and directions from the function descriptor parameter definition.
      cpd->copy_parameter_description(pd);
      //OINFO << " CPD:";
      //cpd->debug();
      //OINFO << " CPD:";
      //fpd->debug();
    }
  }
}

// This code was supposed to make "jmp [import]" have a non-NULL successor list.
// Unfortunately, there no easy way to update successors on the import.  I presume this
// function (which is neve called) was left here as a reminder to eventually fix this.
void update_jump_targets(const DescriptorSet& ds, SgAsmInstruction* insn) {
  boost::optional<rose_addr_t> target = insn_get_jump_deref(insn);
  if (target) {
    const ImportDescriptor* id = ds.get_import(*target);
    if (id != NULL) {
      // There's NO add_successor()!!!
    }
  }
}

void DUAnalysis::guess_function_delta() {
  // Because it's shorter than current_function...
  FunctionDescriptor* fd = current_function;


  for (CFGVertex vertex : fd->get_return_vertices()) {
    const SgAsmBlock *block = convert_vertex_to_bblock(cfg, vertex);
    // Find the return instruction.
    const SgAsmStatementPtrList &insns = block->get_statementList();
    assert(insns.size() > 0);
    SgAsmX86Instruction *last = isSgAsmX86Instruction(insns[insns.size() - 1]);
    if (last != NULL and last->get_kind() == x86_ret) {
      // Get the number of bytes popped off the stack by the return instruction (not counting the
      // return address).
      SgAsmExpressionPtrList &ops = last->get_operandList()->get_operands();
      if (ops.size() > 0) {
        SgAsmIntegerValueExpression *val = isSgAsmIntegerValueExpression(ops[0]);
        if (val != NULL) {
          // This is the number on the RETN instruction and is also our expected stack delta.
          int64_t retn_size  = val->get_absoluteValue();
          SDEBUG << "Guessing that function " << fd->address_string() << " pops "
                 << retn_size << " additional bytes off the stack." << LEND;
          // Mak a StackDelta() obect and record it as _our_ stack delta.  This value will get
          // used if the analyzed function is recursive and calls itself.
          StackDelta guessed = StackDelta(retn_size, ConfidenceGuess);
          fd->update_stack_delta(guessed);
          return;
        }
      }
    }
  }
}

void DUAnalysis::update_function_delta() {
  // Because it's shorter than current_function...
  FunctionDescriptor* fd = current_function;

  // Our unified stack delta across all return instructions.
  StackDelta unified = StackDelta(0, ConfidenceNone);
  bool first = true;
  // This is the number on the RETN instruction and is also our expected stack delta.
  int64_t retn_size = 0;

  for (CFGVertex vertex : fd->get_return_vertices()) {
    const SgAsmBlock *block = convert_vertex_to_bblock(cfg, vertex);
    // Find the return instruction.
    const SgAsmStatementPtrList &insns = block->get_statementList();
    assert(insns.size() > 0);
    SgAsmX86Instruction *last = isSgAsmX86Instruction(insns[insns.size() - 1]);
    if (last == NULL) {
      // An error should be reported later in the return block merging code.
      continue;
    }
    SDEBUG << "Last instruction in ret-block:" << debug_instruction(last) << LEND;
    StackDelta ld = sp_tracker.get_delta(last->get_address());
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
        const ImportDescriptor* id = ds.get_import(target);
        if (id != NULL) {
          td = id->get_stack_delta();
          SDEBUG << "Branch target is to " << *id << LEND;
        }
      }
      // If that failed, maybe we're just a branch directly to some other function.
      else {
        boost::optional<rose_addr_t> opt_target = insn_get_branch_target(last);
        // If insn_get_branch_target() failed, don't update the stack delta based on that.
        if (!opt_target) continue;
        target = *opt_target;
        td = sp_tracker.get_delta(target);
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
  if (unified.confidence <= ConfidenceConfident && unified.delta != retn_size) {
    SWARN << "Unified stack delta for function " << fd->address_string()
          << " does not match RETN size of: " << retn_size
          << " unified stack delta was: " << unified << LEND;
    // We used to charge ahead, knowing that we were wrong...  It seems wiser to use the RETN
    // size, at least until we have a better guessing algorithm, and a more reliable stack
    // delta system in general.
    unified.delta = retn_size;
    unified.confidence = ConfidenceGuess;
  }
  // In this case, we lost confidence in our stack delta, but in the end it appears to have
  // worked out ok, because the final stack delta matches our expected return size, and that's
  // what is most important.  Rather than panicking upstream callers about our lack of
  // confidence, move the confidence back to "guess".
  if (unified.confidence == ConfidenceWrong && unified.delta == retn_size) {
    SDEBUG << "Restoring stack delta confidence for expected delta to 'guess'." << LEND;
    unified.confidence = ConfidenceGuess;
  }
  if (unified.confidence > ConfidenceNone) {
    fd->update_stack_delta(unified);
  }
  SDEBUG << "Final unified stack delta (reread) for function " << fd->address_string()
         << " is: " << fd->get_stack_delta() << LEND;
}

// Determine whether we return a value at all, and if it's the initial value of ECX.  This
// routine should probably continue to be part of the DUAnalysis class because it uses
// input_state and output_state to do it's work.
void DUAnalysis::analyze_return_code() {
  // Because it's shorter than current_function...
  FunctionDescriptor* fd = current_function;

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
  // hack to make up for a lack of real calling convention detection.  We have sufficient
  // calling convention data to improve this code now, but that's not my current goal.
  RegisterDescriptor eaxrd = ds.get_arch_reg("eax");
  RegisterDescriptor ecxrd = ds.get_arch_reg("ecx");

  SymbolicValuePtr retvalue = output_state->read_register(eaxrd);
  SymbolicValuePtr initial_ecx = input_state->read_register(ecxrd);

  // If EAX at the end of the function contains the same value as ECX at the beginning of the
  // function, then we're return ECX in EAX...
  bool returns_ecx = (*retvalue == *initial_ecx);
  STRACE << "Checking return values for function " << fd->address_string() << LEND;
  STRACE << "Returns ECX=" << returns_ecx
         << " EAX=" << retvalue->str() << " ECX=" << initial_ecx->str() << LEND;
  fd->set_returns_this_pointer(returns_ecx);

  // Emitted once per function...
  SDEBUG << "Returns thisptr=" << fd->get_returns_this_pointer()
         << " function=" << fd->address_string() << LEND;
}

// This function attempts to assign a value to the function summary output state variable.  In
// theory, it does this by merging all return blocks into a single consistent result.  Wes'
// original code appeared to have multiple problems, and there used to be a horrible
// hodge-podge set of parameters passed, but apparently the function got cleaned up quite a lot
// because now it only needs the state histories.  Cory has not reviewed this function
// carefully to see if it's actually correct yet, but it's certainly on the road to being
// reasonable now.
void
DUAnalysis::update_output_state()
{

  // Until we reach the end of this function, assume that we're malformed with respect to
  // having a well formed set of return blocks.
  output_valid = false;
  all_returns = false;

  // Because it's shorter than current_function...
  FunctionDescriptor* fd = current_function;

  // This list isn't really the return blocks, but rather all "out" edges in the control flow
  // graph which can contain jumps, and other strange things as a result of bad partitioning.
  std::vector<CFGVertex> out_vertices = fd->get_return_vertices();

  // Create an empty output state when we don't know what else to do...  In this case because
  // there are no out edges from the function...  For example a jump to itself...  This choice
  // can result in confusing downstream behavior, because the output state is not related to the input
  if (out_vertices.size() == 0) {
    SERROR << "Function " << fd->address_string() << " has no out edges." << LEND;
    SymbolicValuePtr proto = SymbolicValue::instance();
    RegisterDictionaryPtrArg regdict = ds.get_regdict();
    SymbolicRegisterStatePtr rstate = SymbolicRegisterState::instance(proto, regdict);
    SymbolicMemoryMapStatePtr mstate = SymbolicMemoryMapState::instance();
    output_state = SymbolicState::instance(rstate, mstate);
    output_valid = false;
    return;
  }

  // Make a list of real return blocks that are worth merging into the outout state.
  std::vector<const SgAsmBlock*> ret_blocks;
  for (CFGVertex vertex : out_vertices) {
    const SgAsmBlock* block = convert_vertex_to_bblock(cfg, vertex);
    rose_addr_t addr = block->get_address();
    // The call to at() should not throw unless our code is using the wrong CFG.
    const BlockAnalysis & analysis = blocks.at(addr);

    // Blocks that we've previously identified as "bad" are not valid return blocks.
    if (analysis.bad) continue;

    // The block also needs to have an entry in the state history to be useful.
    if (!analysis.output_state) continue;

    // Find the last instruction, and check to see if it's a return.
    const SgAsmStatementPtrList &insns = block->get_statementList();
    if (insns.size() == 0) continue;

    SgAsmX86Instruction *last = isSgAsmX86Instruction(insns[insns.size() - 1]);
    if (last == NULL) {
      GERROR << "Last instruction in block " << addr_str(block->get_address())
             << " was not an X86 instruction!" << LEND;
      continue;
    }
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
    SymbolicValuePtr proto = SymbolicValue::instance();
    RegisterDictionaryPtrArg regdict = ds.get_regdict();
    SymbolicRegisterStatePtr rstate = SymbolicRegisterState::instance(proto, regdict);
    SymbolicMemoryMapStatePtr mstate = SymbolicMemoryMapState::instance();
    output_state = SymbolicState::instance(rstate, mstate);
    output_valid = false;
    return;
  }

  // This means that we were able to merge output blocks.  It does not mean that all out-edges
  // were merged, since some of them might have been non-return blocks.  (See all_returns).
  output_valid = true;

  // If not all of the blocks got copied into the return blocks set, then we must have
  // discarded one or more for being bad code, or lacking return statements.  That means that
  // there's something a wrong with the function, and we should only indicate that it has a
  // well formed return block structure if every block ended with a return.
  if (ret_blocks.size() == out_vertices.size()) all_returns = true;

  // Regardless of whether all or just some of the blocks ended in returns, we can still create
  // an output state.  Do that now by beginning with the first state, and merging into it all
  // of the other states.  There's no need to confirm that each address is in state histories,
  // because w did that when filtering the blocks earlier.
  rose_addr_t addr = ret_blocks[0]->get_address();
  output_state = blocks.at(addr).output_state->sclone();
  for (const SgAsmBlock *block : ret_blocks) {
    addr = block->get_address();
    SymbolicRiscOperatorsPtr rops = SymbolicRiscOperators::promote(dispatcher->operators());
    output_state->merge(blocks.at(addr).output_state, rops.get(), SymbolicValue::incomplete(1));
  }
}

void DUAnalysis::save_treenodes() {

  // Map for every treenode we every find
  SymbolicRiscOperatorsPtr rops = SymbolicRiscOperators::promote(dispatcher->operators());

  unique_treenodes_ = rops->unique_treenodes;
  memory_accesses_ = rops->memory_accesses;
}

void
DUAnalysis::create_blocks()
{
  // The entry block is always zero when it exists (see more detailed test in CDG constructor).
  static constexpr CFGVertex entry_vertex = 0;

  // Which control flow graph we're using here depends on how we were called.  If we're using
  // the trimmed Pharos CFG, we won't even know about "bad" blocks, but if we're using the ROSE
  // CFG they'll still be in there.  Either way, the block list will match the CFG.
  for (auto vertex : cfg_vertices(cfg)) {
    BlockAnalysis block = BlockAnalysis(*this, cfg, vertex, vertex == entry_vertex);
    blocks.emplace(block.get_address(), std::move(block));
  }
}

// Print some information about a state to simplify debugging of the merge algorithm.
// No effect on the analysis and enabled/disabled with STATE_DEBUG.
void
DUAnalysis::debug_state_merge(UNUSED const SymbolicStatePtr& cstate,
                              UNUSED const std::string label) const
{
#ifdef STATE_DEBUG
  Semantics2::BaseSemantics::Formatter formatter;
  formatter.set_suppress_initial_values(true);
  formatter.set_show_latest_writers(false);
  formatter.set_show_properties(false);
  formatter.set_indentation_suffix("...");

  if (cstate) {
    OINFO << "================= " << label << " ================" << LEND;
    // This is the magic syntax that makes the formatter work (most conveniently).
    OINFO << (*cstate+formatter);
  }
  else {
    OINFO << "============= " << label << " (NONE) =============" << LEND;
  }
#endif
}

// Print some information about a state to simplify debugging of the merge algorithm.
// No effect on the analysis and enabled/disabled with STATE_DEBUG.
void
DUAnalysis::debug_state_replaced(UNUSED const rose_addr_t baddr) const
{
#ifdef STATE_DEBUG
  Semantics2::BaseSemantics::Formatter formatter;
  formatter.set_suppress_initial_values(true);
  formatter.set_show_latest_writers(false);
  formatter.set_show_properties(false);
  formatter.set_indentation_suffix("...");

  const BlockAnalysis & analysis = blocks.at(baddr);
  if (!analysis.output_state) {
    OINFO << "============ STATE BEING REPLACED (NONE) ===============" << LEND;
  }
  else {
    OINFO << "================ STATE BEING REPLACED ==================" << LEND;

    const SymbolicStatePtr fstate = analysis.output_state;
    OINFO << (*fstate+formatter);
  }
  DSTREAM << "Updating state history for " << addr_str(baddr) << LEND;
#endif
}

SymbolicValuePtr
DUAnalysis::get_address_condition(const BlockAnalysis& pred_analysis,
                                  SgAsmBlock* pblock, const rose_addr_t bb_addr)
{
  using namespace Rose::BinaryAnalysis;
  static auto nullnode = TreeNodePtr();

  if (insn_is_call(last_x86insn_in_block(pblock))) {
    return SymbolicValue::treenode_instance(SymbolicExpr::makeBooleanConstant(true));
  }

  if (!pred_analysis.output_state) {
    return SymbolicValuePtr();
  }
  SymbolicRegisterStatePtr ip_reg_state = pred_analysis.output_state->get_register_state();

  if (!ip_reg_state) {
    return SymbolicValuePtr();
  }

  size_t arch_bits = ds.get_arch_bits();
  TreeNodePtr leaf_addr = SymbolicExpr::makeIntegerConstant(arch_bits, bb_addr);
  RegisterDescriptor iprd = ds.get_ip_reg();
  SymbolicValuePtr ip_sv = ip_reg_state->read_register(iprd);

  return get_leaf_condition(ip_sv, leaf_addr, nullnode);

  // return final_condition;
}

// Merge all predecessor block's output states into a single state that becomes the input state
// for the next this block.
// Merge all predecessor block's output states into a single state that becomes the input state
// for the next this block.
SymbolicStatePtr
DUAnalysis::merge_predecessors(CFGVertex vertex)
{
  // The merged state that we return.
  SymbolicStatePtr cstate;

  SymbolicRiscOperatorsPtr rops = SymbolicRiscOperators::promote(dispatcher->operators());

  SgAsmBlock *bblock = get(boost::vertex_name, cfg, vertex);
  assert(bblock!=NULL);
  rose_addr_t baddr = bblock->get_address();

  // The loop to merge predecessors.
  size_t merge_cnt = 0;
  size_t edge_cnt = 0;
  const BlockAnalysis & analysis = blocks.at(baddr);
  ResourceLimit merge_limit;
  for (SgAsmBlock *pblock : cfg_in_bblocks(cfg, vertex)) {
    rose_addr_t paddr = pblock->get_address();
    DSTREAM << "Merging states for predecessor " << addr_str(paddr)
            << " into block " << addr_str(baddr) << LEND;

    const BlockAnalysis & pred_analysis = blocks.at(paddr);
    if (pred_analysis.output_state) {
      merge_cnt++;
      debug_state_merge(cstate, "STATE BEFORE MERGE");
      debug_state_merge(pred_analysis.output_state, "STATE BEING MERGED");
      if (cstate) {
        assert(edge_cnt > 0);
        cstate->merge(pred_analysis.output_state, rops.get(),
                      analysis.conditions[edge_cnt - 1]);
      }
      else {
        cstate = pred_analysis.output_state->sclone();
      }
      debug_state_merge(cstate, "STATE AFTER MERGE");
    }

    ++edge_cnt;
  }

  DSTREAM << "Merging " << merge_cnt << " predecessors for block " << addr_str(baddr)
          << " in function " << current_function->address_string()
          << " (loop #" << func_limit.get_counter() << ") took "
          << merge_limit.get_relative_clock().count() << " seconds." << LEND;

  if (!cstate) {
    if (bblock != current_function->get_entry_block()) {
      GERROR << "Block " << addr_str(baddr) << " has no predecessors." << LEND;
    }
    // This is apparently not the same as input_state. :-(
    return initial_state;
  }

  return cstate;
}

// Merge the predecessor block's output state while *preserving* condtions. The other merge
// predecessory routine uses fresh expressions for condtions rather than accumulating
// conditions during analysis. This is performant and suitable for certain types of analysis,
// but it will not work for other types of analysis
SymbolicStatePtr
DUAnalysis::merge_predecessors_with_conditions(CFGVertex vertex)
{
  using namespace Rose::BinaryAnalysis;

  // The merged state that we return.
  SymbolicStatePtr cstate;

  SymbolicRiscOperatorsPtr rops = SymbolicRiscOperators::promote(dispatcher->operators());

  SgAsmBlock *bblock = get(boost::vertex_name, cfg, vertex);
  assert(bblock!=NULL);
  rose_addr_t baddr = bblock->get_address();

  // The loop to merge predecessors.
  size_t merge_cnt = 0;
  BlockAnalysis & analysis = blocks.at(baddr);
  ResourceLimit merge_limit;

  // The entry condition treenode, which will include ancestors
  TreeNodePtr entry_cond_tnp;

  for (SgAsmBlock *pblock : cfg_in_bblocks(cfg, vertex)) {
    rose_addr_t paddr = pblock->get_address();

    DSTREAM << "Merging states for predecessor " << addr_str(paddr)
            << " into block " << addr_str(baddr) << LEND;

    // Every direct predecessor must be and'd with the current analysis
    const BlockAnalysis & pred_analysis = blocks.at(paddr);
    if (pred_analysis.output_state) {

      merge_cnt++;
      debug_state_merge(cstate, "STATE BEFORE MERGE");
      debug_state_merge(pred_analysis.output_state, "STATE BEING MERGED");

      // This is a predecessor condition that must be conjoined with
      SymbolicValuePtr prev_cond = pred_analysis.entry_condition;
      SymbolicValuePtr addr_cond = get_address_condition(pred_analysis, pblock, baddr);
      SymbolicValuePtr merge_cond =
        SymbolicValue::treenode_instance(
          SymbolicExpr::makeAnd(addr_cond->get_expression(),
                                prev_cond->get_expression()));
      DSTREAM << "Merged condition addr=" << addr_str(baddr)
              << " cond=" << *merge_cond << LEND;

      if (cstate) {
        // There is a state, so it must be disjoined with the previous state
        entry_cond_tnp =
          SymbolicExpr::makeOr(merge_cond->get_expression(), entry_cond_tnp);

        SymbolicValuePtr inverted_merge_cond = SymbolicValue::treenode_instance(
          SymbolicExpr::makeInvert(merge_cond->get_expression()));

        cstate->merge(pred_analysis.output_state, rops.get(), inverted_merge_cond);
      }
      else {
        // First time through the loop the complete condition is the merge condition; on
        // subsequent iterations it will be disjoined
        entry_cond_tnp = merge_cond->get_expression();
        cstate = pred_analysis.output_state->sclone();
      }
      debug_state_merge(cstate, "STATE AFTER MERGE");
    }
  }

  if (entry_cond_tnp) {
    DSTREAM << "Final condition addr=" << addr_str(baddr)
            << " cond=" << *entry_cond_tnp << LEND;
    analysis.entry_condition = SymbolicValue::treenode_instance(entry_cond_tnp);
  }

  DSTREAM << "Merging " << merge_cnt << " predecessors for block " << addr_str(baddr)
          << " in function " << current_function->address_string()
          << " (loop #" << func_limit.get_counter() << ") took "
          << merge_limit.get_relative_clock().count() << " seconds." << LEND;

  if (!cstate) {
    if (bblock != current_function->get_entry_block()) {
      GERROR << "Block " << addr_str(baddr) << " has no predecessors." << LEND;
    }
    // This is apparently not the same as input_state. :-(
    return initial_state;
  }

  return cstate;
}

// Process one basic block (identified by a CFG vertex).  Merge the output states of the
// predcessor blocks, evaulate the specified block, save the resulting state in the state
// histories map, and mark the successors as pending.  Return true is the output state changed
// from the previous iteration.
bool
DUAnalysis::process_block_with_limit(CFGVertex vertex)
{
  bool changed = false;

  SgAsmBlock *bblock = get(boost::vertex_name, cfg, vertex);
  assert(bblock!=NULL);
  rose_addr_t baddr = bblock->get_address();
  BlockAnalysis& analysis = blocks.at(baddr);

  ResourceLimit block_limit;
  DSTREAM << "Starting iteration " << analysis.iterations << " for block " << addr_str(baddr)
          << " Reason " << bblock->reason_str("", bblock->get_reason()) << LEND;

  // Incoming rops for the block.  This is the merge of all out policies of predecessor
  // vertices, with special consideration for the function entry block.
  SymbolicRiscOperatorsPtr rops = SymbolicRiscOperators::promote(dispatcher->operators());

  // There is now a setting to determine whether the conditions computed for basic blocks are
  // preserved and propogated when merging predecessors. Real conditions are needed for certain
  // classes of analysis, such as path finding where program state
  SymbolicStatePtr cstate = nullptr;
  if (propagate_conditions) {
    cstate = merge_predecessors_with_conditions(vertex);
  }
  else {
    cstate = merge_predecessors(vertex);
  }
  analysis.input_state = cstate->sclone();
  rops->currentState(cstate);


  analysis.analyze(true);

  // If output of this block changed from what we previously calculated, then mark all its
  // children as pending.
  if (!(analysis.output_state && cstate->equals(analysis.output_state))) {
    changed = true;

    debug_state_merge(cstate, "STATE AFTER EXECUTION");
    debug_state_replaced(baddr);
    analysis.output_state = cstate;
    debug_state_merge(analysis.output_state, "STATE AFTER UPDATE");

    for (SgAsmBlock *sblock : cfg_out_bblocks(cfg, vertex)) {
      rose_addr_t saddr = sblock->get_address();
      blocks.at(saddr).pending = true;
      DSTREAM << "Marking successor block " << addr_str(saddr) << " for revisting." << LEND;
    }
  }


  DSTREAM << "Analysis of basic block " << addr_str(baddr) << " in function "
          << current_function->address_string() << " (loop #" << func_limit.get_counter()
          << ") took " << block_limit.get_relative_clock().count() << " seconds." << LEND;

  DSTREAM << "========================================================================" << LEND;

  return changed;
}

// This must be called, post block analysis
// void
// DUAnalysis::add_edge_conditions() {

//   struct EdgeCondition {
//     SymbolicValuePtr condition;
//   };
//   using Cfg2 = boost::adjacency_list<boost::vecS, boost::vecS,
//                                      boost::bidirectionalS,
//                                      boost::vertex_name_t, EdgeCondition>;

//    using Cfg2Vertex = boost::graph_traits<Cfg2>::vertex_descriptor;
//    using Cfg2VertexIter = boost::graph_traits<Cfg2>::vertex_iterator;
//    using Cfg2OutEdgeIter = boost::graph_traits<Cfg2>::out_edge_iterator;
//    using Cfg2InEdgeIter = boost::graph_traits<Cfg2>::in_edge_iterator;
//    using Cfg2Edge = boost::graph_traits<Cfg2>::edge_descriptor;
//    using Cfg2EdgeIter = boost::graph_traits<Cfg2>::edge_iterator;

//   Cfg2 cfg2;
//   boost::copy_graph(cfg, cfg2);

//   std::pair<Cfg2EdgeIter, Cfg2EdgeIter> edge_iter_range = boost::edges(cfg2);
//   for(Cfg2EdgeIter edge_iter = edge_iter_range.first; edge_iter != edge_iter_range.second; ++edge_iter) {
//     auto edge = *edge_iter;

//     Cfg2Vertex sv = boost::source(edge, cfg2);
//     SgAsmBlock *src_bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg2, sv));
//     Cfg2Vertex tv = boost::target(edge, cfg2);
//     SgAsmBlock *tgt_bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg2, tv));

//     BlockAnalysis src_analysis = blocks.at(src_bb->get_address());
//     BlockAnalysis tgt_analysis = blocks.at(tgt_bb->get_address());

//     SymbolicRegisterStatePtr tgt_reg_state = tgt_analysis.output_state->get_register_state();
//     SymbolicRegisterStatePtr src_reg_state = src_analysis.output_state->get_register_state();
//     if (tgt_reg_state && src_reg_state) {
//       RegisterDescriptor eiprd = ds.get_arch_reg("eip");

//       SymbolicValuePtr src_eip = src_reg_state->read_register(eiprd);
//       SymbolicValuePtr tgt_eip = tgt_reg_state->read_register(eiprd);

//       OINFO << "\nThe edge " << addr_str(src_bb->get_address()) << " -> " << addr_str(tgt_bb->get_address())
//             << " is " << *(src_eip->get_expression()) << LEND;

//       cfg2[*edge_iter].condition = src_eip;

//     }
//   }
// }

// This is the supposedly intermediate basic block analysis for each block in a function
const BlockAnalysisMap&
DUAnalysis::get_block_analysis() const {
  return blocks;
}

// Loop over the control flow graph several times, processing each basic block and keeping a
// list of which blocks need to bew revisited.  This code need to be rewritten so that is uses
// a proper worklist.
LimitCode
DUAnalysis::loop_over_cfg()
{
  // Because it's shorter than current_function...
  FunctionDescriptor* & fd = current_function;

  // add_edge_conditions();

  // Now that the control flow graph has been cleaned up, we can construct a flow order list of
  // the blocks reachable from the entry point.  This graph should now be internally consistent.
  std::vector<CFGVertex> flowlist = fd->get_vertices_in_flow_order();
  if (blocks.size() != flowlist.size()) {
    // Info level because the message is fairly common.  Could be moved to WARN level if we
    // were processing exception handlers a little better.
    GINFO << "Function " << fd->address_string() << " includes only " << flowlist.size()
          << " of " << num_vertices(cfg) << " blocks in the control flow." << LEND;
  }

  SymbolicRiscOperatorsPtr rops = SymbolicRiscOperators::promote(dispatcher->operators());
  initial_state = rops->get_sstate();
  // Cory thinks the clone here is wrong, because it won't include subsequent "updates" to the
  // initial state for values that are created as we read them.
  input_state = rops->get_sstate()->sclone();

  // Solve the flow equation iteratively to find out what's defined at the end of every basic
  // block.  The policies[] stores this info for each vertex.
  bool changed = true;
  LimitCode rstatus = func_limit.check();
  while (changed && rstatus == LimitSuccess) {
    changed = false;
    func_limit.increment_counter();

    SDEBUG << "loop try #" << func_limit.get_counter() << LEND;
    for (auto vertex : flowlist) {
      SgAsmBlock *bblock = convert_vertex_to_bblock(cfg, vertex);
      assert(bblock!=NULL);
      rose_addr_t baddr = bblock->get_address();
      // The call to at() should not throw unless our code is using the wrong CFG.
      BlockAnalysis& analysis = blocks.at(baddr);

      // If the block is a "bad" block, then skip it.
      if (analysis.bad) continue;

      // If this block is in the processed list (meaning we've processed it before) and it it
      // is no longer pending then continue with the next basic block.  This is a very common
      // case and we could probably simplify the logic some by adding and removing entries
      // from a worklist that would prevent us from being in this loop in the first place.
      if (analysis.pending == false) continue;

      // If we're really pending, but we've visited this block more than max iteration times,
      // then we should give up even though it produces incorrect answers.  Report the condition
      // as an error so that the user knows something went wrong.
      if (analysis.iterations >= MAX_LOOP) {
        // Cory thinks that this should really be an error, but it's still too common to be
        // considered a true error, and so he moved it to warning importance.
        SWARN << "Maximum iterations (" << MAX_LOOP << ") exceeded for block "
              << addr_str(baddr) << " in function " << fd->address_string() << LEND;
        // Setting the block so that it is not pending should help prevent the error message
        // from being generated repeatedly for the same block.
        analysis.pending = false;
        continue;
      }

      // We're processing the block now, so it's no longer pending (and we've interated once more).
      analysis.pending = false;
      analysis.iterations++;

      // Process a block with a resource limit, and if it changed our status, update our boolean.
      if (process_block_with_limit(vertex)) changed = true;

      rstatus = func_limit.check();
      // The intention is that rstatus and changed would be the only clauses on the while condition.
      if (rstatus != LimitSuccess) {
        // Break out of the loop of basic blocks.
        break;
      }
    } // foreach block in flow list...

    // Cory would like for this to become: func_limit.report("Func X took: "); ?
    SDEBUG << "Flow equation loop #" << func_limit.get_counter() << " for " << fd->address_string()
           << " took " << func_limit.get_relative_clock().count() << " seconds." << LEND;
  }

  if (GTRACE) {
    for (auto& bpair : blocks) {
      const BlockAnalysis& block = bpair.second;
      GTRACE << " Basic block: " << block.address_string() << " in function " << fd->address_string()
             << " took " << block.iterations << " iterations." << LEND;
    }
  }

  return rstatus;
}

LimitCode
DUAnalysis::solve_flow_equation_iteratively()
{
  // Start by checking absolute limits.
  LimitCode rstatus = func_limit.check();
  if (rstatus != LimitSuccess) return rstatus;

  // This limits the number of times we complain about discarded expressions.  It's a naughty
  // global variable.   Go read about it in SymbolicValue::scopy().
  discarded_expressions = 0;

  // This analysis requires the filtered version of the control flow graph because we don't
  // know how to merge predecessors in cases where there are none.
  cfg = current_function->get_pharos_cfg();

  // Create a BlockAnalysis object for every basic block in function.  Create conditions for
  // each of the predecessor edges, and analyze the blocks to see if they look like bad code.
  create_blocks();

  // Set the stack delta of the first instruction to zero, with confidence Certain (by definition).
  sp_tracker.update_delta(current_function->get_address(), StackDelta(0, ConfidenceCertain),
                          sd_failures);

  // If this function is recursive, we need a better guess for our own stack delta than just
  // zero.  Make that guess and store it in the stack delta tracker cache before starting
  // anlaysis.
  guess_function_delta();

  // Do most of the real work.  Visit each block in the control flow graph, possibly multiple
  // times, merging predecessor states, emulating each block, and updating state histories.
  rstatus = loop_over_cfg();

  // Look at all of the return blocks, and bring them together into a unified stack delta.
  update_function_delta();

  // Merge all states at each return block into a single unified output state.
  update_output_state();

  // Determine whether we return a value at all, and if it's the initial value of ECX.
  analyze_return_code();

  // Currently the decision on whether to analyze tree node types depends on a command line argument to
  // prevent a dependancy on prolog
  save_treenodes();

  // Free the resources consumed by the ROSE emulation environment.
  dispatcher.reset();

  return rstatus;
}

// Convert a list-based memory state into a map-based memory state.
SymbolicMemoryMapStatePtr convert_memory_list_to_map(
  SymbolicMemoryListStatePtr list_mem,
  size_t max_aliases, bool give_up);

LimitCode
DUAnalysis::analyze_basic_blocks_independently()
{
  // Start by checking absolute limits.
  LimitCode rstatus = func_limit.check();
  if (rstatus != LimitSuccess) return rstatus;

  // Because it's shorter than current_function...
  FunctionDescriptor* & fd = current_function;

  // In analyze_flow_equation_iteratively() we discarded blocks with various problems such as
  // not having predecessors.  We don't want that filter here because we're computing per-block
  // semantics, and can do so even if we don't understand how they fit into the control flow.
  // Most of the otehr fields in the function descriptor are based on the Pharos (filtered)
  // control flow graph, so some extra caution is required qhen using this CFG.
  cfg = fd->get_rose_cfg();

  // Create a BlockAnalysis object for every basic block in function.  Create conditions for
  // each of the predecessor edges, and analyze the blocks to see if they look like bad code.
  create_blocks();

  // Set the stack delta of the first instruction to zero, with confidence Certain (by definition).
  sp_tracker.update_delta(current_function->get_address(), StackDelta(0, ConfidenceCertain),
                          sd_failures);

  // Instead of loop_over_cfg(), this algorithm is going to be simpler, so it's right here.

  // The RISC operators were built in the constructor based on how much rigor we wanted.
  SymbolicRiscOperatorsPtr rops = SymbolicRiscOperators::promote(dispatcher->operators());

  // Visit each basic block in the function without regard to the ordering in the control flow,
  // or even whether the blocks are connected to the control flow.
  for (auto vertex : cfg_vertices(cfg)) {
    SgAsmBlock *bblock = convert_vertex_to_bblock(cfg, vertex);
    assert(bblock!=NULL);
    rose_addr_t baddr = bblock->get_address();
    BlockAnalysis& analysis = blocks.at(baddr);

    // If the block is a "bad" block, then skip it.
    if (analysis.bad) continue;

    // Create a basic block limit just for tracking time. Perhaps this limit should really be
    // moved to analyze, so it can be evaluated after each instruction?
    ResourceLimit block_limit;
    GTRACE << "Starting analysis of block " << addr_str(baddr)
           << " Reason " << bblock->reason_str("", bblock->get_reason()) << LEND;

    analysis.analyze(false);

    const SymbolicStatePtr& cstate = rops->get_sstate();
    GTRACE << "-----------------------------------------------------------------" << LEND;
    GTRACE << "Machine state before conversion from list to map." << LEND;
    GTRACE << "-----------------------------------------------------------------" << LEND;
    GTRACE << *cstate;

    // save the block output state (current state)
    analysis.output_state = cstate;

    GTRACE << "-----------------------------------------------------------------" << LEND;
    // const SymbolicMemoryListStatePtr& list_mem = SymbolicMemoryListState::promote(cstate->memoryState());
    // SymbolicMemoryMapStatePtr map_mem = convert_memory_list_to_map(list_mem, 5, false);

    GTRACE << "-----------------------------------------------------------------" << LEND;
    GTRACE << "Memory state after conversion from list to map." << LEND;
    GTRACE << "-----------------------------------------------------------------" << LEND;
    // GTRACE << *map_mem;

    GTRACE << "Analysis of basic block " << addr_str(baddr) << " in function "
           << current_function->address_string() << ", took "
           << block_limit.get_relative_clock().count() << " seconds." << LEND;
  }

  return rstatus;
}

SymbolicValuePtr
get_leaf_condition(SymbolicValuePtr sv, TreeNodePtr target_leaf, TreeNodePtr parent_condition, bool direction) {

  using namespace Rose::BinaryAnalysis;
  // static auto nullsval = SymbolicValuePtr

  if (!target_leaf) {
    return SymbolicValue::incomplete(1);
  }

  TreeNodePtr tn = sv->get_expression();
  if (!tn) {
    return SymbolicValue::incomplete(1);
  }

  // We are at a leaf, is it the target?
  if (tn->isLeafNode()) {
    if (target_leaf->isEquivalentTo(tn)) {
      // if we came here on the false branch, invert the last condition (via the reference
      if (parent_condition) {
        if (false==direction) {
          parent_condition = SymbolicExpr::makeInvert(parent_condition);
        }
        return SymbolicValue::treenode_instance(parent_condition);
      }
      // Can always get here
      return SymbolicValue::treenode_instance(SymbolicExpr::makeBooleanConstant(true));
    }
    // This leaf is not the address we are looking for
    return SymbolicValue::incomplete(1);
  }

  const InternalNodePtr in = tn->isInteriorNode();

  SymbolicValuePtr result = SymbolicValue::incomplete(1);

  // If an ITE, then recurse through the branches
  if (in && in->getOperator() == SymbolicExpr::OP_ITE) {

    const TreeNodePtrVector& children = in->children();

    SymbolicValuePtr true_cond = get_leaf_condition(SymbolicValue::treenode_instance(children[1]), target_leaf, children[0], true);
    SymbolicValuePtr false_cond = get_leaf_condition(SymbolicValue::treenode_instance(children[2]), target_leaf, children[0], false);

    result = false == true_cond->is_incomplete() ? true_cond : false_cond;

    if (result->is_incomplete() == false) {
      if (parent_condition) {
        if (!direction) {
          // Came from a false branch, so invert the last controlling condition
          parent_condition = SymbolicExpr::makeInvert(parent_condition);
        }
        result = SymbolicValue::treenode_instance(SymbolicExpr::makeAnd(result->get_expression(), parent_condition));
      }
    }
  }
  return result;
}

} // Namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
