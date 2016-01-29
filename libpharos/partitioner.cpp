// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/foreach.hpp>
#include <stdarg.h>

#include <rose.h>

#include "partitioner.hpp"
#include "masm.hpp"
#include "util.hpp"
#include "limit.hpp"
#include "misc.hpp"
#include "options.hpp"

// Construct the partitioner limits when we begin.
CERTPartitioner::CERTPartitioner() : Partitioner() {
  get_global_limits().set_limits(partitioner_limit, PharosLimits::limit_type::PARTITIONER);
}

// For debugging partitioner reasons.
std::string CERTPartitioner::reason_string(unsigned r) {
  if (r & SgAsmBlock::BLK_LEFTOVERS) return "leftovers";
  else if (r & SgAsmBlock::BLK_PADDING) return "padding";
  else if (r & SgAsmBlock::BLK_FRAGMENT) return "fragment";
  else if (r & SgAsmBlock::BLK_JUMPTABLE) return "jumptable";
  else if (r & SgAsmBlock::BLK_ENTRY_POINT) return "entry-point";
  else if (r & SgAsmBlock::BLK_CFGHEAD)  return "CFG head";
  else if (r & SgAsmBlock::BLK_GRAPH1) return "graph-1";
  else if (r & SgAsmBlock::BLK_GRAPH2) return "graph-2";
  else if (r & SgAsmBlock::BLK_GRAPH3) return "graph-3";
  else if (r & SgAsmBlock::BLK_USERDEF)  return "user-defined";
  else return "misc";
}

// This appears to be where we've hooked into the partitioner flow.
void CERTPartitioner::post_cfg(SgAsmInterpretation *interp) {

  LimitCode rstatus = partitioner_limit.check();
  if (rstatus != LimitSuccess) {
    MERROR << "Skipping add_save_restore() "
           << " " << partitioner_limit.get_message() << LEND;
  }
  else {
    // Look for save-restore patterns and make functions from them.
    size_t found = add_save_restore_funcs();
    MDEBUG << "Found " << found << " save-restore functions." << LEND;
    // If we've made more functions, go re-analyze the control flow graph?
    if (found) analyze_cfg(SgAsmBlock::BLK_GRAPH2);
  }

  // Call the standard ROSE version of this routine.
  Partitioner::post_cfg(interp);

  rstatus = partitioner_limit.check();
  if (rstatus != LimitSuccess) {
    MERROR << "Skipping find_funcs_in_blocks() "
           << " " << partitioner_limit.get_message() << LEND;
  }
  else {
    // Do something else...
    findFuncsInDataBlocks();
  }
}

#if 1
// Override parent just to add logging
void CERTPartitioner::append(BasicBlock *bb, DataBlock *db, unsigned reason) {
  MTRACE << "Appending data block " << db->address() << " to bb " << bb->address() << LEND;
  Partitioner::append(bb, db, reason);
}

// Override parent just to add logging
void CERTPartitioner::append(Function *func, DataBlock *block, unsigned reason, bool force) {
  MTRACE << "Appending data block " << block->address() << " to function "
         << func->entry_va << LEND;
  Partitioner::append(func, block, reason, force);
}

void CERTPartitioner::append(Function* f, BasicBlock *bb, unsigned reason, bool keep/*=false*/) {

  if (reason & SgAsmBlock::BLK_FRAGMENT) {
    MTRACE << "Verifying block fragment" << LEND;

    // Check to see if control flow can reach bb before appending
    for (BasicBlocks::iterator bi=f->basic_blocks.begin(); bi!=f->basic_blocks.end(); ++bi) {
      RoseDisassembler::AddressSet succs = Partitioner::successors(bi->second);
      for (RoseDisassembler::AddressSet::iterator si=succs.begin(); si!=succs.end(); ++si) {
        if (bb->address() == *si) {
          MINFO << "Fragment verified: Appending block at " << bb->address()
                << " to function at " << addr_str(f->entry_va) << LEND;
          Partitioner::append(f,bb,reason,keep);
          return;
        }
      }
    }

    if (bb->function) {
      MDEBUG << "Not appending function fragment at " << addr_str(bb->function->entry_va) << LEND;
    }
    else {
      MDEBUG << "Not appending function fragment at unknown location." << LEND;
    }
    /*
      if (bb->function)
      std::cout << "Not appending function fragment at " << std::hex
      << bb->function->entry_va << ", because we could not find a control-flow path from the predecessor func\n ";
      else std::cout << "Not appending block at " << std::hex << bb->address() << " to " << f->entry_va << ", because we could not find a control-flow path from the predecessor func\n ";
    */

    //if (bb->code_likelihood >= 0.7) {
    // MTRACE << "Creating function from fragment @" << std::hex << bb->address() << LEND;

    //  add_function(bb->address(), SgAsmFunction::FUNC_GRAPH);
    //analyze_cfg(SgAsmBlock::BLK_GRAPH2);
    //}

    return;
  }

  Partitioner::append(f, bb, reason, keep);
}
#endif

// Create functions for any basic blocks that consist of only a JMP to another function.  This
// is verbatim copy of the ROSE function because Cory wanted to experiment with the assertion
// that was being triggered.
bool CERTPartitioner::FindThunks::operator()(bool enabled, const Args &args)
{
    if (!enabled)
        return false;

    Partitioner *p = args.partitioner;
    rose_addr_t va = args.insn_begin->get_address();
    rose_addr_t next_va = 0;
    for (size_t i=0; i<args.ninsns; i++, va=next_va) {
        Instruction *insn = p->find_instruction(va);
        ASSERT_not_null(insn);
        next_va = va + insn->get_size();

        /* Instruction must be an x86 JMP */
        SgAsmX86Instruction *insn_x86 = isSgAsmX86Instruction(insn);
        if (!insn_x86 || (insn_x86->get_kind()!=x86_jmp && insn_x86->get_kind()!=x86_farjmp))
            continue;

        /* Instruction must not be in the middle of an existing basic block. */
        BasicBlock *bb = p->find_bb_containing(va, false);
        if (bb && bb->address()!=va)
            continue;

        if (validate_targets) {
            /* Instruction must have a single successor */
            bool complete;
            Disassembler::AddressSet succs = insn->getSuccessors(&complete);
            if (!complete && 1!=succs.size())
                continue;
            rose_addr_t target_va = *succs.begin();

            /* The target (single successor) must be a known function which is not padding. */
            Functions::iterator fi = p->functions.find(target_va);
            if (fi==p->functions.end() || 0!=(fi->second->reason & SgAsmFunction::FUNC_PADDING))
                continue;
        }

        /* Create the basic block for the JMP instruction.  This block must be a single
         * instruction, which it should be since we already checked that its only successor is
         * another function. */
        if (!bb)
            bb = p->find_bb_starting(va);
        ASSERT_not_null(bb);
        // SEI removed the assert, and replaced it with a log message.
        //assert(1==bb->insns.size());
        if (bb->insns.size() != 1) {
          MDEBUG << "Number of instructions in basic block at "
                 << addr_str(va) << " is " << bb->insns.size() << LEND;
          BOOST_FOREACH(Instruction* cinsn, bb->insns) {
            SgAsmInstruction* xinsn = p->isSgAsmInstruction(cinsn);
            MDEBUG << "Insn is: " << debug_instruction(xinsn) << LEND;
          }
          // Since Robb didn't want to create thunks when there was more than 1 instruction,
          // just continue like he did in the other cases.
          continue;
        }
        Function *thunk = p->add_function(va, SgAsmFunction::FUNC_THUNK);
        p->append(thunk, bb, SgAsmBlock::BLK_ENTRY_POINT);
        ++nfound;

        MTRACE <<"FindThunks: found F" << addr_str(va) << LEND;
    }

    return true;
}

// This function detects a code pattern of the form: zero or more instructions, followed by a
// push, followed by zero or more instructions, followed by a pop, and then a ret.
// Additionally, the push must not push ESP, and the push/pop pair must save and restore the
// same general purpose register.  If the pattern is matched, we call add_function(), starting
// with the first instruction encountered.  This serves as a good example of how to add a
// function detector, and presumably it solved some problem that Wes encountered in practice,
// although Cory has a number of questions about what it does in cases other than the one that
// was expected.  He's also encountered cases where
bool CERTPartitioner::find_save_restore_pattern(Partitioner::InstructionMap range) {
  // The first instruction encountered.
  rose_addr_t start = 0;
  // The expressions for the pushed and popped values.
  SgAsmDirectRegisterExpression *push_reg = NULL;
  SgAsmDirectRegisterExpression *pop_reg = NULL;

  for (Partitioner::InstructionMap::iterator iit = range.begin(); iit != range.end(); iit++) {
    SgAsmX86Instruction *i = isSgAsmX86Instruction(iit->second);
    if (!i) continue;

    // On the first instruction, save the address.  The real start of the function is probably
    // somewhere between here and the first push that we find.  Consider for example an
    // undiscovered function preceeded by NOP padding (or worse int3 instructions).
    if (start == 0) {
      start = i->get_address();
      MTRACE << "Testing range at 0x" << std::hex << start << std::dec
             << " for the save-restore function pattern." << LEND;
    }

    MTRACE << "Evaluating save-restore instruction: " << debug_instruction(i) << LEND;

    // If we haven't seen a push instruction yet, look for one.
    if (!push_reg && i->get_kind() == x86_push) {
      const SgAsmExpressionPtrList &opands = i->get_operandList()->get_operands();
      assert(opands.size() != 0);
      SgAsmDirectRegisterExpression *rre = isSgAsmDirectRegisterExpression(opands[0]);
      if (rre && rre->get_descriptor().get_major() == x86_regclass_gpr &&
          rre->get_descriptor().get_minor() != x86_gpr_sp) {
        push_reg = rre;
        MDEBUG << "Candidate save-restore pattern, push: " << debug_instruction(i) << LEND;
      }
      continue; // next instruction
    }

    // If we have a seen a push, look for a matching pop.
    if (push_reg && i->get_kind() == x86_pop) {
      const SgAsmExpressionPtrList &opands = i->get_operandList()->get_operands();
      assert(opands.size() != 0);
      SgAsmDirectRegisterExpression *rre = isSgAsmDirectRegisterExpression(opands[0]);
      if (rre && rre->get_descriptor().get_major() == x86_regclass_gpr) {
        pop_reg = rre;
        MDEBUG << "Candidate save-restore pattern, pop: " << debug_instruction(i) << LEND;
      }
      continue; // next instruction
    }

    // If we've come to ret instrution, we're finished...
    if (i->get_kind() == x86_ret) {
      // If we've seen and push, a pop, and the pushed register matches the popped register,
      // then make a function.
      if (push_reg && pop_reg &&
          push_reg->get_descriptor().get_minor() == pop_reg->get_descriptor().get_minor()) {
        // We've matched the pattern.  Instruct the partitioner to make a function.
        add_function(start, SgAsmFunction::FUNC_USERDEF);
        MDEBUG << "Adding save-restore function at 0x" << std::hex << start << std::dec << LEND;
        return true;
      }
      // Otherwise, we don't match the pattern.
      return false;
    }
  }

  // We must have reached the end of the range without finding a ret instruction, so we do not
  // match the pattern.
  return false;
}

// Look for the save-restore pattern and create functions in all unassigned ranges.  Wes says:
// Copied from scan_unassigned_insn().  He thinks there might be a bug in
// scan_unassigned_insns(), because it's not calling scan_interfunc_insns(), like the comment
// claims...
size_t CERTPartitioner::add_save_restore_funcs() {
  // The number of times we've matches the pattern.
  size_t found = 0;
  // An accumulated range of instructions awaiting analysis.
  Partitioner::InstructionMap range;

  // The InstructionMap is address to Partitioner::Instruction...
  for (Partitioner::InstructionMap::const_iterator ai=insns.begin(); ai!=insns.end(); ai++) {
    Partitioner::BasicBlock *bb = find_bb_containing(ai->first, false);
    Partitioner::Function *func = bb ? bb->function : NULL;
    SgAsmInstruction* insn = isSgAsmInstruction(ai->second);

    // This gets emitted for each unassigned instruction (e.g. lots of times).
    MTRACE << "Considering: func=0x" << std::hex << (func == NULL ? 0 : func->entry_va)
           << std::dec << " insn=" << debug_instruction(insn) << LEND;

    // If this instruction is already in a function, we should analyze the accumulated range.
    if (func) {
      // Analyze any accumulated instructions, and then clear the accumulated range.
      if (!range.empty()) {
        if (find_save_restore_pattern(range)) found++;
        range.clear();
      }
    }
    // But if the instruction is not already in a fuction, add it to the accumulated range.
    else {
      MTRACE << "Inserting: " << debug_instruction(insn) << LEND;
      range.insert(*ai);
    }

    LimitCode rstatus = partitioner_limit.check();
    if (rstatus != LimitSuccess) {
      MERROR << "Basic block " << addr_str(insn->get_address())
             << " " << partitioner_limit.get_message() << LEND;
      // Break out of the loop of basic blocks.
      break;
    }
  }

  // Analyze any instructions left over in the accumulated range.
  if (!range.empty()) {
    if (find_save_restore_pattern(range)) found++;
  }

  // Return the number of times we matched the pattern.
  return found;
}

// Wes says: Iterate through the list of basic blocks that have not been assigned to functions
// in address order.  Determine if the successors of a block can reach any of the other
// unassigned blocks.  If it can, mark the first block as a function start and reanalyze the
// CFG.  Repeat this process until the list of unassigned data blocks stops changing.

// Cory says: Find code in unassigned data blocks based on the heuristic that if they have a
// high code likelihood and the bytes disassemble into instructions that flow into other
// unassigned blocks, then those bytes are a function.  This heuristic appears to do a fairly
// good job of making code that was otherwise missed, but it's still unclear how well this
// performs at finding correct function boundaries.  In many of these cases I've looked at,
// it's creating functions out of fragments that belonged in another function.  It's unclear
// why they weren't assigned to the correct function earlier.  I suppose that's better than
// missing the code entirely.  I'm also a little unclear about why we're only making functions
// out bytes that flowed into unassigned blocks versus assigned blocks, unless that's already
// happening by calling add_function() and analyze_cfg().  Finally, it's got to be pretty
// expensive to make the complete list of unassigned blocks every time, only to bail on the
// first function creation because we need to return to analyze_cfg().  If we're going to do
// this, we should probably maintain the unassigned blocks map.
void CERTPartitioner::findFuncsInDataBlocks() {
  bool changed;
  size_t iteration = 0;

  do {
    changed = false;

    // This limit is pretty arbitrary because we break once we've found a function.  In large
    // sequential sequences of new functions, we're going to reach this limit after 100
    // funtions, not 100 iterations of some complex analysis pass...  Perhaps we should
    // complete each pass before breaking, or the limit should be larger or something?
    if (iteration >= 100) break;
    iteration++;

    // Find the list of unassigned blocks
    Partitioner::BasicBlocks unassigned_blocks;
    BOOST_FOREACH(Partitioner::BasicBlocks::value_type& bpair, basic_blocks) {
      Partitioner::BasicBlock* bb = bpair.second;
      if (!bb->function && bb->code_likelihood >= CODE_THRESHOLD) {
        MTRACE << "Unassigned block 0x" << std::hex << bb->address()
               << " has code likelihood " << std::dec << bb->code_likelihood << LEND;
        unassigned_blocks[bpair.first] = bb;
      }
    }
    MDEBUG << "There are " << unassigned_blocks.size()
           << " unassigned block remaining, iteration " << iteration << "." << LEND;

    // No process each unassigned block.
    BOOST_FOREACH(Partitioner::BasicBlocks::value_type& bpair, basic_blocks) {
      Partitioner::BasicBlock* bb = bpair.second;
      bool ignored = false;
      BOOST_FOREACH(rose_addr_t saddr, Partitioner::successors(bb, &ignored)) {
        // The successor address corresponds to one of the unassigned blocks
        if (unassigned_blocks.find(saddr) != unassigned_blocks.end()) {
          MDEBUG << "Creating function at 0x" << std::hex << bb->address()
                 << " because it flows into unassigned block 0x" << saddr << std::dec << "." << LEND;

          // If this basic block has been labeled as data, remove it.  Also, if this data block
          // has been appended to another function, remove it from the list of data blocks.
          if (data_blocks.find(bb->address()) != data_blocks.end()) {
            Partitioner::DataBlock* db = data_blocks[bb->address()];
            Partitioner::Function* func = db->function;
            if (func && func->data_blocks.find(bb->address()) != func->data_blocks.end()) {
              func->data_blocks.erase(func->data_blocks.find(bb->address()));
            }

            data_blocks.erase(data_blocks.find(bb->address()));
          }

          // Add a function using the basic block as a starting point.
          add_function(bb->address(), SgAsmFunction::FUNC_USERDEF);
          // Analyze the control flow graph again.
          analyze_cfg(SgAsmBlock::BLK_GRAPH3);
          // And then rebuild the unassigned blocks map.
          changed = true;
          break;
        }
      }
      if (changed) break;
    }
  } while(changed);
}

// Unknown?
RoseDisassembler::AddressSet CERTPartitioner::successors(BasicBlock *bb, bool *complete) {
  RoseDisassembler::AddressSet out = Partitioner::successors(bb,complete);

  if (bb->cache.is_function_call) {
    rose_addr_t fall_through_va = canonic_block(bb->last_insn()->get_address()
                                                + bb->last_insn()->get_size());

    for (RoseDisassembler::AddressSet::iterator ait = bb->cache.sucs.begin();
         ait != bb->cache.sucs.end(); ait++) {
      if (*ait != fall_through_va) {
        add_function(*ait, SgAsmFunction::FUNC_CALL_TARGET, "");
      }
    }

    if (find_instruction(fall_through_va, false)) {
      out.insert(fall_through_va);
    }
  }

  return out;
}

// ===============================================================================================
// Partitioner2
// ===============================================================================================

// This custom BasicBlockCallback is much like PreventDiscontiguousBlocks, except that it only
// rejects unconditional jump instructions.  The real intention is to ensure that thunks (jumps
// to the entry point of a function) are NOT coalesced into the function, since this alters the
// percevied entry point of the function, which is likely to be inconvenient when later more
// advanced analysis find references to the function.
bool ThunkDetacher::operator()(bool chain, const Args &args) {
  if (chain) {
    bool complete;
    std::vector<rose_addr_t> successors = args.partitioner.basicBlockConcreteSuccessors(args.bblock, &complete);
    //OINFO <<"DetachThunks at " <<args.bblock->printableName()
    //       <<" has " <<StringUtility::plural(args.bblock->instructions().size(), "instructions")
    //       <<" and " <<StringUtility::plural(successors.size(), "successors") <<"\n";
    if (complete && 1==successors.size()) {
      // Get the number of instructions in the basic block.
      size_t ninsns = args.bblock->nInstructions();

      // Thunks are always one instruction!
      if (ninsns != 1)
        return chain;
      SgAsmX86Instruction* insn = isSgAsmX86Instruction(args.bblock->instructions()[0]);
      if (insn == NULL)
        return chain;                       // this isn't x86?
      if (insn->get_kind() != x86_jmp)
        return chain;

      P2::ControlFlowGraph::ConstVertexIterator vertex =
        args.partitioner.findPlaceholder(args.bblock->address());

      BOOST_FOREACH(const P2::ControlFlowGraph::Edge& edge, vertex->inEdges()) {
        const P2::ControlFlowGraph::Vertex &source = *edge.source();
        P2::BasicBlock::Ptr sblock = source.value().bblock();
        //OINFO << "Predecessor block is " << sblock->printableName() << LEND;

        // Get the number of instructions in the predecessor basic block.
        size_t pninsns = sblock->nInstructions();

        if (pninsns > 0) {
          SgAsmX86Instruction* pred_insn = isSgAsmX86Instruction(sblock->instructions()[pninsns-1]);
          //OINFO << "Previous instruction is: " << debug_instruction(pred_insn) << LEND;
          rose_addr_t fall_thru = insn_get_fallthru(pred_insn);
          if (fall_thru == args.bblock->address()) {
            //OINFO << "Block " << args.bblock->printableName() << " is not really a thunk!" << LEND;
            return chain;
          }
        }
      }

      // This is a thunk.  Terminate the existing basic block now (at the jmp).  This might
      // also detach some unconditional jumps that are not thunks (e.g. the target of the jump
      // is not really the start of a function).  For right now I don't really care, but if
      // this turns out to be a problem we can use some other heuristics.  But we can't rely on
      // there being other in edges, or the default Partitioner2 will already do the right
      // thing.
      //OINFO <<" thunk detected\n";
      args.results.terminate = TERMINATE_NOW;

      // We also want to make sure that the target address will become a function. We can't
      // modify the partitioner while we're inside the callback, so save them up for later.  We
      // save the addresses, but we could have also created the Function objects (just not
      // attach them to the partitioner).
      jmpVas.insert(insn->get_address());
      targetVas.insert(successors[0]);
    }
  }
  return chain;
}

void ThunkDetacher::makeFunctions(P2::Partitioner &partitioner) {
  // Make each JMP a function.  This could be a little dangerous: if we split off a JMP even
  // though it wasn't a thunk, we would end up making it a function of its own even though it
  // isn't really.  Perhaps this is where we should add the additional heuristics.
  BOOST_FOREACH (rose_addr_t va, jmpVas) {
    P2::Function::Ptr function = P2::Function::instance(va, SgAsmFunction::FUNC_THUNK);
    partitioner.attachOrMergeFunction(function);
  }

  // Make each JMP target a function.
  BOOST_FOREACH (rose_addr_t va, targetVas) {
    P2::Function::Ptr function = P2::Function::instance(va);
    partitioner.attachOrMergeFunction(function);
  }
}

bool Monitor::operator()(bool chain, const AttachedBasicBlock &args) {
  if (args.bblock)
    OINFO << "Attached basic block " << addr_str(args.bblock->address()) << LEND;
  return chain;
}

bool Monitor::operator()(bool chain, const DetachedBasicBlock &args) {
  if (args.bblock)
    OINFO << "Detached basic block " << addr_str(args.bblock->address()) << LEND;
  return chain;
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
