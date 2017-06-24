// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_DefUse_H
#define Pharos_DefUse_H

#include <fstream>
#include <map>
#include <vector>
#include <string>
#include <boost/format.hpp>

#include <rose.h>
#include <sage3basic.h>
#include <BinaryControlFlow.h>

#include "misc.hpp"
#include "cdg.hpp"
#include "masm.hpp"
#include "sptrack.hpp"
#include "riscops.hpp"
#include "limit.hpp"
#include "types.hpp"

namespace pharos {

typedef std::set<std::string> StringSet;
typedef std::map<rose_addr_t, SgAsmFunction*> Addr2FuncMap;
typedef std::map<rose_addr_t, SgAsmx86Instruction*> Addr2InsnMap;

// A definition in definition and use analysis.
class Definition {

public:
  // This is the instruction that did the defining.
  SgAsmx86Instruction* definer;

  // This is the abstract location that was defined.
  AbstractAccess access;

  Definition() { definer = NULL; }
  Definition(SgAsmx86Instruction* d, AbstractAccess a) { definer = d; access = a; }

  // Replace the comparator defined below?
  bool operator<(const Definition& other) const {
    if (definer == NULL && other.definer != NULL) return true;
    if (definer != NULL && other.definer == NULL) return false;
    if (definer == NULL && other.definer == NULL) return (access < other.access);
    if (definer->get_address() < other.definer->get_address()) return true;
    if (definer->get_address() > other.definer->get_address()) return false;
    return (access < other.access);
  }
};

class DUAnalysis;

// This class contains all of the information describing the analysis of a single basic block.
class BlockAnalysis {

  DUAnalysis & du;

  // The address of this block.  Duplicated here for convenience.
  rose_addr_t address;

public:
  // We should probably make more of these members private once the API has settled down a
  // little bit.

  // The vertex in the CFG.  Does this change if we add or remove vertices?
  CFGVertex vertex;

  // The actual ROSE block.
  SgAsmBlock* block;

  // The state of the environment at the beginning of the block.
  SymbolicStatePtr input_state;

  // The state of the environment at the end of the block.
  SymbolicStatePtr output_state;

  // These two lists are essentially the control flow graph, but with any modifications that we
  // needed to make from the standard ROSE result to ensure consistency in our algorithm.  For
  // example, some blocks with no predecessors (like exception handlers) may have been removed.
  // Additonally, Cory finds the code a lot cleaner that using boost::tie on the CFG.

  // How many times we've visited this block during analysis.  Used for debugging and limiting.
  size_t iterations;

  // Is this block "bad code"?
  bool bad;

  // Is this block the entry block?
  bool entry;

  // Is this block "pending" in Wes' workflow algorithm?
  bool pending;

  // The fixed portion of the stack delta (from the non-call instructions).
  StackDelta fixed_delta;

  // The call portion of the stack delta (from the final call instruction).
  StackDelta call_delta;

  // The condition variables representing the conditions under which we enter this block.
  std::vector<SymbolicValuePtr> conditions;

  // A resource limit for this block that can be reused.  Not required here?
  ResourceLimit limit;

  BlockAnalysis(DUAnalysis & du, const ControlFlowGraph& cfg, CFGVertex vertex, bool entry);

  rose_addr_t get_address() const { return address; }
  std::string address_string() const { return boost::str(boost::format("0x%08X") % address); }

  void check_for_bad_code();
  LimitCode analyze();

  LimitCode evaluate();

  void handle_stack_delta(SgAsmBlock* bb, SgAsmx86Instruction* insn,
                          SymbolicStatePtr& before_state);

};

typedef std::set<Definition> DUChain;
typedef std::map<SgAsmx86Instruction *, DUChain> Insn2DUChainMap;

typedef std::map<rose_addr_t, BlockAnalysis> BlockAnalysisMap;
typedef std::map<rose_addr_t, unsigned int> IterationCounterMap;


void print_definitions(DUChain duc);

class DUAnalysis {

  friend class BlockAnalysis;

protected:
  // ==================================================================================
  // Parameters that control analysis.
  // ==================================================================================

  // This is a bit hackish, but very useful to prevent use having to pass it around.
  // Definately private, and maybe even naughty.  I haven't really decided yet.
  FunctionDescriptor* current_function;

  // A stack delta tracker object to determine appropriate stack deltas for calls during
  // analysis.
  spTracker *sp_tracker;

  // A resource limit status code to let us know how soving the flow equation went.
  LimitCode status;

  // ==================================================================================
  // Data produced during analysis
  // ==================================================================================

  // Mapping of an instruction, I, to the set of instructions responsible for defining
  // registers/memory used by I.
  Insn2DUChainMap depends_on;
  // Mapping of an instruction, I, to the set of instructions that use abstract locations set
  // by I.
  Insn2DUChainMap dependents_of;

  // A history of GPRs, flags and memory read
  AccessMap accesses;

  // The input state representing the machine state at the beginning of the function.
  SymbolicStatePtr input_state;
  // The output state representing the merged states at all of the return statements.  If we
  // cannot find a return block, use the state of the last basic block in flow order
  SymbolicStatePtr output_state;

  // Were we able to merge return blocks at all and compute a roughly valid output state?  This
  // includes cases where we had some return blocks and some non-return blocks (handled
  // incorrectly), but not cases where we had no out-edges or no return blocks at all.
  bool output_valid;

  // Did the function consist of only valid return states?  In other words, did it meet one of
  // the most basic requirements of a well-formed function?
  bool all_returns;

  // ==================================================================================
  // Still deciding...
  // ==================================================================================

  X86InsnSet branchesToPackedSections;

  // ==================================================================================
  // ==================================================================================

  // This is the very latest way of approaching the problem.  The block analysis class contains
  // everything we know about an individual block.
  BlockAnalysisMap blocks;

  // ==================================================================================
  // Possibly messy additions required only for analysis.
  // ==================================================================================


  // The Dispatcher provides a way to access the ROSE emulation environment, including the
  // RiscOperators and states that are currnetly in use.  It's also often used just to obtain
  // handles to specific register descriptors.
  DispatcherPtr dispatcher;

  // Resource limits temporarily moved here so that we can check them at any time.
  ResourceLimit func_limit;

  // Initial state needs to be computed very earlier, and then due to a pecularity of how we've
  // structured our loop, it's needed way down in the code that merges predecessor blocks
  // together.  We should structure our code more intelligently, with a per basic block data
  // structure, and then this won't be needed here anymore.  This might be the same as
  // input_state, and then it could be elminated that way as well...
  SymbolicStatePtr initial_state;

  // The control flow graph is pretty important to this analysis.
  ControlFlowGraph cfg;

  // sets of tree nodes needed for analysis
  std::map<TreeNode*, TreeNodePtr> memory_accesses_;

  std::map<TreeNode*, TreeNodePtr> unique_treenodes_;

  // ==================================================================================
  // Private methods.
  // ==================================================================================

  // Create BlockAnalysis objects for each basic block in the function.
  void create_blocks();
  // Remove bad blocks, and those with no predecessors from the CFG.
  void cleanup_cfg();

  LimitCode loop_over_cfg();
  bool process_block_with_limit(CFGVertex vertex);
  SymbolicStatePtr merge_predecessors(CFGVertex vertex);
  bool check_for_eax_read(SgAsmx86Instruction* call_insn);
  LimitCode evaluate_bblock(SgAsmBlock* bblock);
  void update_call_targets(SgAsmx86Instruction* insn, SymbolicRiscOperatorsPtr& ops);
  void update_function_delta();
  bool saved_register(SgAsmx86Instruction* insn, const Definition& def);
  void make_call_dependencies(SgAsmx86Instruction* insn, SymbolicStatePtr& cstate);

  // Report debugging messages.  No analysis.
  void debug_state_merge(const SymbolicStatePtr& cstate, const std::string label) const;
  void debug_state_replaced(const rose_addr_t baddr) const;

  // Analyze the return code situation for the current function.
  void analyze_return_code();

  // Makes a matching pair of dependencies.  e.g. update both dependents and dependencies.
  // i1 reads the aloc defined by i2.  i2 defines the aloc read by i1.
  void add_dependency_pair(SgAsmx86Instruction* i1, SgAsmx86Instruction* i2, AbstractAccess access);

  // This is the main function that drives most of the work...
  LimitCode solve_flow_equation_iteratively();

  // Update the bad blocks set.
  void find_bad_blocks(std::vector<CFGVertex>& flowlist, ControlFlowGraph& cfg);

  void update_output_state();

  void save_treenodes();

  void add_access(SgAsmx86Instruction *insn, const AbstractAccess & aa) {
    accesses[insn].push_back(aa);
  }
  void add_access(SgAsmx86Instruction *insn, AbstractAccess && aa) {
    accesses[insn].push_back(std::move(aa));
  }

public:

  const std::map<TreeNode*, TreeNodePtr>& get_unique_treenodes() const { return unique_treenodes_; }

  const std::map<TreeNode*, TreeNodePtr>& get_memaddr_treenodes() const { return memory_accesses_; }

  // Perhaps the input and output states shouldn't be public.  But they used to be in
  // function_summary where they were public, and so it's a change to make them private.
  DUAnalysis(FunctionDescriptor* f, spTracker* s = NULL);

  const SymbolicStatePtr get_input_state() const { return input_state; }
  const SymbolicStatePtr get_output_state() const { return output_state; }

  bool get_all_returns() const { return all_returns; }
  bool get_output_valid() const { return output_valid; }

  const X86InsnSet & getJmps2UnpackedCode() const { return branchesToPackedSections; }
  X86InsnSet & getJmps2UnpackedCode() { return branchesToPackedSections; }

  const AccessMap & get_accesses() const {
    return accesses;
  }

  // Was the read a fake read?  (A read that wasn't really used)?
  bool fake_read(SgAsmX86Instruction* insn, const AbstractAccess& aa) const;

  access_filters::aa_range get_reads(SgAsmx86Instruction* insn) const {
    return access_filters::read(accesses, insn);
  }
  access_filters::aa_range get_writes(SgAsmx86Instruction* insn) const {
    return access_filters::write(accesses, insn);
  }
  access_filters::aa_range get_mems(SgAsmx86Instruction* insn) const {
    return access_filters::mem(accesses, insn);
  }
  access_filters::aa_range get_regs(SgAsmx86Instruction* insn) const {
    return access_filters::reg(accesses, insn);
  }
  access_filters::aa_range get_mem_reads(SgAsmx86Instruction* insn) const {
    return access_filters::read_mem(accesses, insn);
  }
  access_filters::aa_range get_mem_writes(SgAsmx86Instruction* insn) const {
    return access_filters::write_mem(accesses, insn);
  }
  access_filters::aa_range get_reg_reads(SgAsmx86Instruction* insn) const {
    return access_filters::read_reg(accesses, insn);
  }
  access_filters::aa_range get_reg_writes(SgAsmx86Instruction* insn) const {
    return access_filters::write_reg(accesses, insn);
  }

  // Return the single (expected) write for a given instruction.  If there's more than one,
  // return the first write.
  const AbstractAccess* get_the_write(SgAsmx86Instruction* insn) const;
  // Return the first memory write for a given instruction.
  const AbstractAccess* get_first_mem_write(SgAsmx86Instruction* insn) const;

  const Insn2DUChainMap& get_dependencies() const { return depends_on; }
  const Insn2DUChainMap& get_dependents() const { return dependents_of; }
  const DUChain* get_dependencies(SgAsmx86Instruction* insn) const {
    Insn2DUChainMap::const_iterator finder = depends_on.find(insn);
    if (finder == depends_on.end()) return NULL; else return &(depends_on.at(insn));
  }
  const DUChain* get_dependents(SgAsmx86Instruction* insn) const {
    Insn2DUChainMap::const_iterator finder = dependents_of.find(insn);
    if (finder == dependents_of.end()) return NULL; else return &(dependents_of.at(insn));
  }

  void print_dependencies() const;
  void print_dependents() const;

};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
