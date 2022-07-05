// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_DefUse_H
#define Pharos_DefUse_H

#include <fstream>
#include <map>
#include <vector>
#include <string>
#include <boost/format.hpp>

#include "rose.hpp"
#include <sage3basic.h>
#include <Rose/BinaryAnalysis/ControlFlow.h>

#include "misc.hpp"
#include "cdg.hpp"
#include "sptrack.hpp"
#include "riscops.hpp"
#include "limit.hpp"
#include "types.hpp"

namespace pharos {

using Addr2FuncMap = std::map<rose_addr_t, SgAsmFunction*>;
using Addr2InsnMap = std::map<rose_addr_t, SgAsmX86Instruction*>;

// A definition in definition and use analysis.
class Definition {

 public:
  // This is the instruction that did the defining.
  SgAsmX86Instruction* definer;

  // This is the abstract location that was defined.
  AbstractAccess access;

  Definition() { definer = NULL; }
  Definition(SgAsmX86Instruction* d, AbstractAccess a) : definer(d), access(std::move(a)) {}

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

  // Record the accesses, dependencies, and global memory accesses for the instruction.
  void record_dependencies(SgAsmX86Instruction *insn, const SymbolicStatePtr& cstate);
  // Check to see if the jump/call isntruction goes in invalid code.
  bool check_for_invalid_code(SgAsmX86Instruction *insn, size_t i);

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


  SymbolicValuePtr entry_condition;

  // The condition
  SymbolicValuePtr exit_condition;

  // A resource limit for this block that can be reused.  Not required here?
  ResourceLimit limit;

  BlockAnalysis(DUAnalysis & du, const ControlFlowGraph& cfg, CFGVertex vertex, bool entry);

  rose_addr_t get_address() const { return address; }
  std::string address_string() const { return boost::str(boost::format("0x%08X") % address); }

  LimitCode analyze(bool with_context = true);

  LimitCode evaluate();

  void handle_stack_delta(SgAsmBlock* bb, SgAsmX86Instruction* insn,
                          SymbolicStatePtr& before_state, bool downgrade = false);

};

using DUChain = std::set<Definition>;
using Addr2DUChainMap = std::map<rose_addr_t, DUChain>;

using BlockAnalysisMap = std::map<rose_addr_t, BlockAnalysis>;
using IterationCounterMap = std::map<rose_addr_t, unsigned int>;


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
  spTracker sp_tracker;
  size_t sd_failures = 0;

  // A resource limit status code to let us know how soving the flow equation went.
  LimitCode status;

  // Are we doing the new list-based memory thing that's more rigorous?
  bool rigor;

  // Are we propagating basic block conditions or discarding them?
  bool propagate_conditions;

  // ==================================================================================
  // Data produced during analysis
  // ==================================================================================

  // Mapping of an instruction, I, to the set of instructions responsible for defining
  // registers/memory used by I.
  Addr2DUChainMap depends_on;
  // Mapping of an instruction, I, to the set of instructions that use abstract locations set
  // by I.
  Addr2DUChainMap dependents_of;

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

  // SymbolicRiscOperators callback
  SingleThreadedAnalysisCallbacks rops_callbacks;

  // ==================================================================================
  // Private methods.
  // ==================================================================================

  SymbolicValuePtr
  get_address_condition(const BlockAnalysis& pred_analysis,
                        SgAsmBlock* pblock, const rose_addr_t bb_addr);

  // Create BlockAnalysis objects for each basic block in the function.
  void create_blocks();

  // // add properties to the boost graph for edge path conditions
  // void add_edge_conditions();
  LimitCode loop_over_cfg();
  bool process_block_with_limit(CFGVertex vertex);
  SymbolicStatePtr merge_predecessors(CFGVertex vertex);
  SymbolicStatePtr merge_predecessors_with_conditions(CFGVertex vertex);
  bool check_for_eax_read(SgAsmX86Instruction* call_insn);
  LimitCode evaluate_bblock(SgAsmBlock* bblock);
  void update_call_targets(SgAsmX86Instruction* insn, SymbolicRiscOperatorsPtr& ops);
  void update_function_delta();
  void guess_function_delta();
  void make_call_dependencies(SgAsmX86Instruction* insn, SymbolicStatePtr& cstate);

  // Report debugging messages.  No analysis.
  void debug_state_merge(const SymbolicStatePtr& cstate, const std::string label) const;
  void debug_state_replaced(const rose_addr_t baddr) const;

  // Analyze the return code situation for the current function.
  void analyze_return_code();

  // Makes a matching pair of dependencies.  e.g. update both dependents and dependencies.
  // i1 reads the aloc defined by i2.  i2 defines the aloc read by i1.
  void add_dependency_pair(SgAsmX86Instruction* i1, SgAsmX86Instruction* i2, AbstractAccess access);

  // This is the main function that drives most of the work...
  LimitCode analyze_basic_blocks_independently();
  LimitCode solve_flow_equation_iteratively();

  // Update the bad blocks set.
  void find_bad_blocks(std::vector<CFGVertex>& flowlist, ControlFlowGraph& cfg);

  void update_output_state();

  void save_treenodes();

  void update_accesses(SgAsmX86Instruction *insn, SymbolicRiscOperatorsPtr& rops);

 public:

  DescriptorSet& ds;

  const BlockAnalysisMap& get_block_analysis() const;

  const std::map<TreeNode*, TreeNodePtr>& get_unique_treenodes() const { return unique_treenodes_; }

  const std::map<TreeNode*, TreeNodePtr>& get_memaddr_treenodes() const { return memory_accesses_; }

  // Perhaps the input and output states shouldn't be public.  But they used to be in
  // function_summary where they were public, and so it's a change to make them private.
  DUAnalysis(DescriptorSet& ds, FunctionDescriptor& f);

  const SymbolicStatePtr get_input_state() const { return input_state; }
  const SymbolicStatePtr get_output_state() const { return output_state; }

  bool get_all_returns() const { return all_returns; }
  bool get_output_valid() const { return output_valid; }

  const X86InsnSet & getJmps2UnpackedCode() const { return branchesToPackedSections; }
  X86InsnSet & getJmps2UnpackedCode() { return branchesToPackedSections; }

  const AccessMap & get_accesses() const {
    return accesses;
  }

  const StackDelta get_call_delta(rose_addr_t addr) {
    return sp_tracker.get_call_delta(addr, sd_failures);
  }

  void update_delta(rose_addr_t addr, StackDelta const & sd) {
    return sp_tracker.update_delta(addr, sd, sd_failures);
  }

  size_t get_delta_failures() const {
    return sd_failures;
  }

  // Was the read a fake read?  (A read that wasn't really used)?
  bool fake_read(SgAsmX86Instruction* insn, const AbstractAccess& aa) const;

  access_filters::aa_range get_reads(rose_addr_t addr) const {
    return access_filters::read(accesses, addr);
  }
  access_filters::aa_range get_writes(rose_addr_t addr) const {
    return access_filters::write(accesses, addr);
  }
  access_filters::aa_range get_mems(rose_addr_t addr) const {
    return access_filters::mem(accesses, addr);
  }
  access_filters::aa_range get_regs(rose_addr_t addr) const {
    return access_filters::reg(accesses, addr);
  }
  access_filters::aa_range get_mem_reads(rose_addr_t addr) const {
    return access_filters::read_mem(accesses, addr);
  }
  access_filters::aa_range get_mem_writes(rose_addr_t addr) const {
    return access_filters::write_mem(accesses, addr);
  }
  access_filters::aa_range get_reg_reads(rose_addr_t addr) const {
    return access_filters::read_reg(accesses, addr);
  }
  access_filters::aa_range get_reg_writes(rose_addr_t addr) const {
    return access_filters::write_reg(accesses, addr);
  }

  // Return the single (expected) write for a given instruction.  If there's more than one,
  // return the first write.
  const AbstractAccess* get_the_write(rose_addr_t addr) const;
  // Return the first memory write for a given instruction.
  const AbstractAccess* get_first_mem_write(rose_addr_t addr) const;

  const Addr2DUChainMap& get_dependencies() const { return depends_on; }
  const Addr2DUChainMap& get_dependents() const { return dependents_of; }
  const DUChain* get_dependencies(rose_addr_t addr) const {
    Addr2DUChainMap::const_iterator finder = depends_on.find(addr);
    if (finder == depends_on.end()) return NULL; else return &(depends_on.at(addr));
  }
  const DUChain* get_dependents(rose_addr_t addr) const {
    Addr2DUChainMap::const_iterator finder = dependents_of.find(addr);
    if (finder == dependents_of.end()) return NULL; else return &(dependents_of.at(addr));
  }

  // For debugging
  void print_accesses(rose_addr_t addr) const;
  void print_dependencies() const;
  void print_dependents() const;
};

// Fetch the combinared condition for an address. This method is fairly narrow and meant to
// extract the condtion in a symbolic value that will reach an address (next_addr). This
// condition may be nested or otherwise complex. Coud this be generalized to find the
// conditions to an arbirary node regardless of whether it is a leaf? Probably, but testing
// node equivalence is tricky
SymbolicValuePtr
get_leaf_condition(SymbolicValuePtr sv, TreeNodePtr target_leaf, TreeNodePtr parent_condition, bool direction=true);


} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
