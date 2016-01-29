// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_DefUse_H
#define Pharos_DefUse_H

#include <fstream>
#include <map>
#include <vector>
#include <string>
#include <boost/format.hpp>
#include <boost/foreach.hpp>

#include <rose.h>
#include <sage3basic.h>
#include <BinaryControlFlow.h>

#include "misc.hpp"
#include "cdg.hpp"
#include "masm.hpp"
#include "sptrack.hpp"
#include "riscops.hpp"
#include "limit.hpp"

typedef rose::BinaryAnalysis::ControlFlow::Graph ControlFlowGraph;
typedef boost::graph_traits<ControlFlowGraph>::vertex_descriptor CFGVertex;

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

typedef std::set<Definition> DUChain;
typedef std::map<SgAsmx86Instruction *, DUChain> Insn2DUChainMap;
typedef std::map<SgAsmx86Instruction *, AbstractAccessVector> AccessMap;

typedef std::map<rose_addr_t, SymbolicStatePtr> StateHistoryMap;

void print_definitions(DUChain duc);

class DUAnalysis {

protected:
  // ==================================================================================
  // Parameters that control analysis.
  // ==================================================================================

  // This is a bit hackish, but very useful to prevent use having to pass it around.
  // Definately private, and maybe even naughty.  I haven't really decided yet.
  FunctionDescriptor* current_function;

  // The primary function that we're analyzing.  Analysis starts in this function, and
  // potentially continues into others defined in the following list.
  SgAsmFunction* primary_function;

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
  AccessMap reads;
  AccessMap writes;

  // The input state representing the machine state at the beginning of the function.
  SymbolicStatePtr input_state;
  // The output state representing the merged states at all of the return statements.  If we
  // cannot find a return block, use the state of the last basic block in flow order
  SymbolicStatePtr output_state;

  // Did the function consist of only valid return states?  In other words, did it meet one of
  // the most basic requirements of a well-formed function?
  bool valid_returns;

  // A list of block addresses in this function deemed bad by the BadCodeMetrics module.
  AddrSet bad_blocks;

  // ==================================================================================
  // Still deciding...
  // ==================================================================================

  // Populated in evaluate_bblock, used in patch_call_dependencies.
  Addr2InsnMap address_map;

  std::set<SgAsmx86Instruction *> branchesToPackedSections;

  // ==================================================================================
  // Private methods.
  // ==================================================================================

  bool check_for_eax_read(SgAsmx86Instruction* call_insn);
  LimitCode evaluate_bblock(SgAsmBlock* bblock, CustomDispatcherPtr& dispatcher, int initial_delta);
  bool sameDefiningHistoryInstructions(SymbolicStatePtr& cstate, SymbolicRiscOperatorsPtr& history);

  void handle_stack_delta(SgAsmBlock* bb, SgAsmx86Instruction* insn, CustomDispatcherPtr& dispatcher,
                          SymbolicStatePtr& before_state, int initial_delta);
  void update_call_targets(SgAsmx86Instruction* insn, SymbolicRiscOperatorsPtr& ops);
  void update_function_delta(FunctionDescriptor* fd);
  bool saved_register(SgAsmx86Instruction* insn, const Definition& def);
  void make_call_dependencies(SgAsmx86Instruction* insn, CustomDispatcherPtr& dispatcher,SymbolicStatePtr& cstate);


  // Analyze the return code situation for the current function.  Update returns_eax and
  // returns_this_pointer appropriately.
  void analyze_return_code(FunctionDescriptor* fd, CustomDispatcherPtr dispatcher);

  // Makes a matching pair of dependencies.  e.g. update both dependents and dependencies.
  // i1 reads the aloc defined by i2.  i2 defines the aloc read by i1.
  void add_dependency_pair(SgAsmx86Instruction* i1, SgAsmx86Instruction* i2, AbstractAccess access);

  // This is the main function that drives most of the work...
  LimitCode solve_flow_equation_iteratively();

  // Update the bad blocks set.
  void find_bad_blocks(std::vector<CFGVertex>& flowlist, ControlFlowGraph& cfg);

  void update_output_state(StateHistoryMap& state_histories);

public:

  // Perhaps the input and output states shouldn't be public.  But they used to be in
  // function_summary where they were public, and so it's a change to make them private.
  DUAnalysis(FunctionDescriptor* f, spTracker* s = NULL);

  const SymbolicStatePtr get_input_state() const { return input_state; }
  const SymbolicStatePtr get_output_state() const { return output_state; }

  // Cory asks: What is this doing here?
  const X86InsnSet getJmps2UnpackedCode() const { return branchesToPackedSections; }

  const AccessMap& get_reads() const { return reads; }
  const AccessMap& get_writes() const { return writes; }

  const AbstractAccessVector* get_reads(SgAsmx86Instruction* insn) const {
    AccessMap::const_iterator finder = reads.find(insn);
    if (finder == reads.end()) return NULL; else return &(reads.at(insn));
  }
  const AbstractAccessVector* get_writes(SgAsmx86Instruction* insn) const {
    AccessMap::const_iterator finder = writes.find(insn);
    if (finder == writes.end()) return NULL; else return &(writes.at(insn));
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

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
