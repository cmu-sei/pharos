// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_SPTrack_Header
#define Pharos_SPTrack_Header

#include <string>
#include <vector>
#include <sstream>
#include <rose.h>
// Out of order because of SymbolicSemantics.h
#include "semantics.hpp"
#include <BinaryControlFlow.h>
#include <BinaryFunctionCall.h>

#include "descriptors.hpp"
#include "delta.hpp"
#include "riscops.hpp"

namespace pharos {

typedef std::vector<SgNode*> NodeVector;
typedef std::map<SgAsmx86Instruction*, X86InsnSet> ParameterMap;
typedef std::vector<SgAsmFunction*> FuncVector;
typedef std::map<SgAsmBlock*, int> BlockDeltas;
typedef std::map<SgAsmFunction*, int> FuncDeltas;
typedef std::vector<BlockDeltas> BlockDeltasVector;
typedef std::pair<int, int> IntPair;
typedef std::map<SgAsmBlock*, IntPair> Block2IntPairMap;
typedef std::map<SgAsmx86Instruction*, int> Insn2IntMap;
typedef std::pair<SgAsmx86Instruction*, int> InsnIntPair;
typedef std::vector<InsnIntPair> InsnIntPairVector;
typedef std::map<std::string, int> ImportParamMap;
typedef std::map<rose_addr_t, int> Addr2IntMap;
typedef std::set<SgAsmFunction*> FuncSet;

// A single import descriptor, containing a name and an address.
typedef std::pair<std::string, rose_addr_t> ImportDesc;
// A list of import descriptors.
typedef std::vector<ImportDesc> ImportDescVector;
// Map DLL names to a list of import descriptors.
typedef std::map<std::string, ImportDescVector> DLLDesc;

//typedef BinaryAnalysis::InstructionSemantics::X86InstructionSemantics<SymbolicRiscOperators, SymbolicValue> Semantics;

#define DU_REG_ESP get_register_state().gpr[SgAsmx86RegisterReferenceExpression::e_esp]

struct callBlock {
  int callerCleanupBytes;

  bool hasKnownParamBytes;
  int knownParamBytes;

  std::vector<int> paramCombos;
  InsnIntPairVector push_params;
};

typedef std::map<SgAsmBlock *, callBlock> CallBlockMap;

class spTracker {

public:

  spTracker(DescriptorSet* ds);

  // spAfterCalls is a mapping between a call instruction and the SP following the call
  // SP is assumed to be 0 at function entry
  // pushParams contains guessed push parameters to func
  // NOTE: We are not detecting potential fast call setup instructions

  void analyzeFunc(SgAsmFunction* func);

  // New interface to defuse and others...

  // Get params always return NULL right now.
  X86InsnSet* get_params(SgAsmx86Instruction* insn) {
    if (pushParams.find(insn) != pushParams.end()) {
      return &(pushParams[insn]);
    }
    else return NULL;
  }

  // Apparently all def use needs right now is to check for existence?
  bool no_sp_after_call(SgAsmx86Instruction* insn) {
    if (spAfterCalls.find(insn) == spAfterCalls.end()) return true;
    else return false;
  }

  // Hackish.  I'm just trying to get the old API synced up. :-(
  bool has_sp_after_block(SgAsmBlock* bb) {
    if (spBeforeAfterBlock.find(bb) == spBeforeAfterBlock.end()) return false;
    else return true;
  }

  int get_sp_after_block(SgAsmBlock* bb) {
    assert(spBeforeAfterBlock.find(bb) != spBeforeAfterBlock.end());
    return spBeforeAfterBlock[bb].second;
  }

  int get_func_delta(SgAsmFunction* func) {
    if (functionDeltas.find(func) != functionDeltas.end()) return functionDeltas[func];
    // Horrible hackish cheap cheap cheap.
    else return 9999999;
  }

  // Count the number of failures we've encountered for error reporting.
  void reset_recent_failures() { recent_failures = 0; }
  void add_failure() { recent_failures++; }
  size_t get_recent_failures() { return recent_failures; }

  inline void set_delta(rose_addr_t a, int d, GenericConfidence c) { set_delta(a, StackDelta(d, c)); }
  inline void set_delta(rose_addr_t a, StackDelta s) { deltas[a] = s; }
  inline void update_delta(rose_addr_t a, int d, GenericConfidence c) { update_delta(a, StackDelta(d, c)); }
  void update_delta(rose_addr_t addr, StackDelta sd);
  StackDelta get_call_delta(rose_addr_t);
  const StackDelta get_delta(rose_addr_t addr);

  void dump_deltas(std::string filename);

  // The pointer after calls?  Only populated in Z3 code?
  // Should not be public.
  Insn2IntMap spAfterCalls;

  // I'm not sure that this should here, but it's easier for now to pretend like it is.
  // There's currently no code to populate this map, so get_params will always return NULL.
  // Should not be public.
  ParameterMap pushParams;

protected:

  // The delta at the end of every block?  Only populated in non-Z3 code?
  BlockDeltas bDeltas;
  // The pointer before and after each block?  Largely duplicative of bDeltas?
  // Only populated in Z3 code?
  Block2IntPairMap spBeforeAfterBlock;

  FuncDeltas functionDeltas;

  // The new grand unified store everything data structure!

  // StackDeltaMap is a map from rose_addr_t to to a StackDelta structure.  It maps the address
  // of each instruction to the delta and confidence for the instruction starting at that
  // address.  In other words, the stack delta before the instruction is executed.  See the
  // declaration of StackDelta for more details.
  StackDeltaMap deltas;

  // This counts "recent" failures to help control the amount of logging that occurs.
  // Currently, it's set in back to zero at the beginning of teh analysis of every function,
  // and then tested again at the end of the analysis for the function.
  size_t recent_failures;

  FuncSet processed;
  DescriptorSet* descriptor_set;

  bool validate_func_delta(FunctionDescriptor *fd);

  Insn2IntMap getStackDepthAfterCalls(FunctionDescriptor* fd);

  bool getBlockDeltas(FunctionDescriptor* fd, SymbolicRiscOperators *opsFromCall);

  void analyzeFunctions();

};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
