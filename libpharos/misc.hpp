// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Misc_H
#define Pharos_Misc_H

// This file contains utility functions for ROSE and the like.

#include <rose.h>
// For TreeNodePtr, LeafNodePtr, etc.
#include <BinarySymbolicExpr.h>
// For Semantics2 namespace.
#include <SymbolicSemantics2.h>

// Duplicative with funcs.hpp. :-(
typedef std::set<rose_addr_t> AddrSet;
// Duplicative with semantics.hpp. :-(
typedef rose::BinaryAnalysis::SymbolicExpr::Leaf LeafNode;
typedef rose::BinaryAnalysis::SymbolicExpr::LeafPtr LeafNodePtr;
typedef rose::BinaryAnalysis::SymbolicExpr::Interior InternalNode;
typedef rose::BinaryAnalysis::SymbolicExpr::InteriorPtr InternalNodePtr;
typedef rose::BinaryAnalysis::SymbolicExpr::Node TreeNode;
typedef rose::BinaryAnalysis::SymbolicExpr::Ptr TreeNodePtr;

typedef rose::BinaryAnalysis::Disassembler RoseDisassembler;
typedef rose::BinaryAnalysis::Partitioner RosePartitioner;

typedef std::set<LeafNodePtr> LeafNodePtrSet;
typedef std::set<TreeNodePtr> TreeNodePtrSet;

// Make the ROSE Semantics2 namespace a little shorter to type...
namespace Semantics2 = rose::BinaryAnalysis::InstructionSemantics2;

// Import InsnSet from ROSE.
typedef Semantics2::SymbolicSemantics::InsnSet InsnSet;

// A set of X86 instructions.
typedef std::set<SgAsmx86Instruction*> X86InsnSet;

// An ordered list of register descriptors.
typedef std::vector<const RegisterDescriptor*> RegisterVector;

// Limit the maximum number of parameters.  This is arbitrary and incorrect, but if we don't
// limit it to some reasonable number, then we generate tons of error spew.  Some experience
// with actual code and an error level message, should keep this arbitrary limit from becoming
// a real problem.  Alternatively, we can remove the limit once we're confident that the
// parameter detection code always works.
#define ARBITRARY_PARAM_LIMIT 60

// An unordered set of register descriptors.  There's been a lot of flailing with respect to
// register descriptors, sets, const, etc. In the end this is the approach that appears to work
// best.
class RegisterCompare {
  public:
  bool operator()(const RegisterDescriptor* x, const RegisterDescriptor* y)
    const { return (*x < *y); }
};

typedef std::set<const RegisterDescriptor*, RegisterCompare> RegisterSet;

// The main program need to provide a global logging facility.
extern Sawyer::Message::Facility glog;
#define GCRAZY (glog[Sawyer::Message::DEBUG]) && glog[Sawyer::Message::DEBUG]
#define GTRACE (glog[Sawyer::Message::TRACE]) && glog[Sawyer::Message::TRACE]
#define GDEBUG (glog[Sawyer::Message::WHERE]) && glog[Sawyer::Message::WHERE]
#define GMARCH (glog[Sawyer::Message::MARCH]) && glog[Sawyer::Message::MARCH]
#define GINFO  (glog[Sawyer::Message::INFO])  && glog[Sawyer::Message::INFO]
#define GWARN  (glog[Sawyer::Message::WARN])  && glog[Sawyer::Message::WARN]
#define GERROR glog[Sawyer::Message::ERROR]
#define GFATAL glog[Sawyer::Message::FATAL]

// The semantics module provides a logging facility as well.
extern Sawyer::Message::Facility slog;
#define SCRAZY (slog[Sawyer::Message::DEBUG]) && slog[Sawyer::Message::DEBUG]
#define STRACE (slog[Sawyer::Message::TRACE]) && slog[Sawyer::Message::TRACE]
#define SDEBUG (slog[Sawyer::Message::WHERE]) && slog[Sawyer::Message::WHERE]
#define SMARCH (slog[Sawyer::Message::MARCH]) && slog[Sawyer::Message::MARCH]
#define SINFO  (slog[Sawyer::Message::INFO])  && slog[Sawyer::Message::INFO]
#define SWARN  (slog[Sawyer::Message::WARN])  && slog[Sawyer::Message::WARN]
#define SERROR slog[Sawyer::Message::ERROR]
#define SFATAL slog[Sawyer::Message::FATAL]

// For local context logging
#define MCRAZY (mlog[Sawyer::Message::DEBUG]) && mlog[Sawyer::Message::DEBUG]
#define MTRACE (mlog[Sawyer::Message::TRACE]) && mlog[Sawyer::Message::TRACE]
#define MDEBUG (mlog[Sawyer::Message::WHERE]) && mlog[Sawyer::Message::WHERE]
#define MMARCH (mlog[Sawyer::Message::MARCH]) && mlog[Sawyer::Message::MARCH]
#define MINFO  (mlog[Sawyer::Message::INFO])  && mlog[Sawyer::Message::INFO]
#define MWARN  (mlog[Sawyer::Message::WARN])  && mlog[Sawyer::Message::WARN]
#define MERROR mlog[Sawyer::Message::ERROR]
#define MFATAL mlog[Sawyer::Message::FATAL]

namespace pharos {

void backtrace(
  Sawyer::Message::Facility & log = glog,
  Sawyer::Message::Importance level = Sawyer::Message::FATAL,
  int maxlen = 20);

} // namespace pharos

#include "options.hpp"
#include "util.hpp"

// The distinction between this files and Cory's utils is poorly defined.  The restrictions on
// preconditions for things in this file is also poorly defined.  In general, this header
// should not include anything but rose headers (e.g. it should be lightweight with respect to
// our code).

// This file should only be included once from the main program, since it's not really a
// header.

// Compare two RegisterDescriptors, ought to be on RegisterDescriptor
bool RegisterDescriptorLtCmp(const RegisterDescriptor a, const RegisterDescriptor b);

// Compute the difference in seconds between to timestamps.
double tdiff(timespec start, timespec end);

// A replacement for the ROSE front end.
SgAsmInterpretation* get_interpretation(ProgOptVarMap& vm);
// Get the Win32 interpretation out of a PE file project.
SgAsmInterpretation* GetWin32Interpretation(SgProject* project);

// This should be a method on SgAsmX86Instruction and possibly on SgAsmInstruction as well.
bool insn_is_call(const SgAsmx86Instruction* insn);

// I think we meant insn_is_call() in all of these cases...
bool insn_is_callNF(const SgAsmx86Instruction* insn);

// Conditional jumps, but not uncoditional jumps.
bool insn_is_jcc(const SgAsmx86Instruction* insn);

// Calls and conditional jumps, but not unconditional jumps.  Should be renamed?
bool insn_is_branch(const SgAsmx86Instruction* insn);

// All control flow instructions (calls, jumps, and conditional jumps).
bool insn_is_control_flow(const SgAsmx86Instruction* insn);

// Get the fallthru address of this instruction.
rose_addr_t insn_get_fallthru(SgAsmInstruction* insn);
// Get the non-fallthru (branch) address of this instruction.
rose_addr_t insn_get_branch_target(SgAsmInstruction* insn);
// Get the fixed portion of an instruction in the form: "jmp [X]"
rose_addr_t insn_get_jump_deref(SgAsmInstruction* insn);

// Get the block containing the instruction.
SgAsmBlock* insn_get_block(const SgAsmInstruction* insn);
// Get the function containing the instruction.
SgAsmFunction* insn_get_func(const SgAsmInstruction* insn);

// Get the successors for the basic block.
AddrSet bb_get_successors(SgAsmBlock* bb);

// Determine whether an expression contains an additive offset
class AddConstantExtractor {
public:
  // Well formed means that we had both a variable and a constant portion, although the
  // variable portion might be more complex than the caller desired.  If desired the caller can
  // confirm that the variable portion is a simple leaf node (and not an ADD operation).
  bool well_formed;

  // The variable portion of the expression (everything not a constant addition).
  TreeNodePtr variable_portion;

  // The constant portion of the expression.
  int64_t constant_portion;

  // The end results are:
  //
  // Input expression   Well formed   Constant  Variable portion
  // ----------------   -----------   --------  ----------------
  // 3                  false         3         NULL!
  // 3+4                false         7         NULL!
  // x                  false         0         x
  // x+y                false         0         x+y
  // x+3                true          3         x
  // x+3+4              true          7         x
  // x+y+3              true          3         x+y
  // x+y+3+4            true          7         x+y

  AddConstantExtractor(const TreeNodePtr& tn);
};

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
