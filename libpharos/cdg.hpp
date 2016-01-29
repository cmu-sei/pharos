// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_CDG_H
#define Pharos_CDG_H

#include <rose.h>
// For rose::BinaryAnalysis::Dominance
#include <BinaryDominance.h>

#include "misc.hpp"

typedef std::map<SgAsmx86Instruction*, InsnSet> Insn2InsnSetMap;
typedef rose::BinaryAnalysis::ControlFlow::Graph ControlFlowGraph;
typedef boost::graph_traits<ControlFlowGraph>::vertex_descriptor CFGVertex;
typedef std::set<CFGVertex> CFGVertexSet;

class CDG {
  std::vector<CFGVertex> forward_list;
  ControlFlowGraph cfg;
  std::map<SgAsmBlock *, CFGVertex> block_to_vertex;
  SgAsmFunction *func;
  // The immediate strict dominance vector of control flow graph vertexes.
  rose::BinaryAnalysis::Dominance::RelationMap<ControlFlowGraph> imm_dom;
  // The immediate strict post-dominance vector of control flow graph vertexes.
  rose::BinaryAnalysis::Dominance::RelationMap<ControlFlowGraph> imm_post_dom;

  // Initialize "block dependencies".
  void initialize_block_dependencies();

 public:

  // Forward and inverse mappings of dependents.
  std::map<CFGVertex, CFGVertexSet> depends_on;
  // This mapping is essentially unused at the present time.  Purpose unclear.
  std::map<CFGVertex, CFGVertexSet> dependents_of;

  CDG(FunctionDescriptor* f);

  // Ed's thesis made this clear in a way that I never understood from Wes.  A block D
  // dominates block B if and only if every path from the program entry point to the block B
  // includes block D.  A block P post-dominates block B if and only if every path from block B
  // to the program exit includes block P.

  // Return true if A dominates B.
  bool dominates(const CFGVertex& a, const CFGVertex& b) const {
    return dominance_helper(imm_dom, a, b);
  }
  // Return true if i1 dominates i2.
  bool dominates(const SgAsmx86Instruction *i1, const SgAsmx86Instruction *i2) const;

  // Return true if A post-dominates B.
  bool post_dominates(const CFGVertex& a, const CFGVertex& b) const {
    return dominance_helper(imm_post_dom, a, b);
  }
  // Return true if i1 post-dominates i2.
  bool post_dominates(const SgAsmx86Instruction *i1, const SgAsmx86Instruction *i2) const;

  // Dump dominance maps for debugging.
  void dump_dominance_maps() const;

  void get_dependents_between(const CFGVertex& a, const CFGVertex& b, CFGVertexSet &dependents) const;
  SgAsmx86Instruction* getControllingInstruction(const CFGVertex& vertex) const;
  X86InsnSet getControlDependencies(const SgAsmx86Instruction *insn) const;
  Insn2InsnSetMap getControlDependencies() const;
  void dumpBlock(const CFGVertex& vertex) const;
  void dumpControlDependencies() const;
  void dumpInsnDependencies() const;

 private:
  static bool dominance_helper(
    const rose::BinaryAnalysis::Dominance::RelationMap<ControlFlowGraph> & map,
    const CFGVertex &a, const CFGVertex &b);
};

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
