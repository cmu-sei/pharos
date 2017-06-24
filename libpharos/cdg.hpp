// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_CDG_H
#define Pharos_CDG_H

#include <rose.h>
// For Rose::BinaryAnalysis::Dominance
#include <BinaryDominance.h>

#include "misc.hpp"
#include <boost/range/adaptor/transformed.hpp>

namespace pharos {

typedef std::map<SgAsmx86Instruction*, InsnSet> Insn2InsnSetMap;
typedef Rose::BinaryAnalysis::ControlFlow::Graph ControlFlowGraph;
typedef boost::graph_traits<ControlFlowGraph>::vertex_descriptor CFGVertex;
typedef boost::graph_traits<ControlFlowGraph>::edge_descriptor CFGEdge;
typedef std::set<CFGVertex> CFGVertexSet;

class CDG {
  std::vector<CFGVertex> forward_list;
  ControlFlowGraph cfg;
  std::map<SgAsmBlock *, CFGVertex> block_to_vertex;
  SgAsmFunction *func;
  // The immediate strict dominance vector of control flow graph vertexes.
  Rose::BinaryAnalysis::Dominance::RelationMap<ControlFlowGraph> imm_dom;
  // The immediate strict post-dominance vector of control flow graph vertexes.
  Rose::BinaryAnalysis::Dominance::RelationMap<ControlFlowGraph> imm_post_dom;

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
    const Rose::BinaryAnalysis::Dominance::RelationMap<ControlFlowGraph> & map,
    const CFGVertex &a, const CFGVertex &b);
};

template <typename G>
boost::iterator_range<typename boost::graph_traits<G>::vertex_iterator>
cfg_vertices(const G & cfg)
{
  return boost::make_iterator_range(boost::vertices(cfg));
}

template <typename G>
boost::iterator_range<typename boost::graph_traits<G>::out_edge_iterator>
cfg_out_edges(const G & cfg, typename boost::graph_traits<G>::vertex_descriptor v)
{
  return boost::make_iterator_range(boost::out_edges(v, cfg));
}

template <typename G>
boost::iterator_range<typename boost::graph_traits<G>::in_edge_iterator>
cfg_in_edges(const G & cfg, typename boost::graph_traits<G>::vertex_descriptor v)
{
  return boost::make_iterator_range(boost::in_edges(v, cfg));
}

template <typename G, bool forwards = true>
struct Convert_Edge_To_Vertex {
  using edge = typename boost::graph_traits<G>::edge_descriptor;
  using vertex = typename boost::graph_traits<G>::vertex_descriptor;
  Convert_Edge_To_Vertex(const G & g) : graph(g) {}
  Convert_Edge_To_Vertex &operator=(const Convert_Edge_To_Vertex &) = default;
  vertex operator()(edge e) const {
    return forwards ? boost::target(e, graph) : boost::source(e, graph);
  }
  const G & graph;
};

template <bool forwards, typename G>
Convert_Edge_To_Vertex<G, forwards> convert_edge_to_vertex(const G & g) {
  return Convert_Edge_To_Vertex<G, forwards>(g);
}

template <bool forwards, typename G>
typename Convert_Edge_To_Vertex<G, forwards>::vertex
convert_edge_to_vertex(const G & g, typename Convert_Edge_To_Vertex<G, forwards>::edge e) {
  return convert_edge_to_vertex<forwards>(g)(e);
}

template <typename G>
auto cfg_out_vertices(const G & cfg, typename boost::graph_traits<G>::vertex_descriptor v) ->
  decltype(cfg_out_edges(cfg, v)
           | boost::adaptors::transformed(convert_edge_to_vertex<true>(cfg)))
{
  return (cfg_out_edges(cfg, v)
          | boost::adaptors::transformed(convert_edge_to_vertex<true>(cfg)));
}

template <typename G>
auto cfg_in_vertices(const G & cfg, typename boost::graph_traits<G>::vertex_descriptor v) ->
  decltype(cfg_in_edges(cfg, v)
           | boost::adaptors::transformed(convert_edge_to_vertex<false>(cfg)))
{
  return (cfg_in_edges(cfg, v)
          | boost::adaptors::transformed(convert_edge_to_vertex<false>(cfg)));
}

template <typename G>
struct Convert_Vertex_To_BBlock {
  using vertex = typename boost::graph_traits<G>::vertex_descriptor;
  using bblock = SgAsmBlock *;
  Convert_Vertex_To_BBlock(const G & g) : graph(g) {}
  Convert_Vertex_To_BBlock &operator=(const Convert_Vertex_To_BBlock &) = default;
  bblock operator()(vertex e) const { return boost::get(boost::vertex_name, graph, e); }
  const G & graph;
};

template <typename G>
Convert_Vertex_To_BBlock<G> convert_vertex_to_bblock(const G & g) {
  return Convert_Vertex_To_BBlock<G>(g);
}

template <typename G>
typename Convert_Vertex_To_BBlock<G>::bblock
convert_vertex_to_bblock(const G & g, typename Convert_Vertex_To_BBlock<G>::vertex v) {
  return convert_vertex_to_bblock(g)(v);
}

template <typename G>
auto cfg_bblocks(const G & cfg) ->
  decltype(cfg_vertices(cfg) | boost::adaptors::transformed(convert_vertex_to_bblock(cfg)))
{
  return (cfg_vertices(cfg) | boost::adaptors::transformed(convert_vertex_to_bblock(cfg)));
}

template <typename G>
auto cfg_out_bblocks(const G & cfg, typename boost::graph_traits<G>::vertex_descriptor v) ->
  decltype(cfg_out_vertices(cfg, v)
           | boost::adaptors::transformed(convert_vertex_to_bblock(cfg)))
{
  return (cfg_out_vertices(cfg, v)
          | boost::adaptors::transformed(convert_vertex_to_bblock(cfg)));
}

template <typename G>
auto cfg_in_bblocks(const G & cfg, typename boost::graph_traits<G>::vertex_descriptor v) ->
  decltype(cfg_in_vertices(cfg, v)
           | boost::adaptors::transformed(convert_vertex_to_bblock(cfg)))
{
  return (cfg_in_vertices(cfg, v)
          | boost::adaptors::transformed(convert_vertex_to_bblock(cfg)));
}

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
