// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#include "cdg.hpp"
#include "masm.hpp"
#include "util.hpp"
#include "funcs.hpp"

#include <boost/graph/dominator_tree.hpp>
#include <boost/graph/reverse_graph.hpp>

namespace pharos {

#define NULL_VERTEX boost::graph_traits<ControlFlowGraph>::null_vertex()
using DomIdx = typename boost::property_map<ControlFlowGraph, boost::vertex_index_t>::type;

CDG::CDG(FunctionDescriptor *f) {
  Rose::BinaryAnalysis::ControlFlow cfg_analysis;

  // Save a copy of the SgAsmFunction.
  func = f->get_func();

  // Build the CFG and get the blocks in forward flow order
  cfg = cfg_analysis.build_block_cfg_from_ast<ControlFlowGraph>(func);

  // Some sanity checking to prove that the true entry vertex is always zero.  This test still
  // fails in some rare cases where function's entry_block() is NULL.  This is apparently due
  // to some bug in the partitioner, because the case I looked at was garbage code made from
  // bytes in the import segment.  More analysis is sadly still required.
  CFGVertex entry = 0;

  // The entry block from the perspective of the control flow graph.
  SgAsmBlock *eblock = get(boost::vertex_name, cfg, entry);
  // The entry block from the perspective of the SgAsmFunction object.
  SgAsmBlock *feblock = func->get_entry_block();

  // Now report various failures without asserting.
  if (eblock == NULL) {
    GERROR << "CFG entry block is NULL for function: " << f->address_string() << LEND;
  }
  if (feblock == NULL) {
    GERROR << "Entry block is NULL for function: " << f->address_string() << LEND;
  }
  if (eblock != NULL and feblock != NULL and eblock != feblock) {
    GERROR << "Unexpected entry block mismatch " << addr_str(eblock->get_address())
           << " != " << addr_str(feblock->get_address()) << "." << LEND;
  }

  forward_list = cfg_analysis.flow_order(cfg,entry,NULL);

  // If building the dominance and post-dominance maps turns out to be expensive, we could
  // improve performance by deferring it's computation until someone asks a dominance question.

  // Build the immediate-dominator array
  auto idx = DomIdx(get(boost::vertex_index, cfg));
  imm_dom = DomVec(num_vertices(cfg), NULL_VERTEX);
  auto dom_map = make_iterator_property_map(imm_dom.begin(), idx);
  lengauer_tarjan_dominator_tree(cfg, entry, dom_map);

  // Dominance analysis failed
  // We won't have a correct dominance analysis
  if (imm_dom.size() == 0) {
    GERROR << "Dominance analysis failed for function: "
           << addr_str(func->get_entry_va()) << LEND;
  }

  // Build the immediate-post-dominator array.
  auto retblocks = cfg_analysis.return_blocks(cfg, entry);
  switch (retblocks.size()) {
   case 0:
    imm_post_dom = DomVec(num_vertices(cfg), NULL_VERTEX);
    break;
   case 1:
    {
      // This function has one exit block
      auto rev_cfg = make_reverse_graph(cfg);
      auto post_idx = DomIdx(get(boost::vertex_index, rev_cfg));
      imm_post_dom = DomVec(num_vertices(rev_cfg), NULL_VERTEX);
      auto post_map = make_iterator_property_map(imm_post_dom.begin(), post_idx);
      lengauer_tarjan_dominator_tree(rev_cfg, retblocks[0], post_map);
    }
    break;
   default:
    {
      // This function has multiple exit blocks.
      ControlFlowGraph copy = cfg;
      auto unique_exit = add_vertex(copy);
      for (auto v : retblocks) {
        add_edge(v, unique_exit, copy);
      }
      auto rev_cfg = make_reverse_graph(cfg);
      auto post_idx = DomIdx(get(boost::vertex_index, rev_cfg));
      imm_post_dom = DomVec(num_vertices(rev_cfg), NULL_VERTEX);
      auto post_map = make_iterator_property_map(imm_post_dom.begin(), post_idx);
      lengauer_tarjan_dominator_tree(rev_cfg, retblocks[0], post_map);
      for (auto & v : imm_post_dom) {
        if (v == unique_exit) {
          v = NULL_VERTEX;
        }
      }
    }
  }

  // Post-dominance analysis failed
  // We won't have a correct dominance analysis
  if (imm_post_dom.size() == 0) {
    GERROR << "Post-dominance analysis failed for function: "
           << addr_str(func->get_entry_va()) << LEND;
  }

  initialize_block_dependencies();
  // dumpControlDependencies();
}

// A helper routine to evaluate the immediate (or post) dominance map recursively, turning an
// immediate result into an overall result.  The return value is whether A dominates B.
bool CDG::dominance_helper(
  const DomVec & map,
  const CFGVertex &a, const CFGVertex &b)
{
  // This at() call will throw an exception if b is not in the map.
  const CFGVertex& bs_dominator = map.at(b);
  // If B's not immediately dominated by anybody, it's not immediately dominated A.
  if (bs_dominator == NULL_VERTEX) return false;
  // If B is immediately dominated by A, then requested condition is true.
  if (bs_dominator == a) return true;
  // Otherwise, we need to determine whether A dominates B's immediate dominator.
  else return dominance_helper(map, a, bs_dominator);
}

// Does i1 dominate i2?  This convenience version takes two instructions instead of two basic
// blocks or two control flow graph vertices.
bool CDG::dominates(const SgAsmX86Instruction *i1, const SgAsmX86Instruction *i2) const {
  if (!i1 || !i2) return false;
  SgAsmBlock *bb1 = insn_get_block(i1);
  assert(bb1);
  SgAsmBlock *bb2 = insn_get_block(i2);
  assert(bb2);

  //GTRACE << "Insn " << addr_str(i1->get_address()) << " is in block " << addr_str(bb1->get_address()) << LEND;
  //GTRACE << "Insn " << addr_str(i2->get_address()) << " is in block " << addr_str(bb2->get_address()) << LEND;
  if (bb1 == bb2) return i1->get_address() <= i2->get_address();

  // If the basic blocks aren't in the map return false.
  if (block_to_vertex.find(bb1) == block_to_vertex.end() ||
      block_to_vertex.find(bb2) == block_to_vertex.end()) return false;

  // Return the dominance result based on the vertexes.  Calling at() cannot throw since we
  // just checked that both blocks are in the map.
  //GTRACE << "Asking helper(" << block_to_vertex.at(bb1) << ", " << block_to_vertex.at(bb2) << ")" << LEND;
  return dominates(block_to_vertex.at(bb1), block_to_vertex.at(bb2));
}

// Does i1 post-dominate i2?  This convenience version takes two instructions instead of two
// basic blocks or two control flow graph vertices.
bool CDG::post_dominates(const SgAsmX86Instruction *i1, const SgAsmX86Instruction *i2) const {
  if (!i1 || !i2) return false;
  SgAsmBlock *bb1 = insn_get_block(i1);
  assert(bb1);
  SgAsmBlock *bb2 = insn_get_block(i2);
  assert(bb2);

  if (bb1 == bb2) return i1->get_address() >= i2->get_address();

  // If the basic blocks aren't in the map return false.
  if (block_to_vertex.find(bb1) == block_to_vertex.end() ||
      block_to_vertex.find(bb2) == block_to_vertex.end()) return false;

  // Return the post dominance result based on the vertexes.  Calling at() cannot throw since
  // we just checked that both blocks are in the map.
  return post_dominates(block_to_vertex.at(bb1), block_to_vertex.at(bb2));
}

void CDG::get_dependents_between(const CFGVertex& a, const CFGVertex& b, CFGVertexSet &dependents) const {
  // Either of these at() calls might throw, but that's probably better than blindly creating nodes.
  const CFGVertex& apd = imm_post_dom.at(a);
  const CFGVertex& bpd = imm_post_dom.at(b);

  dependents.insert(b);
  if (apd != NULL_VERTEX && bpd == apd) {
    return;
  } else if (bpd == a) {
    dependents.insert(a);
    return;
  } else if (bpd != NULL_VERTEX) {
    get_dependents_between(a, bpd, dependents);
  }
}

// This method has not been carefully reviewed since Wes wrote it...  It appears to be part of
// the constructor really.  It looks like it builds block_to_vertex, depends_on, and
// dependents_of.
void CDG::initialize_block_dependencies() {
  // Find all edges (A,B) in the CFG such that B is not
  // an ancestor of A in the post-dominator tree
  for (size_t x = 0; x < forward_list.size(); x++) {
    CFGVertex vertex = forward_list[x];

    // Get the basic block
    SgAsmBlock *bb = get(boost::vertex_name, cfg, vertex);
    assert(bb != NULL);
    block_to_vertex[bb] = vertex;

    // dumpBlock(vertex);

    // Get the successors
    boost::graph_traits<ControlFlowGraph>::out_edge_iterator ei, ei_end;
    for (boost::tie(ei, ei_end)=out_edges(vertex, cfg); ei!=ei_end; ++ei) {
      CFGVertex successor = target(*ei, cfg);
      if (!post_dominates(successor, vertex)) {
        CFGVertexSet dependants;

        // If we can find a way to get to the END from vertex without going through successor,
        // All nodes that are post-dominated by successor upto the least-common post-dominator
        // of vertex, are control dependant on vertex (FOW'87)
        get_dependents_between(vertex,successor,dependants);
        if (dependents_of.find(vertex) == dependents_of.end())
          dependents_of[vertex] = dependants;
        else
          dependents_of[vertex].insert(dependants.begin(),dependants.end());

        for (CFGVertexSet::iterator it = dependants.begin(); it != dependants.end(); it++) {
          if (depends_on.find(*it) == depends_on.end()) {
            CFGVertexSet d;
            d.insert(vertex);
            depends_on[*it] = d;
          }
          else {
            depends_on[*it].insert(vertex);
          }
        }

        STRACE << "Adding (" << vertex << "," << successor << ")" << LEND;
      }
    }
  }
}

SgAsmX86Instruction* CDG::getControllingInstruction(const CFGVertex& vertex) const {
  SgAsmBlock *bb = get(boost::vertex_name, cfg, vertex);
  assert(bb != NULL);

  SgAsmStatementPtrList & l = bb->get_statementList();
  assert(l.size() > 0);
  SgAsmX86Instruction *lastInsn = isSgAsmX86Instruction(l[l.size()-1]);
  assert(lastInsn);

  if (lastInsn->get_kind() >= x86_ja && lastInsn->get_kind() <= x86_js) {
    return lastInsn;
  }
  else {
    //SERROR << "Control-flow depends on a block that doesn't have a conditional branch..." << LEND;
    return NULL;
  }
}

X86InsnSet CDG::getControlDependencies(const SgAsmX86Instruction *insn) const {
  X86InsnSet out;

  if (insn == NULL) return out;

  // Get the parent block
  SgAsmBlock *bb = insn_get_block(insn);
  assert(bb);
  if (block_to_vertex.find(bb) == block_to_vertex.end()) {
    STRACE << "Parent of " << debug_instruction(insn) << " resides in another function" << LEND;
    return out;
  }

  // Get the controling blocks
  // STRACE << debug_instruction(insn) << " depends on blocks: ";
  const CFGVertex& v = block_to_vertex.at(bb);
  // Previously, this very suspiciously created entries in depends_on due to the undesired
  // creation behavior of the [x] operator.  It's unclear what the impact of that was, but it
  // seems very unlikely to have been intentional.
  if (depends_on.find(v) != depends_on.end()) {
    for (const CFGVertex &o : depends_on.at(v)) {
      SgAsmX86Instruction *c = getControllingInstruction(o);
      if (c)
        out.insert(c);
    }
  }

  return out;
}

Insn2InsnSetMap CDG::getControlDependencies() const {
  Insn2InsnSetMap out;
  for (const SgAsmStatement* bs : func->get_statementList()) {
    const SgAsmBlock *bb = isSgAsmBlock(bs);
    assert(bb);
    for (SgAsmStatement* is : bb->get_statementList()) {
      SgAsmX86Instruction *insn = isSgAsmX86Instruction(is);
      InsnSet temp;
      X86InsnSet deps = getControlDependencies(insn);
      if (deps.size() > 0) {
        for (X86InsnSet::iterator it = deps.begin(); it != deps.end(); it++) {
          temp.insert(*it);
        }
        out[insn] = temp;
      }
    }
  }
  return out;
}

// Dump the strict immediate dominance relationship maps generated by ROSE.
void CDG::dump_dominance_maps() const
{
  // Writing this routine helped clear up a lot of the previous confusion about dominance.
  // Since each node (except the entry node) is immediately dominated _BY_ one and only one
  // node, it makes sense for the map to be keyed by the node being dominated, and the value to
  // be the node doing the dominating, which is of course backwards of the API that most folks
  // would find "natural", which is to list the node doing the dominating first.  Thus we have
  // Wes' strangely named functions, and confusion about which parameter is dominating which.

  OINFO << "Dominance Map contains:" << LEND;
  for (size_t v = 0; v < imm_dom.size(); ++v) {
    const CFGVertex& t = imm_dom[v];
    rose_addr_t addr1 = 0;
    rose_addr_t addr2 = 0;
    SgAsmBlock *bb1 = isSgAsmBlock(get(boost::vertex_name, cfg, v));
    if (bb1 != NULL) addr1 = bb1->get_address();
    OINFO << "  vertex=" << v << " bb=" << addr_str(addr1) << " is immediately dominated by ";

    if (t == NULL_VERTEX) {
      OINFO << "nothing." << LEND;
    }
    else {
      SgAsmBlock *bb2 = isSgAsmBlock(get(boost::vertex_name, cfg, t));
      if (bb2 != NULL) addr2 = bb2->get_address();
      OINFO << "vertex=" << t << " bb=" << addr_str(addr2) << LEND;
    }
  }

  OINFO << "Post-Dominance Map contains:" << LEND;
  for (size_t v = 0; v < imm_post_dom.size() - 1; ++v) {
    const CFGVertex& t = imm_post_dom[v];
    rose_addr_t addr1 = 0;
    rose_addr_t addr2 = 0;
    SgAsmBlock *bb1 = isSgAsmBlock(get(boost::vertex_name, cfg, v));
    if (bb1 != NULL) addr1 = bb1->get_address();
    OINFO << "  vertex=" << v << " bb=" << addr_str(addr1) << " is immediately post-dominated by ";
    if (t == NULL_VERTEX) {
      OINFO << "nothing." << LEND;
    }
    else {
      SgAsmBlock *bb2 = isSgAsmBlock(get(boost::vertex_name, cfg, t));
      if (bb2 != NULL) addr2 = bb2->get_address();
      OINFO << "vertex=" << t << " bb=" << addr_str(addr2) << LEND;
    }
  }
}

void CDG::dumpBlock(const CFGVertex& vertex) const {
  // Get the basic block
  SgAsmBlock *bb = get(boost::vertex_name, cfg, vertex);
  assert(bb != NULL);

  // Dump statements
  SINFO << "CFG Vertex " << vertex << " " << addr_str(bb->get_address()) <<LEND;
  for (const SgAsmStatement* s : bb->get_statementList()) {
    const SgAsmX86Instruction *insn = isSgAsmX86Instruction(s);
    SINFO << debug_instruction(insn) << LEND;
  }
}

void CDG::dumpControlDependencies() const {
  SINFO << "Control dependencies:" << LEND;

  for (size_t y = 0; y < forward_list.size(); y++) {
    CFGVertex v = forward_list.at(y);
    SINFO << "Vertex: " << v << LEND;
    if (depends_on.find(v) != depends_on.end()) {
      SINFO << "  Depends on:";
      for (const CFGVertex& dv : depends_on.at(v)) {
        SINFO << " " << dv;
      }
      SINFO << LEND;
    }
    if (dependents_of.find(v) != dependents_of.end()) {
      SINFO << "  Dependants:";
      for (const CFGVertex& dv : dependents_of.at(v)) {
        SINFO << " " << dv;
      }
      SINFO << LEND;
    }
  }
}

void CDG::dumpInsnDependencies() const {
  for (const SgAsmStatement* bs : func->get_statementList()) {
    const SgAsmBlock *bb = isSgAsmBlock(bs);
    assert(bb);
    for (const SgAsmStatement* is : bb->get_statementList()) {
      const SgAsmX86Instruction *insn = isSgAsmX86Instruction(is);
      SINFO << debug_instruction(insn) << " =f=> ";
      X86InsnSet deps = getControlDependencies(insn);
      if (deps.size() == 0) {
        SINFO << "ENTRY" << LEND;
      } else {
        for (const SgAsmX86Instruction *dep : deps) {
          SINFO << addr_str(dep->get_address()) << " ";
        }
        SINFO << LEND;
      }
    }
  }
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
