// Copyright 2019-2024 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/range/adaptors.hpp>

#include <Sawyer/GraphTraversal.h>
#include <Sawyer/GraphIteratorSet.h>

#include "graph.hpp"
#include "descriptors.hpp"
#include "masm.hpp"

namespace pharos {
namespace PD {

Graph::Graph() : SawyerPDG()
{
  // Create the indeterminate vertex.
  indeterminate = insertVertex(PDGVertex(V_INDETERMINATE));
}

SawyerPDG::ConstEdgeIterator
Graph::get_edge(const SawyerPDG::ConstVertexIterator& fromv,
                const SawyerPDG::ConstVertexIterator& tov) const {

  for (SawyerPDG::ConstEdgeIterator edge = fromv->outEdges().begin(); edge != fromv->outEdges().end(); ++edge) {
    if (edge->target()->id() == tov->id()) return edge;
  }
  return fromv->outEdges().end();
}

void
Graph::populate(const DescriptorSet& ds, const P2::Partitioner& p)
{
  using clock = std::chrono::steady_clock;
  using time_point = std::chrono::time_point<clock>;
  using duration = std::chrono::duration<double>;

  time_point start_ts = clock::now();
  GINFO << "Creating the whole-program instruction level control flow graph." << LEND;
  // ----------------------------------------------------------------------------------------
  // First create all the vertices...
  // ----------------------------------------------------------------------------------------

  // Create a vertex for every known instruction.
  for (P2::BasicBlock::Ptr b : p.basicBlocks()) {
    for (SgAsmInstruction* insn : b->instructions()) {
      bool inserted = false;

      // Try creating a vertex with a call descriptor.
      SgAsmX86Instruction* xinsn = isSgAsmX86Instruction(insn);
      if (xinsn) {
        if (insn_is_call(xinsn)) {
          const CallDescriptor* cd = ds.get_call(insn->get_address());
          if (cd) {
            insertVertexMaybe(PDGVertex(*cd, b));
            inserted = true;
          }
        }
      }

      // Create an instruction vertex if we haven't already created a call vertex.
      if (!inserted) {
        insertVertexMaybe(PDGVertex(insn, b));
      }
    }
  }


  // Create a vertex for every import.
  const ImportDescriptorMap& imports = ds.get_import_map();
  for (const ImportDescriptor& id : boost::adaptors::values(imports)) {
    //OINFO << "Creating import vertex at " << id.address_string() << LEND;
    insertVertexMaybe(PDGVertex(id));
  }

  // Create a vertex for every global memory variable.
  const GlobalMemoryDescriptorMap& globals = ds.get_global_map();
  for (const GlobalMemoryDescriptor& gmd : boost::adaptors::values(globals)) {
    // There can be global memory descriptors for instructions, so we'll need to rethink this a
    // little.   There are also probably global memory references to imports in some cases too.
    insertVertexMaybe(PDGVertex(gmd));
    // else { GWARN << "Duplicate vertex: " << gmd.address_string() << LEND; }
  }

  // From a multi-threading perspective, I think all of the vertices that will ever exist have
  // been created at this point, and all that remains is to create edges between them.  There
  // are some scenarios where we might want to create additional vertices in the future
  // including dynamic import resolution and analysis while partitioning, but thos will all
  // require additional thought.

  std::set<rose_addr_t> calls;

  // ----------------------------------------------------------------------------------------
  // Then create all of the edges.
  // ----------------------------------------------------------------------------------------
  for (P2::BasicBlock::Ptr b : p.basicBlocks()) {

    // This is the edge type that we're using for non-fallthru edges.  It starts as E_BRANCH,
    // and may be set to something else for the last instruction of the block.
    PDGEdgeType edge_type = E_BRANCH;

    // Visit each instruction in block.
    size_t num_insns = b->instructions().size();
    for (size_t i = 0; i < num_insns; ++i) {
      SgAsmInstruction* insn = b->instructions()[i];
      SgAsmX86Instruction* xinsn = isSgAsmX86Instruction(insn);

      // Find the corresponding instruction vertex.
      SawyerPDG::VertexIterator fromv = findVertexKey(insn->get_address());

      // Instructions with REP/REPE/REPNE prefixes should have a self-referencing edge.
      if (xinsn && insn_is_repeat(xinsn)) {
        insertEdge(fromv, fromv, PDGEdge(E_REPEAT));
      }

      // True if we know all of the successors for the instruction (handled last).
      bool complete;
      // Get the list of successor addresses.
      auto successors = insn->architecture()->getSuccessors(insn, complete);

      // The edge type for the last instruction in the block is either E_RETURN or E_CALL based
      // on the instruction.  Blocks ending in CALL instructions will be marked E_CALL, while
      // jumps will be E_BRANCH, and RET instructions will be E_RETURN.
      if (i == (num_insns - 1)) {
        if (xinsn && insn_is_call(xinsn)) {
          edge_type = E_CALL;
          calls.insert(insn->get_address());

          // Now create the fake E_CALL_FALLTHRU edge for analyses that find that convenient.
          // We should really be filtering based on non-returning calls here as well.  The most
          // obvious non-returning cases were handled by placing the CALL in the middle of a
          // basic block, and we'll not have an edge type of E_CALL in those situations, but
          // the stock ROSE partitioner can also do no-return analysis.  Currently we have that
          // disabled, so I'm not checking for it here, but perhaps we should in the future.
          rose_addr_t fallthru_address = insn->get_address() + insn->get_size();
          SawyerPDG::VertexIterator fallthruv = findVertexKey(fallthru_address);
          if (fallthruv != vertices().end()) {
            insertEdge(fromv, fallthruv, PDGEdge(E_CALL_FALLTHRU));
          }
          else {
            // This condition occurs as a result of bad disassembly, so it's really more of a
            // warning than an error.
            GWARN << "No fallthru edge for call at " << addr_str(insn->get_address()) << LEND;
          }
        }
      }

      // For each successor address...
      for (rose_addr_t successor : successors.values()) {
        SawyerPDG::VertexIterator tov = findVertexKey(successor);
        // We're not always able to find successors in the graph, when there is bad
        // disassembly.  This is really a partitioning problem, and should probably be correct
        // there.  In the meantime, this is definitely a warning, and not an error.
        if (tov == vertices().end()) {
          GWARN << "Successor " << addr_str(successor) << " of "
                << debug_instruction(insn) << " not found." << LEND;
          continue;
        }

        // Only the last instruction is allowed to have more than one successor.  If there's
        // more than one successor, we need to determine if this is the one that's taken.
        if (i != (num_insns - 1) && successors.size() != 1) {
          // All edges except the one to the next instruction in the basic block are edges of
          // type E_NOT_TAKEN.  Make those edges here, and only allow the taken edge to proceed
          // past this logic, where it will be created with the appropriate edge type.
          SgAsmInstruction* next_insn = b->instructions()[i+1];
          if (successor != next_insn->get_address()) {
            insertEdge(fromv, tov, PDGEdge(E_NOT_TAKEN));
            //GDEBUG << "Instruction " << debug_instruction(insn)
            //       << " has not taken edge to " << addr_str(successor) << LEND;
            continue;
          }
        }

        // The fallthru address is easy to compute and well defined, so handle it immediately.
        // Corner cases such as JMP +5 would be characterized as a fallthru edge, which can be
        // confusing to code that wants to analyze every jump target, so let's exclude jump
        // instructions from this case.
        rose_addr_t fallthru_address = insn->get_address() + insn->get_size();
        if (!insn_is_jmp(xinsn) && successor == fallthru_address) {
          insertEdge(fromv, tov, PDGEdge(E_FALLTHRU));
          continue;
        }

        // At this point, there's an edge and it's not the fallthru edge.  If we're NOT the
        // last instruction, the edge must be a branch edge such as an unconditional jump or
        // call that is known to never return.  If we are the last instruction, we'll have set
        // the edge type based on inspecting the instruction type earlier.
        insertEdge(fromv, tov, PDGEdge(edge_type));
      }

      // If we're the last instruction in the block we also need to check the basic block
      // successors, because certain kinds of successors are stored there instead (for example
      // targets computed from switch jump table detection).  If we find indirect branches,
      // we're going to presume that we've resolved all edges for the branch/call
      if (i == num_insns - 1) {
        PDGEdgeType itype = E_INDIRECT_BRANCH;
        if (xinsn && insn_is_call(xinsn)) {
          itype = E_INDIRECT_CALL;
        }
        for (auto bsuccessor : b->successors().get()) {
          const BaseSValuePtr& expr = bsuccessor.expr();
          if (expr && expr->is_number()) {
            rose_addr_t target = expr->get_number();
            SawyerPDG::VertexIterator tov = findVertexKey(target);
            //OINFO << "Insn: " << addr_str(insn->get_address()) << " has bblock successor value="
            //      << expr << " addr=" << addr_str(target) << " type="
            //      << bsuccessor.type() << " conf=" << bsuccessor.confidence() << LEND;
            if (isValidVertex(tov)) {
              SawyerPDG::ConstEdgeIterator existing = get_edge(fromv, tov);
              if (existing != fromv->outEdges().end()) {
                // If the edge already existed, it wasn't one of the indirect computed edges
                // that we were really looking for, so just skip it.  These appear to be a
                // variety of unusual cases that we've already handled in our graph through our
                // own logic (call fallthru edges, etc).

                //OINFO << "Edge from " << addr_str(insn->get_address()) << " to "
                //      << addr_str(target) << " already existed type="
                //      << existing->value().get_type() << LEND;
              }
              else {
                // This is the case that we were really looking for.  New edges on the basic
                // block succesors that we didn't already know about.  Typically this will be
                // branch tragets caused by analysis on switch jump tables, but if ROSE adds
                // more analysis in the future it might include other indirect branches and
                // calls as well.

                //OINFO << "Creating edge from " << addr_str(insn->get_address()) << " to "
                //      << addr_str(target) << " type=" << itype << LEND;
                insertEdge(fromv, tov, PDGEdge(itype));

                // Since we found some new edges, let's not create the indeterminate edge.
                complete = true;
              }
            }
            else {
              // These seem to all be branches/call into a data structure in Windows PE exes,
              // so ignoring them is probably the right thing to do.  Perhaps the ROSE code was
              // written with ELF executables in mind, where this is a valid address?

              //OINFO << "Edge from " << addr_str(insn->get_address())
              //      << " is to invalid vertex at " << addr_str(target) << LEND;
            }
          }
        }
      }

      // Now we need to handle creating an edge to the indeterminate vertex if the successor
      // list is not complete.
      if (!complete) {
        // Indeterminate successors should only occur on the last instruction in a block.
        // assert(i == (num_insns - 1));
        if (i != (num_insns - 1)) {
          GINFO << "Instruction " << debug_instruction(insn) << " had incomplete successors." << LEND;
        }

        // If it's a RET instruction, and then the type should always be E_RETURN.  Otherwise
        // create the indeterminate edge with the same edge type as the other edges on the last
        // instruction.  This distinguishes between indeterminate jumps and calls.
        if (xinsn && xinsn->get_kind() == x86_ret) {
          insertEdge(fromv, indeterminate, PDGEdge(E_RETURN));
        }
        else {
          insertEdge(fromv, indeterminate, PDGEdge(edge_type));
        }
      }
    }
  }

  create_return_edges(calls);

  duration secs = clock::now() - start_ts;
  GINFO << "Creation of the control flow graph took " << secs.count() << " seconds." << LEND;
}

void
Graph::create_return_edges(std::set<rose_addr_t> calls)
{
  // For each call that we previously found...
  for (rose_addr_t call_addr : calls) {
    SawyerPDG::VertexIterator call_vertex = findVertexKey(call_addr);

    // OINFO << "Processing call from " << addr_str(call_addr) << LEND;

    // This is not the right way to do this...
    const SgAsmInstruction* cinsn = call_vertex->value().get_insn();
    rose_addr_t fallthru_address = cinsn->get_address() + cinsn->get_size();
    SawyerPDG::VertexIterator fallthruv = findVertexKey(fallthru_address);
    if (fallthruv == vertices().end()) {
      GERROR << "Unable to find fallthru edge for call at " << addr_str(call_addr) << LEND;
      continue;
    }
    // OINFO << "Call fallthru address is " << addr_str(fallthru_address) << LEND;

    for (SawyerPDG::Edge call_edge : call_vertex->outEdges()) {
      const PDGEdge& call_pdg_edge = call_edge.value();
      // We can only return from the call targets, not the call  fallthru edge.
      if (call_pdg_edge.get_type() != E_CALL) continue;
      SawyerPDG::VertexIterator call_target_vertex = call_edge.target();

      Sawyer::Container::Algorithm::DepthFirstForwardEdgeTraversal<SawyerPDG>
        traversal(*this, call_target_vertex);

      // The edges we've decided to create during the traversal can't be created until we're done
      // with the traversal, so keep a list of the source addresses (return instructions) each of
      // which should have a return edge to the call's fallthru address.
      std::set<rose_addr_t> ret_edges;

      while (traversal.hasNext()) {
        // The Sawyer graph edge.
        auto edge = traversal.edge();
        // Our custom edge object.
        const PDGEdge& pedge = edge->value();
        // The type of the edge.
        PDGEdgeType etype = pedge.get_type();

        // Source and target vertices.
        auto sourcev = edge->source();
        auto targetv = edge->target();

#if 0
        // Debugging.
        std::string target_str;
        if (targetv == indeterminate) {
          target_str = "INDETERMINATE";
        }
        else {
          target_str = addr_str(targetv->value().get_address());
        }

        std::string type_str;
        if (etype == E_CALL)               type_str = "CALL";
        else if (etype == E_FALLTHRU)      type_str = "FALLTHRU";
        else if (etype == E_BRANCH)        type_str = "BRANCH";
        else if (etype == E_RETURN)        type_str = "RETURN";
        else if (etype == E_NOT_TAKEN)     type_str = "NOT_TAKEN";
        else if (etype == E_CALL_FALLTHRU) type_str = "CALL_FALL";
        else                               type_str = "OTHER";

        OINFO << "DFT: src=" << addr_str(sourcev->value().get_address()) << " tgt="
              << target_str << " type=" << type_str << LEND;
#endif

        // The return instructions should all have existing E_RETURN edges to the indeterminate
        // vertex, but not to specific addresses (which is why we're doing this analysis).
        // When we find a return to indeterminate, add the correct fallthru address to the list
        // of E_RETURN edges to create.
        if (etype == E_RETURN && targetv == indeterminate) {
          const PDGVertex& sv = sourcev->value();
          ret_edges.insert(sv.get_address());
          //OINFO << "Proposing return edge from " << addr_str(sv.get_address())
          //      << " to " << addr_str(fallthru_address) << LEND;
        }

        // Skip all children for call edges and not taken edges.  This may need some additional
        // analysis to fully understand what skipChildren() really does.  I don't want to
        // permanently exclude those vertices, I just don't want to follow _this_ edge.
        if (etype != E_FALLTHRU && etype != E_BRANCH && etype != E_CALL_FALLTHRU) {
          traversal.skipChildren();
        }

        // Advance to the next edge in the traversal.
        ++traversal;
      }

      // Now actually create the edges.
      for (rose_addr_t saddr: ret_edges) {
        SawyerPDG::VertexIterator sourcev = findVertexKey(saddr);
        insertEdge(sourcev, fallthruv, PDGEdge(E_RETURN));
        //OINFO << "Created return edge from " << addr_str(saddr)
        //      << " to " << addr_str(fallthru_address) << LEND;
      }
    }
  }
}

#if 0
// Unfortunately, this algorithm doesn't appear to actually do the correct thing (in my
// opinion at least).  It seems to just be missing edges. :-(

// ROSE's control flow graph doesn't have RETURN edges by default.  You have to call
// expandFunctionReturnEdges() which modifies the ROSE cfg using the same algorithm as below,
// and then erases the old edges to the indeterminate vertex.  After calling that routine,
// I'd then need to walk the graph again to create the edges in our graph.  Copying the
// algorithm to here is more efficient and not much more complicated than the code to
// subsequently walk the resulting graph.  Of course the downside is that this code might
// become inconsistent with the ROSE routine.

// Sawyer::Container::Map<P2::Function::Ptr, P2::CfgConstEdgeSet>
auto fre = findFunctionReturnEdges(p, p.cfg());
P2::CfgConstEdgeSet crEdges = findCallReturnEdges(p, p.cfg());
for (const P2::ControlFlowGraph::ConstEdgeIterator &crEdge : crEdges) {
  P2::ControlFlowGraph::ConstVertexIterator callSite = crEdge->source();
  P2::ControlFlowGraph::ConstVertexIterator returnSite = crEdge->target();
  P2::CfgConstEdgeSet callEdges = P2::findCallEdges(callSite);
  for (const P2::ControlFlowGraph::ConstEdgeIterator &callEdge : callEdges) {
    if (callEdge->target()->value().type() != P2::V_BASIC_BLOCK)
      continue; // functionCallEdge is not a call to a known function, so ignore it

    P2::BasicBlock::Ptr functionBlock = callEdge->target()->value().bblock();
    std::vector<P2::Function::Ptr> functions = p.functionsOwningBasicBlock(functionBlock);
    for (const P2::Function::Ptr &function : functions) {
      for (auto oldReturnEdge : fre.getOrDefault(function)) {

        rose_addr_t saddr = oldReturnEdge->source()->value().address();
        rose_addr_t taddr = returnSite->value().address();
        OINFO << "Return edge from " << addr_str(saddr) << " to " << addr_str(taddr) << LEND;
        //cfg.insertEdge(oldReturnEdge->source(), returnSite, E_FUNCTION_RETURN);
      }
    }
  }
}
#endif

#if 0
// And this was the beginning of an implementation that was going to read the vertices out of
// the ROSE CFG (assuming that they already existed).

// Sawyer::Container::Map<P2::Function::Ptr, P2::CfgConstEdgeSet>
auto rmap = P2::findFunctionReturnEdges(p);

// Iterators to the end vertex, and the indeterminate vertex in the ROSE cfg.
auto vend = p.cfg().vertices().end();
auto vindeterminate = p.indeterminateVertex();

// For each function in the ROSE control flow graph.
for (auto redges : rmap.values()) {
  // For each return edge in the ROSE control flow graph.
  for (auto edge : redges) {
    auto sourcev = edge->source();
    auto targetv = edge->target();
    // Probably just being overly defensive.
    if (sourcev == vend) continue;
    if (targetv == vend) continue;
    // Definitely needed.
    if (targetv == vindeterminate) continue;

    // Now that our vertices should both be valid, get the addresses.
  }
}
#endif

// Mostly just a mock up to show how we might alter the API.
bool Graph::add_call_target(rose_addr_t from, rose_addr_t to) {
  SawyerPDG::VertexIterator fromv = findVertexKey(from);
  if (fromv == vertices().end()) return false;
  SawyerPDG::VertexIterator tov = findVertexKey(to);
  if (tov == vertices().end()) return false;
  insertEdge(fromv, tov, PDGEdge(E_CALL));
  return true;
}

bool Graph::call_targets_complete(rose_addr_t call_addr) const {
  SawyerPDG::ConstVertexIterator vi = findVertexKey(call_addr);
  if (vi == vertices().end()) return false;

  // TODO: Test for edge from vi to indeterminate here!

  return true;
}

Graph Graph::getFunctionCfgByReachability (const FunctionDescriptor *fd) const {
  Graph fcfg (*this);
  SgAsmBlock* entry_block = fd->get_entry_block ();
  SawyerPDG::VertexIterator entry_vi = fcfg.findVertexKey (entry_block->get_address ());
  assert (entry_vi != vertices ().end ());

  Sawyer::Container::GraphIteratorSet<SawyerPDG::ConstEdgeIterator> reachable_edges;
  std::vector<EdgeIterator> remove_edges;
  std::vector<VertexIterator> remove_vertices;

  Sawyer::Container::Algorithm::DepthFirstForwardGraphTraversal<SawyerPDG>
    t(fcfg, entry_vi, Sawyer::Container::Algorithm::ENTER_EVENTS);

  for (; t; ++t) {
    switch (t.event ()) {

     case Sawyer::Container::Algorithm::ENTER_EDGE: {
       auto edge_type = t.edge ()->value ().get_type ();
       if (edge_type == E_CALL || edge_type == E_RETURN)
         t.skipChildren ();
       else
         reachable_edges.insert (t.edge ());
       break;
     }

     default:
      break;
    }
  }

  for (SawyerPDG::EdgeIterator ei = fcfg.edges ().begin (); ei != fcfg.edges ().end (); ei++) {
    if (!reachable_edges.exists(ei)) {
      remove_edges.push_back (ei);
    }
  }

  for (const auto & ei : remove_edges) {
    fcfg.eraseEdge (ei);
  }

  // Finally remove unreachable vertices and edges
  for (t.start (entry_vi); t; ++t) {}
  for (auto vi = fcfg.vertices ().begin (); vi != fcfg.vertices ().end (); vi++) {
    if (!t.isDiscovered (vi))
      remove_vertices.push_back (vi);
  }
  for (auto vi : remove_vertices) {
    fcfg.eraseVertex (vi);
  }

#if 0
  // Test
  for (auto v : fcfg.vertices ()) {
    std::cout << "Vertex remaining " << std::hex << std::showbase << v.value ().get_address () << std::endl;
  }
  for (auto e : fcfg.edges ()) {
    auto src = e.source ();
    auto dst = e.target ();
    std::cout << "Edge remaining from " << src->value ().get_address () << " to " << dst->value ().get_address () << " of type " << e.value ().get_type () << std::endl;
  }
#endif

  return fcfg;
}

} // namespace PD
} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
