// Copyright 2019-2023 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Graph_H
#define Pharos_Graph_H

#include "rose.hpp"
#include <Rose/BinaryAnalysis/Partitioner2/Partitioner.h>
#include <Rose/BinaryAnalysis/Partitioner2/BasicBlock.h>

#include <Sawyer/Graph.h>

#include "semantics.hpp"
#include "imports.hpp"
#include "calls.hpp"
#include "globals.hpp"

namespace pharos {

// Forward declaration for initialization of Graph.
class DescriptorSet;

// This can be renamed to PDG when the PDG class is removed.
namespace PD {

enum PDGVertexType {
  // For the default constructor, only needed for serialization?
  V_DEFAULT,

  // The usual type, a vertex representing an instruction.
  V_INSTRUCTION,

  // Vertexes can also represent a few kinds of addresses.
  V_GLOBAL_MEMORY,
  V_IMPORT,

  // The special vertex for indeterminate branch targets, for example branches to registers
  // whose value is not conclusively known.
  V_INDETERMINATE
};

class PDGVertex {
 private:
  PDGVertexType type;

  // Practically all vertices have an address.  The only exception that I'm currently aware of
  // is the single indeterminate vertex, and it can be obtained via a special method.
  rose_addr_t address;

  // Most vertices also have an instruction, but not all them.  Imports and global memory
  // references need to be in the graph so that we can create data dependency edges, but don't
  // have instructions.
  SgAsmInstruction* insn;

  // If the vertex has an instruction, this is a pointer to the basic block that contains this
  // instruction.  We should review where I have and have not used references on the Ptr class.
  P2::BasicBlock::Ptr block;

  // An optional descriptor for for this vertex.  The type of the descriptor varies according
  // to the type of the vertex.  Currently storing pointers to the descriptors owned by the
  // global descriptor set, but that could change in the future if desired.  Since they're all
  // pointers, the union version boost::variant is probably better.
  boost::any descriptor;

  // Stack delta could go here also.

 public:
  // Construct a typical instruction vertex.
  PDGVertex(SgAsmInstruction* i, P2::BasicBlock::Ptr b) :
    type(V_INSTRUCTION), address(i->get_address()), insn(i), block(b) {}

  // Construct an import vertex.
  PDGVertex(const ImportDescriptor& id) :
    type(V_IMPORT), address(id.get_address()), insn(nullptr)
  {
    // error: use of deleted function ‘pharos::ImportDescriptor::ImportDescriptor(const pharos::ImportDescriptor&)’
    // So I switched to storing pointers to the descriptors in the boost::any.
    descriptor = &id;
  }

  // Construct a global memory vertex.
  PDGVertex(const GlobalMemoryDescriptor& gmd) :
    type(V_GLOBAL_MEMORY), address(gmd.get_address()), insn(nullptr)
  {
    descriptor = &gmd;
  }

  // Construct a call vertex.
  PDGVertex(const CallDescriptor& cd, P2::BasicBlock::Ptr b) :
    type(V_INSTRUCTION), address(cd.get_address()), insn(cd.get_insn()), block(b)
  {
    descriptor = &cd;
  }

  // Construct the special indeterminate vertex.
  PDGVertex(PDGVertexType t) : type(t), address(0), insn(nullptr)
  {
    assert(type == V_INDETERMINATE);
  }

  // Perhaps required for serialization?
  PDGVertex() : type(V_DEFAULT), address(0), insn(nullptr) {}

  // Return the vertex type.
  PDGVertexType get_type() const { return type; }

  // Return the address, instruction, or block.
  rose_addr_t get_address() const { return address; }
  const SgAsmInstruction* get_insn() const { return insn; }
  const P2::BasicBlock::Ptr& get_block() const { return block; }

  // If this instruction is a call, are the call edges complete?
  bool calls_complete() const;

};

enum PDGEdgeType {
  // For the default constructor, only needed for serialization?
  E_DEFAULT,

  // ----------------------------------------------------------------------------------------
  // Control flow edges
  // ----------------------------------------------------------------------------------------

  // The fallthru edge of an instruction is the default control flow to the instruction
  // immediately following the current instruction, implied by the normal logic for advancing
  // the instruction pointer register by the length of the current instruction.
  E_FALLTHRU,

  // A branch edge represents an explicit update of the instruction pointer register, usually
  // by a conditional computation.  Unlike the E_CALL_TO edge type, there is no expectation
  // that control flow will return to the E_FALLLTHRU edge if the branch edge is taken.
  E_BRANCH,

  // A branch edge that was indirect, for example through a jump table created by a switch
  // statement, and resolved through a more complex program analysis involving instruction
  // semantics, and static memory.
  E_INDIRECT_BRANCH,

  // A branch edge that always self references the current vertex, representing the semantics
  // of a repeat prefix.  This edge has it's own type because of the ambiguity about whether
  // the edge represents a true loop and thus a separate basic block, or whether it represents
  // the complex semantics of a single instruction within a block.
  E_REPEAT,

  // Call edges are computed control flow edges (E_BRANCH) where there's an expectation that
  // execution will eventually return to the E_CALL_FALLTHRU edge.  In the X86 instruction set,
  // these are edges from the CALL instruction to the call target (and their inverse).
  E_CALL,

  // A call edge that was indirect, for example through a virtual function table.  Such calls
  // are typicall resolved through a more complex program analysis.  Like E_CALL,
  // E_INDIRECT_CALL edges are expected to eventually returns to the E_CALL_FALLTHRU edge.
  E_INDIRECT_CALL,

  // A return edge is an edge between the return instruction and all possible instructions that
  // the return might return to.
  E_RETURN,

  // Some analyses may want to interpret CALL instructions as implicitly returning to the
  // instruction immediately following the call.  Of course in fact it's not obvious that the
  // following instruction will actually be executed, and even when it is, it's certainly not
  // executed immmediately after the call, so these are not true fallthru edges.  This edge
  // type represents the convenient abstraction that the call falls through to the instruction
  // following it.  The edge will not be present for calls that known to never return.
  E_CALL_FALLTHRU,

  // A control flow edge that has been determined to not be taken, usually due to an opaque
  // predicate during partitioning.
  E_NOT_TAKEN,

  // ----------------------------------------------------------------------------------------
  // Data flow edges
  // ----------------------------------------------------------------------------------------

  // This instruction defines a value that is used by the target of the the edge.  When
  // accessed as an in-edge from the target, this type may also be referred to as E_USAGE.
  E_DEFINITION,
  E_USAGE = E_DEFINITION,

  // This instruction reads from a global memory address.
  E_GLOBAL_MEMORY_READ,

  // This instruction writes to a global memory address.
  E_GLOBAL_MEMORY_WRITE
};

// A more natural label when inspecting in-edges.
// constexpr PDGEdgeType E_USAGE = E_DEFINITION;

class PDGEdge {
 private:
  // The type of the edge.
  PDGEdgeType type;

  // The type of edge data varies according to the edge type.  For many edge types, it is a
  // null pointer.  For E_DEFINITION and E_USAGE it's a pointer to an AbstractAccess.  For
  // E_IMPORT, it could be a pointer to an ImportDescriptor.
  boost::any edge_data;

 public:

  PDGEdge(PDGEdgeType t) : type(t), edge_data(nullptr) { }

  // Perhaps required for serialization?
  PDGEdge() : type(E_DEFAULT), edge_data(nullptr) { }

  // Return the edge type.
  PDGEdgeType get_type() const { return type; }

  void set_edge_data(boost::any ed) { edge_data = ed; }

  // Is this the right way to do this?
  void set_abstract_access(AbstractAccess& aa) {
    assert(type == E_DEFINITION || type == E_USAGE);
    edge_data = &aa;
  }
  const AbstractAccess& get_abstract_access() {
    assert(type == E_DEFINITION || type == E_USAGE);
    return *(boost::any_cast<AbstractAccess*>(edge_data));
  }
};

// A helper class for identifying the key of a PDGVertex.
class PDGKey {
 private:
  rose_addr_t address;
 public:
  PDGKey(const PDGVertex& v) : address(v.get_address()) { }
  PDGKey(rose_addr_t a) : address(a) { }

  bool operator<(const PDGKey& other) const {
    return address < other.address;
  }
};

// In addition to the standard graph with both custom vertex and edge types (PDGVertex and
// PDGEdge), we also want an index into the vertices by address (PDGKey).
using SawyerPDG = Sawyer::Container::Graph<PDGVertex, PDGEdge, PDGKey>;

// The program dependency graph is a primarily a Sawyer Graph, but there are some additional
// APIs that we'd like to add as well.
class Graph: public SawyerPDG {

 private:

  SawyerPDG::VertexIterator indeterminate;

  void create_return_edges(std::set<rose_addr_t> calls);

 public:

  Graph();

  // Populate the graph.
  void populate(const DescriptorSet& ds, const P2::Partitioner& p);

  SawyerPDG::VertexIterator get_indeterminate() const { return indeterminate; }

  bool add_call_target(rose_addr_t from, rose_addr_t to);
  bool call_targets_complete(rose_addr_t call_addr) const;

  // Is there an edge in the graph?
  SawyerPDG::ConstEdgeIterator get_edge(
    const SawyerPDG::ConstVertexIterator& from,
    const SawyerPDG::ConstVertexIterator& to) const;

  Graph getFunctionCfgByReachability(const FunctionDescriptor *fd) const;

};

} // namespace PD

// Is this a compromise betweewn clarity and people not wanting to type the full name of the
// class everywhere, or is it an abomination?
using ProgramDependencyGraph = PD::Graph;
using ProgramDependencyEdge = PD::PDGEdge;
using ProgramDependencyVertex = PD::PDGVertex;

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
