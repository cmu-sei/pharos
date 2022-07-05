// Copyright 2015-2022 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Ir_H
#define Pharos_Ir_H

#include <map>
#include <vector>

#include <boost/range/algorithm/copy.hpp>
#include <boost/range/algorithm/find.hpp>
#include <boost/range/algorithm/find_if.hpp>

#include <boost/optional.hpp>
#include <boost/tuple/tuple_io.hpp>
#include <boost/variant.hpp>

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/labeled_graph.hpp>
#include <boost/graph/iteration_macros.hpp>
#include <boost/graph/graphviz.hpp>

#include "rose.hpp"
#if PHAROS_ROSE_SYMBOLIC_EXTENSION_HACK
#include <Rose/BinaryAnalysis/InstructionSemantics/SymbolicSemantics.h>
#else
#include <Rose/BinaryAnalysis/InstructionSemantics2/SymbolicSemantics.h>
#endif

#include "calls.hpp"
#include "cdg.hpp"
#include "funcs.hpp"
#include "descriptors.hpp"

namespace pharos {

using CFG = Rose::BinaryAnalysis::ControlFlow::Graph;
using CFGVertex = boost::graph_traits<CFG>::vertex_descriptor;

namespace SymbolicExpr = Rose::BinaryAnalysis::SymbolicExpr;
namespace BaseSemantics = Rose::BinaryAnalysis::InstructionSemantics::BaseSemantics;
using SymbolicExprPtr = SymbolicExpr::Ptr;
using SymbolicLeaf = SymbolicExpr::Leaf;
using SymbolicLeafPtr = SymbolicExpr::LeafPtr;
using SymbolicInterior = SymbolicExpr::Interior;
using SymbolicInteriorPtr = SymbolicExpr::InteriorPtr;

using BasicBlock = Rose::BinaryAnalysis::Partitioner2::BasicBlock;
using BasicBlockPtr = Rose::BinaryAnalysis::Partitioner2::BasicBlockPtr;
using DataBlock = Rose::BinaryAnalysis::Partitioner2::DataBlock;
using DataBlockPtr = Rose::BinaryAnalysis::Partitioner2::DataBlockPtr;

using RegPair = BaseSemantics::RegisterStateGeneric::RegPair;

namespace ir {

// IR Types
using Register = SymbolicLeafPtr;

using IRExpr = SymbolicExpr::Node;
using IRExprPtr = SymbolicExprPtr;

struct InternalCall {
};
// DLL and Name
using ImportCallPair = std::pair<std::string, std::string>;
struct ImportCall : ImportCallPair {
  explicit ImportCall (const std::string &a, const std::string &b)
    : ImportCallPair (a, b) {}
  explicit ImportCall (const ImportCallPair &p)
    : ImportCallPair (p) {}
};
using ImportRewriteSet = std::set<ImportCall>;
using Call = boost::variant<InternalCall, ImportCall>;

using RegWriteStmtPair = std::pair<Register, IRExprPtr>;
struct RegWriteStmt : RegWriteStmtPair {
  explicit RegWriteStmt (const Register &r, const IRExprPtr &e)
    : RegWriteStmtPair (r, e) {}
  explicit RegWriteStmt (const RegWriteStmtPair &p)
    : RegWriteStmtPair (p) {}
};
using MemWriteStmtPair = std::pair<IRExprPtr, IRExprPtr>;
struct MemWriteStmt : MemWriteStmtPair {
  explicit MemWriteStmt (const IRExprPtr &a, const IRExprPtr &v)
    : MemWriteStmtPair (a, v) {}
  explicit MemWriteStmt (const MemWriteStmtPair &p)
    : MemWriteStmtPair (p) {}
};
using InsnStmtPair = std::pair<rose_addr_t, std::string>;
struct InsnStmt : InsnStmtPair {
  explicit InsnStmt (const rose_addr_t &a, const std::string &s)
    : InsnStmtPair (a, s) {}
  explicit InsnStmt (const InsnStmtPair &p)
    : InsnStmtPair (p) {}
};
using Special = std::string;
struct SpecialStmt : Special {
  explicit SpecialStmt (const std::string &s) : Special (s) {}
};
using Assert = IRExprPtr;
struct AssertStmt : Assert {
  explicit AssertStmt (const Assert &a) : Assert (a) {}
};
using CallStmtTuple  = std::tuple<IRExprPtr, Call, const CallDescriptor*>;
struct CallStmt : CallStmtTuple {
  explicit CallStmt (const IRExprPtr &e, const Call &c, const CallDescriptor * const &cd)
    : CallStmtTuple (e, c, cd) {}
  explicit CallStmt (const CallStmtTuple &t)
    : CallStmtTuple (t) {}
};
using Comment = std::string;
struct CommentStmt : Comment {
  explicit CommentStmt (const std::string &s) : Comment (s) {}
};

using Stmt = boost::variant<RegWriteStmt, MemWriteStmt, InsnStmt, SpecialStmt, AssertStmt, CallStmt, CommentStmt>;
using Stmts = std::vector<Stmt>;
using StmtsPtr = boost::shared_ptr<Stmts>;

struct OtherNode {};

struct ErrorNode {};

struct IRVertexName : boost::variant<const SgAsmStatement *, ErrorNode, OtherNode> {
  // For some reason inheriting the constructors using 'using' does not work at all.
  // https://stackoverflow.com/questions/50047299/error-passing-boostvariant-derived-class
  IRVertexName (const SgAsmStatement *const &a) :
    boost::variant<const SgAsmStatement *, ErrorNode, OtherNode> (a) {};
  IRVertexName (const ErrorNode &a) :
    boost::variant<const SgAsmStatement *, ErrorNode, OtherNode> (a) {};
  IRVertexName (const OtherNode &a) :
    boost::variant<const SgAsmStatement *, ErrorNode, OtherNode> (a) {};

  // boost::graph requires this to be default constructible, so default to OtherNode
  IRVertexName () :
    boost::variant<const SgAsmStatement *, ErrorNode, OtherNode> (OtherNode ()) {};

  boost::optional<const SgAsmStatement *> get_insn () const {
    const SgAsmStatement* const* ptr = boost::get<const SgAsmStatement*> (this);
    if (ptr) return *ptr;
    return boost::none;
  }

  boost::optional<rose_addr_t> get_insn_addr () const {
    auto insn = get_insn ();
    if (insn) return (*insn)->get_address ();
    else return boost::none;
  }

  bool is_error_node () const {
    return get_insn () == boost::none;
  }
};

// Stream helpers
std::ostream& operator<<(std::ostream &out, const ErrorNode &en);
std::ostream& operator<<(std::ostream &out, const IRVertexName &vn);
std::ostream& operator<<(std::ostream &out, const InternalCall &c);
std::ostream& operator<<(std::ostream &out, const ImportCall &c);
std::ostream& operator<<(std::ostream &out, const RegWriteStmt &stmt);
std::ostream& operator<<(std::ostream &out, const MemWriteStmt &stmt);
std::ostream& operator<<(std::ostream &out, const InsnStmt &stmt);
std::ostream& operator<<(std::ostream &out, const SpecialStmt &stmt);
std::ostream& operator<<(std::ostream &out, const CallStmt &stmt);
std::ostream& operator<<(std::ostream &out, const CommentStmt &stmt);
std::ostream& operator<<(std::ostream &out, const Stmts &stmts);
std::ostream& operator<<(std::ostream &out, const StmtsPtr &stmtsptr);

// Return the expressions referenced in a statement, if any exist.
std::set<IRExprPtr> expsFromStmt(const Stmt &stmt, bool includeWrites = false);

// Return the address stored in an InsnStmt, or nothing.
boost::optional<rose_addr_t> addrFromStmt(const Stmt &stmt);

// Return the absolute address destination of a call, or nothing.
boost::optional<rose_addr_t> targetOfCallStmt (const Stmt &stmt);
}
}

// IR CFG
// Create a new IR property
namespace boost {
enum vertex_ir_t { vertex_ir };
BOOST_INSTALL_PROPERTY(vertex, ir);
}

namespace pharos {
namespace ir {

// This must be a new type or we can't override the stream function
struct EdgeCond : boost::optional<IRExprPtr> {
  EdgeCond (const IRExprPtr &p) : boost::optional<IRExprPtr> (p) {}
  EdgeCond () : boost::optional<IRExprPtr> () {}
  EdgeCond (boost::optional<IRExprPtr> const & o) : boost::optional<IRExprPtr>(o) {}
  EdgeCond (boost::optional<IRExprPtr> && o) : boost::optional<IRExprPtr>(std::move(o)) {}
};
std::ostream& operator<<(std::ostream &out, const EdgeCond &edgecond);

using VertexProperty = boost::property<boost::vertex_ir_t, StmtsPtr,
                                       boost::property<boost::vertex_name_t, IRVertexName>>;
using EdgeProperty = boost::property<boost::edge_name_t, EdgeCond>;

using IRCFG = boost::adjacency_list<boost::setS, boost::vecS, boost::bidirectionalS, VertexProperty, EdgeProperty>;
using IRCFGVertex = boost::graph_traits<IRCFG>::vertex_descriptor;
using IRCFGEdge = boost::graph_traits<IRCFG>::edge_descriptor;

using IRRegState = RegisterStateGenericPtr;

class IR {
 private:
  IRCFG cfg;
  const DescriptorSet* ds;
  // Use SgAsmStatement because it won't change if we copy the graph.
  const SgAsmStatement* entry;
  IRRegState rstate;
  Register mem;
  // We may need access to the rops to build a parser
  BaseSemantics::RiscOperatorsPtr rops;
 public:

  IR(IRCFG cfg_, const DescriptorSet* ds_, IRCFGVertex entry_, IRRegState rstate_, Register mem_, BaseSemantics::RiscOperatorsPtr rops_) :
    ds(ds_), rstate(rstate_), mem(mem_), rops(rops_) {

    cfg = cfg_;

    entry = *boost::get (boost::vertex_name_t (), cfg, entry_).get_insn ();

    if (get_error_opt () == boost::none) {
      auto error = boost::add_vertex (cfg);
      boost::put (boost::vertex_ir_t (), cfg, error, StmtsPtr (new Stmts ()));
      boost::put (boost::vertex_name_t (), cfg, error, ErrorNode ());
    }

  }
  // Update the CFG, and optionally the entry vertex
  IR(const IR &ir, IRCFG cfg_, boost::optional<IRCFGVertex> new_entry_ = boost::none) : IR(ir) {
    cfg = cfg_;
    if (new_entry_) {
      entry = *boost::get (boost::vertex_name_t (), cfg, *new_entry_).get_insn ();
    }
  }

  // Return the IR for the specified function
  static IR get_ir (const FunctionDescriptor* fd);

  IRCFG get_cfg(void) const {
    return cfg;
  }

  IRCFGVertex get_entry(void) const {
    boost::graph_traits<IRCFG>::vertex_iterator vientry;
    auto rng = boost::vertices (cfg);
    auto namemap = boost::get (boost::vertex_name_t (), cfg);
    vientry = boost::find_if (rng,
                              [&] (IRCFGVertex v) {
                                auto name = namemap[v].get_insn ();
                                return name && *name == entry;
                              });
    assert (vientry != boost::end (rng));
    return *vientry;

  }

  IRCFGVertex get_error (void) const {
    boost::optional<IRCFGVertex> error = get_error_opt ();
    assert (error);
    return *error;
  }

  boost::optional<IRCFGVertex> get_error_opt (void) const {
    auto rng = boost::vertices (cfg);
    auto namemap = boost::get (boost::vertex_name_t (), cfg);
    auto error = boost::find_if (rng,
                                 [&namemap] (IRCFGVertex v) {
                                   return namemap[v].is_error_node ();
                                 });
    if (error == boost::end (rng))
      return boost::none;
    else
      return *error;
  }

  std::set<IRCFGVertex> get_exits(void) const {
    std::set<IRCFGVertex> exits;
    auto error = get_error ();

    boost::copy (boost::vertices (cfg)
                 | boost::adaptors::filtered ([this, error] (IRCFGVertex v) { return boost::out_degree (v, cfg) == 0 && v != error; }),
                 std::inserter (exits, exits.end ()));

    return exits;
  }

  // Return the CFG vertex that contains the specified address.
  IRCFGVertex find_addr (rose_addr_t addr) const;

  // Accessor functions
  const DescriptorSet* get_ds(void) const { return ds; }
  Register get_reg (RegisterDescriptor rd) const;
  Register get_mem (void) const { return mem; }
  BaseSemantics::RiscOperatorsPtr get_rops (void) const { return rops; }

  // Stream output
  friend std::ostream& operator<<(std::ostream &out, const IR &ir) {
    auto tmpcfg = ir.get_cfg ();
    boost::write_graphviz (out, tmpcfg,
                           boost::make_label_writer(boost::get(boost::vertex_ir_t(), tmpcfg)),
                           boost::make_label_writer(boost::get(boost::edge_name_t(), tmpcfg)));
    return out;
  }
};


// Arbitrarily remove backedges.  This function is guaranteed to
// return a CFG that does not contain cycles.
IR filter_backedges (const IR& ir);

// Rewrite the CFG so that, for each vertex, there is either
// exactly one incoming edge with a condition on it and no other
// edges, or there is an unlimited number of incoming edges
// without a condition on it.  This is useful for some algorithms
// (e.g., weakest preconditions).
IR split_edges (const IR& ir);

// Rewrite the CFG so that every CallStmt is always the first
// statement in its vertex.  This is currently used in
// hierarchical path encoding to make the encoding simpler.

// WARNING: This currently breaks targetOfCallStmt.  So it
// probably shouldn't be used.

// IR split_calls (const IR& ir);

// Remove any vertices that are unreachable from the entry node.
IR prune_unreachable (const IR& ir);

// This function modifies the IR so that the new entrypoint is the
// specified address.  The address must be present in the IR, and
// can be in the middle of a basic block.
IR change_entry (const IR& ir, rose_addr_t new_entry);

// Initialize the stack pointer to a constant value at the
// beginning of the program.
IR init_stackpointer (const IR& ir_);

// Remove undefined values by replacing them with appropriately
// sized constant bitvectors
IR rm_undefined (const IR& ir_);

// Write data blocks identified by the ROSE/pharos partiioner to
// memory at the IR entry point
IR add_datablocks (const IR& ir_);

// This function returns a set of all registers used by the program.
std::set<Register> get_all_registers (const IR& ir_);

// Callgraph
using CGVertexProperty = boost::property<
  boost::vertex_name_t, const FunctionDescriptor*,
  boost::property<boost::vertex_index_t, std::size_t>>;
using CGEdgeProperty = boost::property<boost::edge_name_t, const CallDescriptor*>;
using CGG = boost::adjacency_list<boost::multisetS, boost::multisetS, boost::bidirectionalS, CGVertexProperty, CGEdgeProperty>;

using CGVertex = boost::graph_traits<CGG>::vertex_descriptor;
using CGEdge = boost::graph_traits<CGG>::edge_descriptor;

class CG {
 private:
  CG(CGG graph_, const DescriptorSet* ds_) : graph(graph_), ds(ds_) {}

  CGG graph;
  const DescriptorSet* ds;

 public:
  const CGG get_graph (void) const { return graph; }
  CGG& get_graph (void) { return graph; }
  const DescriptorSet* get_ds (void) const { return ds; }

  // Get the callgraph of the program
  static CG get_cg(const DescriptorSet& ds);

  // Rebuild the indices of the callgraph.  This must be called any
  // time vertices are added or removed or any algorithm utilizing
  // vertex_index will not work correctly.
  void rebuild_indices ();

  // This function returns the vertex that corresponds to the
  // specified function descriptor in the provided call graph.
  CGVertex findfd(const FunctionDescriptor* fd) const;

  // Stream output
  friend std::ostream& operator<<(std::ostream &out, const CG &cg) {
    auto cgg = cg.get_graph ();
    boost::write_graphviz(out, cgg,
                          boost::make_label_writer(boost::get(boost::vertex_name_t(), cgg)),
                          boost::make_label_writer(boost::get(boost::edge_name_t(), cgg)));
    return out;
  }

};

// This function trims calls that are not reachable (according to
// the call graph) from executions starting from 'from', and
// ending at 'to'.
void cut1_cg(CG& cg, CGVertex from, CGVertex to);

// This function provides a CFG containing code that may be
// executed in executions from 'from' to 'to', with function calls
// inlined.
IR get_inlined_cfg (const CG& cg,
                    rose_addr_t from,
                    rose_addr_t to,
                    std::function<void(CG& cg,
                                       CGVertex from,
                                       CGVertex to)> = cut1_cg);
}
}

#endif
