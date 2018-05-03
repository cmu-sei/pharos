// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Ir_H
#define Pharos_Ir_H

#include <map>
#include <vector>

#include <boost/tuple/tuple_io.hpp>
#include <boost/variant.hpp>
#include <boost/optional.hpp>

#include <rose.h>
#include <SymbolicSemantics2.h>

#include "cdg.hpp"
#include "funcs.hpp"

typedef Rose::BinaryAnalysis::ControlFlow::Graph CFG;
typedef boost::graph_traits<CFG>::vertex_descriptor CFGVertex;

namespace SymbolicExpr = Rose::BinaryAnalysis::SymbolicExpr;
typedef SymbolicExpr::Ptr SymbolicExprPtr;
typedef SymbolicExpr::Leaf SymbolicLeaf;
typedef SymbolicExpr::LeafPtr SymbolicLeafPtr;
typedef SymbolicExpr::Interior SymbolicInterior;
typedef SymbolicExpr::InteriorPtr SymbolicInteriorPtr;

typedef Rose::BinaryAnalysis::InstructionSemantics2::BaseSemantics::RegisterStateGeneric::RegPair RegPair;

namespace pharos {
  namespace ir {

    // IR Types
    typedef SymbolicLeafPtr Register;
    typedef std::string Special;

    typedef SymbolicExpr::Node IRExpr;
    typedef SymbolicExprPtr IRExprPtr;

    enum class CallType {direct, indirect};

    struct RegWriteStmt : std::pair<Register, IRExprPtr> {
      using std::pair<Register, IRExprPtr>::pair;
    };
    struct MemWriteStmt : std::pair<IRExprPtr, IRExprPtr> {
      using std::pair<IRExprPtr, IRExprPtr>::pair;
    };
    struct InsnStmt : std::pair<rose_addr_t, std::string> {
      using std::pair<rose_addr_t, std::string>::pair;
    };
    struct SpecialStmt : Special {
      using Special::basic_string;
      SpecialStmt (const std::string &s) : Special (s) {}
    };
    struct CallStmt : std::pair<CallType, IRExprPtr> {
      using std::pair<CallType, IRExprPtr>::pair;
    };

    typedef boost::variant<RegWriteStmt, MemWriteStmt, InsnStmt, SpecialStmt, CallStmt> Stmt;
    typedef std::vector<Stmt> Stmts;
    typedef boost::shared_ptr<Stmts> StmtsPtr;

    // Stream helpers
    std::ostream& operator<<(std::ostream &out, const RegWriteStmt &stmt);
    std::ostream& operator<<(std::ostream &out, const MemWriteStmt &stmt);
    std::ostream& operator<<(std::ostream &out, const InsnStmt &stmt);
    std::ostream& operator<<(std::ostream &out, const SpecialStmt &stmt);
    std::ostream& operator<<(std::ostream &out, const CallStmt &stmt);
    std::ostream& operator<<(std::ostream &out, const Stmts &stmts);
    std::ostream& operator<<(std::ostream &out, const StmtsPtr &stmtsptr);

    // Return the expressions referenced in a statement, if any exist.
    std::set<IRExprPtr> expsFromStmt(Stmt &stmt);

  };
};

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
      using boost::optional<IRExprPtr>::optional;
      EdgeCond (const IRExprPtr &p) : boost::optional<IRExprPtr> (p) {}
      EdgeCond () : boost::optional<IRExprPtr> () {}
      EdgeCond (boost::optional<IRExprPtr> const & o) : boost::optional<IRExprPtr>(o) {}
      EdgeCond (boost::optional<IRExprPtr> && o) : boost::optional<IRExprPtr>(std::move(o)) {}
    };
    std::ostream& operator<<(std::ostream &out, const EdgeCond &edgecond);

    typedef boost::property<boost::vertex_ir_t, StmtsPtr,
                            boost::property<boost::vertex_name_t, SgAsmBlock*>> VertexProperty;
    typedef boost::property<boost::edge_name_t, EdgeCond> EdgeProperty;

    typedef boost::adjacency_list<boost::setS, boost::vecS, boost::bidirectionalS, VertexProperty, EdgeProperty> IRCFG;
    typedef boost::graph_traits<IRCFG>::vertex_descriptor IRCFGVertex;
    typedef boost::graph_traits<IRCFG>::edge_descriptor IRCFGEdge;

    typedef RegisterStateGenericPtr IRRegState;

    class IR {
    private:
      IRCFG cfg;
      IRRegState rstate;
      Register mem;
    public:
      IR(IRCFG cfg_, IRRegState rstate_, Register mem_) :
        cfg(cfg_), rstate(rstate_), mem(mem_) {}
      IR(const IR &ir, IRCFG cfg_) {
        *this = ir;
        cfg = cfg_;
      }
      IRCFG get_cfg(void) const { return cfg; }
      Register get_reg(RegisterDescriptor rd) const;
      Register get_mem(void) const { return mem; }
    };

    IR get_ir(FunctionDescriptor& fd);

    IR filter_backedges(IR ir);
    IR split_edges(IR ir);
  };
};

#endif
