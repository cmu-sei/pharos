// Copyright 2018-2023 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/graph/topological_sort.hpp>
#include <z3++.h>

#include <boost/range/algorithm/for_each.hpp>

// For the main pharos infastructure that tracks functions.
#include "descriptors.hpp"

// For IR
#include "ir.hpp"

#include "wp.hpp"

// For get_func_containing_addr
#include "path.hpp"

using namespace pharos;
using namespace pharos::ir;

namespace {
using Rose::BinaryAnalysis::SmtSolver;

// LET crap.
auto constexpr OP_LET = Rose::BinaryAnalysis::SymbolicExpression::Operator::OP_LET;

// map from variables to their bound expressions
using letmap = std::map<Register, IRExprPtr>;

using InteriorPtr = SymbolicExpr::InteriorPtr;

// We *must* use pass by value here
IRExprPtr expand_lets (IRExprPtr e, letmap lm) {
  Register v;
  InteriorPtr i;

  if ((v = e->isLeafNode ())) {
    if (v->isVariable2 () && lm.count (v)) {
      // It's a reference to v that has been bound
      return lm[v];
    } else {
      // It's some other leaf node that we don't have to change
      return e;
    }
  } else {
    i = e->isInteriorNode ();
    assert (i);
    auto children = i->children ();
    if (i->getOperator () == OP_LET) {
      // This is a let expression!
      IRExprPtr v_, ve, vin;
      std::tie(v_, ve, vin) = std::make_tuple(children.at (0), children.at (1),
                                              children.at (2));
      v = v_->isLeafNode ();
      // First expand ve
      ve = expand_lets (ve, lm);
      // Now add v -> ve to lm
      lm[v] = ve;
      // And recurse on vin
      return expand_lets (vin, lm);
    } else {
      // A non-let interior expression.  Recurse on each child and rebuild the expression
      std::vector <IRExprPtr> new_children;

      std::transform (children.begin (), children.end (),
                      std::back_inserter (new_children),
                      [lm] (IRExprPtr childe) {
                        return expand_lets (childe, lm);
                      });
      return SymbolicExpr::Interior::instance (i->getOperator (),
                                               new_children);
    }
  }
}

IRExprPtr makeLet (Register a, IRExprPtr b, IRExprPtr c) {
  return SymbolicExpr::Interior::instance (OP_LET, a, b, c);
}

}

namespace pharos {
IRExprPtr expand_lets (const IRExprPtr &e) {
  letmap l;
  return ::expand_lets (e, l);
}
}

// Better names for variables during Z3 translation.
// Very dangerous to enable because it changes all Pharos programs!
// Please do not commit (only for debugging).
#if 0
namespace Rose {
namespace BinaryAnalysis {
void
Z3Solver::ctxVariableDeclarations(const VariableSet &vars) {
  BOOST_FOREACH (const SymbolicExpr::LeafPtr &var, vars.values()) {
    ASSERT_not_null(var);
    ASSERT_require(var->isVariable2());
    if (ctxVarDecls_.exists(var)) {
      // already emitted a declaration for this variable
    } else if (var->isScalar()) {
      z3::sort range = ctx_->bv_sort(var->nBits());
      std::stringstream ss;
      ss << *var;
      z3::func_decl decl = z3::function(ss.str().c_str(), 0, NULL, range);
      ctxVarDecls_.insert(var, decl);
    } else {
      ASSERT_require(var->domainWidth() > 0);
      z3::sort addr = ctx_->bv_sort(var->domainWidth());
      z3::sort value = ctx_->bv_sort(var->nBits());
      z3::sort range = ctx_->array_sort(addr, value);
      std::stringstream ss;
      ss << *var;
      z3::func_decl decl = z3::function(ss.str().c_str(), 0, NULL, range);
      ctxVarDecls_.insert(var, decl);
    }
  }
}
}
}
#endif

namespace {
IRExprPtr wp_stmt(const Stmt& s, const IRExprPtr& post, const Register& mem) {
  struct StmtVisitor : public boost::static_visitor<IRExprPtr> {
    const IRExprPtr& post;
    const Register& mem;
    StmtVisitor(const IRExprPtr& post_, const Register& mem_)
      : post(post_), mem(mem_) {}

    IRExprPtr operator()(const RegWriteStmt &rs) {
      // Substitute instances of var (rs.first) with exp (rs.second) in post
      return makeLet (rs.first, rs.second, post);
      //return post->substitute(rs.first, rs.second);
    }
    IRExprPtr operator()(const MemWriteStmt &ms) {
      // Update memory
      IRExprPtr newmem = SymbolicExpr::makeWrite (mem, ms.first, ms.second);
      return makeLet (mem, newmem, post);
      //return post->substitute(mem, newmem);
    }
    IRExprPtr operator()(UNUSED const SpecialStmt &ss) {
      // Return false? It's not clear what the best thing to do here is.
      return SymbolicExpr::makeBooleanConstant (false);
    }
    IRExprPtr operator()(const AssertStmt &as) {
      // post /\ e
      return SymbolicExpr::makeAnd (post, static_cast<IRExprPtr> (as));
    }
    IRExprPtr operator()(const CallStmt &cs) {
      // Return false? It's not clear what the best thing to do here is.
      GWARN << "Encountered a non-rewritten Call statement " << cs
            << ". This is treated as an unexecutable statement "
            <<  " and is probably not what you want." << LEND;
      return SymbolicExpr::makeBooleanConstant (false);
    }
    IRExprPtr operator()(UNUSED const InsnStmt &is) {
      // Instruction statements do not effect weakest preconditions
      return post;
    }
    IRExprPtr operator()(UNUSED const CommentStmt &cs) {
      // Comment statements do not effect weakest preconditions
      return post;
    }
  };

  StmtVisitor vis(post, mem);
  return boost::apply_visitor(vis, s);
}

IRExprPtr wp_stmts(const Stmts& stmts, const IRExprPtr& post, const Register& mem) {
  return std::accumulate(stmts.rbegin(), stmts.rend(), post,
                         [&mem](const IRExprPtr& e,
                                const Stmt &stmt)
                         { return wp_stmt(stmt, e, mem); });
}

// When we remove edges from the CFG, we are left with some vertices that are partially
// specified.  If we do not do anything, the unspecified executions are 'true' in the WP
// formula which is not what we want.  This function adds edges for those executions to the
// error node.
IR add_error_edges (const IR& ir) {
  IRCFG cfg = ir.get_cfg ();
  auto edgecond_map = boost::get(boost::edge_name_t(), cfg);

  auto error = ir.get_error ();

  BGL_FORALL_VERTICES (v, cfg, IRCFG) {
    if (boost::out_degree (v, cfg) == 1) {
      IRCFGEdge e = *boost::begin (boost::out_edges (v, cfg));
      auto cond = edgecond_map [e];
      if (cond) {
        auto d = boost::target (e, cfg);
        if (d == error) {
          // Conditional edge to error.  Make it unconditional.
          edgecond_map [e] = EdgeCond ();
        } else {
          // Otherwise add a new edge to error.
          IRCFGEdge new_edge;
          bool succ;
          std::tie (new_edge, succ) = boost::add_edge (v, error, cfg);
          assert (succ);
          auto t = SymbolicExpr::makeInvert (*cond);
          edgecond_map [new_edge] = EdgeCond (t);
        }
      }
    }

  }
  return IR (ir, cfg);
}
}

namespace pharos {

IRExprPtr wp_cfg(const IR& ir_, const IRExprPtr &post) {
  std::vector<IRCFGVertex> rtopo;

  IR ir = add_error_edges (split_edges (filter_backedges (ir_)));

  const IRCFG& cfg = ir.get_cfg();
  auto ir_map = boost::get(boost::vertex_ir_t(), cfg);
  //auto name_map = boost::get(boost::vertex_name_t(), cfg);
  auto edgecond_map = boost::get(boost::edge_name_t(), cfg);

  topological_sort (cfg,
                    std::back_inserter (rtopo));

  // This maps a BB to its WP
  std::map<IRCFGVertex, IRExprPtr> bbwp;

  for (auto v : rtopo) {
    IRExprPtr bbpost;
    if (boost::out_degree (v, cfg) == 0) {
      // This is the exit
      bbpost = post;
    } else {
      auto it = boost::out_edges (v, cfg);
      bbpost = std::accumulate (it.first,
                                it.second,
                                TreeNodePtr(SymbolicExpr::makeBooleanConstant (true)),
                                [&] (IRExprPtr exp, const IRCFGEdge &e) {
                                  auto sv = boost::target (e, cfg);
                                  assert (bbwp.count (sv) == 1);
                                  return SymbolicExpr::makeAnd (exp, bbwp[sv]);
                                });
    }

    IRExprPtr wp = wp_stmts (*ir_map[v], bbpost, ir.get_mem ());

    // Because we called split_edges, there is at most one incoming edge that has a condition.
    // If there is one, we treat it like an assume statement, so e => q
    auto incoming_edges = boost::in_edges (v, cfg);
    auto edgeit = std::find_if (incoming_edges.first,
                                incoming_edges.second,
                                [&] (IRCFGEdge e) {
                                  return (edgecond_map[e]);
                                });
    if (edgeit != incoming_edges.second) {
      wp = SymbolicExpr::makeIte (*edgecond_map[*edgeit], wp,
                                  SymbolicExpr::makeBooleanConstant (true));
      //std::cout << "added edge condition " << **edgecond_map[*edgeit] << std::endl;
    }

    bbwp[v] = wp;

    // PharosZ3Solver solver;
    // solver.insert (expand_lets (bbwp[v]));
    // solver.z3Update ();
    // std::cout << "WP " << name_map[v] << " "
    //           << (solver.check() == Rose::BinaryAnalysis::SmtSolver::Satisfiable::SAT_YES)
    //           << " " << solver.z3Assertions ().at (0) << std::endl;
    // if (solver.check () == Rose::BinaryAnalysis::SmtSolver::Satisfiable::SAT_YES) {
    //        std::cout << solver.z3Solver ()->get_model () << std::endl;
    // }
  }

  const IRCFGVertex &entry = ir.get_entry ();

  return bbwp[entry];
}


std::tuple<IR, IRExprPtr, std::set<IRCFGVertex>> add_reached_postcondition (
  const IR& ir, const std::set<rose_addr_t> targets, boost::optional<Register> hit_var_)
{
  IRCFG cfg = ir.get_cfg ();

  Register hit_var;

  std::set<IRCFGVertex> vset;

  // Create the variable if necessary
  if (hit_var_) {
    hit_var = *hit_var_;
  } else {
    hit_var = SymbolicExpr::makeIntegerVariable (1, "hit_target")->isLeafNode ();
  }

  std::set<rose_addr_t> targetbbs;

  // Find the basic blocks that the target addresses are in
  std::transform (targets.begin (),
                  targets.end (),
                  std::inserter (targetbbs, targetbbs.end ()),
                  [&] (rose_addr_t addr) {
                    // Because we are using an instruction level CFG, this is a noop for now.
                    return addr;
                  });

  // Check for NULL

  auto bb_map = boost::get (boost::vertex_name_t (), cfg);
  auto ir_map = boost::get (boost::vertex_ir_t (), cfg);

  // Initialize the variable to false in the entry
  auto entry = ir.get_entry ();
  auto irstmts = ir_map[entry];
  auto newstmt = RegWriteStmt (hit_var, SymbolicExpr::makeBooleanConstant (false));
  irstmts->insert (irstmts->begin (), newstmt);

  // Loop over each BB.  If the BB matches one of the targets, adjust
  // the IR to insert writes at the proper places.

  // Note that we do NOT care if we successfully reach the exit.
  // Therefore we add a write before the first matching target and
  // remove any outgoing edges which effectively makes the node an
  // exit.

  BGL_FORALL_VERTICES(v, cfg, IRCFG) {
    auto insn_addr = bb_map[v].get_insn_addr ();
    if (insn_addr && targetbbs.count (*insn_addr)) {
      auto stmts = ir_map[v];
      auto firstaddrstmt = std::find_if (stmts->begin (),
                                         stmts->end (),
                                         [&] (Stmt s) {
                                           auto addr = addrFromStmt (s);
                                           return addr && targets.count (*addr) == 1;
                                         });
      assert (firstaddrstmt != stmts->end ());

      stmts->erase (firstaddrstmt+1, stmts->end ());
      newstmt = RegWriteStmt (hit_var, SymbolicExpr::makeBooleanConstant (true));
      stmts->push_back (newstmt);
      vset.insert (v);

      // Remove all outgoing edges
      boost::clear_out_edges (v, cfg);
    } else if (boost::out_degree (v, cfg) == 0) {
      // This is just an optimization to make WP simplify a little bit better
      auto stmts = ir_map[v];
      newstmt = RegWriteStmt (hit_var, SymbolicExpr::makeBooleanConstant (false));
      stmts->push_back (newstmt);
    }
  }

  return std::make_tuple (IR (ir, cfg), hit_var, vset);
}

}

namespace {
struct HelperVisitor : public boost::static_visitor<boost::optional<Stmt>> {
  const DescriptorSet &ds;
  const ImportRewriteSet &funcs;
  const IR &ir;
  int &n;
  bool ignore = false;
  HelperVisitor (const DescriptorSet &ds_, IR &ir_, const ImportRewriteSet &funcs_, int &n_)
    : ds(ds_), funcs(funcs_), ir(ir_), n(n_) {}
  boost::optional<Stmt> operator () (const InsnStmt &is) {
    ignore = false;
    return (Stmt) is;
  }
  boost::optional<Stmt> operator () (const CallStmt &cs) {
    if (const ImportCall *ec = boost::get<ImportCall> (&(std::get<1> (cs)))) {
      // Is it one of the targeted functions?
      auto i = std::find (funcs.begin (), funcs.end (), *ec);
      if (i != funcs.end ()) {
        ignore = true;
        n++;
        if (*ec == ImportCall ("ELF", "__assert_symbolic_dummy_import")) {
          // __assert_symbolic_dummy_import(b) is an import that tells us we should rewrite to
          // AssertStmt(b)
          int nbits = ds.get_arch_bits ();
          if (nbits == 64) {
            // On amd64, the first argument goes into rdi
            Register rdi = ir.get_reg(ds.get_arch_reg("rdi"));
            IRExprPtr true_exp = SymbolicExpr::makeIntegerConstant (nbits,
                                                                    1);
            IRExprPtr condition = SymbolicExpr::makeEq (rdi, true_exp);
            return (Stmt) (AssertStmt (condition));

          } else {
            // Normally the first argument would be at esp+4.  But we strip out the push of the
            // return address, so it's at offset 0.
            Register esp = ir.get_reg(ds.get_arch_reg("esp"));
            IRExprPtr argument = SymbolicExpr::makeRead (ir.get_mem (),
                                                         esp);
            // Because SymbolicExpr only makes it easy to read one byte at a time, we'll just
            // compare to the true byte
            IRExprPtr true_exp = SymbolicExpr::makeIntegerConstant (8,
                                                                    1);
            IRExprPtr condition = SymbolicExpr::makeEq (argument, true_exp);
            return (Stmt) (AssertStmt (condition));
          }
        } else {
          int nbits = ds.get_arch_bits ();
          Register eax = ir.get_reg(ds.get_arch_reg("eax"));
          std::stringstream vname;
          vname << ec->first << "!" << ec->second << "@"
                << addr_str (std::get<2> (cs)->get_address ()) << ":" << n;
          IRExprPtr nv = SymbolicExpr::makeIntegerVariable (nbits, vname.str ());
          return (Stmt) (RegWriteStmt (eax, nv));
        }
      }
    }

    return (Stmt) cs;
  }
  template <typename T>
  boost::optional<Stmt> operator () (T const &x) const {
    if (ignore)
      return boost::none;
    else
      return (Stmt) x;
  }
};
}

namespace pharos {
IR rewrite_imported_calls (IR &ir, const ImportRewriteSet& funcs) {
  int n = 0;

  auto ds = ir.get_ds ();
  IRCFG cfg = ir.get_cfg ();
  auto ir_map = boost::get(boost::vertex_ir_t(), cfg);

  BGL_FORALL_VERTICES (v, cfg, IRCFG) {
    auto stmts = *ir_map [v];
    StmtsPtr newstmts (new Stmts ());
    HelperVisitor vis (*ds, ir, funcs, n);
    // Visit each stmt backwards.  If we see a call to a matching
    // callsite, we ignore any stmt until we see the InsnStmt which
    // marks the beginning of that instruction.  This is used to
    // ignore stack adjustments among other things.
    std::for_each (stmts.rbegin (),
                   stmts.rend (),
                   [&] (Stmt &os) {
                     if (boost::optional<Stmt> ns = boost::apply_visitor (vis, os)) {
                       newstmts->push_back (*ns);
                     }
                   });
    // Put the new statements in the right order.
    std::reverse (newstmts->begin (), newstmts->end ());
    ir_map [v] = newstmts;
  }

  GINFO << "Rewrote " << n << " imported calls." << LEND;

  return IR(ir, cfg);
}

void WPPathAnalyzer::setup_path_problem(rose_addr_t source, rose_addr_t target) {
  using namespace ir;

  IR ir = get_inlined_cfg (CG::get_cg (ds), source, target);
  ir = rewrite_imported_calls (ir, imports);
  ir = init_stackpointer (ir);
  ir = rm_undefined (ir);
  ir = add_datablocks (ir);

  IRExprPtr post;
  std::tie (ir, post, std::ignore) = add_reached_postcondition (ir, {target});

  IRExprPtr wp = expand_lets (wp_cfg (ir, post));

  solver.memoizer ({});
  solver.insert (wp);
  solver.z3Update ();
  assert (solver.z3Assertions ().size () == 1);
}

std::ostream & WPPathAnalyzer::output_problem(std::ostream & stream) const
{
  solver.output_options(stream);
  stream << ";; --- Z3 Start\n"
         << *solver.z3Solver()
         << ";; --- Z3 End\n"
         << "(check-sat)\n"
         << "(get-model)" << std::endl;
  return stream;
}

z3::check_result WPPathAnalyzer::solve_path_problem()
{
  using Rose::BinaryAnalysis::SmtSolver;

  auto result = solver.check();
  switch (result) {
   case SmtSolver::Satisfiable::SAT_YES:
    return z3::sat;
   case SmtSolver::Satisfiable::SAT_NO:
    return z3::unsat;
   default:
    return z3::unknown;
  }
}

std::ostream & WPPathAnalyzer::output_solution(std::ostream & stream) const
{
  return stream << ";; WPPathAnalyzer::output_solution not yet implemented" << std::endl;
}

}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
