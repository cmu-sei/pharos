// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Spacer_H
#define Pharos_Spacer_H

#include "ir.hpp"
#include "znode.hpp"

using namespace pharos::ir;

// Move this somewhere more appropriate
template <typename C>
struct back_inserter_iter :
  public std::iterator<std::output_iterator_tag,void,void,void,void> {
 public:
  C * container;
  back_inserter_iter(C & c) : container(&c) {}
  back_inserter_iter(back_inserter_iter const &) = default;
  back_inserter_iter & operator=(back_inserter_iter const &) = default;
  template <typename T>
  auto operator=(T && x) { container->push_back(std::forward<T>(x)); return *this; }
  back_inserter_iter & operator*() { return *this; }
  back_inserter_iter & operator++() { return *this; }
  back_inserter_iter & operator++(int) { return *this; }
};

template <typename C>
auto z3_vector_back_inserter(C & container) {
  return back_inserter_iter<C>(container);
}

namespace pharos {

struct CompareRegisters {
  bool operator()(Register const &a, Register const &b) const {
    auto ah = a->hash(), bh = b->hash();
    return (ah == bh) ? (a < b) : (ah < bh);
  }
};
using Z3RegMap = std::map <Register, z3::expr, CompareRegisters>;

// This information is obtained from find_path_hierarchical
using PartialConvertCallFun = std::function<boost::optional<z3::func_decl>(const CallStmt &callstmt,
                                                                           const z3::expr_vector &call_input_args)>;
// The remaining information is obtained from encode_cfg
using ConvertCallFun = std::function<boost::optional<z3::func_decl>(const CallStmt &callstmt,
                                                                    const IRCFGVertex &before,
                                                                    const z3::expr_vector &call_input_args)>;

// Inter-procedural state, intra-procedural state, fresh variables, and constraints
using TupleState = std::tuple<Z3RegMap, Z3RegMap, std::vector<z3::expr>, z3::expr>;


}

namespace {

pharos::ConvertCallFun dummy_convert_call =
  [] (
    const CallStmt &, const IRCFGVertex &, const z3::expr_vector &)
  -> z3::func_decl {
    throw std::logic_error("Internal logic error: called dummy_convert_call()!");
  };

pharos::PartialConvertCallFun dummy_partial_convert_call =
  [] (
    const CallStmt &, const z3::expr_vector &)
  -> z3::func_decl {
    throw std::logic_error("Internal logic error: called dummy_partial_convert_call()!");
  };

}

namespace pharos {

class SpacerAnalyzer : public Z3PathAnalyzer {
  using Z3FixedpointPtr = std::unique_ptr<PharosZ3Solver::Fixedpoint>;
  typedef struct {
    z3::func_decl before;
    z3::func_decl after;
    Z3RegMap intra_regs;
  } SpacerRelations;
  using SpacerRelationsMap = std::map<boost::graph_traits<IRCFG>::vertex_descriptor,
                                      SpacerRelations>;

  const DescriptorSet& ds_;
  PharosZ3Solver& z3_;
  Z3FixedpointPtr fp_;
  ImportRewriteSet import_set_;
  std::function<void(CG& cg, CGVertex from, CGVertex to)> cutf_ = cut1_cg;
  boost::optional<z3::expr> goal_expr_;
  boost::optional<z3::expr> answer_;

 private:

  // Given a CFG and post-conditions, return the the entry, exit, and
  // goal relations.  If propagate_input is set, all relations will
  // include an input state representing the input state at the start
  // of the function.  This is useful when using function
  // summaries. If regs is supplied, they will be used as the type of
  // the state.  Otherwise all accessed registers will be used.  If
  // convert_call is supplied, it should convert the given CallStmt to
  // a z3 summary relation, which is used for hierarchical encoding.
  std::tuple <Z3RegMap, z3::func_decl, z3::func_decl>
  encode_cfg (const IR &ir,
              const z3::expr &z3post_input,
              const z3::expr &z3post_output,
              bool propagate_input = false,
              std::string name = "",
              boost::optional<std::vector<Register>> regsIn = boost::none,
              boost::optional<z3::func_decl> entry = boost::none,
              boost::optional<z3::func_decl> exit = boost::none,
              boost::optional <std::function<bool(const IRCFGVertex &)>> short_circuit = boost::none,
              ConvertCallFun convert_call = dummy_convert_call);

  // Encode a block, returning mappings of inter-block regstate,
  // intra-block regstate (temporaries), the set of fresh variables,
  // and constraints.
  TupleState
  subst_stmts (const Stmts& s, const Register& mem, const Z3RegMap &z3inputs,
               PartialConvertCallFun convert_call = dummy_partial_convert_call);

  TupleState
  subst_stmt(const Stmt& s, const Register& mem, TupleState& state,
             PartialConvertCallFun convert_call = dummy_partial_convert_call);

 public:
  SpacerAnalyzer(const DescriptorSet& ds, PharosZ3Solver& z3, ImportRewriteSet import_set,
                 std::string const & engine="spacer");

  SpacerAnalyzer(const DescriptorSet& ds, PharosZ3Solver& z3,
                 std::string const & engine="spacer");

  // break everything into discrete steps so we can evaluate each in
  // isolation.

  void setup_path_problem(rose_addr_t source, rose_addr_t target) override;
  std::ostream & output_problem(std::ostream & stream) const override;
  z3::check_result solve_path_problem() override;
  std::ostream & output_solution(std::ostream & stream) const override;

  // Dump the Fixedpoint
  std::string to_string() const;

};

} // end pharos
#endif
