// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Wp_H
#define Pharos_Wp_H

#include "ir.hpp"
#include "znode.hpp"

using namespace pharos::ir;

namespace pharos {
IRExprPtr wp_cfg(const IR& prog, const IRExprPtr& post);

IRExprPtr expand_lets (const IRExprPtr& expr);

// This function adds a new (or optionally specified) hit_var that
// is set to true whenever the specified targets are hit.  Returns
// the instrumented IR, the hit variable, and the vertices
// containing hits.
std::tuple<IR, IRExprPtr, std::set<IRCFGVertex>> add_reached_postcondition (
  const IR& ir,
  const std::set<rose_addr_t> targets,
  boost::optional<Register> hit_var = boost::none);

// This is a helper function that identifies calls to selected
// external functions and replaces them with a write of EAX with a
// fresh symbolic variable.
IR rewrite_imported_calls (IR& prog, const ImportRewriteSet& funcs);

class WPPathAnalyzer : public Z3PathAnalyzer
{
  DescriptorSet const & ds;
  PharosZ3Solver & solver;
  ImportRewriteSet imports;
 public:
  WPPathAnalyzer(
    DescriptorSet const & ds_, PharosZ3Solver & s, ImportRewriteSet const & i)
    : ds(ds_), solver(s), imports(i) {}
  void setup_path_problem(rose_addr_t source, rose_addr_t target) override;
  std::ostream & output_problem(std::ostream & stream) const override;
  z3::check_result solve_path_problem() override;
  std::ostream & output_solution(std::ostream & stream) const override;
};

}

#endif
