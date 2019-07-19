// Copyright 2018 Carnegie Mellon University.  See LICENSE file for terms.
#ifndef Pharos_Z3_H
#define Pharos_Z3_H

#include <z3++.h>
#include <rose.h>
#include <boost/optional.hpp>
#include <BinaryZ3Solver.h>
#include "misc.hpp"

namespace pharos {

using CFG = Rose::BinaryAnalysis::ControlFlow::Graph;
class FunctionDescriptor;

using Z3FixedpointPtr = std::unique_ptr<z3::fixedpoint>;
using Z3ExprVector = std::vector<z3::expr>;
using Z3QueryResult = std::tuple<z3::check_result, boost::optional<z3::expr>>;

// This is JSG's extension of the ROSE Z3 solver, which is close but
// not really ideal for what we want. Also note that we've copied the
// Rose::BinaryAnalysis::Z3Solver and renamed it
class PharosZ3Solver : public Rose::BinaryAnalysis::Z3Solver {

 private:
  // a log file for the state of the z3 solver
  std::ofstream log_file_;
  std::string log_file_name_;

 protected:
  uint64_t get_id_from_string(const std::string & id_str );

 public:
  PharosZ3Solver()
    : Rose::BinaryAnalysis::Z3Solver(Rose::BinaryAnalysis::SmtSolver::LM_LIBRARY) {

    // The default
    log_file_name_ = "znode.log";
  }

  ~PharosZ3Solver() {
    if (log_file_.is_open()) {
      log_file_.flush();
      log_file_.close();
    }
  }

  void set_timeout(unsigned int to);
  void set_seed(int seed);

  // Convert a z3 expression back to a treenode
  TreeNodePtr z3_to_treenode(const z3::expr& expr);
  z3::expr treenode_to_z3(const TreeNodePtr tnp);

  z3::expr simplify(const z3::expr& e);

  z3::expr to_bool(z3::expr z3expr);
  z3::expr to_bv(z3::expr z3expr);

  // Z3 utility routines because expr vectors are weird
  z3::expr mk_and(Z3ExprVector& args);
  z3::expr mk_and(z3::expr_vector& args);

  z3::expr mk_or(z3::expr_vector& args);
  z3::expr mk_or(Z3ExprVector& args);

  z3::expr mk_true();
  z3::expr mk_false();

  void set_log_name(std::string name);
  void do_log(std::string msg);

  // Must expose the cast function to get everything in a uniform type
  z3::expr z3type_cast(z3::expr z3expr,
                       Rose::BinaryAnalysis::SmtSolver::Type from_type,
                       Rose::BinaryAnalysis::SmtSolver::Type to_type);
};

// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// CHC Reasoning
// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
//
// These classes are heavily inspired by Seahorn (aka copied). Each
// rule is of the form: (=> ( and (pred vars ) (body) ) (head vars))).
// The rules are entered into Pharos via the fixedpoint
// class. Considerable hoops are jumpted through to make it all fit
// together
class PharosHornRule {
  Z3ExprVector vars_;
  z3::expr body_;
  z3::expr head_;
 public:

  PharosHornRule(Z3ExprVector &v, z3::expr b, z3::expr h) :
    vars_(boost::begin(v), boost::end (v)),
    body_(b), head_(h) { }

  PharosHornRule(z3::expr b, z3::expr h) : body_(b), head_(h) { }

  // return only the body of the horn clause
  z3::expr body () const;
  void set_body (z3::expr v);

  // return only the head of the horn clause
  z3::expr head () const;
  void set_head (z3::expr v);

  // return the implication body => head
  z3::expr expr(z3::context& ctx);

  const Z3ExprVector &vars () const;
};

// The primary class for handling fixed point analysis of CHC
class PharosHornAnalyzer {
  using PredMap = std::map<const SgAsmBlock*, z3::expr>;
  using RelationMap = std::map<const SgAsmBlock*, z3::func_decl>;

  const std::string goal_name_;
  PharosZ3Solver z3_;
  PredMap bb_preds_;
  RelationMap relations_;
  Z3FixedpointPtr fixedpoint_;
  z3::expr hornify_bb(const SgAsmBlock* bb);
  z3::expr register_goal(z3::expr addr_expr);
 public:

  PharosHornAnalyzer();

  void hornify(const FunctionDescriptor& fd);
  Z3QueryResult query(const rose_addr_t goal);

  std::string to_string() const;
};

} // End pharos

#endif
