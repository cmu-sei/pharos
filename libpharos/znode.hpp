// Copyright 2018-2024 Carnegie Mellon University.  See LICENSE file for terms.
#ifndef Pharos_Z3_H
#define Pharos_Z3_H

#include <z3++.h>
#include <boost/optional.hpp>
#include <boost/variant.hpp>

#include "rose.hpp"
#include <Rose/BinaryAnalysis/Z3Solver.h>
#include <Rose/BinaryAnalysis/ControlFlow.h>

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

  using paramval_t = boost::variant<bool, int, double, std::string>;
  using option_map_t = std::map<std::string, paramval_t>;
  option_map_t options;
  friend class Fixedpoint;

 protected:
  uint64_t get_id_from_string(const std::string & id_str );

 public:
  class Params {
    friend class Fixedpoint;
    friend class PharosZ3Solver;
    z3::params params;
    option_map_t map;
    Params(z3::context & ctx) : params(ctx) {}
   public:
    template<typename T>
    void set(char const *key, T value) {
      params.set(key, value);
      map.emplace(std::string{key}, value);
    }
    void set(char const *key, char const * value) {
      params.set(key, value);
      map.emplace(std::string{key}, std::string{value});
    }
    void set(char const *key, std::string value) {
      params.set(key, value.c_str());
      map.emplace(std::string{key}, std::move(value));
    }
    operator z3::params &() { return params; }
    operator z3::params const &() const { return params; }
  };

  class Context {
    friend class PharosZ3Solver;
    PharosZ3Solver & solver;
    Context(PharosZ3Solver & s) : solver(s) {}
   public:
    z3::context & operator*() {
      return *solver.Rose::BinaryAnalysis::Z3Solver::z3Context(); }
    z3::context const & operator*() const {
      return *solver.Rose::BinaryAnalysis::Z3Solver::z3Context(); }
    explicit operator z3::context *() { return &**this;}
    explicit operator z3::context const *() const { return &**this; }
    z3::context *operator->() { return &**this; }
    z3::context const *operator->() const { return &**this; }
  };

  class Fixedpoint : public z3::fixedpoint {
    option_map_t & map;
   public:
    Fixedpoint(PharosZ3Solver & solver)
      : z3::fixedpoint(*solver.z3Context()),
        map(solver.options) {}
    void set(Params const & p) {
      z3::fixedpoint::set(p);
      map.insert(p.map.begin(), p.map.end());
    }
  };

  PharosZ3Solver()
    : Rose::BinaryAnalysis::Z3Solver(Rose::BinaryAnalysis::SmtSolver::LM_LIBRARY)
  {}

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

  // Must expose the cast function to get everything in a uniform type
  z3::expr z3type_cast(z3::expr z3expr,
                       Rose::BinaryAnalysis::SmtSolver::Type from_type,
                       Rose::BinaryAnalysis::SmtSolver::Type to_type);

  Params mk_params() {
    return {*z3Context()};
  }

  std::ostream & output_options(std::ostream & s) const;

  template<typename T>
  void set_param(char const *key, T value) {
    z3::set_param(key, value);
    options.emplace(std::string{key}, value);
  }
  void set_param(char const *key, char const * value) {
    z3::set_param(key, value);
    options.emplace(std::string{key}, std::string{value});
  }
  void set_param(char const *key, std::string value) {
    z3::set_param(key, value.c_str());
    options.emplace(std::string{key}, std::move(value));
  }
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

class Z3PathAnalyzer {
 public:
  virtual void setup_path_problem(rose_addr_t source, rose_addr_t target) = 0;
  virtual std::ostream & output_problem(std::ostream & stream) const = 0;
  virtual z3::check_result solve_path_problem() = 0;
  virtual std::ostream & output_solution(std::ostream & stream) const = 0;
  virtual ~Z3PathAnalyzer() = default;
};

} // End pharos

#endif
