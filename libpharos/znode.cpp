// Copyright 2018-2024 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/graph/iteration_macros.hpp>
#include "znode.hpp"
#include "options.hpp"
#include "funcs.hpp"

namespace pharos {

// Debugging stuff
void
debug_print_expr(const z3::expr& e);
void
debug_print_expr(const z3::expr& e) {
  std::cout << e << std::endl;
}

void
PharosZ3Solver::set_timeout(unsigned int to) {
  Z3_string timeout = "timeout";
  std::string value = std::to_string(to);
  set_param(timeout, value.c_str());
}

void
PharosZ3Solver::set_seed(int seed) {
  set_param("sat.random_seed", seed);
  set_param("fp.spacer.random_seed", seed);
  set_param("smt.random_seed", seed);
}

uint64_t
PharosZ3Solver::get_id_from_string(const std::string& id_str) {

  assert(id_str.size()>0);

  unsigned start = 1; // always skip the first character: m, v, or 0 ...
  if (id_str[0] == '0') {
    // handle "0x" for hex ... actually, this should not happen (I think)
    start++;
  }

  // convert!
  uint64_t tn_id;
  std::istringstream iss(id_str.substr(start));
  iss >> tn_id;

  return tn_id;
}

// This method converts a z3 expression back to a treenode. Currently,
// we use the createExistingVariable Rose API to look up the treenode,
// but that may change to a map if proven to be inefficient or
// ineffective. Tree nodes are (obviously) tree-like structures, so
// this is a recursive algorithm.
//
// Beware that this method is not complete.
TreeNodePtr
PharosZ3Solver::z3_to_treenode(z3::expr const & e) {

  using namespace Rose::BinaryAnalysis;

  // is_app signifies that this is an application, which is a formula
  // (I think). Most treenodes will be this type of expression
  if (e.is_app()) {

    // Fetch function declaration, which is the core off the application
    z3::func_decl F = e.decl();

    // The sort for the expression is basically its type. I use it to
    // get the size
    z3::sort S = e.get_sort();

    switch (F.decl_kind()) {
     case Z3_OP_INTERNAL:
     case Z3_OP_UNINTERPRETED: {

       // Leaf nodes will be uninterpreted sorts in Z3 terms. These
       // sorts will be bit vectors (that is how they are
       // created). The lone argument should be the name of the
       // sort/treenode itself. Note that the ID for the existing
       // treenode will need to be extracted because they are exported
       // via LeafPtr::toString()
       uint64_t id = get_id_from_string(F.name().str());
       if (S.is_bv() == true) {

         TreeNodePtr tn = SymbolicExpr::makeIntegerVariable(S.bv_size(), id, F.name().str());
         if (!tn) {
           // Can't find the node so create a new one ...
           tn = SymbolicExpr::makeIntegerVariable(S.bv_size(), F.name().str());
         }

         return tn;
       }
       else if (S.is_array()) {

         // If the functon is an array, which it is for memory, the
         // check the domain/range types. If the domain and range are
         // not bit vectors, which they always should be.

         z3::sort d = S.array_domain();
         z3::sort r = S.array_domain();
         if (d.is_bv() && r.is_bv()) {

           // Memory is an array so treenodes are existing memory. The
           // id should be the same as any other existing
           // treenode. The domain is the address width and the range
           // is the value width
           return SymbolicExpr::makeMemoryVariable(d.bv_size(),
                                                   r.bv_size(),
                                                   id,
                                                   F.name().str());
         }
       }
       // In this case the sort is neither array nor bitvector. It
       // could be a boolean, but that should never happen. This
       // will report that an unhandled sort type was encountered.
       //
       // This is just to report something missed prior to returning
       // a null treenode below

       GERROR << "Unhandled uninterpreted sort type. Name:"
              << S.name() << ", type: " << S.sort_kind() << LEND;

       // To make this more clear and surpress fallthrough warnings,
       // we shall return a null treenode here

       return TreeNodePtr();
     }
     case Z3_OP_BNUM: {

       // This is a number in bit-vector form. It appears as tho
       // literal numeric treenodes (i.e. made with createInteger(...))
       // will be this kind
       assert(e.is_numeral()==true);

       // SymbolicExpr::makeIntegerConstant takes a uint64_t so interpret as a unsigned 64b int
       return SymbolicExpr::makeIntegerConstant(S.bv_size(), e.get_numeral_uint64());
     }
     case Z3_OP_TRUE:
      assert(e.is_bool() == true);
      return SymbolicExpr::makeBooleanConstant(true);
     case Z3_OP_FALSE:
      assert(e.is_bool() == true);
      return SymbolicExpr::makeBooleanConstant(false);

      // -----------------------------------------
      // Concat / extract treenodes
      // -----------------------------------------

     case Z3_OP_CONCAT: {
       auto tn = z3_to_treenode(e.arg(0));
       for (size_t i = 1; i < e.num_args(); ++i) {
         tn = SymbolicExpr::makeConcat(tn, z3_to_treenode(e.arg(i)));
       }
       return tn;
       // return SymbolicExpr::makeConcat(z3_to_treenode(e.arg(0)),
       // z3_to_treenode(e.arg(1)));
     }
     case Z3_OP_EXTRACT:

      // There seems to be a slight difference in how the upper bound
      // is evaluated in ROSE and Z3. In Rose you get begin to end
      // point, it is a range (0 to 8 is 8 bits exclusive). In Z3
      // lo/hi are the starting/ending offsets
      //
      // It turns out that the high and low operands will always be 32
      // bits wide when creating an extract expression
      return SymbolicExpr::makeExtract(SymbolicExpr::makeIntegerConstant(32, e.lo()),
                                       SymbolicExpr::makeIntegerConstant(32, e.hi()+1),
                                       z3_to_treenode(e.arg(0)));

      // -----------------------------------------
      // The remaining operations are for RISC-ops
      // -----------------------------------------

     case Z3_OP_AND: {
       case Z3_OP_BAND: {

         // The two versions of AND (boolean and BV) are the same
         auto tn = z3_to_treenode(e.arg(0));
         for (size_t i = 1; i < e.num_args(); ++i) {
           tn = SymbolicExpr::makeAnd(tn, z3_to_treenode(e.arg(i)));
         }
         return tn;
       }
     }
      // Like AND, there is no meaningful difference between OR and BV_OR
     case Z3_OP_OR: {
       case Z3_OP_BOR: {

         auto tn = z3_to_treenode(e.arg(0));
         for (size_t i = 1; i < e.num_args(); ++i) {
           tn = SymbolicExpr::makeOr(tn, z3_to_treenode(e.arg(i)));
         }
         return tn;
       }
     }
     case Z3_OP_BXOR: {
       case Z3_OP_XOR:{

         // The two versions of AND (boolean and BV) are the same
         auto tn = z3_to_treenode(e.arg(0));
         for (size_t i = 1; i < e.num_args(); ++i) {
           tn = SymbolicExpr::makeXor(tn, z3_to_treenode(e.arg(i)));
         }
         return tn;
       }
     }
     case Z3_OP_BASHR: {

       assert(e.num_args() == 2);

       //One of the fun quirks of translating is when Z3 expressions
       //and Rose treenodes are inverted

       auto sa = z3_to_treenode(e.arg(1));
       auto expr = z3_to_treenode(e.arg(0));

       return SymbolicExpr::makeAsr(sa, expr);
     }
     case Z3_OP_EQ: {
       // According to rose, two arguments of the same size are required
       assert(e.num_args() == 2);

       auto a = z3_to_treenode(e.arg(0));
       auto b = z3_to_treenode(e.arg(1));

       // This will fail within rose anyways ...
       assert (a->nBits() == b->nBits());

       return SymbolicExpr::makeEq(a, b);
     }
     case Z3_OP_ADD: {
       case Z3_OP_BADD: {

         auto tn = z3_to_treenode(e.arg(0));
         for (unsigned i = 1; i < e.num_args(); ++i) {
           tn = SymbolicExpr::makeAdd(tn, z3_to_treenode(e.arg(i)));
         }
         return tn;
       }
     }
     case Z3_OP_BSUB:

      assert(e.num_args() == 2);

      // If the first argument is 0 then this is bvsub 0, E, which is
      // really -E
      if (e.arg(0).is_numeral() && 0==e.arg(0).get_numeral_uint()) {
        return SymbolicExpr::makeNegate(z3_to_treenode(e.arg(1)));
      }
      // If the first argument is not 0, then this is a genuine
      // subtraction. Making this into a treenode requires having
      // an addition of an (arithmetically?) negated term
      return SymbolicExpr::makeAdd(z3_to_treenode(e.arg(0)),
                                   SymbolicExpr::makeNegate(z3_to_treenode(e.arg(1))));

      // -----------------------------------------
      // ITE FTW!
      // -----------------------------------------

     case Z3_OP_ITE: {

       // All ITEs have three arguments
       assert(e.num_args() == 3);
       auto cond = z3_to_treenode(e.arg(0));
       auto a = z3_to_treenode(e.arg(1));
       auto b = z3_to_treenode(e.arg(2));

       return SymbolicExpr::makeIte(cond, a, b);
     }
     case Z3_OP_DISTINCT:
      assert(e.num_args() == 2);
      return SymbolicExpr::makeNe(z3_to_treenode(e.arg(0)), z3_to_treenode(e.arg(1)));

     case Z3_OP_BNEG:
      return SymbolicExpr::makeNegate(z3_to_treenode(e.arg(0)));
      // it is unclear if OP_BNOT and OP_NOT should be handled the
      // same way (I think)

     case Z3_OP_NOT:
     case Z3_OP_BNOT:
      return SymbolicExpr::makeInvert(z3_to_treenode(e.arg(0)));

     case Z3_OP_SELECT:
      return SymbolicExpr::makeRead(z3_to_treenode(e.arg(0)), z3_to_treenode(e.arg(1)));

     case Z3_OP_ROTATE_LEFT:
      return SymbolicExpr::makeRol(z3_to_treenode(e.arg(0)), z3_to_treenode(e.arg(1)));

      // I have no idea how to handle zero and one extension when shifting?
     case Z3_OP_BSHL:
      return SymbolicExpr::makeShl0(z3_to_treenode(e.arg(0)), z3_to_treenode(e.arg(1)));
     case Z3_OP_BLSHR:
      return SymbolicExpr::makeShr0(z3_to_treenode(e.arg(0)), z3_to_treenode(e.arg(1)));

     case Z3_OP_ROTATE_RIGHT:
      return SymbolicExpr::makeRor(z3_to_treenode(e.arg(0)), z3_to_treenode(e.arg(1)));

     case Z3_OP_BMUL:
      return SymbolicExpr::makeMul(z3_to_treenode(e.arg(0)), z3_to_treenode(e.arg(0)));

     case Z3_OP_BSDIV0:
     case Z3_OP_BSDIV_I:
      return SymbolicExpr::makeSignedDiv(z3_to_treenode(e.arg(0)), z3_to_treenode(e.arg(1)));

     case Z3_OP_SIGN_EXT:
      return SymbolicExpr::makeSignExtend(z3_to_treenode(e.arg(0)), z3_to_treenode(e.arg(1)));

     case Z3_OP_ZERO_EXT:
      return SymbolicExpr::makeExtend(z3_to_treenode(e.arg(0)), z3_to_treenode(e.arg(1)));

      // Comparisions

     case Z3_OP_ULT:
      return SymbolicExpr::makeLt(z3_to_treenode(e.arg(0)), z3_to_treenode(e.arg(1)));

     case Z3_OP_SLT:
      return SymbolicExpr::makeSignedLt(z3_to_treenode(e.arg(0)), z3_to_treenode(e.arg(1)));

     case Z3_OP_SLEQ:
      return SymbolicExpr::makeSignedLe(z3_to_treenode(e.arg(0)), z3_to_treenode(e.arg(1)));

     case Z3_OP_SGEQ:
      return SymbolicExpr::makeSignedGe(z3_to_treenode(e.arg(0)), z3_to_treenode(e.arg(1)));

     case Z3_OP_SGT:
      return SymbolicExpr::makeSignedGt(z3_to_treenode(e.arg(0)), z3_to_treenode(e.arg(1)));

     case Z3_OP_UGT:
      return SymbolicExpr::makeGt(z3_to_treenode(e.arg(0)), z3_to_treenode(e.arg(1)));

     default:
      // There may be many of these
      GWARN << "Unhandled application type: " << e << LEND;
    }
  }
  else if (e.is_int()) {
    z3::func_decl F = e.decl();
  }
  else {
    GWARN << "Unhandled expression type: " << e << LEND;
  }

  // returning a null tree node is indcative of an error/handled
  // OP. If a RISC operand in a treenode is not handled, then return a
  // null treenode. Perhaps this could be an assert
  return TreeNodePtr();
}

// Method to fetch a z3 representation of a given treenode.
z3::expr
PharosZ3Solver::treenode_to_z3(const TreeNodePtr tnp) {
  Rose::BinaryAnalysis::SmtlibSolver::insert(tnp);

  VariableSet vs;
  findVariables(tnp, vs);
  ctxVariableDeclarations(vs);
  ctxCommonSubexpressions(tnp);

  Z3ExprTypePair z3pair = ctxExpression(&*tnp);
  return z3pair.first;
}

// The tactic ctx-solver-simplify is a much stronger, and more
// expensive simplification scheme. It tends to fail on treenodes :(
// Currently, the error is vague and when it occurs, just resort to
// the basic simplify call
z3::expr
PharosZ3Solver::simplify(const z3::expr& e) {
  z3::expr ret_expr = e;
  try {
    auto c = z3Context();
    z3::tactic t = z3::tactic(*c, "ctx-solver-simplify");
    z3::goal g(*c);
    g.add(to_bool(e)); // goal expressions must be boolean
    z3::apply_result r = t(g);
    ret_expr = r[0].as_expr();
  } catch(z3::exception& z3x) {
    GERROR << "ctx-solver-simplify: Z3 Exception caught: " << z3x
           << LEND;
    ret_expr = e.simplify();
  }
  return ret_expr;
}

// Convert a z3 expression vector into one large AND'd expression
z3::expr
PharosZ3Solver::mk_and(z3::expr_vector& args) {
  std::vector<Z3_ast> array;
  for (unsigned i = 0; i < args.size(); i++) {
    array.push_back(args[i]);
  }
  return z3::to_expr(args.ctx(), Z3_mk_and(args.ctx(), array.size(), &(array[0])));
}

z3::expr
PharosZ3Solver::mk_and(Z3ExprVector& args) {

  z3::expr conjunction = args[0];
  for (unsigned i = 1; i < args.size(); ++i) {
    conjunction = conjunction && args[i];
  }
  return conjunction;
}

// Convert a z3 expression vector into one large OR'd expression
z3::expr
PharosZ3Solver::mk_or(z3::expr_vector& args) {
  std::vector<Z3_ast> array;
  for (unsigned i = 0; i < args.size(); i++) {
    array.push_back(args[i]);
  }
  return z3::to_expr(args.ctx(), Z3_mk_or(args.ctx(), array.size(), &(array[0])));
}

z3::expr
PharosZ3Solver::mk_or(Z3ExprVector& args) {

  z3::expr disjunction = args[0];
  for (unsigned i = 1; i < args.size(); ++i) {
    disjunction = disjunction || args[i];
  }
  return disjunction;
}


// Convenience function to cast an expression to a bool type
z3::expr
PharosZ3Solver::to_bool(z3::expr z3expr) {

  if (z3expr.is_bool()) return z3expr;
  return z3type_cast(z3expr, SmtSolver::Type::BIT_VECTOR, SmtSolver::Type::BOOLEAN);
}

// Convenience function to cast an expression to a bitvector type
z3::expr
PharosZ3Solver::to_bv(z3::expr z3expr) {

  using namespace Rose::BinaryAnalysis;

  if (!z3expr.is_bool()) return z3expr;
  return z3type_cast(z3expr, SmtSolver::Type::BOOLEAN, SmtSolver::Type::BIT_VECTOR);
}

z3::expr
PharosZ3Solver::mk_true() {
  return z3Context()->bool_val(true);
}

z3::expr
PharosZ3Solver::mk_false()
{
  return z3Context()->bool_val(false);
}

// Rose'S Z3 typing system now carries the type with the expression
z3::expr
PharosZ3Solver::z3type_cast(z3::expr z3expr,
                            Rose::BinaryAnalysis::SmtSolver::Type from_type,
                            Rose::BinaryAnalysis::SmtSolver::Type to_type) {

  using namespace Rose::BinaryAnalysis;

  Z3ExprTypePair et = Z3ExprTypePair(z3expr, from_type);
  Z3ExprTypePair tt = ctxCast(et, to_type);
  return tt.first;
}

std::ostream &
PharosZ3Solver::output_options(std::ostream & s) const
{
  for (auto & kv : options) {
    s << std::boolalpha
      << "(set-option :" << kv.first << ' ' << kv.second << ")\n";
  }
  return s;
}


z3::expr
PharosHornRule::body () const {return body_;}

void
PharosHornRule::set_body (z3::expr v) { body_=v; }

z3::expr
PharosHornRule::head () const {return head_;}
void
PharosHornRule::set_head (z3::expr v) { head_=v; }

// return the implication body => head
z3::expr
PharosHornRule::expr(z3::context& ctx)
{
  assert(ctx!=nullptr);

  if (vars_.size()>0) {

    std::for_each(vars_.begin(), vars_.end(), [&b=body_](z3::expr& v) { b = b && v; });
    std::for_each(vars_.begin(), vars_.end(), [&h=head_](z3::expr& v) { h = h && v; });

    z3::expr_vector quantified_var_exprs(ctx);
    for (auto v : vars_) {
      quantified_var_exprs.push_back(v);
    }
    return z3::forall(quantified_var_exprs, z3::implies(body_, head_));
  }
  // without variables, there is nothing to quantify
  return z3::implies(body_, head_);
}

const Z3ExprVector&
PharosHornRule::vars () const {return vars_;}

PharosHornAnalyzer::PharosHornAnalyzer() : goal_name_("goal")
{
  // Set the fixed point engine to use spacer and CHC
  z3::context& ctx = *z3_.z3Context();
  fixedpoint_ = std::make_unique<z3::fixedpoint>(ctx);
  auto params = z3_.mk_params();
  params.set(":engine", "spacer");

  // Optionally disable pre-processing comment this out for faster
  // solving, but less readable output
  params.set ("fp.xform.slice", false);
  params.set ("fp.xform.inline_eager", false);
  params.set ("fp.xform.inline_linear", false);

  fixedpoint_->set(params);
}

// Basic blocks are the predicates to use. Thus we declare them as
// relations
z3::expr
PharosHornAnalyzer::hornify_bb(const SgAsmBlock* bb)
{
  auto bb_finder = bb_preds_.find(bb);
  if (bb_finder != bb_preds_.end()) {
    return bb_finder->second;
  }

  z3::context& ctx = *z3_.z3Context();

  // Every basic block will have a true/false result depending on
  // entry/exit. Eventually, the basic block will take parameters as
  // well in the form of a the CPU context, but that is for a later
  // concern.

  z3::sort B = ctx.bool_sort();
  const z3::symbol bb_name = ctx.str_symbol(addr_str(bb->get_address()).c_str());
  z3::expr bb_expr = ctx.constant(bb_name, B);

  // Save in case we hit the same BB twice in the future
  bb_preds_.emplace(bb, bb_expr);

  z3::func_decl bb_decl = bb_expr.decl();

  // all the basic blocks shall be relations
  fixedpoint_->register_relation(bb_decl);

  return bb_expr;
}

void
PharosHornAnalyzer::hornify(const FunctionDescriptor& fd)
{
  const CFG& cfg = fd.get_pharos_cfg();
  z3::context& ctx = *z3_.z3Context();

  BGL_FORALL_EDGES(edge, cfg, CFG) {

    // hornify_bb() will return the expression for the basic block
    // predicate either by looking it up or creating it

    SgAsmBlock *sb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, boost::source(edge, cfg)));
    z3::expr sb_expr = hornify_bb(sb);
    z3::func_decl sb_decl = sb_expr.decl();

    SgAsmBlock *tb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, boost::target(edge, cfg)));
    z3::expr tb_expr = hornify_bb(tb);
    // z3::func_decl tb_decl = tb_expr.decl();

    // The entry is always executable/taken. It is a fact
    if (sb->get_address() == fd.get_func()->get_entryVa()) {
      fixedpoint_->add_fact(sb_decl, nullptr);
    }

    // (and (pred vars) body)
    // create_body(true, sb);

    PharosHornRule rule(sb_expr, tb_expr);
    z3::expr rule_expr = rule.expr(ctx);

    std::stringstream rule_ss;
    rule_ss << addr_str(sb->get_address()) << "->" << addr_str(tb->get_address());
    z3::symbol rule_name = ctx.str_symbol(rule_ss.str().c_str());
    fixedpoint_->add_rule(rule_expr, rule_name);
  }
}

std::string
PharosHornAnalyzer::to_string() const {
  return fixedpoint_->to_string();
}

// This function registers a rule of the form TARGET_ADDR => GOAL. Querying goal
z3::expr
PharosHornAnalyzer::register_goal(z3::expr addr_expr) {

  z3::context&  ctx = *z3_.z3Context();
  z3::sort      B = ctx.bool_sort();
  z3::symbol    goal_name = ctx.str_symbol(goal_name_.c_str());
  z3::expr      goal_expr = ctx.constant(goal_name, B);
  z3::func_decl goal_decl = goal_expr.decl();

  fixedpoint_->register_relation(goal_decl);

  PharosHornRule goal_rule(addr_expr, goal_expr);
  z3::expr goal_rule_expr = goal_rule.expr(ctx);
  fixedpoint_->add_rule(goal_rule_expr, ctx.str_symbol("goal"));

  return goal_expr;
}

Z3QueryResult
PharosHornAnalyzer::query(const rose_addr_t goal) {

  auto it = std::find_if(bb_preds_.begin(), bb_preds_.end(),
                         [goal](std::pair<const SgAsmBlock*, z3::expr> pair) {
                           const SgAsmBlock* bb =  pair.first;
                           return (bb->get_address() == goal);
                         });

  if (it!=bb_preds_.end()) {
    // found the expression
    z3::expr bb_expr = it->second;

    // create a nullary proposition of the form bb => goal to
    // determine if we can reach the goal.

    z3::expr goal_expr = register_goal(bb_expr);

    z3::check_result result = fixedpoint_->query(goal_expr);
    if (result == z3::sat) {
      Z3_ast a = Z3_fixedpoint_get_ground_sat_answer(*z3_.z3Context(), *fixedpoint_);
      z3::expr sat_answer = z3::to_expr(*z3_.z3Context(), a);
      return Z3QueryResult(result, sat_answer);
    }
    else if (result == z3::unsat) {
      return Z3QueryResult(result, fixedpoint_->get_answer());
    }
  }

  // fall through to unknown / no answer

  // if the basic block expression cannot be found then report the
  // result as unknown and with an emptry expression

  return Z3QueryResult(z3::unknown, boost::optional<z3::expr>());
}

} // End pharos
