#include "path.hpp"
#include "misc.hpp"
#include "stkvar.hpp"
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graph_utility.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/range/adaptors.hpp>
#include <boost/graph/iteration_macros.hpp>
#include <boost/graph/topological_sort.hpp>
#include <boost/graph/breadth_first_search.hpp>

namespace pharos {

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// Beginning of PharosZ3Solver methods
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Method to fetch a z3 representation of a given treenode.
z3::expr
PharosZ3Solver::treenode_to_z3(const TreeNodePtr tnp) {
  Rose::BinaryAnalysis::SmtlibSolver::insert(tnp);
  ctxVariableDeclarations(findVariables(tnp));
  ctxCommonSubexpressions(tnp);

  GDEBUG << "Translating treenode " << *tnp << " to z3" << LEND;

  Z3ExprTypePair z3pair = ctxExpression(tnp);
  return z3pair.first;
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

// Convert a z3 expression vector into one large OR'd expression
z3::expr
PharosZ3Solver::mk_or(z3::expr_vector& args) {
  std::vector<Z3_ast> array;
  for (unsigned i = 0; i < args.size(); i++) {
    array.push_back(args[i]);
  }
  return z3::to_expr(args.ctx(), Z3_mk_or(args.ctx(), array.size(), &(array[0])));
}

// Convenience function to cast an expression to a bool type
z3::expr
PharosZ3Solver::to_bool(z3::expr z3expr) {

  using namespace Rose::BinaryAnalysis;

  if (z3expr.is_bool()) return z3expr;
  return z3type_cast(z3expr, SmtSolver::Type::BIT_VECTOR, SmtSolver::Type::BOOLEAN);
}

// Convenience function to cast an expression to a bitvector type
z3::expr
PharosZ3Solver::to_bv(z3::expr z3expr) {

  using namespace Rose::BinaryAnalysis;

  if (z3expr.is_bv()) return z3expr;
  return z3type_cast(z3expr, SmtSolver::Type::BOOLEAN, SmtSolver::Type::BIT_VECTOR);
}

// Rose's Z3 typing system now carries the type with the expression
z3::expr
PharosZ3Solver::z3type_cast(z3::expr z3expr,
                            Rose::BinaryAnalysis::SmtSolver::Type from_type,
                            Rose::BinaryAnalysis::SmtSolver::Type to_type) {

  using namespace Rose::BinaryAnalysis;

  Z3ExprTypePair et = Z3ExprTypePair(z3expr, from_type);
  Z3ExprTypePair tt = ctxCast(et, to_type);
  return tt.first;
}

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// Beginning of SegmentFinder methods
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

SegmentFinder::SegmentFinder(PharosZ3Solver* z3) : z3_(z3)
{
  segment_info_ = std::make_shared<PathSegmentInfo>();
}

SegmentFinder::~SegmentFinder() { }

struct fcg_bfs_visitor : public boost::default_bfs_visitor {

  // records the functions as they are discovered
  std::vector<rose_addr_t> discovered_funcs;

  void discover_vertex(FCGVertex v, const FCG & g) {
    SgAsmFunction *f = get(boost::vertex_name, g, v);
    discovered_funcs.push_back(f->get_entry_va());
    OINFO << "Discovered " << addr_str(f->get_entry_va()) << LEND;
  }
};

bool
SegmentFinder::generate_cfg_constraints() {

  if (!segment_info_->function) {
    OERROR << "Invalid function descriptor" << LEND;
    return false;
  }

  const CFG &cfg = segment_info_->function->get_pharos_cfg();

  z3::context* ctx = z3_->z3Context();

  // process edges and save edge information
  BGL_FORALL_EDGES(edge, cfg, CFG) {

    EdgeInfo ei(ctx);

    ei.edge = edge;
    SgAsmBlock *sb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, boost::source(edge, cfg)));
    ei.edge_src_addr = sb->get_address();

    SgAsmBlock *tb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, boost::target(edge, cfg)));
    ei.edge_tgt_addr = tb->get_address();

    ei.edge_str =  edge_name(edge, cfg);
    ei.cond_str =  edge_cond(edge, cfg);

    ei.edge_expr = ctx->bool_const(ei.edge_str.c_str());
    ei.cond_expr = ctx->bool_const(ei.cond_str.c_str());

    ei.fd = segment_info_->function;

    segment_info_->edge_info.push_back(ei);
  }

  // fill in predecessors
  for (auto& ei : segment_info_->edge_info) {

    CfgVertex src_vtx = boost::source(ei.edge, cfg);

    std::vector<EdgeInfo> predecessors;
    BGL_FORALL_INEDGES(src_vtx, in_edge, cfg, CFG) {

      std::vector<EdgeInfo>::iterator eni =
        std::find_if(segment_info_->edge_info.begin(), segment_info_->edge_info.end(),
                     [&in_edge](const EdgeInfo &arg) {
                       return arg.edge == in_edge;
                     });

      if (eni != segment_info_->edge_info.end()) {
        EdgeInfo in_ei = *eni;
        predecessors.push_back(in_ei);
      }
    }

    z3::expr cfg_cond(*ctx);
    if (predecessors.size() > 1) {
      z3::expr_vector pred_exprs(*ctx);
      for (auto prev : predecessors) pred_exprs.push_back(prev.edge_expr);

      cfg_cond = z3::expr(ei.edge_expr == (ei.cond_expr && z3_->mk_or(pred_exprs)));
    }

    // single incoming edge
    else if (predecessors.size() == 1) {
      z3::expr in_expr = z3::expr(predecessors.at(0).edge_expr);

      cfg_cond = z3::expr(ei.edge_expr == (ei.cond_expr && in_expr));
    }
    else { // no incoming edge, this must be an entry point (making
           // many assumptions here)
      cfg_cond = z3::expr(ei.edge_expr == ei.cond_expr);
    }

    segment_info_->cfg_conditions.push_back(cfg_cond);
  }

  return (segment_info_->cfg_conditions.size() > 0);
} // end generate_cfg_constraints

// Edge conditions are the conditions that impact decisions in the
// code. In this version the conditions are based on the state of
// decisions nodes (ITEs), but this can change ...
bool
SegmentFinder::generate_edge_conditions(std::map<CfgEdge, z3::expr>& edge_conditions) {

  if (!segment_info_->function) {
    OERROR << "Invalid function descriptor" << LEND;
    return false;
  }

  const CFG &cfg = segment_info_->function->get_pharos_cfg();
  const PDG* pdg = segment_info_->function->get_pdg();

  // Z3 stuff needed for analysis
  if (pdg == NULL) return false;

  const DUAnalysis& du = pdg->get_usedef();
  const BlockAnalysisMap& blocks = du.get_block_analysis();

  z3::context* ctx = z3_->z3Context();

  BGL_FORALL_EDGES(edge, cfg, CFG) {

    // the condition_tnp is on the EIP of the source
    CfgVertex src_vtx = boost::source(edge, cfg);
    SgAsmBlock *src_bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, src_vtx));

    CfgVertex tgt_vtx = boost::target(edge, cfg);
    SgAsmBlock *tgt_bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, tgt_vtx));

    BlockAnalysis src_analysis = blocks.at(src_bb->get_address());
    if (!src_analysis.output_state) {
      OERROR << "Cannot fetch output state for " << addr_str(src_bb->get_address()) << LEND;
      continue;
    }
    SymbolicRegisterStatePtr src_reg_state = src_analysis.output_state->get_register_state();

    if (!src_reg_state) {
      OERROR << "Could not get vertex " << addr_str(src_bb->get_address())
             << " register state" << LEND;
      continue;
    }

    RegisterDescriptor eiprd = global_descriptor_set->get_arch_reg("eip");
    SymbolicValuePtr vtx_eip = src_reg_state->read_register(eiprd);
    TreeNodePtr eip_tnp = vtx_eip->get_expression();

    GDEBUG << "\nThe vertex "
           << addr_str(src_bb->get_address())
           << " has an EIP of " << *eip_tnp << LEND;

    // If the vertex has an out degree greater than one then it is a
    // choice of some type. There are basically two options here:
    // 1. this is in ITE meaning the choice result cannot be
    //    determined. In this case the ITE is analyzed.
    //
    // 2. this is a number meaning that the target address is always known.
    //    This enabled identifying paths that are never taken (i.e. infeasible
    //
    // 3. this is a variable. I'm not entirely sure what to do in this case.

    if (boost::out_degree(src_vtx, cfg) > 1) {

      // If the treenode associated with EIP is an ITE, then it is a
      // decision. The decision part is what we care
      // about. Specifically, the symbolic EIP register will contain
      // the branch decision
      const InternalNodePtr in = eip_tnp->isInteriorNode();
      if (in && in->getOperator() == Rose::BinaryAnalysis::SymbolicExpr::OP_ITE) {

        const TreeNodePtrVector& branches = in->children();
        TreeNodePtr condition_tnp = branches[0];
        rose_addr_t true_address = get_address_from_treenode(branches[1]);

        GDEBUG << "EIP ITE Condition: " << *condition_tnp << LEND;

        try {
          z3::expr condition_expr = z3_->treenode_to_z3(condition_tnp);
          GDEBUG << "Z3 condition is: " <<  condition_expr << LEND;

          if (true_address == tgt_bb->get_address()) {
            edge_conditions.emplace(std::make_pair(edge, condition_expr));
          }
          else {

            // There are two ways to NOT this expression depending on
            // the context: bool or bv. It must be boolean to assert
            // it
            z3::expr not_condition_expr(*ctx);
            if (condition_expr.is_bool() == false) {
              condition_expr = z3_->to_bool(condition_expr);
            }
            not_condition_expr = !condition_expr;
            GDEBUG << "The negated z3 condition is " << not_condition_expr << LEND;

            edge_conditions.emplace(std::make_pair(edge, not_condition_expr.simplify()));
          }
        }
        catch(z3::exception z3x) {
          OERROR << "generate_edge_conditions: Z3 Exception caught: " << z3x << LEND;
          return false;
        }
      }
      // Not an ITE, so that means it will be an expression. If it is
      // a constant expression then it is the address of the next
      // instruction. This hints at infeasible vs. always-taken paths
      else if (eip_tnp->isNumber()) {

        uint64_t target_addr = eip_tnp->toInt();
        // This edge is never taken because Pharos tells us so! Mark
        // it as "false" to indicate that the path is infeasible

        if (target_addr != tgt_bb->get_address()) {
          edge_conditions.emplace(std::make_pair(edge, ctx->bool_val(false)));
        }
      }
    }

    // There are no incoming edges to the source. In this case, the
    // edge should always be taken (given a well-formed CFG with one
    // entry)
    //
    // It turns out this is rarely true in practice let alone malware
    rose_addr_t entry_va = segment_info_->function->get_func()->get_entry_va();
    if (entry_va == src_bb->get_address()) {
      edge_conditions.emplace(std::make_pair(edge, ctx->bool_val(true)));
    }
  }

  // distribute the edge conditions to impacted edges
  propagate_edge_conditions(edge_conditions);

  return true;
}

bool
SegmentFinder::generate_edge_constraints() {

  // we need a context to create Z3 types
  z3::context* ctx = z3_->z3Context();

  std::map<CfgEdge, z3::expr> edge_conditions;
  if (false == generate_edge_conditions(edge_conditions)) {
    return false;
  }

  // Compute and add the edge information. There is probably a
  // more efficient way to do this, but doing it here, separately
  // makes consolidating edge conditions easier.

  for (auto& edge_cond : edge_conditions) {

    CfgEdge edge = edge_cond.first;
    std::vector<EdgeInfo>::iterator eni =
      std::find_if(segment_info_->edge_info.begin(),
                   segment_info_->edge_info.end(),
                   [&edge](const EdgeInfo &arg) {
                     return arg.edge == edge;
                   });

    if (eni == segment_info_->edge_info.end()) continue;

    EdgeInfo edge_info = *eni;

    z3::expr tnp_cond_expr = edge_cond.second;
    if (tnp_cond_expr.is_bool() == false) {
      tnp_cond_expr = z3_->to_bool(tnp_cond_expr);
    }

    // assert that the edge condition is equal to the expressions that
    // control them. It is debatable whether equality is the proper,
    // or most efficient way to do this. Implication is attractive but
    // not strong enough because false can imply true ... JSG cannot
    // see how this will not lead to false expressions implying true
    // paths?


    // If this condition is the goal condition, then it must be
    // true. Save it so callers to this function can access it

    if (edge_info.edge_tgt_addr == segment_info_->goal_addr) {
      // save this for future calls. Should this be tied to parameters?
      segment_info_->edge_constraints.push_back(z3::expr(tnp_cond_expr == ctx->bool_val(true)));
    }
    segment_info_->edge_constraints.push_back(z3::expr(edge_info.cond_expr == tnp_cond_expr));

  }

  // Now assert the edges that we must reach to achieve a goal. This
  // is one way to force a particular path

  z3::expr_vector goal_constraints_exprs(*ctx);
  z3::expr_vector start_constraints_exprs(*ctx);

  for (auto ei : segment_info_->edge_info) {
    if (ei.edge_tgt_addr == segment_info_->goal_addr) {
      goal_constraints_exprs.push_back(z3::expr(ei.edge_expr == ctx->bool_val(true)));
    }
    if (ei.edge_src_addr == segment_info_->start_addr) {
      start_constraints_exprs.push_back(z3::expr(ei.edge_expr == ctx->bool_val(true)));
    }
  }

  // If there is more than one incoming edge to the target vertex,
  // then there can possibly be more than one viable path. The best
  // thing to do is form a disjunction among the incoming edges so
  // that any of them can be viable

  if (goal_constraints_exprs.size() > 1) {
    segment_info_->edge_constraints.push_back(z3_->mk_or(goal_constraints_exprs));
  }
  else if (goal_constraints_exprs.size() == 1) {
    segment_info_->edge_constraints.push_back(goal_constraints_exprs[0]);
  }
  else {
    OERROR << "No goal constraints to assert!" << LEND;
  }

  if (start_constraints_exprs.size() > 1) {
    segment_info_->edge_constraints.push_back(z3_->mk_or(start_constraints_exprs));
  }
  else if (start_constraints_exprs.size() == 1) {
    segment_info_->edge_constraints.push_back(start_constraints_exprs[0]);
  }
  else {
    OERROR << "No starting constraints to assert!" << LEND;
  }

  return true;
} // end generate_edge_constraints()

// edge condition propagation means carrying forward the conditions to
// take a given edge
void
SegmentFinder::propagate_edge_conditions(std::map<CfgEdge, z3::expr>& edge_conditions) {

  const CFG& cfg = segment_info_->function->get_pharos_cfg();

  BGL_FORALL_VERTICES(vtx, cfg, CFG) {

    // if the source of this edge is a target for a condition, then
    // propagate
    BGL_FORALL_INEDGES(vtx, in_edge, cfg, CFG) {

      CfgVertex src_vtx = boost::source(in_edge, cfg);
      SgAsmBlock *in_edge_src_bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, src_vtx));

      for (auto ec : edge_conditions) {
        CfgEdge cond_edge = ec.first;
        z3::expr cond_expr = ec.second;

        CfgVertex ec_target_vtx = boost::target(cond_edge, cfg);
        SgAsmBlock *ec_target_bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, ec_target_vtx));

        // If the target of the edge condition is this in_edge, the
        // the condition affects this edge and must be propagated
        if (ec_target_bb->get_address() == in_edge_src_bb->get_address()) {

          // Get existing condition on in_edge and OR with the new
          // conditions for this edge if multiple incoming edges are present

          unsigned in_deg = boost::in_degree(ec_target_vtx, cfg);
          if (in_deg == 1) {
            // with one incoming edge, just add the condition

            edge_conditions.emplace(std::make_pair(in_edge, cond_expr));
          }
          else {

            // find all incoming edges on the target where this
            // condition shall be propagated
            BGL_FORALL_INEDGES(ec_target_vtx, target_in_edge, cfg, CFG) {

              // Skip the in edge currently being evaluated to avoid duplication
              if (cond_edge == target_in_edge) continue;

              auto ec_search = edge_conditions.find(target_in_edge);
              while (ec_search != edge_conditions.end()) {
                z3::expr& x = ec_search->second;

                if (x.is_bool() == false) {
                  x = z3_->to_bool(x);
                }
                if (cond_expr.is_bool() == false) {
                  cond_expr = z3_->to_bool(cond_expr);
                }
                edge_conditions.emplace(std::make_pair(in_edge, z3::expr(cond_expr || x)));
                ec_search++;
              }
            }
          }
        }
      }
    }
  }
}

static double g_start_time = 0;
static void display_statistics(const z3::solver* solver) UNUSED;
static void
display_statistics(const z3::solver* solver) {

  if (solver) {
    double end_time = static_cast<double>(clock());
    z3::stats stats = solver->statistics();
    OINFO << "+-+-+-+-+-+- Z3 GEEK STATS +-+-+-+-+-+-\n"
          << stats
          << "\n time:   " << (end_time - g_start_time)/CLOCKS_PER_SEC << " secs\n"
          <<    "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+" << LEND;
  }
}

// This method is purely for debugging
static void debug_print_expr(const z3::expr& e) UNUSED;
static void
debug_print_expr(const z3::expr& e) {
  std::cout << e.to_string() << std::endl;
}

PathSegmentInfo::PathSegmentInfo() :
  start_addr(INVALID_ADDRESS),
  goal_addr(INVALID_ADDRESS),
  function(NULL) { }

// The main analytical routine for function analysis, what JSG refers
// to as a segment in the context of path finding. This function
// operates on basic blocks; thus goal and start must be basic block
// addresses. Note that the previous analysis is made available to
// this function to support additional constraints on data values Each
// segment is analyzed from a start to a goal address. The previous
// analysis is also included to assert constraints on incoming values
bool
SegmentFinder::analyze_segment(rose_addr_t start_addr,
                               rose_addr_t goal_addr,
                               FunctionDescriptor* fd,
                               const PathSegmentInfoPtrList* analyzed_segments) {

  OINFO << "----------------------------------------------------------\n"
        << "Analyzing " << addr_str(fd->get_address())
        << "\n----------------------------------------------------------" << LEND;

  if (NULL == segment_info_) segment_info_ = std::make_shared<PathSegmentInfo>();

  if (start_addr == INVALID_ADDRESS || goal_addr == INVALID_ADDRESS) {
    OERROR << "start/goal addresses  not valid!" << LEND;
  }

  segment_info_->start_addr = start_addr;
  segment_info_->goal_addr = goal_addr;

  if (!fd) {
    OERROR << "Function not valid!" << LEND;
    return false;
  }
  segment_info_->function = fd;

  // Check if the goal is "valid" by determining if it is in the
  // function to analyze

  bool valid_goal = false;
  bool valid_start = false;
  const CFG& cfg = segment_info_->function->get_pharos_cfg();

  BGL_FORALL_VERTICES(vtx, cfg, CFG) {
    rose_addr_t vtx_addr = vertex_addr(vtx, cfg);
    if (vtx_addr == segment_info_->goal_addr) valid_goal = true;
    if (vtx_addr == segment_info_->start_addr) valid_start = true;
    if (valid_start && valid_goal) break;
  }

  if (false == valid_goal) {
    GDEBUG << "Cannot find goal vertex in function "
           << addr_str(segment_info_->function->get_address()) << LEND;
    return false;
  }
  if (false == valid_start) {
    GDEBUG << "Cannot find start vertex in function "
           << addr_str(segment_info_->function->get_address()) << LEND;
    return false;
  }

  OINFO << "The start is " << addr_str(segment_info_->start_addr)
        << " goal vertex is: " << addr_str(segment_info_->goal_addr) << LEND;


  // Step 1 is to generate the CFG structures
  if (false == generate_cfg_constraints()) {
    GDEBUG << "Failed to generate CFG conditions" << LEND;
    return false;
  }

  // Step 2 is to generate the conditions necessary to take each edge
  if (false == generate_edge_constraints()) {
    GDEBUG << "Failed to generate edge conditions" << LEND;
    return false;
  }
  // debugging
  // print_edge_conditions(segment_info_->function);

  // Step 3 is to generate the constraints on the path to take
  if (false == generate_value_constraints(analyzed_segments)) {
    GDEBUG << "Failed to generate assertions" << LEND;
    return false;
  }

  return true;

  // print out some statistics about how many resources the solver
  // used. This is mostly for informational/debugging purposes
  //
  // display_statistics(z3_.z3Solver());

} // end analyze_segment


// add all the constraints and solve
bool
PathFinder::evaluate_path() {

  try {

    // Load all the conditions into
    z3::solver* solver = z3_.z3Solver();
    for (auto seg : path_segments_) {
      for (auto cfg_condition : seg->cfg_conditions) solver->add(cfg_condition);
      for (auto edge_constraint : seg->edge_constraints) solver->add(edge_constraint);
      for (auto val_constraint : seg->value_constraints) solver->add(val_constraint);
    }

    GDEBUG << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-\n"
           << "Final representation:"
           <<  "\n---\n" << *solver << "\n---" << LEND;

    switch (solver->check()) {

     case z3::unsat:
      OINFO << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-\n"
            << "Sat check: is NOT valid, there is no path from "
            << addr_str(start_address_) << " to " << addr_str(goal_address_)
            << "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-" << LEND;

      // Without a path, there is no solution
      path_found_ = false;
      break;

     case z3::sat:
      OINFO << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-\n"
            << "Sat check: IS valid, there is a path from "
                        << addr_str(start_address_) << " to " << addr_str(goal_address_)
            << "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-" << LEND;

      // A path was found, given the constraints
      path_found_ = true;
      break;

     case z3::unknown:
      OINFO << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-\n"
            << "Sat check: is UNKOWN???\n"
            << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-" << LEND;
    }
  }
   catch (z3::exception z3x) {
    OERROR << "evaluate: Z3 Exception caught: " << z3x << LEND;
    path_found_ = false;
  }

  return path_found_;
}

// Generate the path for the main segment. Assumes a model exists
// There is a strange symmetry to this analysis. All the contraints
// must be loaded into Z3, analyzed as one, and then re-assigned to
// segments as a traversal
bool
PathFinder::analyze_path_solution() {

  try {

    // Time to analyze the model - This means saving the edges taken
    // and values used. Doing this in three distinct loops keeps
    // things linear

    z3::model model = z3_.z3Solver()->get_model();

    std::map<std::string, z3::expr> modelz3vals;
    OINFO << "Solution:\n" << model << "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-" << LEND;

    for (unsigned i = 0; i<model.size(); i++) {
      z3::func_decl element = model[i];
      std::string element_name = element.name().str();
      if (element.is_const()) {
        z3::expr element_val = model.get_const_interp(element);
        modelz3vals.insert(std::pair<std::string, z3::expr>(element_name, element_val));
      }
    }

    // Create an empty traversal
    for (auto s : path_segments_) {
      PathTraversalPtr t = std::make_shared<PathTraversal>();
      t->function = s->function;
      t->start_addr = s->start_addr;
      t->goal_addr = s->goal_addr;
      path_traversal_.push_back(t);
    }

    // The model is now processed, last step is to distribute into
    // segments/traversals.

    PathSegmentInfoPtrList::iterator segi = path_segments_.begin();
    PathTraversalPtrList::iterator trvi = path_traversal_.begin();

    while (segi!=path_segments_.end() && trvi!=path_traversal_.end()) {

      // these should be lined up
      PathSegmentInfoPtr seg = *segi;
      PathTraversalPtr trv = *trvi;
      // bool found_edge = false, found_cond = false;

      // add to the traversal
      for (auto ei : seg->edge_info) {
        auto evi = modelz3vals.find(ei.edge_str);
        if (evi != modelz3vals.end()) {
          z3::expr val = evi->second;
          if (val.bool_value() == Z3_L_TRUE) trv->path.push_back(ei);
        }
      }

      // Now select actual program values from the traversal
      assign_traversal_values(trv, modelz3vals);

      segi++;
      trvi++;
    }
    GDEBUG << "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-" << LEND;
  }
  catch (z3::exception z3x) {
    OERROR << "analyze_path_solution: Z3 Exception caught: " << z3x << LEND;
    return false;
  }

  return true;

}

// This function add constraints to the possible paths to be taken.
// This should include values used by the analysis
bool
SegmentFinder::generate_value_constraints(const PathSegmentInfoPtrList* analyzed_segments) {

  // To further constrain a path value constraints are added based on
  // previous analysis. This will add additional constraints based on
  // detected input parameters (and eventually return values).

  // for each outgoing call, fetch the parameter constraints
    CallDescriptorSet outgoing_calls = segment_info_->function->get_outgoing_calls();
    for (auto cd : outgoing_calls) {

      FunctionDescriptor* called_fd = cd->get_function_descriptor();
      if (called_fd == NULL) continue;

      // from the perspective of the callee as seen in the called
      // function descriptor
      const ParamVector& callee_params = called_fd->get_parameters().get_params();
      OINFO << "There are " << callee_params.size() << " callee params" << LEND;

      // from the perspective of the caller as seen in the call
      // descriptor
      const ParamVector& caller_params = cd->get_parameters().get_params();
      OINFO << "There are " << caller_params.size() << " caller params" << LEND;

      ParamVector::const_iterator callee_iter = callee_params.begin();
      ParamVector::const_iterator caller_iter = caller_params.begin();

      while (caller_iter!=caller_params.end() && callee_iter!=callee_params.end()) {
        const ParameterDefinition &caller_param = *caller_iter;
        const ParameterDefinition &callee_param = *callee_iter;

        if (caller_param.num == callee_param.num) {
          if (caller_param.value!=NULL && callee_param.value!=NULL) {

            TreeNodePtr caller_tnp = caller_param.value->get_expression(); // the caller is this functio
            TreeNodePtr callee_tnp = callee_param.value->get_expression();

            OINFO << "Paramater (caller) " << *caller_tnp << LEND;
            z3::expr caller_expr = z3_->treenode_to_z3(caller_tnp);

            OINFO << "Paramater (callee) " << *callee_tnp << LEND;
            z3::expr callee_expr = z3_->treenode_to_z3(callee_tnp);

            // basically assert that caller/callee params must be equal
            z3::expr param_expr = z3::expr(caller_expr == callee_expr);
            segment_info_->value_constraints.push_back(param_expr);

            OINFO << "Added paramater constraint (caller) for "
                  << addr_str(segment_info_->function->get_address())
                  << " call to "
                  << addr_str(called_fd->get_address())
                  << " Param treenode: " << *caller_tnp
                  << " Constraint: " << param_expr << LEND;
          }
        }
        caller_iter++;
        callee_iter++;
      }

      // Now assert the calls
      if (analyzed_segments != NULL) {

      for (auto pi=analyzed_segments->begin(); pi!=analyzed_segments->end(); pi++) {
        PathSegmentInfoPtr analyzed_seg = *pi;

        OINFO << "Checking for value constraints from called function "
              << addr_str(analyzed_seg->function->get_address()) << LEND;

        if (called_fd->get_address() == analyzed_seg->function->get_address()) {

          // These are the values for incoming parameters on this call
          // to reach the goal vertex (perhaps the end). They can
          // further constrain the path

          // add the constraints from the previously analyzed
          // segments called from this function
          segment_info_->value_constraints.insert(segment_info_->value_constraints.end(),
                                           analyzed_seg->value_constraints.begin(),
                                           analyzed_seg->value_constraints.end());
        }
      }
    }
  }

  return true;

} // end SegmentFinder::assert_constraints

FunctionDescriptor*
SegmentFinder::get_fd() const {
  return segment_info_->function;
}

rose_addr_t
SegmentFinder::get_segment_start_addr() const {
  return segment_info_->start_addr;
}

void
SegmentFinder::set_segment_start_addr(rose_addr_t saddr) {
  segment_info_->start_addr = saddr;
}

rose_addr_t
SegmentFinder::get_segment_goal_addr() const {
  return segment_info_->goal_addr;
}

void
SegmentFinder::set_segment_goal_addr(rose_addr_t gaddr) {
  segment_info_->goal_addr = gaddr;
}

PathSegmentInfoPtr
SegmentFinder::get_segment_info() {
  return segment_info_;
}

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// Beginning of PathFinder methods
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

void
PathFinder::assign_traversal_values(PathTraversalPtr trv,
                                    std::map<std::string, z3::expr> modelz3vals) {

  // to avoid huge names for variable sets
  using namespace Rose::BinaryAnalysis;

  if (!trv->function) {
    OERROR << "Invalid function descriptor" << LEND;
    return;
  }

  OINFO << "Analyzing solution ..." << LEND;

  // Start with parameters vars ...
  ParamVector params = trv->function->get_parameters().get_params();
  for (ParameterDefinition param : params) {
    TreeNodePtr param_val_tnp = param.value->get_expression();

    if (!param_val_tnp) continue;

    SmtSolver::VariableSet vars = z3_.findVariables(param_val_tnp);
    GDEBUG << "Evaluating param: " << param.to_string() << LEND;

      // This is now on a traversal ...
    for (auto leaf : vars.values()) {
      auto vi = modelz3vals.find(leaf->toString());
      if (vi != modelz3vals.end()) {
        unsigned raw_val = vi->second.get_numeral_uint();

        trv->required_param_values.push_back(ConcreteParameter(param, raw_val));

        OINFO << "Incoming parameter: '" <<  *(param.address->get_expression()) << "'"
              << " (" << leaf->toString() << ")"
              << " must be set to '" << raw_val << "'" << LEND;
      }
    }
  }

  // Now try to find the concrete values used by local (stack
  // variables). This is challenging because

  const StackVariablePtrList& stack_vars = trv->function->get_stack_variables();
  for (auto stkvar : stack_vars) {

    TreeNodePtr stkvar_memaddr_tnp = stkvar->get_memory_address()->get_expression();

    // Must look through value(s) to see if it uses the variables of
    // interest.
    bool found_stkval = false;
    for (auto stkvar_val_sv : stkvar->get_values()) {

      if (!stkvar_val_sv) continue;

      TreeNodePtr stkvar_val_tnp = stkvar_val_sv->get_expression();
      if (!stkvar_val_tnp) continue;

      SmtSolver::VariableSet vars = z3_.findVariables(stkvar_val_tnp);
      GDEBUG << "Evaluating stack variable: " << stkvar->to_string() << LEND;

      // The tricky part is that there can be multiple values per
      // variable depending on how they are set

      for (auto v : vars.values()) {

        auto vi = modelz3vals.find(v->toString());
        if (vi != modelz3vals.end()) {

          unsigned raw_val = vi->second.get_numeral_uint();
          trv->required_stkvar_values.push_back(ConcreteStackVariable(*stkvar, raw_val));
          found_stkval=true;

          OINFO << "Stack variable: '" << *stkvar_memaddr_tnp
                << "' must be set to '" << raw_val << "'" << LEND;
          break;
        }
      }
      if (found_stkval) break;
    }
  }
}

PathFinder::PathFinder()
  : path_found_(false), save_z3_output_(false),
    goal_address_(INVALID_ADDRESS), start_address_(INVALID_ADDRESS) { }

PathTraversalPtrList
PathFinder::get_path() const {
  return path_traversal_;
}

void
PathFinder::set_goal_addr(rose_addr_t g) {
  goal_address_ = g;
}

rose_addr_t
PathFinder::get_goal_addr() const {
  return goal_address_;
}

void
PathFinder::set_start_addr(rose_addr_t s) {
  start_address_ = s;
}

rose_addr_t
PathFinder::get_start_addr() const{
  return start_address_;
}

// If the complete_path isn't empty and we found everything that was
// expected, then we have a path!
bool
PathFinder::path_found() const {
  return (path_found_==true);
}

// The main path finding routine. There are two basic scenarios, the
// path is in one function, or this analysis requires interprocedural
// reasoning This method assumes that the start/goal addresses are
// valid and have a feasible path between them
bool
PathFinder::find_path(rose_addr_t start_addr, rose_addr_t goal_addr) {

  // Step 1. is to initialize the path parameters and make sure they
  // are valid

  if (goal_addr == INVALID_ADDRESS) {
    OERROR << "Invalid goal address!" << LEND;
    return false;
  }

  if (start_addr == INVALID_ADDRESS) {
    OERROR << "Invalid start address!" << LEND;
    return false;
  }

  // save the ultimate start/goal addresses
  start_address_ = start_addr;
  goal_address_ = goal_addr;

  OINFO << "Start address is: " << addr_str(start_addr)
        << ", Goal address is: " << addr_str(goal_addr) << LEND;

  // Step 2: Determine if the goal is reachable from the start
  // address. Presumably, the goal is in here somewhere. Computing the
  // "reachability tree" as a way to down select the set of possible
  // paths. If there is no topological path from start to goal
  // (spanning the FCG), then deeper analysis is unwarranted.

  std::vector<FunctionDescriptor*> reachable_vertices;
  bool is_feasible = compute_reachability(start_addr, goal_addr, reachable_vertices);

  // Once the reachability tree (from start to goal) is computed, a
  // few scenarios are possible:

  // Scenario 0: Infeasible path There is no topological path between
  //
  // start and goal. Barring an incomplete CFG, there is not much to
  // do in this case.

  if (!is_feasible || reachable_vertices.size() == 0) {
    OERROR << "path from "
           << addr_str(start_addr) << " to "
           << addr_str(goal_addr) << " topologically infeasible!" << LEND;
    return false;
  }

  // Scenario 1: intra-procedrual analysis
  //
  // If there Start and end in same function, run typical pathfinding
  else if (reachable_vertices.size() == 1) {

    OINFO << "Start and goal addresses are in the same function." << LEND;

    FunctionDescriptor* start_fd = get_func_containing_address(start_addr);

    // The search occurs on a basic block basis. Arbitrary addresses
    // must be expressed in terms of their basic block address. This
    // should be OK because by definition all sequential instuctions
    SgAsmBlock* goal_bb = insn_get_block(global_descriptor_set->get_insn(goal_addr));
    SgAsmBlock* start_bb = insn_get_block(global_descriptor_set->get_insn(start_addr));

    std::shared_ptr<SegmentFinder> intra_path_finder = std::make_shared<SegmentFinder>(&z3_);
    intra_path_finder->analyze_segment(start_bb->get_address(),
                                       goal_bb->get_address(),
                                       start_fd,
                                       NULL);
  }

  //
  // Scenario 2. Inter-procedrual searches. This is the hardest of the lot.
  //
  // Start and end are in differnt functions because there are more
  // than one reachable_vertices function
  else if (reachable_vertices.size() > 0) {

    OINFO << "Start and goal points are in different functions" << LEND;

    std::vector<FunctionSearchParameters> analysis_queue;

    FunctionDescriptor* goal_fd = get_func_containing_address(goal_addr);
    FunctionDescriptor* start_fd = get_func_containing_address(start_addr);

    // Now we have the start/goal functions. We know that we will need
    // to search the goal function from its entry point to the goal
    // (because start is in a different function).

    analysis_queue.push_back(
      FunctionSearchParameters(
        goal_fd, goal_fd->get_func()->get_entry_va(), goal_addr));

    // build the queue/chain of functions to search, in a DFS way
    std::map<rose_addr_t, rose_addr_t> xrefs = build_xrefs();

    // For each XREF to the current goal function. This will work backwards
    FunctionDescriptor* gfd=goal_fd;
    FunctionDescriptor* sfd=NULL;
    for (auto x : xrefs) {
      rose_addr_t to = x.second;
      rose_addr_t from = x.first;

      OINFO << "Processing XREF " << addr_str(from) << " -> " << addr_str(to) << LEND;

      if (to == gfd->get_address()) {

        sfd = get_func_containing_address(from);

        if (sfd->get_address() == start_fd->get_address()) {

          // found the function containing the real start! Note that
          // 'from' is the address of the call
          analysis_queue.push_back(
            FunctionSearchParameters(
              start_fd, start_addr, from));

          break;
        }

        // This is another link in the chain The goal is now the call
        // to this sfd the start is a previous caller
        else {

          OINFO << "Found another segment: start= " << addr_str(sfd->get_func()->get_entry_va())
                << ", goal= " << addr_str(to) << LEND;

          analysis_queue.push_back(
            FunctionSearchParameters(
              sfd, sfd->get_func()->get_entry_va(), from));

          // we must look up the caller to sfd, this is the new goal
          gfd = sfd;
          sfd = NULL;
        }
      }
    }

    // Now process the queue, which means analyzing each function
    // queued for analysis in terms of it's start/goal

    OINFO << "There are " << analysis_queue.size() << " segments to analyze" << LEND;

    for (auto item : analysis_queue) {

      SgAsmBlock* gbb = insn_get_block(global_descriptor_set->get_insn(item.goal_addr));
      SgAsmBlock* sbb = insn_get_block(global_descriptor_set->get_insn(item.start_addr));

      OINFO << "Analyzing " << addr_str(item.start_addr)
            << " in basic block " << addr_str(sbb->get_address())
            << " to " << addr_str(item.goal_addr)
            << " in basic block " << addr_str(gbb->get_address())
            << " in function " << addr_str(item.fd->get_address()) << LEND;

      // Create a new segment finder to analyze a function
      std::shared_ptr<SegmentFinder> segment_finder
        = std::make_shared<SegmentFinder>(&z3_);

      if (segment_finder->analyze_segment(sbb->get_address(),
                                          gbb->get_address(),
                                          item.fd,
                                          &path_segments_)) {

        path_segments_.push_back(segment_finder->get_segment_info());
      }
    }
  }

  // All the perspective path segments have been analyzed. The
  // constraints and conditions needed for a path have been
  // compiled. Now we must solve!

  // Finally, for the CFG and constraints, attempt to select the path
  // and extract the model.

  // The final path segment entry is contains the starting function
  // and all downstream analysis to the goal. This is because we
  // generate the analysis list from goal to start and then
  // back-propogate dependencies.
  //
  // I do this by adding all the constraints to the solver (repeats
  // not added) and then asking for a solution

  g_start_time = static_cast<double>(clock());
  if (true == evaluate_path()) {
    if (true == analyze_path_solution()) {

      GDEBUG << "Path found and analyzed" << LEND;

      if (save_z3_output_) {
        std::stringstream ss;

        ss << ";; --- Z3 Start\n"
           << *z3_.z3Solver()
           << ";; --- End\n"
          // convenience functions for checking the z3 model in output
           << ";;(check-sat)\n"
           << ";;(get-model)";

        z3_output_.push_back(ss.str());
      }
    }
  }
  else {
    // save the current representation
    GDEBUG << "Failed to generate solution" << LEND;

  }
  return path_found_;
}

void
PathFinder::save_z3_output() {
  save_z3_output_ = true;
}

std::string
PathFinder::get_z3_output() {

  std::stringstream z3ss;
  std::copy(z3_output_.begin(),
            z3_output_.end(),
            std::ostream_iterator<std::string>(z3ss,"\n"));

  return z3ss.str();

}

// This routine builds a list of nodes reachable_vertices from the
// start using a topological search (BFS).
bool
PathFinder::compute_reachability(rose_addr_t start_addr,
                                 rose_addr_t goal_addr,
                                 std::vector<FunctionDescriptor*>& reachable_funcs) {

  const FCGVertex NULL_FCG_VERTEX = boost::graph_traits <FCG>::null_vertex();

  if (goal_addr == INVALID_ADDRESS || start_addr == INVALID_ADDRESS) {
    OERROR << "Invalid start/goal address!" << LEND;
    return false;
  }

  FunctionDescriptor* start_fd = get_func_containing_address(start_addr);
  if (start_fd == NULL) {
    OERROR << "Unreachable: Cannot find start function!" << LEND;
    return false;
  }

  FunctionDescriptor* goal_fd = get_func_containing_address(goal_addr);
  if (goal_fd == NULL) {
    OERROR << "Unreachable: Cannot find goal function!" << LEND;
    return false;
  }

  // Both start and goal addresses are in functions within this
  // program. Now we need to figure out if there is a path from start
  // to goal functions. If there is then this is feasible.
  if (start_fd->get_address() == goal_fd->get_address()) {
    reachable_funcs.push_back(start_fd);
    return true;
  }

  GDEBUG << "Start is in function " << addr_str(start_fd->get_address())
         << "; Goal is in function " << addr_str(goal_fd->get_address())
         << " - checking for tological path" << LEND;

  FCG& fcg = global_descriptor_set->get_function_call_graph();

  // Find the starting vertex, which is the function containing the start.
  // The FCG does not work on function descriptors :(

  FCGVertex start_vertex = NULL_FCG_VERTEX;
  BGL_FORALL_VERTICES(v, fcg, FCG) {
    SgAsmFunction *f = get(boost::vertex_name, fcg, v);
    // entry point enough to match functions?
    if (f->get_entry_va() == start_fd->get_func()->get_entry_va()) {
      start_vertex = v;
      break;
    }
  }
  if (start_vertex == NULL_FCG_VERTEX) {
    OERROR << "Cannot find start vertex" << LEND;
    return false;
  }

  OINFO << "Running BFS for path from "
        << addr_str(start_fd->get_func()->get_entry_va())
        << " looking for "
        << addr_str(goal_fd->get_func()->get_entry_va()) << LEND;


  // Compute the reachability tree saving vertices as they are
  // discovered

  std::vector<FCGVertex> reachable_vertices;
  reachable_vertices.reserve(boost::num_vertices(fcg));
  reachable_funcs.reserve(reachable_vertices.size());

  boost::breadth_first_search(
    fcg, start_vertex,
    boost::visitor(
      boost::make_bfs_visitor(
        boost::write_property(
          boost::identity_property_map(),
          std::back_inserter(reachable_vertices),
          boost::on_discover_vertex()))));

  OINFO << "Reachable vertices: " << reachable_vertices.size() << LEND;

  // Of course, vertices are basically meaningless. We need the addresses
  bool reachable_goal=false;
  for (auto rv : reachable_vertices) {
    SgAsmFunction *f = get(boost::vertex_name, fcg, rv);
    FunctionDescriptor* fd = get_func_containing_address(f->get_entry_va());
    if (fd) {
      reachable_funcs.push_back(fd);

      // Can we find the goal from the start?
      if (fd->get_address() == goal_fd->get_address()) {
        reachable_goal = true;
      }
    }
    else {
      OERROR << "Could not find function " << addr_str(f->get_entry_va()) << LEND;
    }
  }
  return reachable_goal;
}

// End PathFinder methods

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// Beginning of utility methods
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

std::string
edge_str(CfgEdge e, const CFG& cfg) {
  CfgVertex src = boost::source(e, cfg);
  SgAsmBlock *sb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, src));

  CfgVertex tgt = boost::target(e, cfg);
  SgAsmBlock *tb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, tgt));

  std::stringstream ss;
  ss << addr_str(sb->get_address()) << "-" << addr_str(tb->get_address());
  return ss.str();
}

std::string
edge_name(CfgEdge e, const CFG& cfg) {

  std::stringstream ss;
  ss << "edge_" << edge_str(e, cfg);
  return ss.str();
}

std::string
edge_cond(CfgEdge e, const CFG& cfg) {

  std::stringstream ss;
  ss << "cond_" << edge_str(e, cfg);
  return ss.str();
}

rose_addr_t
vertex_addr(CfgVertex v, const CFG& cfg) {
  SgAsmBlock *bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, v));
  return bb->get_address();
}

std::string
vertex_str(CfgVertex v, const CFG& cfg) {
  return addr_str(vertex_addr(v, cfg));
}

rose_addr_t
get_address_from_treenode(TreeNodePtr tnp) {

  LeafNodePtr lp = tnp->isLeafNode();
  if (lp && lp->isNumber()) {
    const Sawyer::Container::BitVector& bits = lp->bits();
    if (bits.size() <= 64) {
      return (rose_addr_t)bits.toInteger();
    }
  }
  return INVALID_ADDRESS;
}

std::map<rose_addr_t, rose_addr_t>
build_xrefs() {
  std::map<rose_addr_t, rose_addr_t> xrefs;
  for (auto& pair : global_descriptor_set->get_call_map()) {
    const CallDescriptor & cd = pair.second;
    const CallTargetSet &call_targets = cd.get_targets();

    rose_addr_t from = cd.get_address();

    // record this xref
    if (!call_targets.empty()) {
      // to address of (first) target   // from address of call
      rose_addr_t to = *(call_targets.begin());
      xrefs.emplace(from, to);
    }

    // check for API call (which will not have a target because the import code is not in the
    // current image)
    const ImportDescriptor *imp = cd.get_import_descriptor(); // is this an import?
    if (imp != NULL) {
      xrefs.emplace(from, imp->get_address());
    }
  }
  return xrefs;
}

FunctionDescriptor*
get_func_containing_address(rose_addr_t addr) {
  // JSG believes that this must be the entry VA or bad things happen
  // ... it's a guess at best
  SgAsmFunction* func = insn_get_func(global_descriptor_set->get_insn(addr));
  return global_descriptor_set->get_func(func->get_entry_va());
}

} // end namespace pharos
