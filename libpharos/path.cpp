// Copyright 2018-2024 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graph_utility.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/range/adaptors.hpp>
#include <boost/range/algorithm.hpp>
#include <boost/graph/iteration_macros.hpp>
#include <boost/graph/topological_sort.hpp>
#include <boost/graph/breadth_first_search.hpp>
#include <boost/graph/depth_first_search.hpp>

#include <Sawyer/GraphTraversal.h>

#include "path.hpp"
#include "misc.hpp"
#include "stkvar.hpp"

namespace pharos {

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// Beginning of PathFinder methods
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

bool
PathFinder::generate_cfg_constraints(CallTraceDescriptorPtr call_trace_desc) {

  if (!call_trace_desc) {
    GERROR << "Invalid call trace information" << LEND;
    return false;
  }

  const FunctionDescriptor& fd = call_trace_desc->get_function();
  const CFG &cfg = fd.get_pharos_cfg();

  auto ctx = z3_->z3Context();

  // process edges and save edge information for this call trace
  // element, which is an entire function

  CallTraceDescriptorPtr prev_call_trace_desc = call_trace_desc->get_caller();
  bool cfg_has_no_edges = boost::num_edges(cfg) == 0;

  if (prev_call_trace_desc && cfg_has_no_edges && boost::num_vertices(cfg) == 1) {

    // This function has no edges ... which is common for highly optimized code

    GWARN << "CFG for function " << addr_str(fd.get_address()) << " has no edges" << LEND;

    CfgEdgeInfo ei(*ctx);

    auto vp = boost::vertices(cfg);
    CfgVertex v = *vp.first;
    SgAsmBlock *vbb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, v));
    ei.edge_src_addr = vbb->get_address();
    ei.edge_tgt_addr = vbb->get_address();

    std::stringstream e_name, c_name;

    e_name << "edge_" << addr_str(vbb->get_address()) << ":" << call_trace_desc->get_index();
    c_name << "cond_" << addr_str(vbb->get_address()) << ":" << call_trace_desc->get_index();

    ei.edge_str = e_name.str();
    ei.cond_str = c_name.str();

    ei.edge_expr = ctx->bool_const(ei.edge_str.c_str());
    ei.cond_expr = ctx->bool_const(ei.cond_str.c_str());

    ei.call_trace_desc = call_trace_desc;

    call_trace_desc->add_edge_info(ei);

  }
  else {

    BGL_FORALL_EDGES(edge, cfg, CFG) {

      CfgEdgeInfo ei(*ctx);

      ei.edge = edge;

      SgAsmBlock *sb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, boost::source(edge, cfg)));
      ei.edge_src_addr = sb->get_address();

      SgAsmBlock *tb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, boost::target(edge, cfg)));
      ei.edge_tgt_addr = tb->get_address();

      std::stringstream e_name, c_name;
      e_name << edge_name(edge, cfg) << ":" << call_trace_desc->get_index();
      ei.edge_str = e_name.str();

      c_name << edge_cond(edge, cfg) << ":" << call_trace_desc->get_index();
      ei.cond_str = c_name.str();

      ei.edge_expr = ctx->bool_const(ei.edge_str.c_str());
      ei.cond_expr = ctx->bool_const(ei.cond_str.c_str());

      // brittle, but effective
      ei.call_trace_desc = call_trace_desc;

      call_trace_desc->add_edge_info(ei);
    }
  }
  // fill in predecessors
  CfgEdgeInfoMap edge_info_map = call_trace_desc->get_edge_info_map();

  for (auto& eipair : edge_info_map) {

    CfgEdge edge = eipair.first;
    CfgEdgeInfo ei = eipair.second;

    CfgEdgeInfoVector predecessors;

    if (!cfg_has_no_edges) {

      // If there are edges in this CFG then collect the predecessors

      CfgVertex src_vtx = boost::source(edge, cfg);

      BGL_FORALL_INEDGES(src_vtx, in_edge, cfg, CFG) {

        auto eiter = edge_info_map.find(in_edge);
        if (eiter != edge_info_map.end()) {
          CfgEdgeInfo in_info = eiter->second;
          predecessors.push_back(std::move(in_info));
        }
      }
    }

    // In edges are not enough, we also need to count callers among
    // the predecessors for the function entry point (which may be called)

    if (prev_call_trace_desc && ei.edge_src_addr == fd.get_address()) {
      rose_addr_t call_addr = call_trace_desc->get_call()->get_address();
      P2::BasicBlockPtr caller_bb = ds_.get_block(call_addr);
      rose_addr_t caller_bb_addr = caller_bb->address();

      boost::optional<CfgEdgeInfo> prev_ei = prev_call_trace_desc->get_edge_info(caller_bb_addr);
      if (prev_ei) {
        predecessors.push_back(std::move(*prev_ei));
      }
    }

    z3::expr cfg_cond(*ctx);
    if (predecessors.size() > 1) {
      z3::expr_vector pred_exprs(*ctx);
      for (auto prev : predecessors) {
        pred_exprs.push_back(prev.edge_expr);
      }
      cfg_cond = z3::expr(ei.edge_expr == (ei.cond_expr && z3_->mk_or(pred_exprs)));
    }
    // single incoming edge
    else if (predecessors.size() == 1) {
      z3::expr in_expr = z3::expr(predecessors.at(0).edge_expr);

      cfg_cond = z3::expr(ei.edge_expr == (ei.cond_expr && in_expr));

    }
    else {
      // no incoming edge, this must be an entry point. There must be
      // a check to determine if this is the genuine entry point or
      // the entry of a called function

      // This should really only be true in the case of the genuine
      // entry point or something not in the control flow

      cfg_cond = z3::expr(ei.edge_expr == ei.cond_expr);
    }

    call_trace_desc->add_cfg_condition(cfg_cond);
  }

  // Special case where the entire function is a single basic
  // block. This will always be executed (obviously)
  if ((boost::num_vertices(cfg) == 1) && (edge_info_map.size() == 0)) {
    return true;
  }

  return (call_trace_desc->get_cfg_conditions().size() > 0);
}

// Edge conditions are the conditions that impact decisions in the
// code. In this version the conditions are based on the state of
// decisions nodes (ITEs).
bool
PathFinder::generate_edge_conditions(CallTraceDescriptorPtr call_trace_desc,
                                     CfgEdgeExprMap& edge_conditions) {

  if (!call_trace_desc) {
    GERROR << "Invalid call trace information" << LEND;
    return false;
  }

  const FunctionDescriptor& func = call_trace_desc->get_function();
  const CFG &cfg = func.get_pharos_cfg();

  auto ctx = z3_->z3Context();

  BGL_FORALL_EDGES(edge, cfg, CFG)  {

    CfgVertex src_vtx = boost::source(edge, cfg);
    SgAsmBlock *src_bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, src_vtx));

    CfgVertex tgt_vtx = boost::target(edge, cfg);
    SgAsmBlock *tgt_bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, tgt_vtx));

    // We need to use the EIP conditons for *this* call frame,
    // not the values in Pharos, which are not indexed
    CfgEdgeValueMap eip_val_map = call_trace_desc->get_edge_values();
    auto edge_cond_iter = std::find_if(eip_val_map.begin(), eip_val_map.end(),
                                       [&edge](const std::pair<CfgEdge,SymbolicValuePtr>& vpair) {
                                         return edge == vpair.first;
                                       });

    if (edge_cond_iter == eip_val_map.end()) {
      GWARN << "Could not find symbolic condition for edge: " << edge_str(edge, cfg) << LEND;
      continue;
    }

    SymbolicValuePtr src_eip_sv = edge_cond_iter->second;
    TreeNodePtr src_eip_tnp = src_eip_sv->get_expression();

    GDEBUG << "\nThe Edge "
           << addr_str(src_bb->get_address())
           << "-" << addr_str(tgt_bb->get_address()) << LEND;

    // If the treenode associated with EIP is an ITE, then it is
    // a decision. The decision part is what we care
    // about. Specifically, the EIP register will contain the
    // branch condition. This condition will be exported to Z3
    // for both the true and false edges

    const InternalNodePtr in = src_eip_tnp->isInteriorNode();
    if (in && in->getOperator() == Rose::BinaryAnalysis::SymbolicExpression::OP_ITE) {

      const TreeNodePtrVector& branches = in->children();
      TreeNodePtr condition_tnp = branches[0];
      rose_addr_t true_address = address_from_node(branches[1]->isLeafNode());
      rose_addr_t false_address = address_from_node(branches[2]->isLeafNode());

      try {

        z3::expr condition_expr = z3_->treenode_to_z3(condition_tnp).simplify();

        if (true_address == tgt_bb->get_address()) {
          edge_conditions.emplace(std::make_pair(edge, condition_expr));
        }
        else if (false_address == tgt_bb->get_address()) {
          z3::expr not_condition_expr(*ctx);
          if (condition_expr.is_bool() == false) {
            condition_expr = z3_->to_bool(condition_expr);
          }
          not_condition_expr = (!condition_expr).simplify();

          edge_conditions.emplace(std::make_pair(edge, not_condition_expr));
        }
      }
      catch(z3::exception &z3x) {
        GERROR << "generate_edge_conditions: Z3 Exception caught: " << z3x << LEND;
        return false;
      }
    }

    // Not an ITE, so that means it will be an expression. If it
    // is a constant expression then it is the address of the
    // next instruction. If the next instructon from here is not
    // the target, then this edge is not taken or the block
    // terminates in a function call. If the block ends in a
    // call, then we cannot declare the edge dead.

    else if (src_eip_tnp->isIntegerConstant()) {
      if (!insn_is_call(last_x86insn_in_block(src_bb))) {
        rose_addr_t next_addr = static_cast<rose_addr_t>(*src_eip_tnp->toUnsigned());

        // If the next address is the entry to a known function,
        // then it is probably not an taken edge that is never
        // taken, or at least we cannot tell. Conversely, if it is
        // not a known function and the next address is not the
        // target, then Pharos has figured out the edge is not taken.

        if (next_addr != tgt_bb->get_address()) {
          edge_conditions.emplace(std::make_pair(edge, ctx->bool_val(false)));
        }
      }
    }

    // If this edge is the entry of the function, then it will be true
    // because it can always be entered.
    if (func.get_func()->get_entryVa() == src_bb->get_address()) {
      edge_conditions.emplace(std::make_pair(edge, ctx->bool_val(true)));
    }
  }

  // Distribute the edge conditions throughout the CFG for consistent
  // reasoning
  propagate_edge_conditions(call_trace_desc, edge_conditions);

  return true;
}

void
PathFinder::generate_chc() {

  std::vector<z3::func_decl> relations;
  Z3FixedpointPtr fp = std::make_unique<z3::fixedpoint>(*z3_->z3Context());

  /// For each call trace
  BGL_FORALL_VERTICES(v, call_trace_, CallTraceGraph) {

    CallTraceDescriptorPtr trx = boost::get(boost::vertex_calltrace, call_trace_, v);

    auto existing_constraints = trx->get_edge_constraints();

    boost::for_each(existing_constraints,
                    [this, trx, &fp] (const auto &x) {

                      z3::context& ctx = *z3_->z3Context();
                      CfgEdge cfg_edge = x.first;
                      z3::expr cond_expr = x.second;

                      CfgEdgeInfoMap edge_info_map = trx->get_edge_info_map();
                      auto eit = edge_info_map.find(cfg_edge);
                      if (eit != edge_info_map.end()) {
                        CfgEdgeInfo ei = eit->second;
                        std::string edge_name = ei.edge_str;
                        z3::sort cond_sort = cond_expr.get_sort();

                        z3::func_decl rel = z3::function(edge_name.c_str(),
                                                         cond_sort,
                                                         ctx.bool_sort());
                        fp->register_relation(rel);
                      }
                    });
  }

  OINFO << "FP: " << *fp << LEND;

}

bool
PathFinder::generate_edge_constraints(CallTraceDescriptorPtr call_trace_desc) {

  CfgEdgeExprMap edge_conditions;

  // Before assembling the proper edge constraint we must examine each
  // choice to figure out the condtions for the constraint. After this
  // call, the edge_conditions contain the EIP conditions

  if (false == generate_edge_conditions(call_trace_desc, edge_conditions)) {
    return false;
  }

  // Compute and add the edge information. There is probably a
  // more efficient way to do this, but doing it here, separately
  // makes consolidating edge conditions easier.

  for (auto& edge_cond : edge_conditions) {

    CfgEdge edge = edge_cond.first;
    CfgEdgeInfoMap edge_info_map = call_trace_desc->get_edge_info_map();

    auto eni = edge_info_map.find(edge);

    if (eni == edge_info_map.end()) continue;

    CfgEdgeInfo new_edge_info = eni->second;

    z3::expr tnp_cond_expr = edge_cond.second;
    if (tnp_cond_expr.is_bool() == false) {
      tnp_cond_expr = z3_->to_bool(tnp_cond_expr);
    }

    z3::expr edge_constraint_expr = z3::expr(new_edge_info.cond_expr == tnp_cond_expr);

    // Don't add duplicate constraints
    auto skip_it = std::find_if(edge_conditions.begin(), edge_conditions.end(),
                                [edge_constraint_expr] ( const auto& cond_pair) {
                                  z3::expr expression = cond_pair.second;
                                  return z3::eq(expression, edge_constraint_expr);
                                });
    if (skip_it == edge_conditions.end()) {
      call_trace_desc->add_edge_constraint(edge, edge_constraint_expr);
    }
  }
  return true;
} // end generate edge constraints


// Path constraints are global across all call trace elements; thus
// they live in the PathFinder. Additionally, there is only one goal
// and one start. The goal may be disjoined to include multiple
// edges
bool
PathFinder::generate_path_constraints(z3::expr& start_constraint,
                                      z3::expr& goal_constraint) {

  // Now assert the edges that we must reach to achieve a goal. This
  // is one way to force a particular path. Notably, the start/goal
  // addresses need to be lifted to the BB address to conform with the
  // CFG

  bool goal_set=true, start_set = true;

  P2::BasicBlockPtr start_bb = ds_.get_block(start_address_);
  rose_addr_t start_bb_addr = start_bb->address();

  P2::BasicBlockPtr goal_bb = ds_.get_block(goal_address_);
  rose_addr_t goal_bb_addr = goal_bb->address();

  auto ctx = z3_->z3Context();
  z3::expr_vector goal_edge_constraints(*ctx);
  z3::expr_vector start_edge_constraints(*ctx);

  // The goals and starts need to be evaluated over each call
  // trace. If there are multiple paths to a goal, then the goals will be disjoined
  BGL_FORALL_VERTICES(vtx, call_trace_, CallTraceGraph) {

    CallTraceDescriptorPtr call_trx = boost::get(boost::vertex_calltrace, call_trace_, vtx);

    for (auto pair : call_trx->get_edge_info_map()) {

      auto ei = pair.second;

      z3::expr edgex = z3::expr(ei.edge_expr == ctx->bool_val(true));

      // the start/goal belong to the same edge (source->target)
      if (ei.edge_tgt_addr == goal_bb_addr && ei.edge_src_addr == start_bb_addr) {
        goal_edge_constraints.push_back(edgex);
        start_edge_constraints.push_back(edgex);
        GDEBUG << "Possible Goal/Start Edge: " << edgex << LEND;
        break;
      }
      else {

        // The goal can either be the target or source. The target
        // part is obvious. The goal can be the source if the goal is
        // the first block in a function

        if ((ei.edge_tgt_addr == goal_bb_addr) || (ei.edge_src_addr == goal_bb_addr)) {
          GDEBUG << "Possible Goal Edge: " << edgex << LEND;
          goal_edge_constraints.push_back(edgex);
        }
        // The source cannot be a target
        if (ei.edge_src_addr == start_bb_addr) {
          GDEBUG << "Possible Start Edge: " << edgex << LEND;
          start_edge_constraints.push_back(edgex);
        }
      }
    }
  }

  // If there is more than one incoming edge to the target vertex,
  // then there can possibly be more than one viable path. The best
  // thing to do is form a disjunction among the incoming edges so
  // that any of them can be viable.

  if (goal_edge_constraints.size() > 1) {
    goal_constraint = z3_->mk_or(goal_edge_constraints);
  }
  else if (goal_edge_constraints.size() == 1) {
    goal_constraint = goal_edge_constraints[0];
  }
  else {
    goal_set=false;
    GWARN << "No goal edge constraints to assert!" << LEND;
  }

  // because there can be TWO+ paths flowing into a goal, we need to
  // disjoin the possibilities could start have two incoming edges?
  // Not entirely sure, but the approach is the same

  if (start_edge_constraints.size() > 1) {
    start_constraint = z3_->mk_or(start_edge_constraints);
  }
  else if (start_edge_constraints.size() == 1) {
    start_constraint = start_edge_constraints[0];
  }
  else {
    start_set=false;
    GWARN << "No start edge constraints to assert!" << LEND;
  }

  return start_set && goal_set;
}

// edge condition propagation means carrying forward the conditions to
// take a given edge
void
PathFinder::propagate_edge_conditions(CallTraceDescriptorPtr call_trace_desc, CfgEdgeExprMap& edge_conditions) {

  const FunctionDescriptor& func = call_trace_desc->get_function();
  const CFG& cfg = func.get_pharos_cfg();

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

// add all the constraints and solve
bool
PathFinder::evaluate_path() {

  z3::solver* solver = z3_->z3Solver();

  try {
    GDEBUG << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-\n"
           << "Final representation:"
           <<  "\n---\n" << *solver << "\n---" << LEND;

    switch (solver->check()) {

     case z3::unsat:
      GINFO << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-\n"
            << "Sat check: is NOT valid, there is no path from "
            << addr_str(start_address_) << " to " << addr_str(goal_address_)
            << "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-" << LEND;

      // Without a path, there is no solution
      path_found_ = false;
      break;

     case z3::sat:
      GINFO << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-\n"
            << "Sat check: IS valid, there is a path from "
            << addr_str(start_address_) << " to " << addr_str(goal_address_)
            << "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-" << LEND;

      // A path was found, given the constraints
      path_found_ = true;
      break;

     case z3::unknown:
      GINFO << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-\n"
            << "Sat check: is UNKOWN???\n"
            << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-" << LEND;
    }
  }
  catch (z3::exception &z3x) {
    GERROR << "evaluate: Z3 Exception caught: " << z3x << LEND;
    path_found_ = false;
  }

  // print out some statistics about how many resources the solver
  // used. This is mostly for informational/debugging purposes
  //
  // z3_->report_statistics(OINFO);

  return path_found_;
}

// Generate the path for the main call_trace. Assumes a model exists
// There is a strange symmetry to this analysis. All the contraints
// must be loaded into Z3, analyzed as one, and then re-assigned to
// call_traces as a traversal
bool
PathFinder::analyze_path_solution() {

  try {

    // Time to analyze the model - This means saving the edges taken
    // and values used. Doing this in three distinct loops keeps
    // things linear

    z3::model model = z3_->z3Solver()->get_model();

    // This map will hold the values that are assigned to the
    ExprMap modelz3vals;

    GDEBUG << "Solution:\n" << model << "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-" << LEND;

    for (unsigned i = 0; i<model.size(); i++) {
      z3::func_decl element = model[i];
      std::string element_name = element.name().str();

      if (element.is_const()) {
        z3::expr element_val = model.get_const_interp(element);
        modelz3vals.insert(std::pair<std::string, z3::expr>(element_name, element_val));

        GDEBUG << "Inserting element: " << element_name << " value: " << element_val << LEND;
      }
    }

    // Create the taken path
    std::vector<rose_addr_t> called_funcs;
    BGL_FORALL_VERTICES(vtx, call_trace_, CallTraceGraph) {
      PathPtr path_taken = std::make_shared<Path>();
      path_taken->call_trace_desc = boost::get(boost::vertex_calltrace, call_trace_, vtx);

      const FunctionDescriptor& ctd_func = path_taken->call_trace_desc->get_function();
      const CFG &cfg = ctd_func.get_pharos_cfg();

      // add the edges to the traversal

      for (auto pair : path_taken->call_trace_desc->get_edge_info_map()) {

        CfgEdgeInfo ei = pair.second;

        auto evi = modelz3vals.find(ei.edge_str);
        if (evi != modelz3vals.end()) {
          z3::expr val = evi->second;
          if (val.bool_value() == Z3_L_TRUE) {
            path_taken->traversal.push_back(std::move(ei));

            if (boost::num_edges(cfg)>0) {
              // This edge is taken, does it end in a call
              SgAsmBlock *source_bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, boost::source(ei.edge, cfg)));
              const SgAsmX86Instruction* last_insn = last_x86insn_in_block(source_bb);
              if (insn_is_call(last_insn)) {
                called_funcs.push_back(last_insn->get_address());
              }

              SgAsmBlock *target_bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, boost::target(ei.edge, cfg)));
              if (target_bb->get_address() == goal_address_) {
                // Once the target is found there is no need to continue processing a path. Indeed some
                break;
              }
            }
          }
        }
      }

      // If the taken path is not empty *or* the function is actually
      // called (some function CFGs are a single BB and have no edges)
      if (!path_taken->traversal.empty() ||
          std::find(called_funcs.begin(), called_funcs.end(),
                    path_taken->call_trace_desc->get_call()->get_address())!=called_funcs.end()) {
        // Now select actual program values from the traversal
        assign_traversal_values(path_taken, modelz3vals);
        path_.push_back(path_taken);
      }
    }
  }
  catch (z3::exception &z3x) {
    GERROR << "analyze_path_solution: Z3 Exception caught: " << z3x << LEND;
    return false;
  }
  return true;
}

// The root of the execution trace will have a null call descriptor
// because it has no callers.
CallTraceDescriptorPtr
PathFinder::create_call_trace_element(CallTraceGraphVertex caller_vtx,
                                      const FunctionDescriptor *fd,
                                      const CallDescriptor* cd,
                                      CallFrameManager& valmgr) {
  if (!fd) {
    return nullptr;
  }
  OINFO << "*** Creating call trace descriptor for "
        << addr_str(fd->get_address()) << ":" << frame_index_ << LEND;

  auto ctx = z3_->z3Context();
  CallTraceDescriptorPtr call_trace_desc
    = std::make_shared<CallTraceDescriptor>(*fd, cd, frame_index_, *ctx);

  if (!call_trace_desc) {
    return nullptr;
  }

  // According to CFC the algorithm should be to "clone" the function
  // parameters and then substitute back to the call parameters

  call_trace_desc->create_frame(valmgr);

  frame_index_++;

  CallTraceDescriptorPtr prev_call_trace_desc = nullptr;
  if (caller_vtx != NULL_CTG_VERTEX) {
    prev_call_trace_desc = boost::get(boost::vertex_calltrace, call_trace_, caller_vtx);
  }
  call_trace_desc->set_caller(prev_call_trace_desc);

  // Step 1 is to generate the structures that will encode the CFG as
  // a set of constraints
  if (false == generate_cfg_constraints(call_trace_desc)) {
    GWARN << "Failed to generate CFG constraints for function: "
          << addr_str(fd->get_address()) << LEND;
  }

  // Step 2 is to generate the conditions necessary to take each CFG
  // edge
  if (false == generate_edge_constraints(call_trace_desc)) {
    GWARN << "Failed to generate edge constraints for function: "
          << addr_str(fd->get_address()) << LEND;
  }
  return call_trace_desc;
}

void
PathFinder::generate_call_trace(CallTraceGraphVertex src_vtx,
                                const FunctionDescriptor* fd,
                                const CallDescriptor* cd,
                                std::vector<rose_addr_t>& trace_stack) {

  // base case: no where else to go
  if (fd == nullptr) {
    return;
  }

  // Attempt to avoid infinite recursion and loops by checking for cycles
  auto trace_iter = std::find_if(trace_stack.begin(),
                                 trace_stack.end(),
                                 [fd](const rose_addr_t trace_addr) {
                                   return trace_addr == fd->get_address();
                                 });

  if (trace_iter != trace_stack.end()) {
    return;
  }

  // first time in this function, push it on the stack
  trace_stack.push_back(fd->get_address());

  // declared here to preserve state down the call chain
  static CallFrameManager valmgr;

  // Create the new call trace element
  CallTraceDescriptorPtr new_trx = create_call_trace_element(src_vtx, fd, cd, valmgr);
  if (new_trx == nullptr) {
    GERROR << "Could not create root call trace descriptor!" << LEND;
    return;
  }

  // and connect it to the graph
  CallTraceGraphVertex new_vtx = boost::add_vertex(call_trace_);
  boost::put(boost::vertex_calltrace, call_trace_, new_vtx, new_trx);

  if (src_vtx != NULL_CTG_VERTEX) {
    boost::add_edge(src_vtx, new_vtx, call_trace_);
  }

  // Now recurse in to all the outgoing calls.

  for (auto out_cd : fd->get_outgoing_calls()) {

    // imports do not have function desc
    if (!out_cd || out_cd->get_import_descriptor()) {
      continue;
    }

    // the next element will be called from this vertex
    generate_call_trace(new_vtx, out_cd->get_function_descriptor(), out_cd, trace_stack);

  }

  valmgr.pop(new_trx->get_index());
  trace_stack.pop_back();
}

bool
PathFinder::generate_value_constraints() {

  // This doesn'path_taken need to be done in a DFS, but hey, why not
  struct GenValVis : public boost::default_dfs_visitor {
    PathFinder* path_finder;
    GenValVis(PathFinder* pf) : path_finder(pf) { }
    void tree_edge(CallTraceGraphEdge e, const CallTraceGraph& g) {

      CallTraceGraphVertex caller_vtx = boost::source(e, g);
      CallTraceGraphVertex called_vtx = boost::target(e, g);

      CallTraceDescriptorPtr called_info = boost::get(boost::vertex_calltrace, g, called_vtx);
      CallTraceDescriptorPtr caller_info = boost::get(boost::vertex_calltrace, g, caller_vtx);

      if (!called_info || !caller_info) {
        GERROR << "Could not find call trace descriptor for call" << LEND;
        return;
      }

      const CallDescriptor* called_from = called_info->get_call();
      P2::BasicBlockPtr caller_bb = called_from->ds.get_block(called_from->get_address());

      GDEBUG << "Looking for edge: " << addr_str(caller_bb->address())
             << " index " <<  caller_info->get_index() << LEND;

      boost::optional<CfgEdgeInfo> caller_edge_info = caller_info->get_edge_info(caller_bb->address());

      if (!caller_edge_info) {
        GWARN << "Could not find edge information for call at BB: "
              << addr_str(caller_bb->address()) << LEND;
        return;
      }

      const ParamVector& callee_params = called_info->get_parameters();
      const ParamVector& caller_params = called_info->get_called_from_parameters();

      ParamVector::const_iterator callee_iter = callee_params.begin();
      ParamVector::const_iterator caller_iter = caller_params.begin();

      while (caller_iter!=caller_params.end() && callee_iter!=callee_params.end()) {

        const ParameterDefinition &caller_param = *caller_iter;
        if (caller_param.get_value()) {

          // Now map caller to callee parameters
          const ParameterDefinition &callee_param = *callee_iter;
          if (callee_param.get_value()) {

            if (caller_param.get_num() == callee_param.get_num()) {

              TreeNodePtr caller_tnp = caller_param.get_value()->get_expression();
              TreeNodePtr callee_tnp = callee_param.get_value()->get_expression();

              if (caller_tnp && callee_tnp) {

                z3::expr par_caller_expr = path_finder->z3_->treenode_to_z3(caller_tnp);
                z3::expr par_callee_expr = path_finder->z3_->treenode_to_z3(callee_tnp);

                if (caller_tnp->nBits() != callee_tnp->nBits()) {

                  GWARN << addr_str(caller_bb->address()) << ": Caller/Callee parmater sizes differ: caller_tnp: '"
                        << *caller_tnp << "', callee_tnp: " << *callee_tnp << "' - skipping constraint" << LEND;
                }
                else {
                  z3::expr parval_expr = z3::implies(caller_edge_info->edge_expr, par_caller_expr == par_callee_expr);
                  // don't add duplicate value constraints per call_trace

                  z3::expr_vector called_value_constraints = called_info->get_value_constraints();


                  // Don't add duplicate constraints. Because this is
                  // a z3::expr_vector is funny, this check is done
                  // the old fashioned way

                  bool skip_constraint = false;
                  for (unsigned i=0; i<called_value_constraints.size(); i++) {
                    if (z3::eq(called_value_constraints[i], parval_expr)) {
                      skip_constraint=true;
                      break;
                    }
                  }
                  if (!skip_constraint) {
                    called_info->add_value_constraint(parval_expr);

                    GDEBUG << "Added paramater constraint for call to "
                           << addr_str(called_info->get_function().get_address())
                           << ", Edge: " << caller_edge_info->edge_str
                           << ", caller param expr: " << par_caller_expr
                           << ", callee param expr: " << par_callee_expr
                           << ", Constraint: " << parval_expr
                           << LEND;
                  }
                }
              }
            }
          }
        }
        caller_iter++;
        callee_iter++;
      }

      // Handle return values
      RegisterDescriptor eax_reg = called_from->ds.get_arch_reg("eax");
      const ParamVector& caller_rets = called_info->get_called_from_return_values();
      const ParamVector& callee_rets = called_info->get_return_values();

      // There is only one "return" value so to speak, whatever is in EAX

      auto RvLambda = [eax_reg](ParameterDefinition const & rv) {
        return rv.get_register() == eax_reg; };
      auto clr_iter = std::find_if(caller_rets.begin(), caller_rets.end(), RvLambda);
      auto cle_iter = std::find_if(callee_rets.begin(), callee_rets.end(), RvLambda);

      if (clr_iter!=caller_rets.end() && cle_iter!=callee_rets.end()) {

        if (clr_iter->get_value() && cle_iter->get_value()) {

          TreeNodePtr clr_tnp = clr_iter->get_value()->get_expression();
          TreeNodePtr cle_tnp = cle_iter->get_value()->get_expression();

          if (clr_tnp && cle_tnp) {

            z3::expr ret_caller_expr = path_finder->z3_->treenode_to_z3(clr_tnp);
            z3::expr ret_callee_expr = path_finder->z3_->treenode_to_z3(cle_tnp);

            z3::expr retval_expr = z3::implies(caller_edge_info->edge_expr, ret_caller_expr == ret_callee_expr);

            GDEBUG << "Added return value constraint for call to " << addr_str(called_info->get_function().get_address())
                   << ", Edge: " << caller_edge_info->edge_str
                   << ", caller return expr: " << ret_caller_expr
                   << ", callee return expr: " << ret_callee_expr
                   << ", Constraint expr: " << retval_expr
                   << LEND;

            called_info->add_value_constraint(retval_expr);
          }
        }
      }
    }
  };

  GenValVis gv_vis(this);

  // Running a DFS ensures everything is linked appropriately
  std::vector<boost::default_color_type> colors(boost::num_vertices(call_trace_));

  boost::depth_first_search(call_trace_, gv_vis,
                            boost::make_iterator_property_map(colors.begin(), boost::get(boost::vertex_index, call_trace_)));

  return true;
}

// Actually map the model values to pharos data structures (parameters
// and variables)
void
PathFinder::assign_traversal_values(PathPtr trv, ExprMap& modelz3vals) {

  // to avoid huge names for variable sets
  using namespace Rose::BinaryAnalysis;

  if (!trv->call_trace_desc) {
    GERROR << "Invalid call trace element" << LEND;
    return;
  }

  const FunctionDescriptor& func = trv->call_trace_desc->get_function();
  GDEBUG << "*** Assigning data values to call trace for " << addr_str(func.get_address()) << LEND;

  // SymbolicExpr::Formatter fmt;
  // fmt.show_width = false;

  // Start with incoming parameters vars ...  Try to find the concrete
  // stack variables by first directly querying the model (for
  // variables) and then by filling in component values from the model
  const ParamVector& params = trv->call_trace_desc->get_parameters();

  for (ParameterDefinition const & param : params) {
    TreeNodePtr param_tnp = param.get_value()->get_expression();

    if (!param_tnp) continue;

    GDEBUG << "Evaluating param: " << *param_tnp <<  LEND;
    TreeNodePtr pt = evaluate_model_value(param_tnp, modelz3vals);

    if (pt && pt->isIntegerConstant()) {
      GDEBUG << "Returned parameter treenode : " << *pt << LEND;

      uint64_t raw_val = *pt->toUnsigned();
      trv->required_param_values.emplace_back(param, raw_val);
    }
  }

  // The return value is the value of EAX for x86. The caller
  // perspective is evaluated to get the value actually returned, not
  // the computation of the input parameter
  const ParamVector& rets = trv->call_trace_desc->get_called_from_return_values();
  if (rets.size() > 0) {
    ParameterDefinition const & ret = rets.at(0);
    TreeNodePtr ret_tnp = ret.get_value()->get_expression();

    if (ret_tnp) {

      GDEBUG << "Evaluating return value: " << *ret_tnp
             << ", search term: " << *ret_tnp << LEND;

      TreeNodePtr rt = evaluate_model_value(ret_tnp, modelz3vals);
      if (rt && rt->isIntegerConstant()) {
        uint64_t raw_val = *rt->toUnsigned();
        trv->required_ret_values.emplace_back(ret, raw_val);
      }
    }
  }

  const std::vector<StackVariable>& stack_vars = trv->call_trace_desc->get_stack_variables();
  for (auto stkvar : stack_vars) {

    TreeNodePtr stkvar_addr_tnp = stkvar.get_memory_address()->get_expression();

    // Must look through value(s) to see if it uses the variables of
    // interest.

    for (auto stkvar_val_sv : stkvar.get_values()) {

      if (!stkvar_val_sv) continue;

      TreeNodePtr stkvar_val_tnp = stkvar_val_sv->get_expression();
      if (!stkvar_val_tnp) continue;

      GDEBUG << "Evaluating stack variable: " << *stkvar_val_tnp
             << ", search term: " << *stkvar_val_tnp << LEND;

      // The tricky part is that there can be multiple values per
      // variable depending on how they are set
      TreeNodePtr st = evaluate_model_value(stkvar_val_tnp, modelz3vals);
      if (st && st->isIntegerConstant()) {
        uint64_t raw_val = *st->toUnsigned();
        trv->required_stkvar_values.push_back(ConcreteStackVariable(stkvar, raw_val));
      }
    }
  }
}

TreeNodePtr
PathFinder::evaluate_model_value(TreeNodePtr tn, const ExprMap& modelz3vals) {
  using namespace Rose::BinaryAnalysis;

  auto leaves = tn->getVariables();
  SymbolicExpr::ExprExprHashMap leaf_map;

  for (auto leaf : leaves) {

    GDEBUG << "evaluate_model_value leaf value: " << *leaf << LEND;

    std::stringstream leaf_comment;
    leaf_comment << *leaf;

    auto leaf_iter = modelz3vals.find(leaf->toString().c_str());
    if (leaf_iter != modelz3vals.end()) {
      uint64_t leaf_val = leaf_iter->second.get_numeral_uint64();
      auto leaf_tnp = SymbolicExpr::makeIntegerConstant(
        leaf->nBits(), leaf_val, leaf_comment.str());
      leaf_map.emplace(leaf, leaf_tnp);
    }
  }
  if (leaf_map.size() > 0) {
    // simplify values as needed
    return tn->substituteMultiple(leaf_map);
  }
  return TreeNodePtr();
}


PathFinder::PathFinder(const DescriptorSet& ds, PharosZ3Solver & solver)
  : ds_(ds),
    z3_(&solver, SolverDeleter{false})
{}

PathFinder::PathFinder(const DescriptorSet& ds)
  : ds_(ds),
    z3_(new PharosZ3Solver, SolverDeleter{})
{}


PathFinder::~PathFinder() {
  // this is probably overkill
  z3::solver* solver = z3_->z3Solver();
  solver->reset();
}


PathPtrList
PathFinder::get_path() const {
  return path_;
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
    GERROR << "Invalid goal address!" << LEND;
    return false;
  }

  if (start_addr == INVALID_ADDRESS) {
    GERROR << "Invalid start address!" << LEND;
    return false;
  }

  try {
    setup_path_problem(start_addr, goal_addr);
  } catch (FindPathError const & e) {
    GERROR << e.what() << LEND;
    return false;
  } catch (z3::exception const & x3x) {
    GERROR << "evaluate: Z3 Exception caught: " << x3x << LEND;
    path_found_ = false;
    return false;
  }

  if (true == evaluate_path()) {
    if (true == analyze_path_solution()) {
      GDEBUG << "Path found and analyzed" << LEND;
    }
  }
  else {
    GDEBUG << "Failed to generate solution" << LEND;
  }

  if (save_z3_output_) {
    std::stringstream ss;
    output_problem(ss);
    z3_output_.push_back(ss.str());
  }
  return path_found_;
}

void
PathFinder::print_call_trace() {

  struct FrameVis : public boost::default_bfs_visitor {
    CallFrameManager valmgr;
    unsigned cur_index;

    FrameVis() : cur_index(INVALID_INDEX) { }

    void tree_edge(CallTraceGraphEdge e, const CallTraceGraph& g) {

      CallTraceGraphVertex caller_vtx = boost::source(e, g);
      CallTraceGraphVertex called_vtx = boost::target(e, g);

      CallTraceDescriptorPtr caller_info = boost::get(boost::vertex_calltrace, g, caller_vtx);
      CallTraceDescriptorPtr called_info = boost::get(boost::vertex_calltrace, g, called_vtx);

      GDEBUG << "Call Trace edge: " << addr_str(called_info->get_call()->get_address())
             << ":" << caller_info->get_index()
             << " => " << addr_str(called_info->get_function().get_address())
             << ":" << called_info->get_index() << LEND;
    }
  };

  FrameVis cv;
  CallTraceGraphVertex v = boost::vertex(0, call_trace_);
  boost::breadth_first_search(call_trace_, v, boost::visitor(cv));
}

void
PathFinder::save_call_trace(std::ostream& o) {

  struct CallTraceVertexWriter {
    CallTraceGraph& ctg;
    CallTraceVertexWriter(CallTraceGraph& g) : ctg(g) { }
    void operator()(std::ostream &output, const CallTraceGraphVertex &v) {
      CallTraceDescriptorPtr call_trx = boost::get(boost::vertex_calltrace, ctg, v);
      output << "[label=\" " << addr_str(call_trx->get_function().get_address())
             << ":" << call_trx->get_index() << "\"]";
    }
  };
  struct CallTraceGraphWriter {
    void operator()(std::ostream &output) {
      output << "graph [nojustify=true,fontname=courier]\n";
      output << "node [shape=box, style=\"rounded,filled\",fontname=courier]\n";
    }
  };

  boost::write_graphviz(o, call_trace_,
                        CallTraceVertexWriter(call_trace_),
                        boost::default_writer(),
                        CallTraceGraphWriter());
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

// This routine builds a list of nodes reachable vertices from the
// start using a topological search (BFS).
bool
PathFinder::detect_recursion() {

  if (goal_address_ == INVALID_ADDRESS || start_address_ == INVALID_ADDRESS) {
    GERROR << "Invalid start/goal address!" << LEND;
    return false;
  }

  const FunctionDescriptor* start_fd = ds_.get_func_containing_address(start_address_);
  if (start_fd) {
    return false;
  }

  const FunctionDescriptor* goal_fd = ds_.get_func_containing_address(goal_address_);
  if (goal_fd) {
    return false;
  }

  // Both start and goal addresses are in functions within this
  // program. Now we need to figure out if there is a path from start
  // to goal functions. If there is then this is feasible.
  const FCG& fcg = ds_.get_function_call_graph();

  auto& g = fcg.graph();
  auto rootId = fcg.findFunction(start_fd->get_address())->id();

  namespace GA = Sawyer::Container::Algorithm;
  using Traversal = GA::DepthFirstForwardGraphTraversal<const FCG::Graph>;

  // Have we seen this vertex already?
  std::vector<bool> visited(g.nVertices(), false);
  // Is this vertex on the path we're currently evaluating?
  std::vector<bool> onPath(g.nVertices(), false);
  visited[rootId] = true;
  //  ASSERT_require(!onPath[rootId]);
  onPath[rootId] = true;
  auto flags = GA::TraversalEvent::ENTER_EDGE|GA::TraversalEvent::LEAVE_EDGE;
  for (Traversal t(g, g.findVertex(rootId), flags); t; ++t) {
    size_t targetId = t.edge()->target()->id();
    if (t.event() == GA::TraversalEvent::ENTER_EDGE) {
      // If the vertex is already on the path it must be a back edge
      // representing recursion.
      if (onPath[targetId]) return true;
      onPath[targetId] = true;
      if (visited[targetId]) {
        t.skipChildren();
      } else {
        visited[targetId] = true;
      }
    } else {
      //ASSERT_require(t.event() == LEAVE_EDGE);
      //ASSERT_require(onPath[targetId]);
      onPath[targetId] = false;
    }
  }

  return false;
}

void
PathFinder::setup_path_problem(rose_addr_t source, rose_addr_t target)
{
  // save the ultimate start/goal addresses
  start_address_ = source;
  goal_address_ = target;

  OINFO << "Start address is: " << addr_str(start_address_)
        << ", Goal address is: " << addr_str(goal_address_) << LEND;

  const FunctionDescriptor* start_fd = ds_.get_func_containing_address(start_address_);
  const FunctionDescriptor* goal_fd = ds_.get_func_containing_address(goal_address_);

  if (start_fd && goal_fd) {

    // if (detect_recursion()) {
    //   GWARN << "Recursion not yet handled!" << LEND;
    //   return false;
    // }

    std::vector<rose_addr_t> trace_stack;

    // JSG is trying to turn this into a graph problem. The first step
    // is to "unwind" the call relationships in to a trace.

    generate_call_trace(NULL_CTG_VERTEX, start_fd, nullptr, trace_stack);

    generate_chc();

  }
  else {
    throw FindPathError("Could not find valid functions for start and/or goal");
  }

  generate_value_constraints();

  auto ctx = z3_->z3Context();

  z3::expr start_constraint(*ctx);
  z3::expr goal_constraint(*ctx);

  if (!generate_path_constraints(start_constraint, goal_constraint)) {
    path_found_ = false;
    throw FindPathError("Could not establish start/goal!");
  }

  // Load all the conditions into
  z3::solver* solver = z3_->z3Solver();

  BGL_FORALL_VERTICES(vtx, call_trace_, CallTraceGraph) {

    calltrace_value_t trc_info = boost::get(boost::vertex_calltrace, call_trace_, vtx);

    z3::expr_vector cfg_conds = trc_info->get_cfg_conditions();
    for (unsigned c=0; c<cfg_conds.size(); c++) solver->add(cfg_conds[c]);

    auto edge_constraint = trc_info->get_edge_constraints();
    boost::for_each(edge_constraint | boost::adaptors::map_values,
                    [solver](z3::expr edge_expr) { solver->add(edge_expr); });

    // TODO Remove this if the above loop works
    // for (unsigned e=0; e<edge_constraint.size(); e++) solver->add(edge_constraint[e]);

    z3::expr_vector val_const = trc_info->get_value_constraints();
    for (unsigned v=0; v<val_const.size(); v++)  solver->add(val_const[v]);
  }

  solver->add(start_constraint);
  solver->add(goal_constraint);
}

z3::check_result PathFinder::solve_path_problem()
{
  return z3_->z3Solver()->check();
}

std::ostream &
PathFinder::output_problem(std::ostream & stream) const
{
  z3_->output_options(stream);
  stream << ";; --- Z3 Start\n"
         << *z3_->z3Solver()
         << ";; --- Z3 End\n"
         << "(check-sat)\n"
         << "(get-model)" << std::endl;
  return stream;
}

std::ostream &
PathFinder::output_solution(std::ostream & stream) const
{
  return stream << ";; PathFinder::output_solution not yet implemented" << std::endl;
}


// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// Beginning of CallTraceDescriptor methods
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

CallTraceDescriptorPtr
CallTraceDescriptor::get_caller() const {
  return prev_call_trace_desc_;
}

void
CallTraceDescriptor::set_caller(CallTraceDescriptorPtr c) {
  prev_call_trace_desc_ = c;
}

void
CallTraceDescriptor::create_frame(CallFrameManager& valmgr) {

  // Step 1: Clone the called function. This makes the values
  // connecting functions (parameters, returns, and stack variables unique)
  const ParameterList& parameters = function_descriptor_.get_parameters();
  for (auto & par : parameters.get_params()) {

    // By convention parameters need to be a certain size (32b on
    // x86). There is a quasi-bug where pharos does not follow this
    SymbolicValuePtr sv = par.get_value();
    if (!sv) {
      GERROR << "Parameter in function " << function_descriptor_.address_string()
             << " was NULL.  Unused function parameter?" << LEND;
      continue;
    }
    TreeNodePtr old_var = par.get_value()->get_expression();
    if (old_var->nBits() != CONVENTION_PARAMETER_SIZE) {
      auto conv_var = SymbolicExpr::makeIntegerVariable(
        CONVENTION_PARAMETER_SIZE, old_var->comment());
      SymbolicValuePtr conv_val = SymbolicValue::treenode_instance(conv_var);
      add_parameter(par, valmgr.create_frame_value(conv_val, index_));
    }
    else {
      add_parameter(par, valmgr.create_frame_value(par.get_value(), index_));
    }
  }
  for (auto & rv : parameters.get_returns()) {
    add_return_value(rv, valmgr.create_frame_value(rv.get_value(), index_));
  }

  for (auto& stkvar : function_descriptor_.get_stack_variables()) {
    StackVariable new_stkvar(stkvar->get_offset());
    for (auto u : stkvar->get_usages()) new_stkvar.add_usage(u);
    new_stkvar.set_memory_address(stkvar->get_memory_address());

    // Must look through value(s) to see if it uses the variables of
    // interest.
    for (SymbolicValuePtr val : stkvar->get_values()) {
      SymbolicValuePtr sub_sv = valmgr.create_frame_value(val, index_);
      if (sub_sv) {
        new_stkvar.add_value(sub_sv);
      }
    }
    add_stack_variable(new_stkvar);
  }

  // Step 2: substitute back the cloned parameters to the call

  if (call_descriptor_!=nullptr) {

    const ParameterList& caller_parameters = call_descriptor_->get_parameters();

    for (ParameterDefinition const & par : caller_parameters.get_params()) {
      SymbolicValuePtr sub_sv = valmgr.create_frame_value(par.get_value(), index_);
      add_called_from_parameter(par, sub_sv);
    }
    for (ParameterDefinition const & ret : caller_parameters.get_returns()) {
      SymbolicValuePtr sub_sv = valmgr.create_frame_value(ret.get_value(), index_);
      add_called_from_return_value(ret, sub_sv);
    }
  }

  // Step 3: substitute all the path controlling values (i.e. the
  // instruction pointer).

  const CFG &cfg = function_descriptor_.get_pharos_cfg();
  const PDG* pdg = function_descriptor_.get_pdg();
  const DUAnalysis& du = pdg->get_usedef();
  const BlockAnalysisMap& blocks = du.get_block_analysis();

  BGL_FORALL_EDGES(edge, cfg, CFG) {

    // the condition_tnp is on the EIP of the source
    CfgVertex src_vtx = boost::source(edge, cfg);
    SgAsmBlock *src_bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, src_vtx));

    BlockAnalysis src_analysis = blocks.at(src_bb->get_address());
    if (!src_analysis.output_state) {
      GERROR << "Cannot fetch output state for " << addr_str(src_bb->get_address()) << LEND;
      continue;
    }
    SymbolicRegisterStatePtr src_reg_state = src_analysis.output_state->get_register_state();

    if (!src_reg_state) {
      GERROR << "Could not get vertex " << addr_str(src_bb->get_address())
             << " register state" << LEND;
      continue;
    }

    RegisterDescriptor eiprd = function_descriptor_.ds.get_arch_reg("eip");
    SymbolicValuePtr vtx_eip_sv = src_reg_state->read_register(eiprd);
    SymbolicValuePtr sub_eip_sv = valmgr.create_frame_value(vtx_eip_sv, index_);

    if (sub_eip_sv) {
      edge_values_.emplace(edge, sub_eip_sv);
    }
    SymbolicValuePtr entry_sv = src_analysis.entry_condition;
    SymbolicValuePtr sub_entry_sv = valmgr.create_frame_value(entry_sv, index_);
    if (sub_entry_sv) {
      edge_values_.emplace(edge, sub_entry_sv);
    }
  }
}

const CfgEdgeValueMap&
CallTraceDescriptor::get_edge_values() { return edge_values_; }

const FunctionDescriptor&
CallTraceDescriptor::get_function() const { return function_descriptor_; }

const CallDescriptor*
CallTraceDescriptor::get_call() const { return call_descriptor_; }

const ParamVector&
CallTraceDescriptor::get_parameters() const { return parameters_; }

const std::vector<StackVariable>&
CallTraceDescriptor::get_stack_variables() const { return stkvars_; }

const ParamVector&
CallTraceDescriptor::get_return_values() const { return  return_values_; }

const ParamVector&
CallTraceDescriptor::get_called_from_parameters() const { return called_from_parameters_; }

const ParamVector&
CallTraceDescriptor::get_called_from_return_values() const { return called_from_return_values_; }

unsigned
CallTraceDescriptor::get_index() const { return index_; }

void
CallTraceDescriptor::add_stack_variable(StackVariable new_stkvar) { stkvars_.push_back(new_stkvar); }

void
CallTraceDescriptor::add_parameter(ParameterDefinition const & old_param,
                                   SymbolicValuePtr new_value)
{
  parameters_.push_back(old_param);
  parameters_.back().set_value(new_value);
}

void
CallTraceDescriptor::add_called_from_parameter(ParameterDefinition const & old_param,
                                               SymbolicValuePtr new_value)
{
  called_from_parameters_.push_back(old_param);
  called_from_parameters_.back().set_value(new_value);
}

void
CallTraceDescriptor::add_return_value(ParameterDefinition const & old_param,
                                      SymbolicValuePtr new_value)
{
  return_values_.push_back(old_param);
  return_values_.back().set_value(new_value);
}

void
CallTraceDescriptor::add_called_from_return_value(ParameterDefinition const & old_param,
                                                  SymbolicValuePtr new_value)
{
  called_from_return_values_.push_back(old_param);
  called_from_return_values_.back().set_value(new_value);
}

boost::optional<CfgEdgeInfo>
CallTraceDescriptor::get_edge_info(rose_addr_t addr) {

  auto edge_it = std::find_if(
    edge_info_.begin(), edge_info_.end(),
    [addr](auto entry) {
      CfgEdgeInfo edge_info = entry.second;
      return ((edge_info.edge_tgt_addr == addr) || (edge_info.edge_src_addr == addr));
    });

  // The edge information is a map keyed by edge (which is really just
  // a number).
  if (edge_it != edge_info_.end()) {
    return edge_it->second;
  }
  return boost::optional<CfgEdgeInfo>();
}

z3::expr_vector
CallTraceDescriptor::get_cfg_conditions() { return cfg_conditions_; }

void
CallTraceDescriptor::add_cfg_condition(z3::expr cond) { cfg_conditions_.push_back(cond); }

z3::expr_vector
CallTraceDescriptor::get_value_constraints() { return value_constraints_; }

void
CallTraceDescriptor::add_value_constraint(z3::expr vconst) { value_constraints_.push_back(vconst); }

const CfgEdgeExprMap&
CallTraceDescriptor::get_edge_constraints() { return edge_constraints_; }

void
CallTraceDescriptor::add_edge_constraint(CfgEdge edge, z3::expr constraint) {
  edge_constraints_.emplace(std::make_pair(edge, constraint));
}

CfgEdgeInfoMap
CallTraceDescriptor::get_edge_info_map() { return edge_info_; }

void
CallTraceDescriptor::add_edge_info(CfgEdgeInfo ei) { edge_info_.emplace(ei.edge, ei); }

// The index uniquely identifies this call trace element
bool
CallTraceDescriptor::operator==(const CallTraceDescriptor& other) {
  return index_ == other.index_;
}

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// Beginning of CallFrameManager methods
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

void CallFrameManager::print() {

  for(auto entry : frame_vars_) {

    TreeNodePtr k = entry.old_var;
    TreeNodePtr v = entry.new_var;
    unsigned i = entry.index;

    OINFO << "Frame value list [" << i << "]: " << *k << " => " << *v << LEND;
  }
}

TreeNodePtr
CallFrameManager::create_frame_tnp(const TreeNodePtr old_tnp, unsigned id) {

  // to avoid huge names for variable sets
  using namespace Rose::BinaryAnalysis;

  if (!old_tnp) {
    GERROR << "invalid treenode" << LEND;
    return  TreeNodePtr();
  }

  // must match all the variables, not just the top-level treenodes
  auto vars = old_tnp->getVariables();
  if (vars.size()==0) {
    GDEBUG << "No variables to substitute, preserving value. " << LEND;
    return old_tnp;
  }

  // Variables must be cloned everywhere (assuming they are globally
  // unique). To make this happen a map of old to new vars

  SymbolicExpr::ExprExprHashMap var_map;

  for (auto old_var : vars) {

    auto clone_iter = std::find_if(frame_vars_.begin(),
                                   frame_vars_.end(),
                                   [old_var](const CallFrameValue& val)
                                   { return val.old_var->isEquivalentTo(old_var); });

    if (clone_iter == frame_vars_.end()) {

      // Comments are meaningful labels now.
      std::string cmt = old_var->comment();
      if (cmt == "") {
        cmt = old_var->toString();
      }
      std::stringstream cmt_ss;
      cmt_ss << cmt << ":" << id;

      // this is a new variable, so clone it and save it
      auto new_var = SymbolicExpr::makeIntegerVariable(old_var->nBits(), cmt_ss.str());

      GDEBUG << "Replacing old var " << *old_var << " with new var " << *new_var << LEND;

      var_map.emplace(old_var, new_var);

      // Save the new cloned var
      frame_vars_.push_back(CallFrameValue(id, old_var, new_var));
    }
    else {
      // this is a known treenode var, so use the previously cloned
      // value

      GDEBUG << "Replacing old var " << *old_var
             << " with existing " << *clone_iter->new_var << LEND;

      var_map.emplace(old_var, clone_iter->new_var);
    }
  }

  // All the variables are cloned, now replace the tree node
  return old_tnp->substituteMultiple(var_map);
}

void
CallFrameManager::resetAll() {
  frame_vars_.clear();
}

// remove all values from the frame up to index
void
CallFrameManager::pop(unsigned index) {

  frame_vars_.erase(
    std::remove_if(frame_vars_.begin(), frame_vars_.end(),
                   [index](const CallFrameValue & val)
                   { return val.index == index; }),
    frame_vars_.end());
}

const CallFrameValueList&
CallFrameManager::get_clone_list() { return frame_vars_; }

TreeNodePtr
CallFrameManager::substitute_tnp(TreeNodePtr tnp, unsigned id) {

  using namespace Rose::BinaryAnalysis;

  auto vars = tnp->getVariables();

  SymbolicExpr::ExprExprHashMap var_map;
  for (auto old_var : vars) {
    auto sub_iter = std::find_if(frame_vars_.begin(), frame_vars_.end(),
                                 [old_var](const CallFrameValue& val) {
                                   return val.old_var->isEquivalentTo(old_var);
                                 });

    if (sub_iter != frame_vars_.end()) {
      var_map.emplace(old_var, sub_iter->new_var);
    }
    else {
      // Not found. a new value is needed
      TreeNodePtr new_var = create_frame_tnp(old_var, id);
      var_map.emplace(old_var, new_var);
    }
  }

  return tnp->substituteMultiple(var_map);
}

SymbolicValuePtr
CallFrameManager::create_frame_value(const SymbolicValuePtr value, unsigned id) {

  if (value) {

    TreeNodePtr tnp = value->get_expression();

    if (tnp) {

      TreeNodePtr new_tnp = substitute_tnp(tnp, id);

      GDEBUG << "Replacing old var " << *tnp << " with new var " << *new_tnp << LEND;

      return SymbolicValue::treenode_instance(new_tnp);
    }
  }
  GERROR << "Could not substitute frame symbolic value" << LEND;
  return SymbolicValuePtr();
}

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




} // end namespace pharos
