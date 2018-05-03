// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Jeff Gennari
// Date: 2015-06-22
// Version: 2.0

#include <rose.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graph_utility.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/graph/iteration_macros.hpp>
#include <boost/graph/copy.hpp>
#include <boost/algorithm/string.hpp>
#include <Sawyer/GraphBoost.h>

#include "pdg.hpp"
#include "misc.hpp"
#include "masm.hpp"
#include "defuse.hpp"
#include "sptrack.hpp"

#include "apigraph.hpp"

namespace pharos {

using namespace Sawyer::Message::Common;

// ********************************************************************************************
// * Utility Functions
// ********************************************************************************************


// Return the last instruction in a given basic block
SgAsmX86Instruction* GetLastBlkInsn(const SgAsmBlock *blk) {

  if (!blk) return NULL;


  const SgAsmStatementPtrList& ins_list = blk->get_statementList();
  if (ins_list.size() == 0) {
    return NULL;
  }
  return isSgAsmX86Instruction(isSgAsmInstruction(ins_list[ins_list.size() - 1]));
}

// Return the first instruction in a given basic block
SgAsmX86Instruction* GetFirstBlkInsn(const SgAsmBlock *blk) {

  const SgAsmStatementPtrList& ins_list = blk->get_statementList();
  if (ins_list.size() == 0) {
    return NULL;
  }
  return isSgAsmX86Instruction(isSgAsmInstruction(ins_list[0]));
}

// ********************************************************************************************
// * Start of ApiSearchState methods
// ********************************************************************************************


ApiSearchState::ApiSearchState() {
  ClearState();
}

void ApiSearchState::UpdateState() {

  progress++;

  // check to see if the signature has been full matched
  if (IsSearchComplete()) {
    throw SearchCompleteException();
  }

  start_api = goal_api;

  start_point = last_point;

  GDEBUG << "New segment start is " << start_api.name
         << " @ " << addr_str(start_point.block->get_address()) << LEND;

  goal_api = sig.api_calls[progress];

  last_point = NULL_WAYPOINT;

  GDEBUG << "New segment goal is " << goal_api.name << LEND;
}

bool ApiSearchState::IsSearchComplete() {

  return  (progress == sig.api_count);
}

void ApiSearchState::ClearState() {

  ResetState();

  sig.name.clear();
  results.clear();

  sig.api_calls.clear();
  sig.name.clear();
}

// completely reset the state of the search
void ApiSearchState::ResetState() {

  GDEBUG << "Purging all state" << LEND;

  search_tree.clear();
  deadends.clear();

  // free the parameter list
  for (ApiParamMatchPair & mpair : match_table) {
    ApiParamPtrList *plist = mpair.second;

    for (ApiParameter *p : *plist) {
      if (p) delete p;
      p = NULL;
    }

    if (plist) delete plist;
    plist = NULL;
  }

  match_table.clear();

  start_api.Clear();
  start_point.Reset();

  start_component = INVALID_ADDRESS;

  goal_api.Clear();
  last_point.Reset();

  progress = 0;
}

void ApiSearchState::ResetSearchState() {

  GDEBUG << "Purging search state" << LEND;

  search_tree.clear();
  deadends.clear();

  start_api.Clear();
  start_point.Reset();

  start_component = INVALID_ADDRESS;

  goal_api.Clear();
  last_point.Reset();

  progress = 0;
}

// revert the state of a search
void ApiSearchState::RevertState(ApiCfgVertex revert_vertex, ApiWaypointDescriptor &revert_point) {

  // This is a signature vertex
  if (revert_point.name == start_api.name) {
    goal_api = start_api;
    progress--;
    if (progress > 0) {
      start_api = sig.api_calls[progress-1];
    }
    else {
      start_api = sig.api_calls[progress];
    }
  }

  GDEBUG << "Revert start is " << start_api.name << " goal is " << goal_api.name << LEND;

  start_point.vertex = revert_vertex;
  last_point.vertex = NULL_VERTEX;

  ApiWaypointDescriptor p = search_tree.back();
  start_point.component = p.component;
  last_point.component = p.component;

  start_point.block = p.block;
  last_point.block = NULL;
}

// ********************************************************************************************
// * Start of Visitor methods
// ********************************************************************************************

// the tree edge visitor is needed to remember the last vertex visited that made it to the
// search tree
template <class Edge, class Graph>
inline void ApiTreeEdgeVisitor::operator()( Edge e, const Graph &g ) {

  ApiCfgVertex tgt = boost::target(e,g);
  ApiCfgVertex src = boost::source(e,g);

  ApiSearchState *state = search_executor_->GetState();

  const ApiVertexInfo & src_info = g[src];
  const ApiVertexInfo & tgt_info = g[tgt];

  // this is where the sub search shall begin
  if (tgt_info.GetType() == ApiVertexInfo::CALL) {
    if (tgt_info.target_address != INVALID_ADDRESS) {

      GDEBUG << "Non-API call detected, src: "<< src_info.ToString()
             << ", tgt: " << tgt_info.ToString() << LEND;

      ApiGraph *graph = search_executor_->GetGraph();
      ApiCfgComponentPtr tgt_cmp = graph->GetComponent(tgt_info.target_address);
      ApiCfgComponentPtr src_cmp = graph->GetComponent(state->start_component);

      if (src_cmp != NULL && tgt_cmp != NULL) {

        rose_addr_t src_addr = src_cmp->GetEntryAddr();
        rose_addr_t tgt_addr = tgt_cmp->GetEntryAddr();

        // search the list of merged addresses for this call
        // It is unclear why the same call is encountered twice, but it happens

        SgAsmX86Instruction *call_insn = GetLastBlkInsn(tgt_info.block);
        rose_addr_t caller_addr = call_insn->get_address();
        rose_addr_t callee_addr = tgt_info.target_address;

        GDEBUG << "DFS Merge src: " << addr_str(src_addr)
                      << ", tgt: " << addr_str(tgt_addr) << ", from: " << addr_str(caller_addr)
                      << ", to: " << addr_str(callee_addr) << LEND;


        ApiMergeInfo merge_info(src_addr, tgt_addr, caller_addr, callee_addr);

        std::vector<ApiMergeInfo>::iterator mi=std::find_if(state->merged_list.begin(),
                   state->merged_list.end(),
                   ApiMergeFindPredicate(src_addr, tgt_addr, caller_addr, callee_addr));
                   //ApiMergeFindPredicate(src_addr, tgt_addr, tgt_info.block->get_address(), call_addr));

        if (mi == state->merged_list.end()) {

          // Notify the SearchExecutor that a merge is needed.

          throw MergeAndRestartSearchException(merge_info);
        }
      }
    }
  }

  GDEBUG << "Tree edge: " << addr_str(src_info.block->get_address()) << " -> "
         << addr_str(tgt_info.block->get_address()) << LEND;

  // Determine if this current segment is a  deadend by searching the list of deadends. If it
  // is a deadend, then ignore it so that it doesn't factor into the search goals

  DeadendList::iterator di = std::find_if(state->deadends.begin(),state->deadends.end(),
          PathFindPredicate(src_info.block->get_address(), tgt_info.block->get_address()));

  if (di != state->deadends.end()) {

    GDEBUG << "Not following deadend " << addr_str(src_info.block->get_address()) << "->"
          << addr_str(tgt_info.block->get_address()) << LEND;

    state->last_point.vertex = tgt;
    state->last_point.component = state->start_point.component;
    state->last_point.block = tgt_info.block;

    return;
  }

  if (true == search_executor_->CheckMatch(tgt_info)) {

    // check for this goal based on API Function Name

    GDEBUG << "Found goal edge is "
           << addr_str(src_info.block->get_address()) << "->"
           << addr_str(tgt_info.block->get_address())
           << LEND;

    state->last_point.vertex = tgt;
    state->last_point.component = state->start_point.component;
    state->last_point.block = tgt_info.block;

    // signal that the goal is found
    throw ReachedGoalException();
  }
}

// This visitor is here to capture self loops on API calls
template <class Edge, class Graph>
inline void ApiBackEdgeVisitor::operator()(Edge e, const Graph &g) {

  ApiCfgVertex tgt = boost::target(e,g);
  ApiCfgVertex src = boost::source(e,g);

  ApiSearchState *state = search_executor_->GetState();

  const ApiVertexInfo & src_info = g[src];
  const ApiVertexInfo & tgt_info = g[tgt];

  if (state->goal_api == state->start_api) {
    // are we at the goal
    if (src == tgt && src_info.api_name == state->goal_api.name) {

      GDEBUG << "Detected self loop: "
          << addr_str(tgt_info.block->get_address()) << "->"
          << addr_str(src_info.block->get_address())
          << LEND;

      state->last_point.vertex = tgt;
      state->last_point.component = state->start_point.component;
      state->last_point.block = tgt_info.block;

      throw ReachedGoalException();
    }
  }
}

// ********************************************************************************************
// * Start of ApiSearchResult methods
// ********************************************************************************************

ApiSearchResult::ApiSearchResult(const ApiSearchResult &copy) {

  match_start = copy.match_start;
  match_component_start = copy.match_component_start;
  match_name = copy.match_name;
  match_category = copy.match_category;
  search_tree = copy.search_tree;
}

ApiSearchResult & ApiSearchResult::operator=(const ApiSearchResult & other) {

  match_start = other.match_start;
  match_component_start = other.match_component_start;
  match_name = other.match_name;
  match_category = other.match_category;
  search_tree = other.search_tree;

  return *this;
}

bool ApiSearchResult::operator==(const ApiSearchResult& other) {

  if (match_start != other.match_start) {
    return false;
  }
  if (match_component_start != other.match_component_start) {
    return false;
  }
  if  (match_name != other.match_name) {
    return false;
  }
  if (match_category != other.match_category) {
    return false;
  }

  if (search_tree.size() != other.search_tree.size()) {
    return false;
  }

  for (size_t i=0; i< search_tree.size(); i++) {
    if (!(search_tree.at(i) == other.search_tree.at(i))) {
        return false;
    }
  }
  return true;
}


// ********************************************************************************************
// * Start of ApiSearchExecutor methods
// ********************************************************************************************

bool ApiSearchExecutor::CheckMatch(const ApiVertexInfo &match_vertex) {

  // First check if the APIs match
  if (false == boost::iequals(match_vertex.api_name, state_.goal_api.name)) {
    return false;
  }
  // If the APIs match, then check parameters if there are any
  if (true == state_.goal_api.has_params || true == state_.goal_api.has_retval) {
    return EvaluateApiMatchTable(state_.goal_api,match_vertex);
  }
  // No params/retval to match, default to function names
  return true;
}

void ApiSearchExecutor::Initialize(ApiGraph *g) {

  state_.ClearState();
  graph_ = g;
}

void ApiSearchExecutor::UpdateSearchTree(PredecessorMap pred_map) {

  std::vector<ApiCfgVertex> vtx;
  rose_addr_t current_component = state_.last_point.component;
  ApiCfgComponentPtr comp = graph_->GetComponent(current_component);

  if (comp == NULL) {
    GWARN << "Could not find component" << LEND;
    return;
  }

  ApiCfg *graph = comp->GetCfg();
  const ApiVertexInfo &start_info = (*graph)[state_.start_point.vertex];

  // check to see if this update is a self-loop
  if (state_.start_point != NULL_WAYPOINT) {
    if (state_.start_point.vertex==state_.last_point.vertex) {

      GDEBUG << "Saving self-loop " << addr_str(state_.start_point.block->get_address()) << LEND;

      state_.search_tree.push_back(ApiWaypointDescriptor(state_.start_point));
      return;
    }
  }

  ApiCfgVertex current = state_.last_point.vertex;
  while(current != state_.start_point.vertex) {
    vtx.push_back(current);
    current = pred_map[current];
  }

  if (state_.search_tree.empty()) {
    vtx.push_back(state_.start_point.vertex);
  }
  else {
    ApiWaypointDescriptor &last_entry = state_.search_tree.back();
    if (last_entry.block->get_address() != start_info.block->get_address()) {
      vtx.push_back(state_.start_point.vertex);
    }
  }

  // update the search tree with the path taken to this goal
  for (std::vector<ApiCfgVertex>::reverse_iterator ri=vtx.rbegin(); ri!=vtx.rend(); ri++) {

    const ApiVertexInfo &vi = (*graph)[*ri];
    bool part_of_sig = false;
    if (state_.last_point.block->get_address() == vi.block->get_address()) {
      part_of_sig = true;
    }

    state_.search_tree.push_back(
        ApiWaypointDescriptor(vi.block,current_component,*ri,vi.api_name,part_of_sig));
  }
}

// These functions check to see if the current result element is new. Currently, there
// are two ways to check this - by vertex and by address
bool ApiSearchExecutor::IsNewResult(const ApiVertexInfo &vi) {

  if (vi.block) {
    return IsNewResult(vi.block->get_address());
  }
  return true;
}

bool ApiSearchExecutor::IsNewResult(rose_addr_t addr) {

  if (state_.results.empty()) {
    return true;
  }

  for (ApiSearchResultVector::iterator ri=state_.results.begin(), end=state_.results.end(); ri!=end; ri++) {
    ApiSearchResult& r = *ri;
    // this vertex has already been encountered as part of the result set
    if (r.match_start == addr && boost::iequals(r.match_name, state_.sig.name)) {
      return false;
    }
  }
  return true;
}

// Deprecated. This function is no longer called. insead the search start is
// inlined in the Search function. I'm keeping this here for posterity
void ApiSearchExecutor::FindSearchStart(ApiSigFunc &start_api, ApiCfgComponentPtr comp, ApiCfgVertexVector &starts) {

  ApiCfg *cfg = comp->GetCfg();

  if (comp->ContainsApi(start_api.name) == true) {

    BGL_FORALL_VERTICES(vtx, *cfg, ApiCfg) {

      ApiVertexInfo &vtx_info = (*cfg)[vtx];

      if (boost::iequals(vtx_info.api_name, start_api.name) && IsNewResult(vtx_info)) {
        // this is a possible start for the search
        starts.push_back(vtx);
      }
    }
  }
}

void ApiSearchExecutor::PrintSearchTree() {

  OINFO << "Printing search tree " << state_.search_tree.size() << LEND;

  for (const ApiWaypointDescriptor & path : state_.search_tree) {
    rose_addr_t vertex_addr = path.block->get_address();
    rose_addr_t comp_addr = path.component;

    ApiCfgComponentPtr comp = graph_->GetComponent(comp_addr);
    ApiCfg *cfg = comp->GetCfg();
    ApiVertexInfo & vi = (*cfg)[path.vertex];

    OINFO << "path = " << addr_str(vertex_addr) << " in " << addr_str(comp_addr)
    << " " << ((vi.GetType() == ApiVertexInfo::API) ? vi.api_name : "") << LEND;
  }
}

bool ApiSearchExecutor::CheckConnected(const ApiWaypointDescriptor &src,
    const ApiWaypointDescriptor &dst) {

  // same component
  if (src.component == dst.component) {
    if (src.vertex == NULL_VERTEX || dst.vertex == NULL_VERTEX) {
      return false;
    }

    ApiCfgComponentPtr comp = graph_->GetComponent(src.component);
    ApiCfg *cfg = comp->GetCfg();

    return boost::edge(src.vertex, dst.vertex, *cfg).second;

  }
  // TODO: Should connectivity across components be checked?

  return false;
}

bool ApiSearchExecutor::Backtrack() {

  GINFO << "Backtracking ... " << LEND;

  if (state_.search_tree.size() < 2) {
    return false;
  }

  // get the last and next to last vertices traversed - these are needed to backtrack
  ApiWaypointDescriptor last = state_.search_tree.back();

  // remove the last element
  state_.search_tree.pop_back();

  // this is the next to last vertex in the search tree
  ApiWaypointDescriptor next_to_last = state_.search_tree.back();

  // is this check redundant because the node is in the search tree?
  if (CheckConnected(next_to_last, last) == true) {

    AddDeadends(next_to_last,last);

    ApiCfgComponentPtr comp = graph_->GetComponent(state_.start_point.component);
    if (NULL == comp) {
      return false;
    }

    state_.RevertState(next_to_last.vertex, state_.start_point);

    ApiCfg *cfg = comp->GetCfg();
    const ApiVertexInfo & revert_info = (*cfg)[state_.start_point.vertex];

    GDEBUG << "start vertex = " << addr_str(revert_info.block->get_address()) << LEND;

    return true;
  }
  return false;
}

void ApiSearchExecutor::AddDeadends(ApiWaypointDescriptor &next_to_last, ApiWaypointDescriptor &last) {

  GDEBUG << "Adding dead end "
            << addr_str(next_to_last.block->get_address())
            << "->" << addr_str(last.block->get_address()) << LEND;

     state_.deadends.insert(std::make_pair(next_to_last, last));
}


// Run the depth-first for the current segment
bool ApiSearchExecutor::RunSearch() {


  GDEBUG << "Running new search for " << state_.goal_api.name
         << " starting from " << addr_str(state_.start_point.block->get_address()) << LEND;

  ApiCfg *cfg = graph_->GetComponent(state_.start_point.component)->GetCfg();

  std::vector<boost::default_color_type> colors(boost::num_vertices(*cfg));
  IndexMap indexMap = boost::get(boost::vertex_index, *cfg);
  std::vector<ApiCfgVertex> pv(boost::num_vertices(*cfg));
  PredecessorMap predecessors(&pv[0], indexMap);

  try {

     boost::depth_first_visit(*cfg,
        state_.start_point.vertex,
        boost::make_dfs_visitor(
           boost::make_list(
             boost::record_predecessors(predecessors, boost::on_tree_edge()),
             ApiTreeEdgeVisitor(this),
             ApiBackEdgeVisitor(this))),
             boost::make_iterator_property_map(colors.begin(),
             boost::get(boost::vertex_index, *cfg)));
  }
  catch (MergeAndRestartSearchException mrse) {

     // There are cases when the merge will fail. In that case, abort this search
     if (graph_->MergeComponents(mrse.merge_info,false) == true) {

        UpdateApiMatchTable(mrse.merge_info.from_addr, mrse.merge_info.tgt_cmp_addr); // 1st: was to_addr

        // update the list of addresses that have already been merged. For some, unknown, reason
        // addresses may be repeated.
        state_.merged_list.push_back(ApiMergeInfo(mrse.merge_info));

        // restart the search with the merged graph
        return true;
     }
  }
  catch (ReachedGoalException) {

    // save the path so far
    UpdateSearchTree(predecessors);

    // The search found the goal without traversing dead ends
    state_.UpdateState();

    // move on to the next segment
    return true;
  }

  // The search failed and a backtrack is needed
  return false;
}

void ApiSearchExecutor::SaveResult() {

  ApiSearchResult *res = new ApiSearchResult();
  if (res != NULL) {

    if (state_.search_tree.empty()) return;

    ApiWaypointDescriptor wp = state_.search_tree.front();

    if (wp.block == NULL) return;

    rose_addr_t addr = wp.block->get_address();

    // only save unique results
    ApiCfgComponentPtr start_comp = graph_->GetContainingComponent(addr);

    if (start_comp != NULL) {

      ApiCfg *start_graph = start_comp->GetCfg();
      if (start_graph != NULL) {

        if (false == IsNewResult(addr)) {

          // this is not a new result, discard it
          return;
        }
      }
    }

    std::copy(state_.search_tree.begin(),
        state_.search_tree.end(),
        std::back_inserter(res->search_tree));

    res->match_start = state_.search_tree.front().block->get_address();
    res->match_component_start = state_.start_component;
    res->match_name.assign(state_.sig.name);
    res->match_category.assign(state_.sig.category);

    state_.results.push_back(res);
  }
}

// Handle translation from caller to callee in terms of mapping symbolic values
// this function builds the list of aliases across functions
void ApiSearchExecutor::UpdateApiMatchTable(rose_addr_t caller, rose_addr_t callee) {

  // nothing in the table to update
  if (state_.match_table.empty() == true) {
    return;
  }

  GDEBUG << "Updating match table for " << addr_str(caller) << " -> " << addr_str(callee) << LEND;

  GDEBUG << " --- " << LEND;
  GDEBUG <<"Current ApiParamTable:" << LEND;

  for (const ApiParamMatchPair & p : state_.match_table) {

    const std::string & func_label = p.first;
    const ApiParamPtrList *plist = p.second;

    std::ostringstream pstr;;
    for (const ApiParameter * apip : *plist) {
      pstr << *(apip->value) << " | " << LEND;
    }
    GDEBUG << func_label << " ==> [" << pstr.str() << "]" << LEND;

  }
  GDEBUG << " --- " << LEND;

  CallDescriptor * cd = global_descriptor_set->get_call(caller);
  FunctionDescriptor *fd = global_descriptor_set->get_func(callee);

  if (cd == NULL || fd == NULL) {
    OWARN << "Cannot find call or function descriptor to update parameters" << LEND;
    return;
  }

  const ParamVector& cd_params = cd->get_parameters().get_params();
  const ParamVector& fd_params = fd->get_parameters().get_params();

  // For each api, update the set of values per parameter across calls.
  // These are the aliases for the value of interest. The result it a
  // table that maps a label to the set of values associated with that label
  for (ApiParamMatchPair & match_pair : state_.match_table) {
    ApiParamPtrList *cur_list = match_pair.second; // list of aliases

    for (const ApiParameter *cur_pd : *cur_list) { // for each recorded alias

      for (const ParameterDefinition &call_pd : cd_params) { // for each param on the call

        if (cur_pd->value && call_pd.value) {

          if (cur_pd->value->can_be_equal(call_pd.value)) {
            for (const ParameterDefinition &callee_pd : fd_params) {
              if (call_pd.num == callee_pd.num) {
                cur_list->push_back(new ApiParameter(callee_pd));
              }
            }
          }
        }
      }
    }
  }


  GDEBUG << "Updating returns" << LEND;

  RegisterDescriptor eax_reg = global_descriptor_set->get_arch_reg("eax");
  const ParamVector& cd_rets = cd->get_parameters().get_returns();

  for (ApiParamMatchPair & match_pair : state_.match_table) {
    ApiParamPtrList *cur_list = match_pair.second;

    for (const ParameterDefinition &rv : cd_rets) {

      // for now just track eax and the "return value"
      if (rv.reg == eax_reg) {
        cur_list->push_back(new ApiParameter(rv));
        break;
      }
    }
  }
}

// Evaluate whether the parameters passed/returned match with the signature
bool ApiSearchExecutor::EvaluateApiMatchTable(const ApiSigFunc &sig_func,
    const ApiVertexInfo &vertex_info) {

  GDEBUG << "Evaluate: At Vertex " << addr_str(vertex_info.block->get_address()) << LEND;
  GDEBUG << " " << LEND;
  GDEBUG << " --- " << LEND;
  GDEBUG <<"Current ApiParamTable:" << LEND;
  for (const ApiParamMatchPair & p : state_.match_table) {

    const std::string & func_label = p.first;
    const ApiParamPtrList *plist = p.second;

    std::ostringstream pstr;;
    for (const ApiParameter *apip : *plist) {
      pstr << *(apip->value) << " | ";
    }
    GDEBUG << func_label << " ==> [" << pstr.str() << "]" << LEND;

  }
  GDEBUG << " --- " << LEND;

  // the function names match, check parameters and return values

  std::vector<ApiParamMatchPair> candidate_matches;

  SgAsmX86Instruction *insn = GetLastBlkInsn(vertex_info.block);
  rose_addr_t call_addr = insn->get_address();
  CallDescriptor * cd = global_descriptor_set->get_call(call_addr);

  if (!cd) {
    OWARN << "Could not find call descriptor for " << addr_str(call_addr) << LEND;
    return false;
  }

  const ParamVector& cd_params = cd->get_parameters().get_params();

  ApiCfgComponentPtr comp = graph_->GetContainingComponent(call_addr);
  FunctionDescriptor * fd = global_descriptor_set->get_func(comp->GetEntryAddr());

  if (!fd) OWARN << "No FD found" << LEND;

  // const ParamVector& fn_params = vertex_info.import_fd->get_parameters().get_params();
  if (sig_func.has_params) {

    // For the params associated with this signature, determine if each
    // has been added to the param match table
    for (const ApiSigFuncParam & sig_param : sig_func.params)  {

      const ApiParamMatchTableIter & sig_entry = state_.match_table.find(sig_param.name);

      if (sig_entry == state_.match_table.end()) {

        // new param detected, add it and its symbolic parameter to the table

        for (const ParameterDefinition &pd : cd_params) {

          if (sig_param.index == pd.num) {

            ApiParameter *api_param = NULL;
            if (sig_param.type == ApiParamType::OUT) {
              // output parameters are pointers - dereference them
              GDEBUG << "Detected new output parameter - " << sig_param.name << LEND;
              DereferenceParameter(api_param, pd);
            }
            else {
              api_param = new ApiParameter(pd);
            }

            if (api_param) {

              GDEBUG << "Saving new param: " << sig_param.ToString() << LEND;

              ApiParamPtrList *new_params = new ApiParamPtrList();
              new_params->push_back(api_param);
              candidate_matches.push_back(ApiParamMatchPair(sig_param.name, new_params));
            }
          }
        }
      }

      // previously encountered param, make sure the values still match

      else {

        GDEBUG << "Detected existing params: " << cd_params.size() << LEND;

        for (const ParameterDefinition &call_pd : cd_params) {

          if (sig_param.index == call_pd.num) {

            ApiParamPtrList *sig_list = sig_entry->second;

            bool found_match = false;
            for (const ApiParameter * sig_pd : *sig_list) {
              if (call_pd.value->can_be_equal(sig_pd->value)) {
                found_match = true;
                break;
              }
            }

            // no parameters matched
            if (!found_match) {
              GDEBUG << "Symbolic param value MISmatch" << LEND;
              return false;
            }
          }
        }
      }
    }
  }

  // evaluate return values

  if (sig_func.has_retval) {

    GDEBUG << "Checking retn value: " << sig_func.retval.name << LEND;

    RegisterDescriptor eax_reg = global_descriptor_set->get_arch_reg("eax");
    const ParamVector& cd_rets = cd->get_parameters().get_returns();

    const ApiParamMatchTableIter & ret_entry = state_.match_table.find(sig_func.retval.name);

    // New retval found
    if (ret_entry == state_.match_table.end()) {

      GDEBUG << "Detected new retval: " << cd_rets.size() << LEND;

      for (const ParameterDefinition &rv : cd_rets) {

        // for now just track eax
        if (rv.reg == eax_reg) {

          // New return value, add the param def to the table
          ApiParamPtrList *new_rets = new ApiParamPtrList();
          new_rets->push_back(new ApiParameter(rv));
          candidate_matches.push_back(ApiParamMatchPair(sig_func.retval.name, new_rets));
          break;
        }
        else {
          GDEBUG << "Coundn't find return value for eax" << LEND;
        }
      }
    }
    else {

      GDEBUG << "Checking existing retn: "  << LEND;

      for (const ParameterDefinition &rv : cd_rets) {
        if (rv.reg == eax_reg) {

          bool rv_found_match = false;
          ApiParamPtrList *rlist = ret_entry->second;
          for (const ApiParameter *sig_rv : *rlist) {

            if (sig_rv->value && rv.value) {

              const TreeNodePtr & sig_rv_tnp = sig_rv->value->get_expression();
              const TreeNodePtr & rv_tnp = rv.value->get_expression();

              if (sig_rv_tnp && rv_tnp) {
                if (sig_rv_tnp == rv_tnp) {
                  rv_found_match = true;
                  break;
                }
              }
            }
          }

          if (!rv_found_match) {
            GDEBUG << "Symbolic return value MISmatch" << LEND;
            return false;
          }
        }
      }
    }
  }

  if (candidate_matches.empty() == false) {
    // add the candidates
    state_.match_table.insert(std::begin(candidate_matches), std::end(candidate_matches));
  }
  // This is now a successful match
  return true;
}

void ApiSearchExecutor::DereferenceParameter(ApiParameter * &apip, const ParameterDefinition &pd) {

  SymbolicValuePtr ptr = pd.value_pointed_to;

  GDEBUG << "Dereferencing parameter at "<< *(pd.value)  << LEND;

  if (NULL != ptr) {
    GDEBUG << " refers to " << *ptr << LEND;

    if (apip==NULL) {
      apip = new ApiParameter(pd.num, ptr, pd.name);
    }
    else {
      apip->MakeParam(pd);
    }
  }
}

bool ApiSearchExecutor::Search(ApiSig &sig, ApiSearchResultVector *result_list ) {

  GINFO << "Searching for signature: " << sig.name << LEND;

  typedef std::vector<rose_addr_t> WorkList;
  typedef std::vector<rose_addr_t>::iterator WorkListIter;

  if (!sig.api_calls.empty()) {

    state_.sig = sig;

    // Create the initial worklist with the set of components to process
    WorkList worklist;
    ApiCfgComponentMap components = graph_->GetComponents();
    for (ApiCfgComponentMap::value_type & comp : components) {
      worklist.push_back(comp.first);
    }

    ApiSigFunc start_api = sig.api_calls.at(0);

    while (!worklist.empty()) {

      bool purge_state = false;
      WorkListIter workitem = worklist.begin();
      rose_addr_t start_comp_addr = *workitem;
      ApiCfgComponentPtr start_comp = graph_->GetComponent(start_comp_addr);

      GINFO << "Working on function " << addr_str(start_comp_addr)
            << ". Looking for starting API function: " << start_api.name << LEND;

      if (start_comp->ContainsApi(start_api.name)) {
        GINFO << "Found search start in function " << addr_str(start_comp_addr) << LEND;

        ApiCfg *cfg = start_comp->GetCfg();

        // Locate the starting vertex for this search

        ApiCfgVertex startv = NULL_VERTEX;
        BGL_FORALL_VERTICES(vtx, *cfg, ApiCfg) {
          ApiVertexInfo &vtx_info = (*cfg)[vtx];

          if (boost::iequals(vtx_info.api_name, start_api.name) && IsNewResult(vtx_info)) {
            startv = vtx;
            break;
          }
        }
        if (startv == NULL_VERTEX) {

          GWARN << "Could not find starting vertex in "
                << addr_str(start_comp->GetEntryAddr()) << LEND;

          worklist.erase(workitem);

          // Complete reset for next search
          state_.ResetState();

          continue;
        }
        const ApiVertexInfo &vi = (*cfg)[startv];

        // Check the starting call make sure it has the necessary parameters/return
        // values associated with it

        if (start_api.has_params == true || start_api.has_retval == true) {

          if (EvaluateApiMatchTable(start_api, vi) == false) {

            GDEBUG << "Unable to use search start due to parameter mismatches" << LEND;

            worklist.erase(workitem);

            // Complete reset for next search
            state_.ResetState();
            continue;
          }
        }

        // Run the search from this point

        try {

          InitializeSearch(start_comp, startv, sig);

          // RunSearch returns true if the current segment was found. Otherwise the search
          // was not successful and the Backtracking algorithm commences. If backtracking
          // is not success (i.e. there are no alternate paths to take), then the entire search
          // concludes for the current component. The search is considered successful if any
          // results are recorded.

          bool continue_search = true;
          do {

            if (false==RunSearch()) {

              // The search continues as long as backtracking is successful
              continue_search = Backtrack();
            }

          } while (continue_search);

        }
        catch (SearchCompleteException) {

          // the search completed and we every segment of the signature, this means that the
          // search was successful.

          GINFO << "Found " << state_.sig.name << ", saving results" << LEND;

          SaveResult();

          // The search was successful, completely reset the state
          purge_state=true;
        }
      }

      // Handle partial matches by checking callers. A partial match means that the first N
      // elements of the signature matched, but subsequent matches were not made. Process the
      // references to the last function encountered looking for the complete match

      if (state_.progress >= 1 && false == state_.IsSearchComplete()) {

        GDEBUG << "Partial match on " << addr_str(start_comp->GetEntryAddr()) << LEND;

        // Find calls to comp
        XrefMap candidate_callers;
        GetXrefsTo(start_comp, candidate_callers);

        GDEBUG << "Found " << candidate_callers.size() << " callers to "
            << addr_str(start_comp->GetEntryAddr()) << LEND;

        if (candidate_callers.size()>0) {

          XrefMapIter xref = candidate_callers.begin();

          while (xref != candidate_callers.end()) {

            rose_addr_t from = xref->first;
            rose_addr_t to = xref->second;

            GDEBUG << "Processing xref " << addr_str(from) << " -> " << addr_str(to) << LEND;

            ApiCfgComponentPtr from_comp = graph_->GetContainingComponent(from);

            if (from_comp == NULL) {
              OWARN << "Cannot find containing component for " << addr_str(from) << LEND;
              xref++;
              continue;
            }

            rose_addr_t from_cmp_addr =  from_comp->GetEntryAddr();

            ApiMergeInfo mi(from_comp->GetEntryAddr(), start_comp_addr, from, to);

            GDEBUG << "Merging: " << mi.ToString() << LEND;

            if (true == graph_->MergeComponents(mi,true)) {

              UpdateApiMatchTable(mi.from_addr, mi.tgt_cmp_addr);

              // update the list of addresses that have already been merged. For some, unknown,
              // reason addresses may be repeated.

              state_.merged_list.push_back(ApiMergeInfo(mi));

              size_t index = 0;
              bool reprocess=true;
              while (index < worklist.size() && reprocess) {
                rose_addr_t caddr = worklist.at(index);
                if (caddr == from_cmp_addr) {
                  worklist.at(index) = from_comp->GetEntryAddr();
                  GDEBUG << "No need to re-process:"  << addr_str(from_comp->GetEntryAddr()) << LEND;
                  reprocess = false;
                }
                index++;
              }
              if (reprocess) {
                GDEBUG << "Re-process:"  << addr_str(from_comp->GetEntryAddr()) << LEND;
                worklist.insert(workitem+1,from_comp->GetEntryAddr());
              }
            }
            else {
               OWARN << "Search aborted due to control flow graph corruption" << LEND;
            }
            xref++;
          }
        }
      }

      // reset for next search.

      if (purge_state) {
        state_.ResetState();
      }
      else {
        state_.ResetSearchState();
      }

      // remove the current work item
      GDEBUG << "Removing workitem " << addr_str(*workitem) << LEND;
      worklist.erase(workitem);
      GDEBUG << "There are " << worklist.size() << " remaining items" << LEND;
    }
  }

  // if there are any results then the search is successful
  return GetResults(result_list);
}
void ApiSearchExecutor::GetXrefsTo(ApiCfgComponentPtr comp, XrefMap &candidates) {

  XrefMap xrefs = graph_->GetXrefs();

  //from address -> to address
  for (const XrefMapEntry & x : xrefs) {

    rose_addr_t to = x.second;
    rose_addr_t from = x.first;

    if (comp->GetEntryAddr() == to) {
      candidates.insert(XrefMapEntry(from, to));
    }
  }
}

void ApiSearchExecutor::InitializeSearch(ApiCfgComponentPtr comp, ApiCfgVertex startv, ApiSig &sig) {

  ApiCfg *cfg = comp->GetCfg();
  const ApiVertexInfo &vi = (*cfg)[startv];
  rose_addr_t caddr = comp->GetEntryAddr();

  // Found the (possible) search start.
  state_.last_point.component = caddr;
  state_.start_point.component = caddr;
  state_.start_point.vertex = startv;
  state_.start_point.block = vi.block;

  // component where the search starts
  state_.start_component = caddr;

  state_.start_api = sig.api_calls[0];
  state_.progress = 1;   // Found the start so update the progress

  GDEBUG << "Starting search at " << addr_str(vi.block->get_address())
            << ", which calls " << vi.api_name << LEND;

  // the start is the first element of the API signature
  state_.search_tree.push_back(
      ApiWaypointDescriptor(vi.block,caddr,startv,vi.api_name,true));

  // This is the special case where the signature is 1-element and found the start
  // the signature has been matched
  if (sig.api_calls.size() == 1) {

    throw SearchCompleteException();
  }

  // there is more than one part to the signature - set the goal
  state_.goal_api = sig.api_calls[1];
}

bool ApiSearchExecutor::GetResults(ApiSearchResultVector *result_list) {

  if (!state_.results.empty()) {
    result_list->insert(result_list->end(),state_.results.begin(), state_.results.end());
    return true;
  }
  return false;
}

// ********************************************************************************************
// * Start of ApiOutputManager methods.
// ********************************************************************************************

ApiOutputManager::~ApiOutputManager() {

  if (formatter_ != NULL) delete formatter_;
  formatter_ = NULL;
}


bool ApiOutputManager::GenerateOutput(ApiSearchResultVector &res) {

  if (formatter_ == NULL) {
    OWARN << "Output format not specified" << LEND;
    return false;
  }

  formatter_->Format(res, path_level_);

  if (output_mode_ == OutputMode::PRINT) {
    std::cout << formatter_->ToString() << std::endl;
  }
  else if (output_mode_ == OutputMode::FILE) {
    return formatter_->ToFile(output_file_);
  }
  return true;
}

void ApiOutputManager::SetSearchTreeDiplayMode(ApiOutputManager::PathLevel m) {

   path_level_ = m;
 }

void ApiOutputManager::SetOutputFormat(ApiOutputManager::OutputFormat f) {

  output_format_ = f;

  if (f == OutputFormat::TEXT) {
    formatter_ = new ApiResultTextFormatter();
  }
  else if (f == OutputFormat::JSON) {
    formatter_ = new ApiResultJsonFormatter();
  }
  else {
    OWARN << "Defaulting to TEXT output" << LEND;
    formatter_ = new ApiResultTextFormatter();
  }
}

// ********************************************************************************************
// * Start of ApiResultTextFormatter methods.
// ********************************************************************************************

void ApiResultTextFormatter::Format(ApiSearchResultVector &results, ApiOutputManager::PathLevel path_level) {

  typedef std::map<std::string, ApiSearchResultVector> FilterMap;
  typedef std::pair<std::string, ApiSearchResultVector> FilterMapPair;
  typedef std::map<std::string, ApiSearchResultVector>::iterator FilterMapIter;

  // categorize the results
  FilterMap categorized_results;
  for (const ApiSearchResult &res : results) {

    FilterMapIter cri = categorized_results.find(res.match_category);
    if (cri == categorized_results.end()) {
      ApiSearchResultVector srv;
      srv.push_back(new ApiSearchResult(res));
      categorized_results.insert(FilterMapPair(res.match_category, srv));
    }
    else {
      ApiSearchResultVector &cats =  cri->second;
      cats.push_back(new ApiSearchResult(res));
    }
  }

  // format by category
  for (const FilterMap::value_type &pair : categorized_results) {

    const std::string & category = pair.first;
    const ApiSearchResultVector & result = pair.second;

    std::string cat_str = "Category: ";
    cat_str.append(category);

    std::string dashes;
    for (size_t i=0;i<cat_str.size(); i++) {
      dashes.append("-");
    }

    out_stream_ << std::endl << cat_str << std::endl << dashes << std::endl;

    for (const ApiSearchResult &res : result) {

      SgAsmX86Instruction *start_insn = GetLastBlkInsn(res.search_tree.front().block);

      out_stream_ << "   Found: " << res.match_name << " starting at address "
          << addr_str(start_insn->get_address()) << " ";

      if (path_level != ApiOutputManager::PathLevel::NONE) {

        // generate the search path, if specified

        out_stream_ << "Path: ";
        for (auto wpi = res.search_tree.begin(); wpi!=res.search_tree.end(); ++wpi) {

          SgAsmX86Instruction* insn = GetLastBlkInsn(wpi->block);
          rose_addr_t address = insn->get_address();

          if (path_level == ApiOutputManager::PathLevel::FULL_PATH) {

            if (wpi->name != "") {
              out_stream_ <<  addr_str(address)<< "(" << wpi->name << ")";
            }
            else {
              out_stream_ << addr_str(address);
            }
            if (wpi+1 != res.search_tree.end()) {
              out_stream_ << " -> ";
            }
          }
          else if (path_level == ApiOutputManager::PathLevel::SIG_PATH) {
            if (wpi->is_part_of_sig) {
              out_stream_ <<  addr_str(address) << "(" << wpi->name << ")";
              if (wpi+1 != res.search_tree.end()) {
                out_stream_ << " -> ";
              }
            }
          }
        }
      }
      out_stream_ << std::endl;
    }
    out_stream_ << std::endl;
  }
}

std::string ApiResultTextFormatter::ToString() {
  return out_stream_.str();
}

bool ApiResultTextFormatter::ToFile(std::string ofile_name) {

  std::ofstream ofile(ofile_name.c_str());
  ofile << out_stream_.str();
  ofile.close();

  return true;
}

// ********************************************************************************************
// * Start of ApiResultJsonFormatter methods.
// ********************************************************************************************

// C++11 was picky about auto-converting const char[] to string and to boost::property_tree
// simultaneously, so we had to make a helper function that was a little more explicit.
std::pair<const std::string, boost::property_tree::ptree>
make_ptree(const std::string s1, const std::string s2) {
  return std::make_pair(s1, boost::property_tree::ptree(s2));
}

void ApiResultJsonFormatter::Format(ApiSearchResultVector &results, ApiOutputManager::PathLevel path_level) {

  boost::property_tree::ptree matches;
  for (const ApiSearchResult &res : results) {

    boost::property_tree::ptree match;

    match.put("Signature", res.match_name);
    match.put("Category", res.match_category);

    SgAsmX86Instruction *start_insn = GetLastBlkInsn(res.search_tree.front().block);

    if (path_level != ApiOutputManager::PathLevel::NONE) {
      match.put("Start Address", addr_str(start_insn->get_address()));

      // generate the search path, if specified
      boost::property_tree::ptree path;
      for (auto wpi = res.search_tree.begin(); wpi != res.search_tree.end(); ++wpi) {

        boost::property_tree::ptree path_entry;

        SgAsmX86Instruction* insn = GetLastBlkInsn(wpi->block);
        rose_addr_t address = insn->get_address();
        SgAsmFunction *function = insn_get_func(insn);

        if (path_level == ApiOutputManager::PathLevel::FULL_PATH) {
          if (wpi->name != "") {
            path_entry.push_back(make_ptree("API", wpi->name));
          }
          // include the address and function even if the API name isn't found
          path_entry.push_back(make_ptree("Address",addr_str(address)));
          path_entry.push_back(make_ptree("Function",addr_str(function->get_address())));
        }
        else if (path_level == ApiOutputManager::PathLevel::SIG_PATH) {
          if (wpi->is_part_of_sig && wpi->name != "") {
            // if part of sig, then must include API. Only include if the API name is found
            path_entry.push_back(make_ptree("API", wpi->name));
            path_entry.push_back(make_ptree("Address",addr_str(address)));
            path_entry.push_back(make_ptree("Function",addr_str(function->get_address())));
          }
        }

        if (false == path_entry.empty()) {
          path.push_back(std::make_pair("", path_entry));
        }
      }
      match.put_child("Path",path);
    }
    matches.push_back(std::make_pair("",match));
  }
  out_json_.put_child("Matches", matches);
}

std::string ApiResultJsonFormatter::ToString() {

 std::stringstream out;
 write_json(out, out_json_);
 return out.str();
}

bool ApiResultJsonFormatter::ToFile(std::string ofile_name) {

  write_json(ofile_name, out_json_);

  return true;
}

// ********************************************************************************************
// * Start of ApiVertexInfo methods.
// ********************************************************************************************

ApiVertexInfo::ApiVertexInfo() {

  type = UNKN;
  import_fd = NULL;
  target_address = INVALID_ADDRESS;
  block = NULL;
  api_name = "";
}

std::string ApiVertexInfo::ToString() const {

  std::string out = "";

  out += "Address=" + addr_str(block->get_address());
  out += ", type=";
  if (type==CALL) { out += "CALL (" + addr_str(target_address) + ")"; }
  else if (type==API) { out += "API (" + api_name +")"; }
  else if (type==RETN) { out += "RETN"; }
  else if (type==UNKN) { out += "UNKN"; }

  return out;
}

ApiVertexInfo& ApiVertexInfo::operator=(const ApiVertexInfo &rhs) {

  type = rhs.type;
  import_fd = rhs.import_fd;
  target_address = rhs.target_address;
  api_name = rhs.api_name;
  block = rhs.block;

  return *this;
}

ApiVertexInfo::ApiVertexInfo(const ApiVertexInfo& other) {

  type = other.type;
  import_fd = other.import_fd;
  target_address = other.target_address;
  api_name = other.api_name;
  block = other.block;
}

// returns true if the last instruction of a basic block is a retn
ApiVertexInfo::VertexType ApiVertexInfo::GetType() const {
  return type;
}

void ApiVertexInfo::SetType(ApiVertexInfo::VertexType t) {
  type = t;
}

// returns true if the last instruction of a basic block is a call
bool ApiVertexInfo::EndsInCall() const {
  return (type==CALL || type==API);
}

bool ApiVertexInfo::ContainsAddress(const rose_addr_t addr) const {

  SgAsmStatementPtrList& ins_list = block->get_statementList();

  for (const SgAsmStatementPtrList::value_type & ins_entry : ins_list)  {
    const SgAsmX86Instruction *insn = isSgAsmX86Instruction(ins_entry);
    if (insn != NULL) {
      if (insn->get_address() == addr) {
        return true;
      }
    }
  }
  return false;
}

// ********************************************************************************************
// * Start of ApiCfgComponent methods
// ********************************************************************************************

void ApiCfgComponent::Initialize(FunctionDescriptor &fd, AddrSet &api_calls, XrefMap &xrefs) {

  // Build the information for this CFG
  CFG &src = fd.get_pharos_cfg();
  cfg_ = new ApiCfg();

  typedef boost::graph_traits<CFG>::vertex_descriptor CfgVertex;

  // map of vertex address to vertex
  std::map<rose_addr_t, ApiCfgVertex> node_map;

  // for each vertex in the old graph, copy it to the new graph and add the necessary properties
  BGL_FORALL_VERTICES(vtx, src, ApiCfg) {

    // Initialize this vertex information

    ApiCfgVertex new_vtx = boost::add_vertex(*cfg_); // add to the new graph type
    ApiVertexInfo &info = (*cfg_)[new_vtx];

    info.block = isSgAsmBlock(boost::get(boost::vertex_name, src, vtx));

    if (!info.block) {
      OINFO << "Found NULL basic block in CFG - ignoring" << LEND;
      continue;
    }

    SgAsmx86Instruction *last_insn = GetLastBlkInsn(info.block);

    AddrSet::iterator apii = api_calls.find(last_insn->get_address());
    if (apii != api_calls.end()) {

      XrefMapIter xi = xrefs.find(*apii);
      if (xi != xrefs.end()) {

        CallDescriptor * cd = global_descriptor_set->get_call(xi->first);
        if (cd == NULL) {
          OWARN << "No call descriptor found" << LEND;
        }

        ImportDescriptor * id = cd->get_import_descriptor();
        if (id == NULL) {
          OWARN << "Could not find import descriptor for address " << addr_str(xi->second)
                << LEND;
        }

        info.target_address = id->get_address();
        std::string udll = boost::to_upper_copy(id->get_dll_name());
        std::string uapi = boost::to_upper_copy(id->get_name());
        std::string sep  = "!";
        info.api_name = udll + sep + uapi;

        info.type = ApiVertexInfo::API;

        // add this to the set of API names in this component
        if (apis_.find(info.api_name) == apis_.end()) {
          apis_.insert(info.api_name);
        }

        // save the function descriptor for this import
        info.import_fd = id->get_function_descriptor();

        GDEBUG << "Vertex " << addr_str(info.block->get_address())
               << " calls API " << info.api_name << "@"
               << addr_str(info.target_address)
               << LEND;
      }
    }
    if (info.type == ApiVertexInfo::UNKN) {

      if (insn_is_call(last_insn) == true) {

        info.type = ApiVertexInfo::CALL;
        XrefMapIter xi = xrefs.find(last_insn->get_address());

        if (xi!= xrefs.end()) {
          info.target_address = xi->second;
        }
        GDEBUG << "Vertex " << addr_str(info.block->get_address())
                            << " calls function " << addr_str(info.target_address) << LEND;
      }
      else if (x86_ret == last_insn->get_kind()) {

        info.type = ApiVertexInfo::RETN;
        info.target_address = INVALID_ADDRESS;
        GDEBUG << "Vertex " << addr_str(info.block->get_address()) << " is a return" << LEND;
      }
    }

    node_map[info.block->get_address()] = new_vtx;
  }
  // Now connect the edges

  BGL_FORALL_EDGES(edge,src,ApiCfg) {

    // Look up the source/target for each edge in the old graph (by address) and make the
    // necessary connections in the new graph

    CfgVertex sv = boost::source(edge, src);
    SgAsmBlock *sb = isSgAsmBlock(boost::get(boost::vertex_name, src, sv));

    CfgVertex tv = boost::target(edge, src);
    SgAsmBlock *tb = isSgAsmBlock(boost::get(boost::vertex_name, src, tv));

    ApiCfgVertex nsv = node_map[sb->get_address()];
    ApiCfgVertex tsv = node_map[tb->get_address()];

    boost::add_edge(nsv, tsv, *cfg_);
  }

  // set the entry for this ApiCfgComponent to the function entry. The entry is critical to graph
  // consolidation
  entry_ = fd.get_address();
  GDEBUG << "Setting entry to " << addr_str(entry_) << LEND;

  // The following code selects the exit for the graph. One exit is necessary for consolidation
  // so get all the the return blocks, select one as the primary return and then consolidate
  // the other returns to refer to the primary return (if there are multiple retursn

  // pick a return address from the set of return blocks
  BlockSet &retns = fd.get_return_blocks();
  exit_ = INVALID_ADDRESS;

  // select the primary return
  if (retns.empty() == false) {
    SgAsmBlock *bb = *(retns.begin());
    exit_ = bb->get_address();
  }
  else {

    // No returns found. Select a node with a 0 out degree to be the exit
    GDEBUG << "Could not find return vertex for " << addr_str(entry_)
           << ", defaulting to the first vertex with 0 out degree" << LEND;

    BGL_FORALL_VERTICES(rvtx,*cfg_,ApiCfg) {
      ApiVertexInfo &vertex_info = (*cfg_)[rvtx];
      if (0 == boost::out_degree(rvtx,*cfg_)) {
        exit_ = vertex_info.block->get_address();
        break;
      }
    }
  }
  // There is more than one return, consolidate them to refer to the primary return
  if (retns.size() > 1) {
    // there are multiple returns
    exit_ = ConsolidateReturns(retns);
  }
  if (exit_ == INVALID_ADDRESS) {
    GWARN << "Warning: could not find exit vertex for " << addr_str(entry_) << LEND;
  }

  // Finally, remove all vertices not needed for consolidation
  Simplify();
}


size_t ApiCfgComponent::GetSize() const {

  return boost::num_vertices(*cfg_);
}

// Make a complete, distinct & deep copy of the ApiCfg
ApiCfg * ApiCfgComponent::CloneApiCfg(ApiCfg *src_cfg) {

  ApiCfg *new_cfg = new ApiCfg();

  // map of vertex address to vertex
  std::map<rose_addr_t, ApiCfgVertex> node_map;

  // for each vertex in the old graph, copy it to the new graph and add the necessary properties
  BGL_FORALL_VERTICES(vtx, *src_cfg, ApiCfg) {
    ApiVertexInfo &src_vertex_info = (*src_cfg)[vtx];

    ApiCfgVertex new_vtx = boost::add_vertex(*new_cfg); // add to the new graph type
    ApiVertexInfo &new_vertex_info = (*new_cfg)[new_vtx];

    // copy over the other vertex properties
    new_vertex_info = src_vertex_info;

    node_map[new_vertex_info.block->get_address()] = new_vtx;
  }

  // Now connect the edges
  BGL_FORALL_EDGES(edge,*src_cfg,ApiCfg) {

    // Now look up the source/target for each edge in the old graph (by address) and make the
    // necessary connections in the new graph
    ApiCfgVertex sv = boost::source(edge, *src_cfg);
    ApiVertexInfo & src_info = (*src_cfg)[sv];

    ApiCfgVertex tv = boost::target(edge, *src_cfg);
    ApiVertexInfo & tgt_info = (*src_cfg)[tv];

    ApiCfgVertex new_src_vertex = node_map[src_info.block->get_address()];
    ApiCfgVertex new_tgt_vertex = node_map[tgt_info.block->get_address()];

    boost::add_edge(new_src_vertex, new_tgt_vertex, *new_cfg);
  }
  return new_cfg;
}

ApiCfgComponent & ApiCfgComponent::operator=(const ApiCfgComponent & other) {

  entry_ = other.entry_;
  exit_ = other.exit_;
  cfg_ = CloneApiCfg(other.cfg_);

  return *this;
}

// Copy constructor creates a deep, distinct copy of the ApiCfgComponent
ApiCfgComponent::ApiCfgComponent(const ApiCfgComponent &copy) {

  entry_ = copy.entry_;
  exit_ = copy.exit_;
  cfg_ = CloneApiCfg(copy.cfg_);
}

ApiCfgComponent::~ApiCfgComponent() {

  if (cfg_ != NULL)
    delete cfg_;
  cfg_ = NULL;

  entry_ = INVALID_ADDRESS;
  exit_ = INVALID_ADDRESS;
}

bool ApiCfgComponent::ContainsApi(std::string api) const {

  return apis_.find(api) != apis_.end();
}

// returns true if there are ANY api calls in this CFG
bool ApiCfgComponent::ContainsApiCalls() const {

  return (!apis_.empty());
}

bool ApiCfgComponent::ContainsAddress(const rose_addr_t addr) const {

  BGL_FORALL_VERTICES(vtx,*cfg_,ApiCfg) {
    ApiVertexInfo & vertex_info = (*cfg_)[vtx];
    if (vertex_info.ContainsAddress(addr) == true) {
      return true;
    }
  }
  return false;
}

// returns true if there are ANY calls (api or otherwise) in this CFG
bool ApiCfgComponent::ContainsCalls() const {

  if (!apis_.empty()) {
    return true;
  }

  BGL_FORALL_VERTICES(vtx,*cfg_,ApiCfg) {
    ApiVertexInfo & vertex_info = (*cfg_)[vtx];
    if (vertex_info.EndsInCall()) {
      return true;
    }
  }
  return false;
}

void ApiCfgComponent::DisconnectVertex(ApiCfgVertex &v) {

  rose_addr_t vaddr = (*cfg_)[v].block->get_address();
  GDEBUG << "Disconnecting vertex: " << addr_str(vaddr) << LEND;

  // removing only vertex - the entry and exit are now invalid
  if (boost::num_vertices(*cfg_) == 1) {
    entry_ = exit_ = INVALID_ADDRESS;
  }
  // Number of vertices > 1
  else {
    // for each in-edge to the vertex to remove

    BGL_FORALL_INEDGES(v, in_edge,*cfg_,ApiCfg) {
      // get the previous vertex (source of the in edge)
      ApiCfgVertex prev = boost::source(in_edge, *cfg_);
      // connect the prev vertex to the next vertex with an edge

      BGL_FORALL_OUTEDGES(v, out_edge,*cfg_,ApiCfg) {
        ApiCfgVertex next = boost::target(out_edge, *cfg_);

        // if the edge doesn't already exist between these vertices
        if (false == boost::edge(prev, next, *cfg_).second) {

          // take the in edge and make it refer to next out edge vertex
          boost::add_edge(prev, next, *cfg_);

          GDEBUG << "Adding edge from "
                 << addr_str((*cfg_)[prev].block->get_address()) << " to "
                 << addr_str((*cfg_)[next].block->get_address()) << LEND;
        }
      }
    }
  }

  GDEBUG << "Deleting edges for " << addr_str(vaddr) << LEND;
  // remove in/out edges from the vertex to delete
  boost::clear_vertex(v, *cfg_);

  // delete the vertex
  boost::remove_vertex(v, *cfg_);
}

// remove every vertex that is not the entry, exit, of contains a function call
void ApiCfgComponent::Simplify() {

  std::vector < rose_addr_t > kill_list;

  BGL_FORALL_VERTICES(vtx,*cfg_,ApiCfg) {
    ApiVertexInfo &vtxi = (*cfg_)[vtx];
    if (vtxi.block->get_address()!=entry_ && vtxi.block->get_address()!=exit_ && !vtxi.EndsInCall()) {
      kill_list.push_back(vtxi.block->get_address());
    }
  }
  KillVertices(kill_list);
}

// disconnect and delete a list of vertices
void ApiCfgComponent::KillVertices(std::vector< rose_addr_t > &kill_list) {

  if (kill_list.empty() == true) {
    return;
  }
  for (rose_addr_t kill_addr : kill_list)  {
    ApiCfgVertex vertex2kill = GetVertexByAddr(kill_addr);
    if (vertex2kill != NULL_VERTEX) {
      DisconnectVertex(vertex2kill);
    }
  }
}

// Fetch the vertex associated with an address (by basic block address)
ApiCfgVertex ApiCfgComponent::GetVertexByAddr(const rose_addr_t addr) const {

  if (addr == INVALID_ADDRESS) return NULL_VERTEX;

  BGL_FORALL_VERTICES(v, *cfg_, ApiCfg) {
    ApiVertexInfo &vertex_info = (*cfg_)[v];
    if (vertex_info.ContainsAddress(addr) == true) {
      return v;
    }
  }
  GDEBUG << "Could not find vertex for address " << addr_str(addr) << LEND;
  return NULL_VERTEX;
}

ApiCfg* ApiCfgComponent::GetCfg() const {

  return cfg_;
}

void ApiCfgComponent::SetCfg(ApiCfg* cfg) {

  this->cfg_ = cfg;
}

rose_addr_t ApiCfgComponent::GetEntryAddr() const {

  return entry_;
}

void ApiCfgComponent::SetEntryAddr(rose_addr_t entry) {

  this->entry_ = entry;
}

rose_addr_t ApiCfgComponent::GetExitAddr() const {

  return exit_;
}

void ApiCfgComponent::SetExitAddr(rose_addr_t exit) {

  this->exit_ = exit;
}

ApiCfgVertex ApiCfgComponent::GetEntryVertex() const {

  return GetVertexByAddr(entry_);
}

ApiCfgVertex ApiCfgComponent::GetExitVertex() const {

  return GetVertexByAddr(exit_);
}

bool ApiCfgComponent::Merge(ApiCfgComponentPtr to_insert, rose_addr_t merge_addr,
    bool preserve_entry) {

  typedef boost::property_map<ApiCfg, boost::vertex_index_t>::type index_map_t;

  typedef boost::iterator_property_map<typename std::vector<ApiCfgVertex>::iterator,
      index_map_t, ApiCfgVertex, ApiCfgVertex&> IsoMap;


  GDEBUG << "Merging " << addr_str(entry_) << " (" << boost::num_vertices(*cfg_)
         << ") with " << addr_str(to_insert->GetEntryAddr())
         << " (" << boost::num_vertices(*(to_insert->GetCfg())) << ")"
         << " at " << addr_str(merge_addr) << LEND;

  // There is something to patch in. The insert_in_calls list contains
  // a list of addresses to patch in to

  ApiCfgVertex merge_vertex = GetVertexByAddr(merge_addr);

  // the call address should be unique in the CFG
  if (merge_vertex == NULL_VERTEX) {

    GWARN << "Could not find call vertex - cannot merge" << LEND;
    return false;
  }

  // A distinct, deep copy of the graph to insert must be made for each address to patch.
  // The deep copy will generate new vertex ID's

  ApiCfgComponent to_insert_copy(*to_insert);
  ApiCfg *cfg_copy = to_insert_copy.GetCfg();

  ApiCfgVertex orig_insert_entry_vertex = to_insert_copy.GetEntryVertex();
  ApiCfgVertex orig_insert_exit_vertex  = to_insert_copy.GetExitVertex();

 if (orig_insert_entry_vertex == NULL_VERTEX || orig_insert_exit_vertex == NULL_VERTEX) {
    GWARN << "Could not find to_insert entry/exit vertices - cannot merge" << LEND;
    return false;
 }


  std::vector<ApiCfgVertex> iso_vec(boost::num_vertices(*cfg_copy));
  IsoMap iso_map(iso_vec.begin(), boost::get(boost::vertex_index, *cfg_copy));

  boost::copy_graph(*cfg_copy, *cfg_, boost::orig_to_copy(iso_map)); // cfg_ += cfg_copy

  GDEBUG << "New CFG has " << boost::num_vertices(*cfg_) << " vertices"
        << " +" << boost::num_vertices(*(to_insert_copy.GetCfg())) << LEND;

  // Assuming that the in_exit_vertex is in the graph. At any time there should only be one
  // non-patched vertex with a given address. This works because the copying is
  // done incrementally

  ApiCfgVertex insert_entry_vertex = iso_map[orig_insert_entry_vertex];
  ApiCfgVertex insert_exit_vertex = iso_map[orig_insert_exit_vertex];

  if (insert_entry_vertex==NULL_VERTEX || insert_exit_vertex==NULL_VERTEX) {
    GWARN << "Could not find to_insert entry/exit vertices - cannot merge" << LEND;
    return false;
  }

  const ApiVertexInfo& merge_info = (*cfg_)[merge_vertex];
  const ApiVertexInfo& insert_entry_info = (*cfg_)[insert_entry_vertex];

  if (exit_ == merge_info.block->get_address()) {
    exit_ = to_insert_copy.GetExitAddr();
  }

  // If the vertex to merge doesn't end in an API call or the target of the merge is the address
  // of the call, then replace the call vertex with the subgraph. Otherwise insert before the
  // vertex to preserve the control flow.

  if (false == merge_info.EndsInCall()) {
    // the vertex to replace is not a call, just replace it with the new graph
    Replace(merge_vertex, insert_entry_vertex, insert_exit_vertex);
  }

  // the vertex ends in call of some type
  else {
    // If the entry point is not to be preserved, then just replace the entry
    // vertex with the body of the call target
    if (!preserve_entry) {

      // This vertex is a call (API or Function)
      if (merge_info.target_address == insert_entry_info.block->get_address()) {

        // the call target is the merge target. Connect the CFGs by replacing
        // the call with the target CFG
        Replace(merge_vertex, insert_entry_vertex, insert_exit_vertex);
      }
      else {
        // the call target is not the merge target. Preserve control flow by
        // prepending the target CFG

        InsertBefore(merge_vertex, insert_entry_vertex, insert_exit_vertex);
      }
      if (entry_ == merge_info.block->get_address()) {
        entry_ = insert_entry_info.block->get_address();
      }
    }
    //  Need to preserve the entry point as the entry point for the new CFG,
    //  otherwise the search indices will be incorrect. Simply insert after
    else {

      if (entry_ == merge_info.block->get_address()) {

        InsertAfter(merge_vertex, insert_entry_vertex, insert_exit_vertex);
        if (merge_info.target_address == insert_entry_info.block->get_address()) {
          ApiVertexInfo& ev_info = (*cfg_)[GetEntryVertex()];
          ev_info.SetType(ApiVertexInfo::UNKN);
        }
      }
    }
  }

  // when merging two components, the APIs must also be merged
  apis_.insert(to_insert->apis_.begin(), to_insert->apis_.end());

  return true;
}

// inserts a graph after a given node
void ApiCfgComponent::InsertBefore(ApiCfgVertex &before_vertex, ApiCfgVertex &in_entry_vertex,
    ApiCfgVertex &in_exit_vertex) {

  ApiVertexInfo &in_entry_info = (*cfg_)[in_entry_vertex]; // entry block to insert
  ApiVertexInfo &in_exit_info  = (*cfg_)[in_exit_vertex];  // exit block to insert
  ApiVertexInfo &before_vertex_info   = (*cfg_)[before_vertex];   // the block to prepend

  GDEBUG << "Inserting before vertices: " << addr_str(before_vertex_info.block->get_address())
         << " with " << addr_str(in_entry_info.block->get_address())
         << ":" << addr_str(in_exit_info.block->get_address()) << LEND;

  std::vector<ApiCfgVertex> edge_kill_list;
  // Connect the exit to successors of the before_vertex

  BGL_FORALL_INEDGES(before_vertex, in_edge,*cfg_, ApiCfg) {
    // get the next vertex
    ApiCfgVertex prev = boost::source(in_edge, *cfg_);
    edge_kill_list.push_back(prev);

    // if the edge doesn't already exist between these vertices. This will catch  and prevent
    // self edges
    if (false == boost::edge(in_entry_vertex, prev, *cfg_).second) {

      // take the in edge and make it refer to next out edge vertex
      boost::add_edge(prev, in_entry_vertex, *cfg_);

      GDEBUG << "Adding edge from "
          << addr_str((*cfg_)[prev].block->get_address()) << " to "
          << addr_str(in_entry_info.block->get_address()) << LEND;
    }
  }

  // connect the entry to the before_vertex
  boost::add_edge(in_exit_vertex, before_vertex, *cfg_);

  // remove the edges in to the before_vertex
  for (const ApiCfgVertex & vtx : edge_kill_list) {
    boost::remove_edge(vtx, before_vertex, *cfg_);
  }
}

// inserts a graph after a given node
   void ApiCfgComponent::InsertAfter(ApiCfgVertex &insert_vertex, ApiCfgVertex &in_entry_vertex,
       ApiCfgVertex &in_exit_vertex) {

  ApiVertexInfo &in_entry_info = (*cfg_)[in_entry_vertex]; // entry block to insert
  ApiVertexInfo &in_exit_info  = (*cfg_)[in_exit_vertex];  // exit block to insert
  ApiVertexInfo &insert_info   = (*cfg_)[insert_vertex];   // the block to remove

  GDEBUG << "Inserting after vertices: " << addr_str(insert_info.block->get_address())
         << " with " << addr_str(in_entry_info.block->get_address())
         << ":" << addr_str(in_exit_info.block->get_address()) << LEND;

  std::vector<ApiCfgVertex> edge_kill_list;
  // Connect the exit to successors of the insert_vertex

  BGL_FORALL_OUTEDGES(insert_vertex, out_edge,*cfg_, ApiCfg) {
    // get the next vertex
    ApiCfgVertex next = boost::target(out_edge, *cfg_);
    edge_kill_list.push_back(next);

    // if the edge doesn't already exist between these vertices. This will catch  and prevent
    // self edges
    if (false == boost::edge(in_exit_vertex, next, *cfg_).second) {

      // take the in edge and make it refer to next out edge vertex
      boost::add_edge(in_exit_vertex, next, *cfg_);

      GDEBUG << "Adding edge from "
             << addr_str(in_exit_info.block->get_address()) << " to "
             << addr_str((*cfg_)[next].block->get_address()) << LEND;
    }
  }

  // connect the entry to the insert_vertex
  boost::add_edge(insert_vertex,in_entry_vertex,*cfg_);

  // remove the edges out of the insert_vertex
  for (const ApiCfgVertex & vtx : edge_kill_list) {
    boost::remove_edge(insert_vertex,vtx,*cfg_);
  }
}

// Replace vertex with a completely new graph. The in_entry_vertex is the start
// of the new graph and in_exit_vertex is the end point of the new graph. out_vertex is where
// the graph will patched in.
void ApiCfgComponent::Replace(ApiCfgVertex &out_vertex, ApiCfgVertex &in_entry_vertex,
    ApiCfgVertex &in_exit_vertex) {

  ApiVertexInfo &in_entry_info = (*cfg_)[in_entry_vertex]; // entry block to insert
  ApiVertexInfo &in_exit_info = (*cfg_)[in_exit_vertex];    // exit block to insert
  ApiVertexInfo &out_info = (*cfg_)[out_vertex]; // the block to remove

  GINFO << "Replacing vertices: " << addr_str(out_info.block->get_address())
         << " with " << addr_str(in_entry_info.block->get_address())
         << ":" << addr_str(in_exit_info.block->get_address()) << LEND;

  if (entry_ == out_info.block->get_address()) {
    entry_ = in_entry_info.block->get_address();
  }
  // removing exit point. Like entry, there can be multiple exits (should this be allowed?)
  if (exit_ == out_info.block->get_address()) {
    exit_ = in_exit_info.block->get_address();
  }

  // for each in-edge to the vertex to remove (out), make the previous vertex refer to the
  // in vertex entry

  BGL_FORALL_INEDGES(out_vertex,edge,*cfg_,ApiCfg) {
    // get the previous vertex (source of the in edge)
    ApiCfgVertex prev = boost::source(edge, *cfg_);

    // this is a special case where the out vertex has an edge to itself. When this happens,
    // then the in vertex should also have an edge to itself

    if ((*cfg_)[prev].block->get_address() == out_info.block->get_address()) {
      boost::add_edge(in_entry_vertex, in_entry_vertex, *cfg_);

      GINFO << "Adding self edge from "
             << addr_str((*cfg_)[prev].block->get_address()) << " to "
             << addr_str(out_info.block->get_address()) << LEND;

    }
    else if (false == boost::edge(prev, in_entry_vertex, *cfg_).second) {
      // make the source of the out refer to the in
      boost::add_edge(prev, in_entry_vertex, *cfg_);

      GDEBUG << "Adding edge from "
             << addr_str((*cfg_)[prev].block->get_address()) << " to "
             << addr_str(in_entry_info.block->get_address()) << LEND;
    }
  }

  // for each out edge of the out vertex, make the in_exit vertex refer to the out next vertex
  BGL_FORALL_OUTEDGES(out_vertex,edge,*cfg_,ApiCfg) {
    // get the next vertex
    ApiCfgVertex next = boost::target(edge, *cfg_);

    // if the edge doesn't already exist between these vertices. This will catch  and prevent
    // self edges
    if (false == boost::edge(in_exit_vertex, next, *cfg_).second) {

      // take the in edge and make it refer to next out edge vertex
      boost::add_edge(in_exit_vertex, next, *cfg_);

      GINFO << "Adding edge from "
             << addr_str(in_exit_info.block->get_address()) << " to "
             << addr_str((*cfg_)[next].block->get_address()) << LEND;
    }
  }

  // disconnect and remove the out vertex
  boost::clear_vertex(out_vertex, *cfg_);
  boost::remove_vertex(out_vertex, *cfg_);
}

void ApiCfgComponent::Print() {

  GINFO << LEND << "Function: " << addr_str(entry_) << LEND;

  BGL_FORALL_VERTICES(vtx,*cfg_,ApiCfg) {
    ApiVertexInfo &vertex_info = (*cfg_)[vtx];

    GINFO << "   " << addr_str(vertex_info.block->get_address()) << " --> ";

    BGL_FORALL_OUTEDGES(vtx,edge,*cfg_,ApiCfg) {
      ApiCfgVertex ov = boost::target(edge,*cfg_);
      ApiVertexInfo &out_vertex_info = (*cfg_)[ov];
      GINFO << addr_str(out_vertex_info.block->get_address()) << " ";
    }

    if (vertex_info.GetType() == ApiVertexInfo::API) {
      GINFO << " (calls API " << vertex_info.api_name << ")";
    }
    GINFO << std::dec << LEND;
  }
}

void ApiCfgComponent::ApiCfgComponentGraphvizVertexWriter::operator()(std::ostream &output,
    const ApiCfgVertex &v) {

  ApiCfg *cfg = cfg_comp->GetCfg();
  const ApiVertexInfo &vertex_info = (*cfg)[v];

  output << "[ label=\"Basic block " << addr_str(vertex_info.block->get_address());

  if (vertex_info.GetType() == ApiVertexInfo::API) {
    output << " contains call to " << vertex_info.api_name;
  }
  else if (vertex_info.GetType() == ApiVertexInfo::CALL) {
    output << " calls " << addr_str(vertex_info.target_address);
  }
  output << "\"";

  if (vertex_info.block->get_address() == cfg_comp->GetEntryAddr()) {
    output << " shape=\"doublecircle\"";
  }
  else if (vertex_info.block->get_address() == cfg_comp->GetExitAddr()) {
    output << " shape=\"doubleoctagon\"";
  }

  output << "]";
}

void ApiCfgComponent::GenerateGraphViz(std::ostream &o) {
  boost::write_graphviz(o, *cfg_, ApiCfgComponentGraphvizVertexWriter(this));
}

// ********************************************************************************************
// * Start of ApiGraph methods
// ********************************************************************************************

// Because a complete copy of the CFGs are made, they must be copied to be consolidated. This
// memory is freed here
ApiGraph::~ApiGraph() {
  Reset();
}

void ApiGraph::Reset() {

  components_.clear();
  xrefs_.clear();
  api_calls_.clear();
  graph_constructed_ = false;
}

ApiCfgComponentPtr ApiGraph::GetComponent(rose_addr_t addr) {

  ApiCfgComponentMapIter fmi = components_.find(addr);
  if (fmi == components_.end()) {
    return NULL;
  }
  return fmi->second;
}

// Build a set of cross references of function calls (from) to target functions (to). This
// function also builds a set of API call addresses for convenience
void ApiGraph::BuildXrefs() {

  const ImportDescriptorMap & idm = global_descriptor_set->get_import_map();
  if (idm.size() == 0) {
    // No imports
    return;
  }

  const CallDescriptorMap & cdm = global_descriptor_set->get_call_map();
  for (const CallDescriptorMap::value_type & pair : cdm) {

    const CallDescriptor & cd = pair.second;
    const CallTargetSet &call_targets = cd.get_targets();

    rose_addr_t from = cd.get_address();

    // record this xref
    if (!call_targets.empty()) {
      // to address of (first) target   // from address of call
      rose_addr_t to =  *(call_targets.begin());
      xrefs_.insert(XrefMapEntry(from, to));
    }

    // check for API call (which will not have a target because the import code is not in the
    // current image)
    const ImportDescriptor *imp = cd.get_import_descriptor(); // is this an import?
    if (imp != NULL) {
      api_calls_.insert(from);
      xrefs_.insert(XrefMapEntry(from, imp->get_address()));
    }
  }

  GDEBUG << "XREFS:" << LEND;
  for (const XrefMap::value_type &p : xrefs_) {
    rose_addr_t to = p.second;
    rose_addr_t from = p.first;
    GDEBUG << "to = " << addr_str(to) << " from = " << addr_str(from) << LEND;
  }

  GDEBUG << "API Calls" << LEND;
  for (const AddrSet::value_type &p : api_calls_) {
    GDEBUG << "call = " << addr_str(p) << LEND;
  }
}

rose_addr_t ApiCfgComponent::ConsolidateReturns(BlockSet & retns) {

  std::vector < rose_addr_t > kill_list; // the list of vertices (by address) to remove

  ApiCfgVertex exit_vertex = GetExitVertex();
  if (exit_vertex == NULL_VERTEX) {
    return INVALID_ADDRESS;
  }

  ApiVertexInfo &exit_info = (*cfg_)[exit_vertex]; // the vertex that corresponds to exit_

  for (const BlockSet::value_type & block : retns) {
    if (block->get_address() != exit_info.block->get_address()) { // Not the exit vertex
      ApiCfgVertex vtx = GetVertexByAddr(block->get_address());
      if (vtx == NULL_VERTEX) {
        continue;
      }

      // make the predecessors of the vertex to remove point to the one true return
      BGL_FORALL_INEDGES(vtx,in_edge,*cfg_,ApiCfg) {
        ApiCfgVertex src = boost::source(in_edge, *cfg_);
        boost::add_edge(src, exit_vertex, *cfg_);
      }
      // queue this vertex to be removed
      kill_list.push_back(block->get_address());
    }
  }

  KillVertices(kill_list);

  return exit_info.block->get_address();
}


// collapse empty functions (i.e. functions that do not contain API calls)
void ApiGraph::ConsolidateEmptyFunctions() {

  GINFO << "Consolidating empty functions" << LEND;

  std::set< rose_addr_t > kill_list;

  CallDescriptorMap cdm = global_descriptor_set->get_call_map();
  for (CallDescriptorMap::value_type & pair : cdm) {

    const CallDescriptor & cd = pair.second;
    rose_addr_t call_address = cd.get_address();

    FunctionDescriptor *call_target_fd = cd.get_function_descriptor();
    FunctionDescriptor *containing_fd  = cd.get_containing_function();

    if (call_target_fd != NULL) {

      ApiCfgComponentPtr empty_cfg_comp = GetComponent(call_target_fd->get_address());
      ApiCfgComponentPtr calling_cfg_comp = GetComponent(containing_fd->get_address());

      if (empty_cfg_comp != NULL && calling_cfg_comp!=NULL) {
        if (empty_cfg_comp->ContainsCalls() == false) {

          ApiCfgVertex call_vertex = calling_cfg_comp->GetVertexByAddr(call_address);
          if (call_vertex != NULL_VERTEX) {

            // disconnect the call to the empty component. This will connect the vertices before
            // the call vertex directly to the subsequent vertices.

            ApiCfg *calling_cfg = calling_cfg_comp->GetCfg();
            ApiVertexInfo &call_vtx_info = (*calling_cfg)[call_vertex];

            if (call_vtx_info.block->get_address() == calling_cfg_comp->GetEntryAddr()) {

              // setting the type to UNKN ensures it will not be followed
              call_vtx_info.type = ApiVertexInfo::UNKN;

              GDEBUG << "Preserving graph entry "
                     << addr_str(call_vtx_info.block->get_address()) << LEND;
            }
            else {

              calling_cfg_comp->DisconnectVertex(call_vertex);

              if (kill_list.find(empty_cfg_comp->GetEntryAddr()) == kill_list.end()) {
                kill_list.insert(empty_cfg_comp->GetEntryAddr());
              }
            }
          }
        }
      }
    }
  }

  // remove the remaining empty components
  for (const ApiCfgComponentMap::value_type &c : components_) {
    ApiCfgComponentPtr cfg_comp = c.second;
    if  (cfg_comp != NULL) {
      if (cfg_comp->ContainsCalls() == false) {
        kill_list.insert(cfg_comp->GetEntryAddr());
      }
    }
  }

  for (rose_addr_t addr : kill_list) {
    ApiCfgComponentMapIter target = components_.find(addr);
    if (target != components_.end()) {
      GDEBUG << "Removing empty function " << addr_str(addr) << LEND;
      components_.erase(target);
    }
  }
  GINFO << "All empty functions removed" << LEND;
}

void ApiGraph::ConsolidateThunks() {

  GINFO << "Consolidating thunks " << LEND;

  // The list of functions that were merged into other functions
  std::set< rose_addr_t > merge_list;
  ApiCfgComponentMap replace_list;

  const CallDescriptorMap & cdm = global_descriptor_set->get_call_map();
  for (const CallDescriptorMap::value_type & pair : cdm) {

    const CallDescriptor & cd = pair.second;
    rose_addr_t call_address = cd.get_address();
    ApiCfgComponentPtr insert_in=NULL;
    ApiCfgComponentPtr insert_to=NULL;

    FunctionDescriptor *call_target_fd = cd.get_function_descriptor(); // FD of call target
    FunctionDescriptor *containing_fd  = cd.get_containing_function(); // FD of containing function

    if (call_target_fd != NULL) {
      if (call_target_fd->is_thunk()) {

        rose_addr_t insert_in_addr = containing_fd->get_address();
        ApiCfgComponentMapIter in_iter = components_.find(insert_in_addr);
        if (in_iter != components_.end()) {
          insert_in = in_iter->second;
        }

        rose_addr_t insert_to_addr = call_target_fd->get_address();
        ApiCfgComponentMapIter to_iter = components_.find(insert_to_addr);
        if (to_iter != components_.end()) {
          insert_to = to_iter->second;
        }

        // merge thunks into their calling positions
        if (insert_in!=NULL && insert_to!=NULL) {

          GDEBUG << "Merging thunk call at " << addr_str(call_address) << LEND;

          rose_addr_t old_entry_addr = insert_in->GetEntryAddr();

          if (insert_in->Merge(insert_to, call_address, false) == true) {

            // update the entry if it changed. If the entry changed, then the new merged component
            // should not be erased
            if (old_entry_addr != insert_in->GetEntryAddr()) {
              replace_list.insert(ApiCfgComponentMapEntry(insert_in->GetEntryAddr(), insert_in));
              merge_list.insert(old_entry_addr);
            }
            if (merge_list.find(insert_to->GetEntryAddr()) == merge_list.end()) {
              merge_list.insert(insert_to->GetEntryAddr());
            }
         } else {
            OWARN << "Warning: Thunk consolidation failed. Some results may be incorrect." << LEND;
         }
        }
      }
    }
  }

  // remove the functions that were merged
  for (rose_addr_t addr : merge_list) {
    ApiCfgComponentMapIter target = components_.find(addr);
    if (target != components_.end()) {
      GDEBUG << "Removing thunk " << addr_str(addr) << LEND;
      components_.erase(target);
    }
  }

  for (const ApiCfgComponentMap::value_type & r : replace_list) {
    rose_addr_t key = r.first;
    GDEBUG << "Replacing thunk " << addr_str(key) << LEND;
    const ApiCfgComponentPtr & value = r.second;

    if (components_.find(key) != components_.end()) {
      components_[key] = value;
    }
    else {
      components_.insert(ApiCfgComponentMapEntry(key, value));
    }
  }
  GINFO << "All thunks removed" << LEND;
}

bool ApiGraph::MergeComponents(ApiMergeInfo &merge_info, bool preserve_entry) {

  bool merge_result = false;

  // When merging, the different parameters much be merged
  ApiCfgComponentPtr src_cmp = GetComponent(merge_info.src_cmp_addr);
  ApiCfgComponentPtr tgt_cmp = GetComponent(merge_info.tgt_cmp_addr);

  // Fetch the components needed for the merge

  if (src_cmp!=NULL && tgt_cmp!=NULL) {

    merge_result = src_cmp->Merge(tgt_cmp, merge_info.from_addr, preserve_entry);
    if (merge_result == true) {

      // re-simplify the merged graph to remove extraneous nodes
      src_cmp->Simplify();

      // remove the xref for this specific merge because it no longer exists
      RemoveXref(merge_info.from_addr, merge_info.to_addr);
    }
  }
  if (!merge_result) {
    OWARN << "Merge failed: " << merge_info.ToString() << LEND;
  }
  return merge_result;
}


size_t ApiGraph::Build() {

  GINFO << "Building graphs" << LEND;

  if (graph_constructed_ == true) {
     GDEBUG << "Graph already constructed - Rebuilding" << LEND;
     Reset();
  }

  FunctionDescriptorMap &fm = global_descriptor_set->get_func_map();

  // build all the xrefs needed to process the graph
  BuildXrefs();

  // In the first pass the CFGs are generated and copied into function map
  for (FunctionDescriptorMap::value_type & fdpair : fm)  {

    FunctionDescriptor& fd = fdpair.second;

    // At this point the true exit is not known
    ApiCfgComponentPtr cfg_comp(new ApiCfgComponent());

    cfg_comp->Initialize(fd, api_calls_, xrefs_);

    // save the simplified CFG
    components_.insert(ApiCfgComponentMapEntry(cfg_comp->GetEntryAddr(), cfg_comp));
  }

  // Once the components have been initialized and simplified to just API calls, run two analysis
  // passes to collapse thunks and prune out routines that do not call APIs

  ConsolidateThunks();

  ConsolidateEmptyFunctions();

  // Clean up xrefs based on simplification

  for (const ApiCfgComponentMap::value_type & r : components_) {
    GDEBUG << "Final component " << addr_str(r.first) << LEND;
  }

  graph_constructed_ = true;

  return components_.size();
}

void ApiGraph::RemoveComponent(rose_addr_t addr) {

  GDEBUG << "Removing component " << addr_str(addr) << LEND;
  ApiCfgComponentMapIter ci = components_.find(addr);
  if (ci != components_.end()) {
    components_.erase(ci);
    UpdateXrefs();
  }
}

void ApiGraph::UpdateXrefs() {

  for (XrefMapIter x = xrefs_.begin(); x != xrefs_.end(); ) {
    rose_addr_t to = x->second;

    // either the to or from are no longer components - remove
    if (components_.find(to) == components_.end()) {
      xrefs_.erase(x++);
    }
    else {
      ++x;
    }
  }
}

void ApiGraph::GenerateGraphViz(std::ostream & o) {

  for (const ApiCfgComponentMap::value_type & f : components_) {
    const ApiCfgComponentPtr & cfg_comp = f.second;
    cfg_comp->GenerateGraphViz(o);
  }
}

// The current search algorithm starts by using the connected_components function to determine
bool ApiGraph::Search(ApiSig & sig, ApiSearchResultVector * results) {

  if (graph_constructed_ == false || sig.api_calls.empty() == true) {
    OWARN << "Invalid signature for " << sig.name << LEND;
    return false;
  }

  // Initialize the Search Executor with the necessary elements needed for a search
  search_executor_.Initialize(this);

  return search_executor_.Search(sig, results);

}

// Print the APIGraph
void ApiGraph::Print() {

  if (!graph_constructed_)
    return;

  GINFO << "Printing API Block Graph" << LEND;

  for (const ApiCfgComponentMap::value_type & f2b : components_)  {
    const ApiCfgComponentPtr & cfg_comp = f2b.second;
    cfg_comp->Print();
  }
}

ApiCfgComponentPtr ApiGraph::GetContainingComponent(const rose_addr_t addr) const {

  for (const ApiCfgComponentMap::value_type & ci : components_) {
    const ApiCfgComponentPtr & comp = ci.second;
    if (addr == ci.first || comp->ContainsAddress(addr)) {
      return comp;
    }
  }
  return NULL;
}

void ApiGraph::RemoveXref(rose_addr_t from, rose_addr_t to) {

  for (XrefMapIter x = xrefs_.begin(); x != xrefs_.end(); ) {
    rose_addr_t xfrom = x->first;
    rose_addr_t xto = x->second;

    // either the to or from are no longer components - remove
    if (xto==to && xfrom==from) {
      xrefs_.erase(x++);
    }
    else {
      ++x;
    }
  }
}

// ********************************************************************************************
// * Start of ApiSearchManager methods
// ********************************************************************************************

// Update the progress of the search and display the progress bar (if necessary)
void ApiSearchManager::UpdateProgress(ApiSig &sig) {

  static Sawyer::ProgressBar<size_t, ApiSearchProgressSuffix> *progressBar = NULL;
  if (!progressBar) {
    Sawyer::ProgressBarSettings::initialDelay(0.0);
    Sawyer::ProgressBarSettings::minimumUpdateInterval(0.0);
    progressBar = new Sawyer::ProgressBar<size_t, ApiSearchProgressSuffix>(olog[MARCH], "");

  }
  progressBar->suffix(ApiSearchProgressSuffix(&sig,sig_count_));
  progressBar->value(sig_progress_);

  sig_progress_++;
}

std::ostream& operator<<(std::ostream &o, const ApiSearchProgressSuffix &suffix) {
  suffix.print(o);
  return o;
}

bool ApiSearchManager::Search(SigPtrVector &sigs, ApiSearchResultVector &results) {

  sig_count_ = sigs.size();
  sig_progress_ = 0;

  for (ApiSig &sig : sigs) {
    GINFO << "Processing signature: " << sig.name << LEND;

    UpdateProgress(sig);

    ApiSearchResultVector search_result;
    if (graph_.Search(sig, &search_result) == true) {
      results.insert(results.end(), search_result.begin(), search_result.end());
    }
  }
  return true;
}

} // namespace pharos
