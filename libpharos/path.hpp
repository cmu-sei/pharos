// Copyright 2018-2024 Carnegie Mellon University.  See LICENSE file for terms.
#ifndef Pharos_Path_H
#define Pharos_Path_H

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/graph/graph_utility.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/graph/iteration_macros.hpp>
#include <boost/graph/properties.hpp>
#include <boost/property_map/property_map.hpp>
#include <boost/algorithm/string.hpp>
// #include <z3++.h>

#include <Sawyer/GraphBoost.h>
// #include "rose.hpp"
// #include <BinaryZ3Solver.h>

#include "znode.hpp"
#include "stkvar.hpp"
#include "pdg.hpp"
#include "misc.hpp"
#include "defuse.hpp"

// Install new properties on the graph. This allows us to use the
// poper boost interior properties. Checkout the documentation on
// boost PropertyGraphs for more information on properties in graphs
namespace boost {
enum vertex_calltrace_t { vertex_calltrace };
BOOST_INSTALL_PROPERTY(vertex, calltrace);
}

namespace pharos {

struct CallFrameValue {
  CallFrameValue(unsigned i, TreeNodePtr o, TreeNodePtr n)
    : index(i), old_var(o), new_var(n) { }
  unsigned index;
  TreeNodePtr old_var, new_var;
};

using CallFrameValueList = std::vector<CallFrameValue>;

// This class will properly clone, substitute and mangage symbolic
// values.

class CallFrameManager {
 private:
  // This list is effectively managed as a stack, simulating a program
  // stack with cloned treenodes
  CallFrameValueList frame_vars_;
  TreeNodePtr create_frame_tnp(const TreeNodePtr old_tnp, unsigned id);
  TreeNodePtr substitute_tnp(const TreeNodePtr tnp, unsigned id);
 public:
  void resetAll();
  void pop(unsigned id);
  void print();
  const CallFrameValueList& get_clone_list();
  SymbolicValuePtr create_frame_value(const SymbolicValuePtr value, unsigned id);
  // SymbolicValuePtr substitute_value(const SymbolicValuePtr value, unsigned id);
};

class CallTraceDescriptor;
using CallTraceDescriptorPtr = std::shared_ptr<CallTraceDescriptor>;
using PathCallTraceDescriptorPtrList = std::vector<CallTraceDescriptorPtr>;

using CfgVertex = boost::graph_traits<CFG>::vertex_descriptor;
using CfgEdge = boost::graph_traits<CFG>::edge_descriptor;

using CfgEdgeValueMap = std::map<CfgEdge, SymbolicValuePtr>;
using CfgEdgeExprMap = std::map<CfgEdge, z3::expr>;

// Custom graph type for a call trace
using CallTraceGraph =
  boost::adjacency_list< boost::setS,
                         boost::vecS,
                         boost::bidirectionalS,
                         // CallTraceDescriptors are attached to
                         // vertices because some functions are
                         // not called
                         boost::property<boost::vertex_calltrace_t, CallTraceDescriptorPtr >,
                         // No edge or graph properties (yet)
                         boost::no_property, boost::no_property >;

// Allow access via boost get/put
using CallTraceMap = boost::property_map<CallTraceGraph, boost::vertex_calltrace_t>::type;
using calltrace_value_t = typename boost::property_traits<CallTraceMap>::value_type;
using calltrace_reference_t = typename boost::property_traits<CallTraceMap>::reference;

// Make this a bit easier to read
using CallTraceGraphVertex = boost::graph_traits<CallTraceGraph>::vertex_descriptor;
using CallTraceGraphEdge = boost::graph_traits<CallTraceGraph>::edge_descriptor;
using CallTraceGraphVertexIter = CallTraceGraph::vertex_iterator;

// Some constants for comparing and convenience
constexpr unsigned    CONVENTION_PARAMETER_SIZE = 32;
constexpr rose_addr_t INVALID_ADDRESS = (rose_addr_t)(-1);
constexpr unsigned    INVALID_INDEX = (unsigned)(-1);
const CfgVertex       NULL_CFG_VERTEX = boost::graph_traits <CFG>::null_vertex();
const CallTraceGraphVertex NULL_CTG_VERTEX = boost::graph_traits <CallTraceGraph>::null_vertex();

// Information about edges, such as the conditions needed to take an
// edge
struct CfgEdgeInfo {

  // default stuff
  CfgEdgeInfo(z3::context & ctx) : edge_expr(ctx), cond_expr(ctx) { }

  CfgEdge edge;
  unsigned index;
  z3::expr edge_expr;
  z3::expr cond_expr;

  // The name of the edge (edge_SRC-DST)
  std::string edge_str;
  std::string cond_str;

  // The call_trace containing this edge
  CallTraceDescriptorPtr call_trace_desc;

  // convenience fields
  rose_addr_t edge_src_addr, edge_tgt_addr;
};

using CfgEdgeInfoVector = std::vector<CfgEdgeInfo>;
using CfgEdgeInfoMap = std::map<CfgEdge, CfgEdgeInfo>;

// This is a class for actual values needed for a traversal. Right now this
// is an unsigned value because it is the lowest common denominator of
// sorts ... it expresses values most completely and everything can be
// reinterpreted as needed

template<typename T>
struct ConcreteValue {
  ConcreteValue(T elm, uint64_t val)
    : element(elm), concrete_value(val) { }
  T element;

  // Currently store the concrete value as unsigned 64b value. This is
  // the widest type available and matches how symbolic value integers
  // are stored. If we had better type support, this could be refined
  uint64_t concrete_value;

  // A way to compare things in this vector
  bool operator==(T& other) {
    return element == other.element;
  }
};

// There are basically three types of values that can influence paths:
// 1. Parameters (incoming, return values, and outgoing)
// 2. Locals
// 3. Global variables

using ConcreteParameter = ConcreteValue<ParameterDefinition const &>;
using ConcreteStackVariable = ConcreteValue<StackVariable>;

using ExprMap = std::map<std::string, z3::expr>;

// We need a better way to
// using ConcreteGlobalVariable = ConceteValue<GlobalMemoryDescriptor>;

// This structure contains a selected path and necessary values to
// take that path
struct Path {

  // A traversal is made of edges that are actually taken
  CfgEdgeInfoVector traversal;

  // These are all the raw values (leaf nodes) required to take the
  // path
  ExprMap value_exprs;

  // This is the call trace element for this solution from entry to
  // exit
  CallTraceDescriptorPtr call_trace_desc;

  // here are all numeric because the tree node variables are all
  // bitvector memory
  std::vector<ConcreteParameter> required_param_values;
  std::vector<ConcreteParameter> required_ret_values;
  std::vector<ConcreteStackVariable> required_stkvar_values;

  // TODO: Figure out the global variable thing
  // std::vector<ConcreteGlobalVariable> required_global_values;
};

// A call trace descriptor captures the elements of the call trace
// (function and call descriptors) in one type. This is done from the
// perspective of the vertex as opposed to edge because the first
// element will have no caller (i.e. no incoming edge).
class CallTraceDescriptor {
 private:

  // this can never be null. The trace must always have a function
  const FunctionDescriptor& function_descriptor_;

  // This can be null, for example the first element in the trace will
  // not be called

  const CallDescriptor* call_descriptor_;

  CallTraceDescriptorPtr prev_call_trace_desc_;

  // index the call trace to uniquely identify it
  unsigned index_;

  CfgEdgeValueMap edge_values_;

  // These values will be part of the frame values
  ParamVector parameters_, return_values_;
  ParamVector called_from_parameters_, called_from_return_values_;
  std::vector<StackVariable> stkvars_;

  // values generated on the traversal
  ExprMap value_exprs_;

  // expressions to describe the call trace in Z3 terms
  z3::expr_vector cfg_conditions_;
  z3::expr_vector value_constraints_;
  CfgEdgeExprMap edge_constraints_;

  // Information about edges in the cfg for this call_trace
  CfgEdgeInfoMap edge_info_;

 public:

  CallTraceDescriptor(const FunctionDescriptor& fd,
                      const CallDescriptor* cd, unsigned i, z3::context & ctx)
    : function_descriptor_(fd), call_descriptor_(cd), index_(i),
      // These z3 structures require a context
      cfg_conditions_(ctx),
      value_constraints_(ctx) {  }

  // The call can be null, if it is the root of the trace (i.e. not
  // called). Otherwise it is the caller function
  const CallDescriptor* get_call() const;
  void set_caller(CallTraceDescriptorPtr c);

  CallTraceDescriptorPtr get_caller() const;
  const FunctionDescriptor& get_function() const;

  // from the function & call
  const std::vector<StackVariable>& get_stack_variables() const;
  const ParamVector& get_parameters() const;
  const ParamVector& get_return_values() const;
  const ParamVector& get_called_from_parameters() const;
  const ParamVector& get_called_from_return_values() const;

  void add_stack_variable(StackVariable new_stkvar);
  void add_parameter(ParameterDefinition const & old_param,
                     SymbolicValuePtr new_value);
  void add_called_from_parameter(ParameterDefinition const & old_param,
                                 SymbolicValuePtr new_value);
  void add_return_value(ParameterDefinition const & old_param,
                        SymbolicValuePtr new_value);
  void add_called_from_return_value(ParameterDefinition const & old_param,
                                    SymbolicValuePtr new_value);

  void create_frame(CallFrameManager& valmgr);

  bool operator==(const CallTraceDescriptor& other);

  const CfgEdgeValueMap& get_edge_values();

  z3::expr_vector get_cfg_conditions();
  void add_cfg_condition(z3::expr cond);

  z3::expr_vector get_value_constraints();
  void add_value_constraint(z3::expr vconst);

  const CfgEdgeExprMap& get_edge_constraints();
  void add_edge_constraint(CfgEdge edge, z3::expr constraint);

  CfgEdgeInfoMap get_edge_info_map();

  boost::optional<CfgEdgeInfo> get_edge_info(rose_addr_t addr);
  void add_edge_info(CfgEdgeInfo ei);

  unsigned get_index() const;
};

using PathPtr = std::shared_ptr<Path>;
using PathPtrList = std::vector<PathPtr>;

// This is the main traversal finding class
class PathFinder : public Z3PathAnalyzer {

 private:

  const DescriptorSet& ds_;

  struct FindPathError : std::runtime_error {
    using std::runtime_error::runtime_error;
  };

  struct SolverDeleter {
    bool owned;
    void operator()(PharosZ3Solver *s) const { if (owned) delete s; }
    explicit SolverDeleter(bool owned_ = true) : owned{owned_} {}
  };

  // We will need Z3 for this analysis
  std::unique_ptr<PharosZ3Solver, SolverDeleter> z3_;

  // Indicates that the traversal was found in it's entirety
  bool path_found_ = false;

  // This value will be used to uniquely identify frames
  unsigned frame_index_ = 0;

  // Flag to save SMT
  bool save_z3_output_ = false;

  // The goal for the analysis.
  rose_addr_t goal_address_ = INVALID_ADDRESS;

  // The start address of the analysis.
  rose_addr_t start_address_ = INVALID_ADDRESS;

  CallTraceGraph call_trace_;

  PathPtrList path_;

  std::vector<std::string> z3_output_;

  bool detect_recursion();

  TreeNodePtr evaluate_model_value(TreeNodePtr tn, const ExprMap& modelz3vals);

  void generate_call_trace(CallTraceGraphVertex caller_vtx,
                           const FunctionDescriptor* fd,
                           const CallDescriptor* cd,
                           std::vector<rose_addr_t>& trace_stack);

  const PharosZ3Solver& get_z3();

  bool analyze_path_solution();

  void generate_chc();

  bool evaluate_path();

  CallTraceDescriptorPtr create_call_trace_element(CallTraceGraphVertex src_vtx,
                                                   const FunctionDescriptor* fd,
                                                   const CallDescriptor* cd,
                                                   CallFrameManager& valmgr);

  // Find the start & goal elements that constrain the traversal
  bool generate_path_constraints(z3::expr& start_constraint,
                                 z3::expr& goal_constraint);

  // The CFG conditions are the Z3 representation of the control flow
  // graph structure
  bool generate_cfg_constraints(CallTraceDescriptorPtr call_trace_desc);

  // The mapping from CFG edge to the conditions under which that edge
  // is taken.
  bool generate_edge_constraints(CallTraceDescriptorPtr call_trace_desc);

  void propagate_edge_conditions(CallTraceDescriptorPtr call_trace_desc,
                                 CfgEdgeExprMap& edge_conditions);

  bool generate_edge_conditions(CallTraceDescriptorPtr call_trace_desc,
                                CfgEdgeExprMap& edge_conditions);

  bool generate_value_constraints();

  // This must be done at a global level
  void assign_traversal_values(PathPtr trv, ExprMap& modelz3vals);

 public:

  PathFinder(const DescriptorSet& ds);
  PathFinder(const DescriptorSet& ds, PharosZ3Solver & solver);
  ~PathFinder();
  bool path_found() const;
  bool find_path(rose_addr_t start_addr,
                 rose_addr_t goal_addr);

  void set_goal_addr(rose_addr_t g);
  void set_start_addr(rose_addr_t s);
  rose_addr_t get_goal_addr() const;
  rose_addr_t get_start_addr() const;
  PathPtrList get_path() const;
  void save_z3_output();
  std::string get_z3_output();
  void save_call_trace(std::ostream& o);
  void print_call_trace();

  // From Z3PathAnalyzer
  void setup_path_problem(rose_addr_t source, rose_addr_t target) override;
  std::ostream & output_problem(std::ostream & stream) const override;
  z3::check_result solve_path_problem() override;
  std::ostream & output_solution(std::ostream & stream) const override;
};

// These are utilities used by the pathfinder utility functions for
// graph elements. We may wish to move some of these to Pharos proper.
std::string edge_str(CfgEdge e, const CFG& cfg);
std::string edge_name(CfgEdge e, const CFG& cfg);
std::string edge_cond(CfgEdge e, const CFG& cfg);
std::string vertex_str(CfgVertex e, const CFG& cfg);
rose_addr_t vertex_addr(CfgVertex e, const CFG& cfg);
rose_addr_t get_address_from_treenode(TreeNodePtr tnp);



} // end namespace pharos

#endif
