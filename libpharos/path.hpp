#ifndef Pharos_Path_H
#define Pharos_Path_H

#include <rose.h>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graph_utility.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/graph/iteration_macros.hpp>
#include <boost/algorithm/string.hpp>
#include <Sawyer/GraphBoost.h>
#include <BinaryZ3Solver.h>

#include "stkvar.hpp"
#include "pdg.hpp"
#include "misc.hpp"
#include "defuse.hpp"

namespace pharos {

typedef boost::graph_traits<CFG>::vertex_descriptor CfgVertex;
typedef boost::graph_traits<CFG>::edge_descriptor CfgEdge;
typedef boost::graph_traits<FCG>::vertex_descriptor FCGVertex;

// Some constants for comparing and convenience
const rose_addr_t INVALID_ADDRESS = (rose_addr_t)(-1);
const CfgVertex NULL_VERTEX = boost::graph_traits < CFG >::null_vertex();

// Information about edges, such as the conditions needed to take an
// edge
struct EdgeInfo {

  // default stuff
  EdgeInfo(z3::context *ctx) : edge_expr(*ctx), cond_expr(*ctx) { }
  EdgeInfo(const EdgeInfo&) = default;
  EdgeInfo(EdgeInfo && ie) = default;
  ~EdgeInfo() = default;
  EdgeInfo& operator=(const EdgeInfo&) = default;
  EdgeInfo& operator=(EdgeInfo&) = default;

  CfgEdge edge;

  z3::expr edge_expr;
  z3::expr cond_expr;

  // The name of the edge (edge_SRC-DST)
  std::string edge_str;
  std::string cond_str;

  // The function containing this edge
  FunctionDescriptor* fd;

  // convenience fields
  rose_addr_t edge_src_addr, edge_tgt_addr;
};

// This is JSG's extension of the ROSE Z3 solver, which is close but
// not really ideal for what we want.
//
// Also note that I've copied the Rose::BinaryAnalysis::Z3Solver and
// renamed it
class PharosZ3Solver : public Rose::BinaryAnalysis::Z3Solver {
 public:
  PharosZ3Solver()
    : Rose::BinaryAnalysis::Z3Solver(Rose::BinaryAnalysis::SmtSolver::LM_LIBRARY) { }
  z3::expr treenode_to_z3(const TreeNodePtr tnp);

  z3::expr to_bool(z3::expr z3expr);
  z3::expr to_bv(z3::expr z3expr);

  // Z3 utility routines because expr vectors are weird
  z3::expr mk_and(z3::expr_vector& args);
  z3::expr mk_or(z3::expr_vector& args);

  // Must expose the cast function to get everything in a uniform type
  z3::expr z3type_cast(z3::expr z3expr,
                       Rose::BinaryAnalysis::SmtSolver::Type from_type,
                       Rose::BinaryAnalysis::SmtSolver::Type to_type);
};

// This is a templated class for actual values needed for a
// path. Right now this is an unsigned value because it is the lowest
// common denominator of sorts ... it expresses values most completely
// and everything can be reinterpreted as needed

template<typename T>
struct ConcreteValue {
  ConcreteValue(T elm, unsigned val)
    : element(elm), concrete_value(val) { }
  T element;

  // Currently store the concrete value as unsigned. If we had better
  // type support, this could be refined
  unsigned concrete_value;

  // A way to compare things in this vector
  bool operator==(T& other) {
    return element == other.element;
  }
};

// There are basically three types of values that can influence paths:
// 1. Parameters (incoming, return values, and outgoing)
// 2. Locals
// 3. Global variables

typedef ConcreteValue<ParameterDefinition> ConcreteParameter;
typedef ConcreteValue<StackVariable> ConcreteStackVariable;

// JSG has no idea how to handle global variables yet.
// typedef ConceteValue<GlobalMemoryDescriptor> ConcreteGlobalVariable;

// This structure holds the pa
struct FunctionSearchParameters {
  FunctionDescriptor* fd;
  rose_addr_t start_addr, goal_addr;
  FunctionSearchParameters(FunctionDescriptor* f,
                           rose_addr_t s, rose_addr_t g)
    : fd(f), start_addr(s), goal_addr(g) { }
};

// This structure contains a selected path and necessary values
struct PathTraversal {

  // A traversal is made of edges that span functions
  std::vector<EdgeInfo> path;

  // These are all the raw values (leaf nodes) required to trigger the
  // path
  std::map<std::string, z3::expr> value_exprs;

  // here are all numeric because the tree node variables are all
  // bitvector memory
  std::vector<ConcreteParameter> required_param_values;
  std::vector<ConcreteStackVariable> required_stkvar_values;
  // TODO: Figure out the global variable thing
  // std::vector<ConcreteGlobalVariable> required_global_values;

  rose_addr_t start_addr, goal_addr;

  // This is the function for this solution from entry to exit
  FunctionDescriptor* function;
};

// No real analysis happens here, the solution is just a data
// container for part of a path. Each solution is really a path
// towards a target vertex. Each path element will basically be a
// function trace for a path.
struct PathSegmentInfo {

 public:

  PathSegmentInfo();

  // // The from/to for the found path
  // rose_addr_t from_address, to_address;

  // thae start and end addresses for the current function
  rose_addr_t start_addr, goal_addr;

  // This is the function for this solution from entry to exit
  FunctionDescriptor* function;

  // values generated on the path
  std::map<std::string, z3::expr> value_exprs;

  // Vectors of constraints for this segment
  std::vector<z3::expr> cfg_conditions;
  std::vector<z3::expr> edge_constraints;
  std::vector<z3::expr> value_constraints;

  // Information about edges in the cfg for this segment
  std::vector<EdgeInfo> edge_info;

}; // End PathSegmentInfo

typedef std::shared_ptr<PathSegmentInfo> PathSegmentInfoPtr;
typedef std::vector<PathSegmentInfoPtr> PathSegmentInfoPtrList;

typedef std::shared_ptr<PathTraversal> PathTraversalPtr;
typedef std::vector<PathTraversalPtr> PathTraversalPtrList;


// The segment finder is the main class for translating a CFG into a
// set of z3 assertions. It generates the constraints for the path
class SegmentFinder {
 private:


  // Access to the Z3 internals by extending the ROSE Z3 class. We
  // need to do this specifically to gain access to the Z3
  // representation of treeenodes. Additional features include
  // convenience functions for wrapping Z3 conversion functions.
  PharosZ3Solver* z3_;

  // The path found for this segment
  PathSegmentInfoPtr segment_info_;

  // The CFG conditions are the Z3 representation of the control flow
  // graph structure
  bool generate_cfg_constraints();

  // The mapping from CFG edge to the conditions under which that edge
  // is taken.
  bool generate_edge_constraints();
  void propagate_edge_conditions(std::map<CfgEdge, z3::expr>& edge_conditions);
  bool generate_edge_conditions(std::map<CfgEdge, z3::expr>& edge_conditions);

  // the value constraints needed for a path
  bool generate_value_constraints(const PathSegmentInfoPtrList* analyzed_segments);

 public:

  SegmentFinder(PharosZ3Solver* z3);
  ~SegmentFinder();
  bool analyze_segment(rose_addr_t start_addr,
                       rose_addr_t goal_addr,
                       FunctionDescriptor* fd,
                       const PathSegmentInfoPtrList* analyzed_segments);


  PathSegmentInfoPtr get_segment_info();
  rose_addr_t get_segment_start_addr() const;
  void set_segment_start_addr(rose_addr_t saddr);
  rose_addr_t get_segment_goal_addr() const;
  void set_segment_goal_addr(rose_addr_t gaddr);
  FunctionDescriptor* get_fd() const;
};

// This is the main path finding class
class PathFinder {

 private:

  // We will need Z3 for this analysis
  PharosZ3Solver z3_;

  // Indicates that the path was found in it's entirety
  bool path_found_;

  // Flag to save SMT
  bool save_z3_output_;

  // Info about the  done from the goal back to the start
  PathSegmentInfoPtrList path_segments_;

  // This is the analysis done from the goal back to the start
  PathTraversalPtrList path_traversal_;

  // The goal for the analysis.
  rose_addr_t goal_address_;

  // The start address of the analysis.
  rose_addr_t start_address_;

  std::vector<std::string> z3_output_;

  bool compute_reachability(rose_addr_t start_addr,
                            rose_addr_t goal_addr,
                            std::vector<FunctionDescriptor*>& reachable_funcs);

  const PharosZ3Solver& get_z3();

  bool analyze_path_solution();

  bool evaluate_path();

  // This must be done at a global level
  void assign_traversal_values(PathTraversalPtr trv,
                               std::map<std::string, z3::expr> modelz3vals);

 public:

  PathFinder();
  bool path_found() const;
  bool find_path(rose_addr_t start_addr,
                 rose_addr_t goal_addr);

  void set_goal_addr(rose_addr_t g);
  void set_start_addr(rose_addr_t s);
  rose_addr_t get_goal_addr() const;
  rose_addr_t get_start_addr() const;
  PathTraversalPtrList get_path() const;
  void save_z3_output();
  std::string get_z3_output();
};

// These are utilities used by the pathfinder utility functions for
// graph elements. We may wish to move some of these to Pharos proper.
std::string edge_str(CfgEdge e, const CFG& cfg);
std::string edge_name(CfgEdge e, const CFG& cfg);
std::string edge_cond(CfgEdge e, const CFG& cfg);
std::string vertex_str(CfgVertex e, const CFG& cfg);
rose_addr_t vertex_addr(CfgVertex e, const CFG& cfg);
rose_addr_t get_address_from_treenode(TreeNodePtr tnp);
std::map<rose_addr_t, rose_addr_t> build_xrefs();
FunctionDescriptor* get_func_containing_address(rose_addr_t addr);

} // end namespace pharos

#endif
