// Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Jeff Gennari
// Date: 2015-06-22
// Version: 2.0

#ifndef Pharos_APIGRAPH_H_
#define Pharos_APIGRAPH_H_

#include <rose.h>
#include <boost/graph/depth_first_search.hpp>
#include <Sawyer/Message.h>
#include <Sawyer/ProgressBar.h>
#include <boost/property_map/property_map.hpp>
#include <boost/ptr_container/ptr_vector.hpp>
#include <BinaryControlFlow.h>

#include "descriptors.hpp"
#include "apisig.hpp"
#include "json.hpp"

namespace pharos {

// Information stored for each vertex including the corresponding basic block, type and import
// function descriptor. Each vertex in the graphs is assigned an ApiVertexInfo structure on
// initialization. Sample retrieval of ApiVertexInfo from CFG:
//   ApiVertexInfo &vertex_info = (*cfg)[vertex_descriptor];
struct ApiVertexInfo {
 public:

  // The type of vertex that are meaningful to the search. CALL refers to non-api function
  // call. RETN is a return instruction and API is an api function call
  enum VertexType {
    UNKN=0,
    CALL,
    RETN,
    API
  };

  // Basic block for this vertex
  SgAsmBlock* block;

  // The name of the API called. Currently this is the long name (DLL:API Name)
  std::string api_name;

  // The FunctionDescriptor for this import, could be NULL
  const FunctionDescriptor * import_fd;

  // if this vertex is a call, then this is the call target
  rose_addr_t target_address;

  // the type of vertex
  VertexType type;

  ApiVertexInfo();

  // returns true if this vertex calls an API function
  VertexType GetType() const;

  void SetType(VertexType t);

  bool EndsInCall() const;

  bool ContainsAddress(const rose_addr_t addr) const;

  std::string ToString() const;
};

// This definition of a graph mirrors the one provided by ROSE, except that it
// contains a ApiVertexInfo structure property instead of an SgAsmBlock *

using ApiCfg = boost::adjacency_list< boost::setS, // edges of each vertex in std::set
                                      boost::vecS, // vertices stored in std::vector
                                      boost::bidirectionalS,
                                      ApiVertexInfo>;

// typedefs for ApiCfG graph elements

using ApiCfgVertex = boost::graph_traits<ApiCfg>::vertex_descriptor;
using ApiCfgVertexIter = boost::graph_traits<ApiCfg>::vertex_iterator;
using ApiCfgOutEdgeIter = boost::graph_traits<ApiCfg>::out_edge_iterator;
using ApiCfgInEdgeIter = boost::graph_traits<ApiCfg>::in_edge_iterator;
using ApiCfgEdge = boost::graph_traits<ApiCfg>::edge_descriptor;
using ApiCfgEdgeIter = boost::graph_traits<ApiCfg>::edge_iterator;
using ApiCfgVertexVector = std::vector<ApiCfgVertex>;


// XREF typedefs
// call site (from) -> call target (to)

using XrefMap = std::map< rose_addr_t, rose_addr_t >;
using XrefMapEntry = XrefMap::value_type;
using XrefMapIter = XrefMap::iterator;

// forward declarations of types needed for typedefs

class  ApiCfgComponent;
struct ApiSearchResult;
struct ApiWaypointDescriptor;

using ApiCfgComponentPtr = std::shared_ptr<ApiCfgComponent>;

// the FuncPtrToApiMaps

using ApiCfgComponentMap = std::map<rose_addr_t,  ApiCfgComponentPtr>;
using ApiCfgComponentMapIter = ApiCfgComponentMap::iterator;

// search types

using IndexMap = boost::property_map < ApiCfg, boost::vertex_index_t >::type;
using PredecessorMap = boost::iterator_property_map <ApiCfgVertex*,IndexMap, ApiCfgVertex, ApiCfgVertex&>;

using ApiSearchResultVector = boost::ptr_vector<ApiSearchResult>;
using ApiWaypointVector = std::vector<ApiWaypointDescriptor>;

// Forward reference for parameter matching structures
struct ApiParamMatchTableCompare;

// Forward declaration for graph class
class ApiGraph;

// Wrapper around ParameterDefinition to capture the needed information for
// parameter match
struct ApiParameter {

  ApiParameter(const ParameterDefinition &pd) {
    MakeParam(pd);
  }

  ApiParameter(size_t i, SymbolicValuePtr s, std::string n)
    : num(i), value(s), name(n) { }

  void MakeParam(const ParameterDefinition &pd) {
    num = pd.get_num();
    value = pd.get_value();
    name = pd.get_name();
  }

  void MakeParam(size_t i, SymbolicValuePtr sv, std::string n) {
    num = i;
    value = sv;
    name = n;
  }

  // Index of the parameter
  size_t num;

  // Symbolic value of the parameter
  SymbolicValuePtr value;

  // Parameter name, which is a label for the parameter
  std::string name;
};

// Types for management of parameter information
using ApiParameterPtr = std::shared_ptr<ApiParameter>;
using ApiParamPtrList = std::vector<ApiParameterPtr>;

using ApiParamPtrListPtr = std::shared_ptr<ApiParamPtrList>;
using ApiParamMatchTable = std::map< std::string, ApiParamPtrListPtr >;
using ApiParamMatchPair = ApiParamMatchTable::value_type;
using ApiParamMatchTableIter = ApiParamMatchTable::iterator;

// Comparison functor to identifying  is needed to search the parameter map for a given key
struct ApiParamMatchTableCompare {

  bool operator() (const std::string &s1, const std::string &s2) const {
    return (s1.compare(s2) < 0);
  }
};


// Represents an invalid vertex and address
extern const ApiCfgVertex NULL_VERTEX;
constexpr rose_addr_t INVALID_ADDRESS = (rose_addr_t)(-1);

// The search tree is a list of waypoints that were followed en route to a signature match
// Each path is a set of information needed to recreate the search.
// All the information needed to determine a search path entry. Currently that is the vertex,
// the address represented by the vertex, and the component the vertex resides in.

struct ApiWaypointDescriptor {

  ApiWaypointDescriptor()
    : block(NULL),
      component(INVALID_ADDRESS),
      vertex(NULL_VERTEX),
      func(INVALID_ADDRESS),
      name(""),
      is_part_of_sig(false)
  {  }

  ApiWaypointDescriptor(SgAsmBlock *b, rose_addr_t c, ApiCfgVertex v,
                        rose_addr_t f, std::string n, bool p)
    : block(b), component(c), vertex(v), func(f), name(n), is_part_of_sig(p)
  {  }

  ApiWaypointDescriptor(const ApiWaypointDescriptor &other) {

    block = other.block;
    component = other.component;
    vertex = other.vertex;
    func = other.func;
    name = other.name;
    is_part_of_sig = other.is_part_of_sig;
  }

  void Reset() {

    block=NULL;
    component=INVALID_ADDRESS;
    vertex=NULL_VERTEX;
    is_part_of_sig = false;
  }

  // various operators to manage path equality

  ApiWaypointDescriptor& operator=(const ApiWaypointDescriptor &rhs) {

    block = rhs.block;
    component = rhs.component;
    vertex = rhs.vertex;
    name = rhs.name;
    is_part_of_sig = rhs.is_part_of_sig;

    return *this;
  }

  bool operator==(const ApiWaypointDescriptor& other) const {

    return (block == other.block // checking the pointer should be fine
            && component==other.component && vertex==other.vertex);
  }

  bool operator!=(const ApiWaypointDescriptor& other) const {
    return !(*this == other);
  }

  // A path has four components: an address, the component containing the waypoint, the
  // vertex of the waypoint, and the API information of the waypoint

  SgAsmBlock* block;

  rose_addr_t component;

  ApiCfgVertex vertex;

  // The address of one of the functions that the block is in.  This
  // code really needs some more attention to handle the case where a
  // single call is in more than one function.
  rose_addr_t func;

  std::string name;

  // Is this waypoint part of the signature match?
  bool is_part_of_sig;
};

// An empty path
const ApiWaypointDescriptor NULL_WAYPOINT = ApiWaypointDescriptor();

// Deadend is a pair of path entries where first is the source and second is the destination
using Deadend = std::pair<ApiWaypointDescriptor, ApiWaypointDescriptor>;

// Predicate to find a path. This search is based on address. Should component also be
// considered?
struct PathFindPredicate {

  PathFindPredicate(rose_addr_t s, rose_addr_t d) : src(s), dst(d) { }

  bool operator() (const Deadend &other) const {
    // should component also be checked?
    return (src==other.first.block->get_address()) && (dst==other.second.block->get_address());
  }
  rose_addr_t src, dst;
};

// Functor to compare two paths currently, path comparison is done completely via
// vertex address.
struct PathComparePredicate {

  bool operator() (Deadend de1, Deadend de2) const {
    return (de1.first.block->get_address() < de2.first.block->get_address())
      ||(de1.second.block->get_address() < de2.second.block->get_address());
  }
};

using DeadendList = std::set<Deadend, PathComparePredicate>;

// This structure contains information needed to merge two components.
struct ApiMergeInfo {

  rose_addr_t src_cmp_addr; // Component with the call
  rose_addr_t tgt_cmp_addr; // Component with the call target
  rose_addr_t from_addr;    // Address of the basic block with the call
  rose_addr_t to_addr;      // Target address of the call

  ApiMergeInfo()
    : src_cmp_addr(INVALID_ADDRESS),
      tgt_cmp_addr(INVALID_ADDRESS),
      from_addr(INVALID_ADDRESS),
      to_addr(INVALID_ADDRESS)
  { }

  ApiMergeInfo(const ApiMergeInfo &other) {
    src_cmp_addr = other.src_cmp_addr;
    tgt_cmp_addr = other.tgt_cmp_addr;
    from_addr = other.from_addr;
    to_addr = other.to_addr;
  }

  ApiMergeInfo(rose_addr_t src, rose_addr_t tgt, rose_addr_t from, rose_addr_t to)
    : src_cmp_addr(src),
      tgt_cmp_addr(tgt),
      from_addr(from),
      to_addr(to)
  { }

  bool operator==(const ApiMergeInfo& other) {
    return (src_cmp_addr==other.src_cmp_addr &&
            tgt_cmp_addr==other.tgt_cmp_addr &&
            from_addr==other.from_addr &&
            to_addr==other.to_addr);
  }

  std::string ToString() {
    std::ostringstream out_stream;
    out_stream << "from_cmp_addr: " << addr_str(src_cmp_addr)
               << ", tgt_cmp_addr: " << addr_str(tgt_cmp_addr)
               << ", from_addr: " << addr_str(from_addr)
               << ", to_addr: " << addr_str(to_addr);

    return out_stream.str();
  }

};

// Compare two merge points
struct ApiMergeFindPredicate {

  ApiMergeFindPredicate(rose_addr_t s, rose_addr_t t, rose_addr_t f, rose_addr_t c)
    : src(s), tgt(t), from(f), to(c) { }

  ApiMergeFindPredicate(ApiMergeInfo mi)
    : src(mi.src_cmp_addr), tgt(mi.tgt_cmp_addr), from(mi.from_addr), to(mi.to_addr) { }

  bool operator() (const ApiMergeInfo &other) const {
    return (src==other.src_cmp_addr)
      && (tgt==other.tgt_cmp_addr)
      && (from==other.from_addr)
      && (to==other.to_addr);
  }
  rose_addr_t src, tgt, from, to;
};

// Results for a search
struct ApiSearchResult {

  // the path taken through the ApiCfg while searching
  std::vector<ApiWaypointDescriptor> search_tree;

  // the starting point of the match in terms of vertex and component
  rose_addr_t match_start, match_component_start;

  // The name of the signature matched
  std::string match_name, match_category;

  ApiSearchResult() : match_start(INVALID_ADDRESS), match_component_start(INVALID_ADDRESS) { }

  ApiSearchResult(const ApiSearchResult &copy);

  ApiSearchResult & operator=(const ApiSearchResult &other);

  bool operator==(const ApiSearchResult& other);
};

class ApiResultFormatter;

// Manage and format ApiAnalyzer output
class ApiOutputManager {

 public:

  enum PathLevel {
    NONE=0,
    SIG_PATH,
    FULL_PATH
  };

  enum OutputFormat {
    TEXT=0,
    JSON
  };

  enum OutputMode {
    PRINT,
    FILE
  };

 private:

  ApiResultFormatter *formatter_;

  OutputFormat output_format_;

  PathLevel path_level_;

  OutputMode output_mode_;

  std::string output_file_;

 public:

  ApiOutputManager()
    : formatter_(NULL), path_level_(FULL_PATH), output_mode_(PRINT), output_file_("") { }

  ~ApiOutputManager();

  // settings for output

  void SetSearchTreeDiplayMode(ApiOutputManager::PathLevel m);

  void SetOutputFormat(ApiOutputManager::OutputFormat f);

  void SetOutputFile(std::string f) {
    output_file_ = f;
    output_mode_ = FILE;
  }

  OutputFormat GetOutputFormat() {
    return output_format_;
  }

  PathLevel GetPathLevel() {
    return path_level_;
  }

  OutputMode GetOutputMode() {
    return output_mode_;
  }

  std::string GetOutputFileName() {
    return output_file_;
  }

  bool GenerateOutput(ApiSearchResultVector &res);
};

// Generic formatter class. For a specific formatter, this class should be extended
// and the Format(). ToFile(), and ToString() methods should be implemented
class ApiResultFormatter {

 public:

  // Generate output according to a specific format
  virtual void Format(ApiSearchResultVector &results, ApiOutputManager::PathLevel m)=0;

  // this should return the formatted output as a string
  virtual std::string ToString()=0;

  // write the formatted output to a file
  virtual bool ToFile(std::string ofile_name)=0;

  virtual ~ApiResultFormatter() { /* Nothing to do */ }
};

// Format output as plain text
class ApiResultTextFormatter : public ApiResultFormatter {

 private:

  std::ostringstream out_stream_;

 public:

  ApiResultTextFormatter() { }

  virtual void Format(ApiSearchResultVector &results, ApiOutputManager::PathLevel m);

  virtual std::string ToString();

  virtual bool ToFile(std::string ofile_name);

  virtual ~ApiResultTextFormatter() { /* Nothing to do*/ }
};

// Format results as JSON
class ApiResultJsonFormatter : public ApiResultFormatter {

 private:

  json::ObjectRef out_json_;

 public:

  ApiResultJsonFormatter() { 
      out_json_ = json::simple_builder()->object();
  }

  virtual void Format(ApiSearchResultVector &results, ApiOutputManager::PathLevel m);

  virtual std::string ToString();

  virtual bool ToFile(std::string ofile_name);

  virtual ~ApiResultJsonFormatter() { /* Nothing to do*/ }

  json::Object const & get_json() const { return *out_json_; }
  json::ObjectRef get_json() { return std::move(out_json_); }
};

// State of the search. The state must be stored as an external because DFS searches
// copy everything by value (including visitors).
struct ApiSearchState {

  ApiSearchState();

  // the start and end point API calls
  ApiSigFunc start_api, goal_api;

  // the start and end vertex for the current segment. both start out as NULL_VERTEX
  // and are set as the search progresses
  ApiWaypointDescriptor start_point, last_point;

  // the address of the component (function) where the search begins.
  rose_addr_t start_component;

  // the progress that the search has made in terms of how many segments have been
  // traversed
  unsigned int progress;

  // the signature to match against
  ApiSig sig;

  // List of elements that have been merged
  std::vector<ApiMergeInfo> merged_list;

  ApiParamMatchTable match_table;

  // Path taken through the ApiCfg while searching
  std::vector<ApiWaypointDescriptor> search_tree;

  // Set of edges that should not be traversed
  DeadendList deadends;

  // Set of results for this search
  ApiSearchResultVector results;

  // Initialize the search state signature information (start, goal, etc)
  //void InitializeSearchState(ApiSigPtr s);

  // Update the state of the search when a segment goal is found
  void UpdateState();

  // Returns true if the search is complete
  bool IsSearchComplete();

  // Reset the search state
  void ResetState();

  // Reset the search state
  void ResetSearchState();

  // Reset the entire state
  void ClearState();

  void RevertState(ApiCfgVertex revert_vertex, ApiWaypointDescriptor &revert_point);

};


// Exceptions are used to terminate searches early
struct MergeAndRestartSearchException {

  MergeAndRestartSearchException(const ApiMergeInfo &mi) : merge_info(mi) { }

  ApiMergeInfo merge_info;
};

struct ReachedGoalException { };

struct SearchCompleteException { };

struct AbortSearchException { };

// Executes a search over an ApiGraph. It uses boost DFS
// visitors traverse API graphs
class ApiSearchExecutor {

 private:

  const DescriptorSet& ds;

  bool IsNewResult(const ApiVertexInfo &vi);

  bool IsNewResult(rose_addr_t addr);

  ApiParameterPtr DereferenceParameter(const ParameterDefinition &pd);

  void UpdateApiMatchTable(rose_addr_t caller, rose_addr_t callee);

  bool EvaluateApiMatchTable(const ApiSigFunc& sig_func, const ApiVertexInfo &vertex_info);

  void UpdateSearchTree(PredecessorMap predecessorMap);

  void FindSearchStart(ApiSigFunc &start_api,
                       ApiCfgComponentPtr comp,
                       ApiCfgVertexVector &starts);

  void InitializeSearch(ApiCfgComponentPtr comp,
                        ApiCfgVertex startv, const ApiSig& sig);

  void GetXrefsTo(ApiCfgComponentPtr comp, XrefMap &candidates);

  void GetCallsToFunction(ApiCfgComponentPtr comp, AddrSet &calls_to_comp);

  bool RunSearch();

  bool Backtrack();

  void SaveResult();

  void MergeGraphs(ApiMergeInfo &merge_info);

  bool GetResults(ApiSearchResultVector *result_list);

  void PrintSearchTree();

  void UpdateSearchProgress() const;

  void AddDeadends(ApiWaypointDescriptor &next_to_last, ApiWaypointDescriptor &last);

  ApiSearchState state_;

  ApiGraph *graph_;

 public:

  ApiSearchExecutor(const DescriptorSet& ds_) : ds(ds_), graph_(NULL) { }

  void Initialize(ApiGraph *g);

  bool Search(ApiSig sig, ApiSearchResultVector *result_list);

  bool CheckConnected (const ApiWaypointDescriptor &src, const ApiWaypointDescriptor &dst);

  ApiSearchState * GetState() { return &state_; }

  ApiGraph * GetGraph() { assert(graph_); return graph_; }

  bool CheckMatch(const ApiVertexInfo &match_vertex);

};

// Boost DFS visitor for tree edges. This is the primary structure for tracking the DFS
struct ApiTreeEdgeVisitor : public boost::base_visitor<ApiTreeEdgeVisitor> {

  ApiTreeEdgeVisitor(ApiSearchExecutor *m) : search_executor_(m) { }

  using event_filter = boost::on_tree_edge;

  template <class Edge, class Graph>
  inline void operator()( Edge e, const Graph &g );

  ApiSearchExecutor *search_executor_;
};

// The back edge visitor handles loops during the search
struct ApiBackEdgeVisitor : public boost::base_visitor<ApiBackEdgeVisitor> {

  ApiBackEdgeVisitor(ApiSearchExecutor *m) : search_executor_(m) { }

  using event_filter = boost::on_back_edge;

  template <class Edge, class Graph>
  inline void operator()( Edge e, const Graph &g );

  ApiSearchExecutor *search_executor_;
};

using ApiCfgPtr = std::shared_ptr<ApiCfg>;

// Represents information about each CFG, notably the CFG itself and entry/exit blocks
class ApiCfgComponent {
 private:

  const DescriptorSet& ds;
  rose_addr_t entry_, exit_;

  ApiCfgPtr cfg_;

  // the set of API calls in this component
  std::set<std::string> apis_;

 public:

  ApiCfgComponent(const DescriptorSet& ds_) :
    ds(ds_), entry_(INVALID_ADDRESS), exit_(INVALID_ADDRESS), cfg_(nullptr) { }

  ApiCfgComponent(const ApiCfgComponent &src);

  ApiCfgComponent & operator=(const ApiCfgComponent & other);

  ApiCfgPtr CloneApiCfg(ApiCfgPtr src_cfg);

  ApiCfgPtr CloneApiCfg(ApiCfgPtr src_cfg, ApiCfgVertex exclude_vtx);

  ~ApiCfgComponent();

  void Initialize(const FunctionDescriptor &fd, AddrSet &api_calls, XrefMap &xrefs);

  bool ContainsApiCalls() const;

  bool ContainsApi(std::string api_call) const;

  bool ContainsCalls() const;

  bool ContainsAddress(const rose_addr_t addr) const;

  // remove a vertex from a CFG
  void DisconnectVertex(ApiCfgVertex &v);

  void RemoveVertices(const std::set<ApiCfgVertex>& kill_list);

  void RemoveVertex(ApiCfgVertex );

  void Replace(ApiCfgVertex &out_vertex, ApiCfgVertex &in_entry, ApiCfgVertex &in_exit_vertex);

  void InsertBefore(ApiCfgVertex &insert_vertex, ApiCfgVertex &in_entry_vertex, ApiCfgVertex &in_exit_vertex);

  void InsertAfter(ApiCfgVertex &insert_vertex, ApiCfgVertex &in_entry_vertex, ApiCfgVertex &in_exit_vertex);

  rose_addr_t ConsolidateReturns(BlockSet &retns);

  bool Merge(ApiCfgComponentPtr to_insert, rose_addr_t merge_addr, bool preserve_entry);

  void Simplify();

  void KillVertices(std::set< ApiCfgVertex > &kill_list);

  ApiCfgVertex GetVertexByAddr(const rose_addr_t addr) const;

  ApiCfgVertex GetEntryVertex() const;

  ApiCfgVertex GetExitVertex() const;

  ApiCfgPtr GetCfg() const;

  size_t GetSize() const;

  void SetCfg(ApiCfgPtr cfg);

  rose_addr_t GetEntryAddr() const;

  void SetEntryAddr(rose_addr_t entry);

  rose_addr_t GetExitAddr() const;

  void SetExitAddr(rose_addr_t exit);

  // Generate GraphViz for a vertex
  struct ApiCfgComponentGraphvizVertexWriter {
   private:
    const ApiCfgComponent * cfg_comp;

   public:

    ApiCfgComponentGraphvizVertexWriter(ApiCfgComponent * g) : cfg_comp(g) {  }

    void operator()(std::ostream &output, const ApiCfgVertex &v);
  };

  void GenerateGraphViz(std::ostream &o);

  void Print();

};

// this class is used to display a progress bar if the signature search takes too long.
struct ApiSearchProgressSuffix {
 private:
  ApiSig sig_;
  size_t sig_count_;
 public:
  ApiSearchProgressSuffix() { sig_count_=0; }
  ApiSearchProgressSuffix(ApiSig s, const size_t c) : sig_(s), sig_count_(c) { }
  void print(std::ostream &o) const {
    o << "/" << sig_count_<< " signatures, searching for: " << sig_.name;
  }
};

// This is the main graph on which all searches are conducted.

class ApiGraph {

 private:

  const DescriptorSet& ds;

  // A cross reference map for calls from address -> to address
  XrefMap xrefs_;

  // A set of API call addresses
  AddrSet api_calls_;

  // the independent graph components for this program.
  ApiCfgComponentMap components_;

  ApiSearchExecutor search_executor_;

  bool graph_constructed_;

  void BuildXrefs();

  void UpdateXrefs();

  void ConsolidateThunks();

  void ConsolidateEmptyFunctions();

 public:

  // This is the public interface for the ApiGraph. The graph is self-searching meaning that
  // given a signature, the graph knows how to conduct a search

  ApiGraph(const DescriptorSet& _ds) : ds(_ds), search_executor_(_ds), graph_constructed_(false) { }

  ~ApiGraph();

  ApiCfgComponentPtr GetComponent(rose_addr_t addr);

  ApiCfgComponentMap GetComponents() const { return components_; }

  ApiCfgComponentPtr GetContainingComponent(const rose_addr_t addr) const;

  XrefMap GetXrefs() const { return xrefs_; }

  void RemoveXref(rose_addr_t from, rose_addr_t to);

  void RemoveComponent(rose_addr_t addr);

  bool MergeComponents(ApiMergeInfo &merge_info, bool preserve_entry);

  AddrSet GetApiCalls() const { return api_calls_; }

  size_t Build();

  void Reset();

  // Generate a graphviz file (.dot) for a constructed graph
  void GenerateGraphViz(std::ostream &o);

  bool Search(ApiSig sig, ApiSearchResultVector *results);

  void Print();

  void UpdateProgress(const ApiSig& sig);
};

class ApiSearchManager {

 private:

  ApiGraph graph_;

  size_t sig_count_, sig_progress_;

  void UpdateProgress(const ApiSig& sig);

 public:

  ApiSearchManager(ApiGraph &g) : graph_(g), sig_count_(0), sig_progress_(0) { }

  bool Search(const ApiSigVector &sigs, ApiSearchResultVector &results);

};

// Free functions for debugging
void debug_print_xrefs(const XrefMap& xrefs, const AddrSet& api_calls);
void debug_print_match_table(const ApiParamMatchTable& match_table);
void debug_cfg(ApiCfg cfg);
} // namespace pharos

#endif  // Pharos_APIGRAPH_H_
