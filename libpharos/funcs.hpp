// Copyright 2015-2024 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Funcs_H
#define Pharos_Funcs_H

#include <boost/format.hpp>
#include <boost/ptr_container/ptr_vector.hpp> // for ptr_vector
#include <boost/iterator/filter_iterator.hpp> // for filter_iterator
#include <boost/range/adaptor/transformed.hpp> // for boost::adaptors::transformed

#include "rose.hpp"
#include <Rose/BinaryAnalysis/ControlFlow.h>
#include <Rose/BinaryAnalysis/Partitioner2/Partitioner.h>

#include <atomic>

#include "convention.hpp"
#include "stkvar.hpp"
#include "threads.hpp"

namespace pharos {

// Forward declaration of function descriptor for recursive includes.
class FunctionDescriptor;
// Forward declaration of the map for update_connections()
class FunctionDescriptorMap;
// This is to keep members in the FunnctionDescriptorSet in a consistent address order.  The
// actual implementation is later in this file once we have a full function descriptor
// definiton.
class FunctionDescriptorCompare {
 public:
  bool operator()(const FunctionDescriptor* x, const FunctionDescriptor* y) const;
};
// A set of function descriptors.
using FunctionDescriptorSet = std::set<FunctionDescriptor*, FunctionDescriptorCompare>;
using ConstFunctionDescriptorSet = std::set<const FunctionDescriptor*, FunctionDescriptorCompare>;
// Forward declaration of call descriptor for recursive includes.
class CallDescriptor;
// This is to keep members in the CallDescriptorSet in a consistent address order.  The actual
// implementation is over in calls.cpp where we have a full call descriptor definition.
class CallDescriptorCompare {
 public:
  bool operator()(const CallDescriptor* x, const CallDescriptor* y) const;
};
// A set of call descriptors.
using CallDescriptorSet = std::set<CallDescriptor*, CallDescriptorCompare>;

// Forward declaration of an import descriptor.
class ImportDescriptor;

class PDG;

} // namespace pharos

#include "util.hpp"
#include "enums.hpp"
#include "delta.hpp"
#include "convention.hpp"
#include "apidb.hpp"

namespace pharos {

using CFG = Rose::BinaryAnalysis::ControlFlow::Graph;
using BlockSet = std::set<SgAsmBlock*>; // Deprecated with get_return_blocks()
using X86InsnVector = std::vector<SgAsmX86Instruction*>;
using InsnVector = std::vector<SgAsmInstruction*>;
using AddrSet = std::set<rose_addr_t>;

// A set of ROSE addresses used in analyzing calls and functions.
using CallTargetSet = Rose::BinaryAnalysis::AddressSet;
// A set of token strings parsed from a config file.
using TokenSet = std::vector<std::string>;

// Forward declaration of object-oriented analysis data structure.
class ThisCallMethod;

class FunctionDescriptor : private Immobile {

 public:
  DescriptorSet& ds;

  mutable shared_mutex mutex;
  mutable std::recursive_mutex pdg_mutex;

 private:

  // The address of the function.  This can refer to address that does not yet have a function
  // object, or it can be an invalid address (typically zero).
  rose_addr_t address;

  // The display name of the function
  std::string display_name;

  // The SgAsmFunction object for the function.  This will be NULL if the function descriptor
  // is one of the "merged" function descriptors on a call descriptor.
  SgAsmFunction* func;

  // The Partitioner2 Function object for the function.  This is intended to be a complete
  // replacement for the old SgAsmFuction pointer above, but the APIs are not identical, which
  // has delayed the elimination of the old pointer.  This pointer will be NULL for "merged"
  // function descriptors on call descriptors as well, although I _think_ that both pointers
  // should be NULL or non-NULL together.
  P2::FunctionPtr p2func;

  // While we've eliminated new and purecall booleans in the function descriptor, there are a
  // couple of hacks that still require knowledge of whether the function is delete or not. :-(
  bool delete_method;

  // The address that this function jumps to if it is a thunk.
  rose_addr_t target_address;

  // The function descriptor of the function that this function jumps to if this function is a
  // thunk.  This could be slightly inconsistent with the target address if the address has not
  // been made into a function.   In that case, this pointer will still be NULL.
  FunctionDescriptor *target_func;

  // A set of functions that are known to be thunks to this function.  While there's typically
  // only one thunk for a given function, it's possible that there could be more than one.
  FunctionDescriptorSet thunks;

  // The addresses of the call instructions that call to this function.
  CallTargetSet callers;
  // The call descriptors that are located within this function (the outgoing calls).
  std::set<const CallDescriptor*, CallDescriptorCompare> outgoing_calls;

  // The list of possible stack variables. Stored as a pointer vector
  StackVariablePtrList stack_vars;

  // Did the user request that this function be excluded?
  bool excluded;

  std::unique_ptr<PDG> pdg;

  // How many failure occured during stack delta analysis?  This value is obtained from
  // recent_failures in the stack tracker on a per function basis.
  size_t stack_analysis_failures;

  // The weighted PDG hash for this function.
  std::string pdg_hash;

  mutable CFG rose_control_flow_graph;
  mutable bool rose_control_flow_graph_cached;

  mutable CFG pharos_control_flow_graph;
  mutable bool pharos_control_flow_graph_cached;
  mutable Rose::BinaryAnalysis::ControlFlow pharos_cfg_analyzer;

  std::atomic<bool> hashes_calculated;

  // The exact bytes, and the corresponding hash.  Computed on demand and cached by
  // get_exact_bytes() or get_exact_hash() by compute_func_bytes().
  std::string exact_bytes; // I'd rather use a vector<byte> here, but old code did it this way so keeping it the same for now...
  std::string exact_hash;
  // The position independent bytes, and the corresponding hash.  Computed on demand and cached
  // by get_pic_bytes() or get_pic_hash() by compute_func_bytes().
  std::string pic_bytes;
  std::string pic_hash;
  std::vector<uint8_t> pic_mask; // A bitmask for the PIC'd bytes

  // might as well collect some fn level stats:
  std::uint64_t num_instructions;
  std::uint64_t num_bytes;

  // This is set to true if we're pretty certain that we never return.  It's a little unclear
  // what level of semantic analysis we mean right now, but I think it would be fine currently
  // to set this to true for endless loops, invalid instructions, calls to exit the process
  // etc.  In the future we'll need to distinguish between these cases more carefully.
  bool never_returns;

  // ----------------------------------------------------------------------------------------
  // Being moved into the top couple of classes...
  // ----------------------------------------------------------------------------------------

  // Which registers were used and how...  This information is function specific, and supports
  // non-standard calling conventions.  In most cases, it's simply used to determine which
  // calling convention(s) match this function, but if the calling convention vector is empty,
  // this class can help fill in some details.  Unfortunately, this information can never be
  // sufficient to build the ordered parameter list, because source-code parameter order is a
  // function of the standardized calling convention.
  RegisterUsage register_usage;

  // The original design for calling convention detection was a single convention and a
  // confidence level.  Over time, that's evolved into a list of matching conventions, because
  // it's less of an issue of uncertainty, and more a matter of unresolvable ambiguity.  This
  // vector will contain all known calling conventions that might match the function.  If it
  // contains a single value, then that can reasonably be assumed to be the correct calling
  // convention.  A number of the fields below should gradually be phased out in preference
  // of the information here...
  CallingConventionPtrVector calling_conventions;

  // The parameters for this call.  This is the "new" way of accessing this information, and is
  // preferred over some of the fields below.  There's a ParameterDefinition for each parameter
  // in source code order.  This information should be consistent with the entries in the
  // calling convention vector, although there's some uncertainty about the details...
  ParameterList parameters;

  // This should be implied by the calling convention, but calling convention detection STILL
  // isn't working.  So in the mean time, this boolean indicates whether return ECX in EAX.
  bool returns_this_pointer;

  // What is the stack delta for this function?
  StackDelta stack_delta;

  // Variable to use for an unknown stack delta
  LeafNodePtr stack_delta_variable;

  // How many bytes does the function read off the stack?
  StackDelta stack_parameters;

  // these are basically the function chunk boundaries:
  AddressIntervalSet address_intervals;

  // The output state for the function can be found on the defuse object under output_state.

  // This method is private because it updates target_address and leaves it out-of-sync with
  // target_func, which is corrected in update_connections().
  void update_target_address();

  // Walk the reads in the function, and identify reads of stack parameters.  Only called while
  // generating the PDG.
  void update_stack_parameters();

  // Add parameters passed in registers to the parameter list.  Only called
  // while generating the PDG.
  void update_register_parameters();

  void update_stack_variables();

  rose_addr_t _follow_thunks(bool* endless) const;
  void _propagate_thunk_info();

  CFG const & _get_rose_cfg() const;

  // Update the return value fields in the parameter list.  Only called while generating
  // the PDG.
  void update_return_values();

  void set_address(rose_addr_t addr);

  void analyze();

  void set_name(const std::string& name);
  void set_stack_parameters(StackDelta sd) {
    write_guard<decltype(mutex)> guard{mutex};
    stack_parameters = sd;
  }

  // The function that does the work for compute_function_hashes().  This is a non-const
  // method.  compute_function_hashes() is const, but uses casting to call this instead.  This
  // is because compute_function_hashes() and the methods that depend on it are semantically
  // const, but defer calculation until needed.
  void _compute_function_hashes();
  // A mutexless version of get_insns_addr_order for internal callers.
  InsnVector _get_insns_addr_order() const;

  const PDG * _get_pdg();

  // Type of vertices
  using CFGVertex = boost::graph_traits<CFG>::vertex_descriptor;
  // Type of edges
  using CFGEdge = boost::graph_traits<CFG>::edge_descriptor;

  // The entry block is always zero when it exists (see more detailed test in CDG constructor).
  static constexpr CFGVertex entry_vertex = 0;

  // two things...#1: why was str() able to be called directly before when it is supposed to be
  // in the boost namespace, and #2: address is technically a 64 bit value and will map to an
  // *ACTUAL* 64 bit value when we start working on 64 bit files...so we'll need to figure out
  // how to cope with that "properly" at some point (likely using PRIx64 & width of 16)
  std::string _address_string() const {
    return boost::str(boost::format("0x%08X") % address);
  }

 public:

  FunctionDescriptor(DescriptorSet& ds);
  FunctionDescriptor(DescriptorSet& ds, SgAsmFunction* f);
  ~FunctionDescriptor();

  bool operator< (const FunctionDescriptor& rhs) const {
    return get_address() < rhs.get_address();
  }

  P2::FunctionPtr get_p2func() const { return p2func; }
  SgAsmFunction* get_func() const { return func; }
  SgAsmBlock* get_entry_block() const;

  // Get and set the name of the function.
  std::string get_name() const;

  rose_addr_t get_address() const {
    read_guard<decltype(mutex)> guard{mutex};
    return address;
  }

  std::string address_string() const {
    read_guard<decltype(mutex)> guard{mutex};
    return _address_string();
  }

  // basically function chunck start/end addresses:
  const AddressIntervalSet & get_address_intervals() const {
    return address_intervals;
  }

  // Const only access to the calling convention from outside the function class.
  auto get_calling_conventions() const {
    return make_read_locked_range(calling_conventions, mutex);
  }

  StackDelta get_stack_delta() const {
    read_guard<decltype(mutex)> guard{mutex};
    return stack_delta;
  }
  const LeafNodePtr get_stack_delta_variable() const {
    read_guard<decltype(mutex)> guard{mutex};
    return stack_delta_variable;
  }
  void update_stack_delta(StackDelta sd);

  // A boolean convenience function for when we only want to test if we're a thunk.
  bool is_thunk() const {
    read_guard<decltype(mutex)> guard{mutex};
    return (target_address != 0);
  }

  // Accessor for the thunk target address, which will be zero if the function is not a thunk.
  // Some confusion has arisen about what this should be if the function is a thunk to a thunk.
  // The existing behavior is for target_address to contain only the most immediate thunk, not
  // the eventual destination of a call to the function.  If you want that, call one of the
  // follow methods listed below instead.
  rose_addr_t get_jmp_addr() const { return target_address; }

  // An accessor that returns the function descriptor.  This will be NULL is the function is
  // not a thunk, but it might also be NULL if the function jumps to an address that is not
  // recognized as a function.
  FunctionDescriptor* get_jmp_fd() const {
    read_guard<decltype(mutex)> guard{mutex};
    return target_func;
  }

  // Follow jump instructions repeatedly until we reach a real target.
  rose_addr_t follow_thunks(bool* endless = NULL) const;
  // Force the result of follow_thunks() into a function descriptor or NULL.
  const FunctionDescriptor* follow_thunks_fd(bool* endless = NULL) const;

  // A convenience function to test whether we're the target of one or more thunks.
  bool is_thunk_target() const {
    read_guard<decltype(mutex)> guard{mutex};
    return (thunks.size() != 0);
  }

  // Add a function to the list of function descriptors who are thunks to this function.
  void add_thunk(FunctionDescriptor *t) {
    write_guard<decltype(mutex)> guard{mutex};
    thunks.insert(t);
  }
  // Return the list of functions that are thunks to this function.
  auto get_thunks() const {
    return make_read_locked_range(thunks, mutex);
  }

  // Add a call descriptor as an outgoing call.
  void add_outgoing_call(const CallDescriptor *cd) {
    write_guard<decltype(mutex)> guard{mutex};
    outgoing_calls.insert(cd);
  }
  // Return the list of outgoing calls.
  auto get_outgoing_calls() const {
    return make_read_locked_range(outgoing_calls, mutex);
  }

  // Add a caller to the list of functions that call this function.
  void add_caller(rose_addr_t addr) {
    write_guard<decltype(mutex)> guard{mutex};
    callers.insert(addr);
  }
  auto get_callers() const { return make_read_locked_range(callers, mutex); }

  StackDelta get_stack_parameters() const {
    read_guard<decltype(mutex)> guard{mutex};
    return stack_parameters;
  }
  // Cory wants to isolate this better.  Maybe with friend, or by moving defuse code into funcs?
  ParameterList& get_rw_parameters() { return parameters; }
  const ParameterList& get_parameters() const { return parameters; }

  void set_returns_this_pointer(bool r) {
    write_guard<decltype(mutex)> guard{mutex};
    returns_this_pointer = r;
  }
  bool get_returns_this_pointer() const {
    read_guard<decltype(mutex)> guard{mutex};
    return returns_this_pointer;
  }
  void set_never_returns(bool n) {
    write_guard<decltype(mutex)> guard{mutex};
    never_returns = n;
  }
  bool get_never_returns() const {
    read_guard<decltype(mutex)> guard{mutex};
    return never_returns;
  }

  // return the computed PDG for this function
  const PDG * get_pdg() const;
  void free_pdg();

  // Get the number of stack delta analysis failures.
  size_t get_stack_analysis_failures() const {
    write_guard<decltype(pdg_mutex)> guard{pdg_mutex};
    return stack_analysis_failures;
  }

  // Compute the exact & PIC bytes & hashes simultaneously.
  void compute_function_hashes() const;

  // Get the weighted PDG hash.
  std::string get_pdg_hash(unsigned int num_hash_funcs = 4);

  // The bytes of the function in the order described by the function hashing specification.
  // This is the value hashed to produce the exact hash.  This value is pretty close to
  // correct, but probably still doesn't follow the exact specification.
  const std::string& get_exact_bytes() const;
  // Get the exact hash for the function.
  const std::string& get_exact_hash() const;
  // The bytes of the function in the order described by the function hashing specification,
  // with the non position independent parts replaced with zeros.  This is the value hashed to
  // produce the PIC hash.
  const std::string& get_pic_bytes() const;
  const std::vector<uint8_t>& get_pic_mask() const; // which bytes in the PIC bytes were PICed out?
  // Get the PIC hash.
  const std::string& get_pic_hash() const;

  unsigned int get_num_instructions() const { return num_instructions; };
  unsigned int get_num_bytes() const { return num_bytes; };

  // The pharos control flow graph is the priumary CFG.  It differs from the ROSE CFG in that
  // certain blocks have been removed.  You should use this CFG if you don't understand the
  // difference between the Pharos CFG and the ROSE CFG.
  CFG const & get_pharos_cfg() const;
  // This is a more complete CFG that contains blocks that are not known to be in the control
  // flow.  Most of the fields in the function descriptor (e.g. the hashes and the standard PDG
  // analysis) are not computed from this CFG.  As a consequence, you should be cautious about
  // this difference when using this CFG.
  CFG const & get_rose_cfg() const;

  // Returns an iterable over P2::BasicBlock::Ptr in (which?) CFG order.
  //BBlockRange get_bblocks() const { return BBlockRange(*this); }

  // Vertices can be converted to SgAsmblocks with: convert_vertex_to_bblock(cfg, vertex);
  using CFGVertexVector = std::vector<CFGVertex>;
  // Return the connected vertices in flow order in the Pharos (filtered) control flow graph.
  CFGVertexVector get_vertices_in_flow_order() const;
  // Return the connected vertices in flow order in the provided control flow graph.
  static CFGVertexVector get_vertices_in_flow_order(const CFG& cfg, CFGVertex entry = entry_vertex);
  // Return the entry vertex
  static CFGVertex get_entry_vertex() { return entry_vertex; }
  // Return the vertices with no successors from the Pharos (filtered) control flow graph.
  CFGVertexVector get_return_vertices() const;
  // Return the vertices with no successors from the provided control flow graph.
  static CFGVertexVector get_return_vertices(const CFG& cfg, CFGVertex entry = entry_vertex);
  BlockSet get_return_blocks() const; // Deprecated in favor of get_return_vertices()

  SgAsmInstruction* get_insn(const rose_addr_t) const;
  InsnVector get_insns_addr_order() const;

  // Called once we've found all of the functions.
  void update_connections(FunctionDescriptorMap& fdmap);
  // Called after we've called update_connections.
  void propagate_thunk_info();

  // Merge is called when a call has multiple targets to merge the attributes of all the target
  // functions into a single unified description of the call target.  All of the targets should
  // have the same properties, especially if the code was generated by a compiler, but it's
  // possible for them differ (e.g. hand coded assembly).  This method imposes the merge logic
  // to select the best available answers and lowered confidence levels.  The resulting function
  // description is stored in the CallDescriptor.
  void merge(const FunctionDescriptor *other);

  // Propagate is called when a call has multiple targets.  After merging all of the targets
  // into a unified description, that description is propagated back to each of the individual
  // targets to see if improved guesses can be made.
  void propagate(const FunctionDescriptor *merged);

  // Validate the function description, complaining about any unusual.
  void validate(std::ostream &o) const;

  void set_api(const APIDefinition& fdata);

  // Is this insn address "in" this function? (Regardless of it's flow-control status)
  bool contains_insn_at(rose_addr_t) const;

  // Provide access to the register usage object.
  const RegisterUsage& get_register_usage() const { return register_usage; }

  // Fetch the list of stack variables. This is made a reference to avoid
  // needless copying
  const StackVariablePtrList& get_stack_variables() const { return stack_vars; }


  void print(std::ostream &o) const;
  std::string debug_deltas() const;
  friend std::ostream& operator<<(std::ostream &o, const FunctionDescriptor &fd) {
    fd.print(o);
    return o;
  }

  std::string disasm() const;
};

using FuncDescVector = std::vector<FunctionDescriptor *>;

class FunctionDescriptorMap: public std::map<rose_addr_t, FunctionDescriptor> {

 public:

  const FunctionDescriptor* get_func(rose_addr_t addr) const {
    FunctionDescriptorMap::const_iterator it = this->find(addr);
    if (it != this->end())
      return &(it->second);
    else
      return NULL;
  }

  FunctionDescriptor* get_func(rose_addr_t addr) {
    FunctionDescriptorMap::iterator it = this->find(addr);
    if (it != this->end())
      return &(it->second);
    else
      return NULL;
  }
};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
