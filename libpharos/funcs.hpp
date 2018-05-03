// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Funcs_H
#define Pharos_Funcs_H

#include <boost/format.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/ptr_container/ptr_vector.hpp> // for ptr_vector
#include <boost/iterator/filter_iterator.hpp> // for filter_iterator

#include <rose.h>
#include <BinaryControlFlow.h>
#include <Partitioner2/Partitioner.h>

#include "convention.hpp"

namespace P2 = Rose::BinaryAnalysis::Partitioner2;

namespace pharos {

class StackVariable;
// a list of stack variable pointers
typedef std::vector<StackVariable*> StackVariablePtrList;

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
typedef std::set<FunctionDescriptor*, FunctionDescriptorCompare> FunctionDescriptorSet;
// Forward declaration of call descriptor for recursive includes.
class CallDescriptor;
// This is to keep members in the CallDescriptorSet in a consistent address order.  The actual
// implementation is over in calls.cpp where we have a full call descriptor definition.
class CallDescriptorCompare {
public:
  bool operator()(const CallDescriptor* x, const CallDescriptor* y) const;
};
// A set of call descriptors.
typedef std::set<CallDescriptor*, CallDescriptorCompare> CallDescriptorSet;

// Forward declaration of an import descriptor.
class ImportDescriptor;

class PDG;
class spTracker;

} // namespace pharos

#include "util.hpp"
#include "enums.hpp"
#include "delta.hpp"
#include "convention.hpp"
#include "apidb.hpp"

namespace pharos {

typedef Rose::BinaryAnalysis::ControlFlow::Graph CFG;
typedef std::set<SgAsmBlock*> BlockSet;
typedef std::vector<SgAsmx86Instruction*> X86InsnVector;
typedef std::set<rose_addr_t> AddrSet;

// A set of ROSE addresses used in analyzing calls and functions.
typedef std::set<rose_addr_t> CallTargetSet;
// A set of token strings parsed from a config file.
typedef std::vector<std::string> TokenSet;

// Forward declaration of some utility functions used by msot of the descriptors.
void read_config_addr_set(const std::string & key, const boost::property_tree::ptree& tree,
                          CallTargetSet &tset);
void write_config_addr_set(const std::string & key, boost::property_tree::ptree* tree,
                           CallTargetSet &tset);

// Forward declaration of object-oriented analysis data structure.
class ThisCallMethod;

class FunctionDescriptor {

public:
  // only fn2hash really cares about these particular hashes, so instead of wasting memory
  // keeping them in the FunctionDescriptor, we'll generate them only if explicitly requested
  // by passing in this classs to populate, and return them in there:
  class ExtraFunctionHashData {
  public:
    std::string mnemonics; // concatenated mnemonics
    std::string mnemcats; // concatenated mnemonic categories

    std::string mnemonic_hash; // variant of EHASH but only mnemonics (no operands) instead of insn bytes
    std::string mnemonic_category_hash; // variant of PHASH but only mnemonic categories
    std::string mnemonic_count_hash; // hash of the ordered mnemonic/count pairs
    std::string mnemonic_category_count_hash; // hash of the orderend mnemcat/count pairs

    std::map< std::string, uint32_t > mnemonic_counts;
    std::map< std::string, uint32_t > mnemonic_category_counts;

    std::vector< rose_addr_t > basic_block_addrs; // added in flow order (take len to get # bbs)
    std::vector< std::pair< rose_addr_t, rose_addr_t > > cfg_edges; // from->to pairs of bb addrs (empty if only 1 bb?)
    class BasicBlockHashData {
    public:
      //rose_addr_t addr; // eh, get addr from list above or map below
      std::string pic;
      std::string cpic;
      std::vector< std::string > mnemonics; // in insn order (take len to see how many insn in bb)
      std::vector< std::string > mnemonic_categories; // in insn order (take len to see how many insn in bb)
    };
    std::map< rose_addr_t, BasicBlockHashData > basic_block_hash_data;
  };

private:

  // The address of the function.  This can refer to address that does not yet have a function
  // object, or it can be an invalid address (typically zero).
  rose_addr_t address;

  // The display name of the function
  std::string display_name;

  // The SgAsmFunction object for the function.  This can be NULL if the function hasn't been
  // found yet.
  SgAsmFunction* func;

  // the Partitioner2 Function object for the function
  P2::FunctionPtr p2func;

  // Is this function believed to be a known new() method?
  bool new_method;
  bool delete_method;
  bool purecall_method;

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
  CallDescriptorSet outgoing_calls;

  // The list of possible stack variables. Stored as a pointer vector
  StackVariablePtrList stack_vars;

  // A pointer to the OO analysis of this method.
  ThisCallMethod* oo_properties;

  // Did the user request that this function be excluded?
  bool excluded;

  PDG *pdg;
  bool pdg_cached;

  // How many failure occured during stack delta analysis?  This value is obtained from
  // recent_failures in the stack tracker on a per function basis.  This field is not
  // meaningful until pdg_cached is true.
  size_t stack_analysis_failures;

  // The weighted PDG hash for this function.
  std::string pdg_hash;

  CFG control_flow_graph;
  Rose::BinaryAnalysis::ControlFlow cfg_analyzer;
  bool control_flow_graph_cached;

  BlockSet return_blocks;
  bool return_blocks_cached;

  bool hashes_calculated;

  // The exact bytes, and the corresponding hash.  Computed on demand and cached by
  // get_exact_bytes() or get_exact_hash() by compute_func_bytes().
  std::string exact_bytes; // I'd rather use a vector<byte> here, but old code did it this way so keeping it the same for now...
  std::string exact_hash;
  // The position independent bytes, and the corresponding hash.  Computed on demand and cached
  // by get_pic_bytes() or get_pic_hash() by compute_func_bytes().
  std::string pic_bytes;
  std::string pic_hash;
  std::list< uint32_t > pic_offsets; // the offsets of the PICed out bytes, so Yara sigs can be generted w/ this data

  std::string composite_pic_hash; // variant of PIC w/ no control flow insn, basic blocks hashed and func hashed by hashing those ordered hashes (ASCII values)...

  // might as well collect some fn level stats:
  unsigned int num_blocks; // basic blocks, that is
  unsigned int num_blocks_in_cfg;
  unsigned int num_instructions;
  unsigned int num_bytes;

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

  void update_global_variables();

  void analyze_type_information(const DUAnalysis& du);

  // Update the return value fields in the parameter list.  Only called while generating
  // the PDG.
  void update_return_values();

public:

  FunctionDescriptor();
  FunctionDescriptor(SgAsmFunction* f);

  ~FunctionDescriptor();

  void analyze();

  // Add a new stack variable to this function
  // void add_stack_variable(SgAsmX86Instruction *i, const AbstractAccess &aa);

  void add_stack_variable(StackVariable *stkvar);

  SgAsmFunction* get_func() const { return func; }

  // Get and set the name of the function.
  std::string get_name() const;
  void set_name(const std::string& name);

  rose_addr_t get_address() const { return address; }
  void set_address(rose_addr_t addr);
  // two things...#1: why was str() able to be called directly before when it is supposed to be
  // in the boost namespace, and #2: address is technically a 64 bit value and will map to an
  // *ACTUAL* 64 bit value when we start working on 64 bit files...so we'll need to figure out
  // how to cope with that "properly" at some point (likely using PRIx64 & width of 16)
  std::string address_string() const { return boost::str(boost::format("0x%08X") % address); }

  // basically function chunck start/end addresses:
  const AddressIntervalSet & get_address_intervals() const {
    return address_intervals;
  }

  // Const only access to the calling convention from outside the function class.
  const CallingConventionPtrVector& get_calling_conventions() const { return calling_conventions; }

  StackDelta get_stack_delta() const { return stack_delta; }
  const LeafNodePtr & get_stack_delta_variable() const { return stack_delta_variable; }
  void update_stack_delta(StackDelta sd);

  // Return whether we think we're a new() method.
  bool is_new_method() const { return new_method; }
  // Record whether we think we're a new() method.  Presumably called with true.
  void set_new_method(bool n) { new_method = n; }

  // If we're going to keep the new operator knowledge on the function descriptor, we might as
  // well keep knowledge of the delete operator
  bool is_delete_method() const { return delete_method; }
  void set_delete_method(bool d) { delete_method = d; }

  // This is getting repetive... :-(
  bool is_purecall_method() const { return purecall_method; }
  void set_purecall_method(bool p) { purecall_method = p; }

  // A boolean convenience function for when we only want to test if we're a thunk.
  bool is_thunk() const { return (target_address != 0); }

  // Mark this function as excluded.
  void set_excluded() { excluded = true; }
  // Test if this function is excluded.
  bool is_excluded() { return excluded; }

  // Accessor for the thunk target address, which will be zero if the function is not a thunk.
  // Some confusion has arisen about what this should be if the function is a thunk to a thunk.
  // The existing behavior is for target_address to contain only the most immediate thunk, not
  // the eventual destination of a call to the function.  If you want that, call one of the
  // follow methods listed below instead.
  rose_addr_t get_jmp_addr() const { return target_address; }

  // An accessor that returns the function descriptor.  This will be NULL is the function is
  // not a thunk, but it might also be NULL if the function jumps to an address that is not
  // recognized as a function.
  FunctionDescriptor* get_jmp_fd() const { return target_func; }

  // Follow jump instructions repeatedly until we reach a real target.
  rose_addr_t follow_thunks(bool* endless = NULL);
  // Force the result of follow_thunks() into a function descriptor or NULL.
  FunctionDescriptor* follow_thunks_fd(bool* endless = NULL);
  // Force the result of follow_thunks() into an import descriptor or NULL.
  ImportDescriptor* follow_thunks_id(bool* endless = NULL);

  // A convenience function to test whether we're the target of one or more thunks.
  bool is_thunk_target() const { return (thunks.size() != 0); }

  // Add a function to the list of function descriptors who are thunks to this function.
  void add_thunk(FunctionDescriptor *t) { thunks.insert(t); }
  // Return the list of functions that are thunks to this function.
  const FunctionDescriptorSet& get_thunks() const { return thunks; }

  // Add a call descriptor as an outgoing call.
  void add_outgoing_call(CallDescriptor *cd) { outgoing_calls.insert(cd); }
  // Return the list of outgoing calls.
  const CallDescriptorSet& get_outgoing_calls() const { return outgoing_calls; }

  ThisCallMethod* get_oo_properties() { return oo_properties; }
  void set_oo_properties(ThisCallMethod* tcm) { oo_properties = tcm; }

  // Add a caller to the list of functions that call this function.
  void add_caller(rose_addr_t addr) { callers.insert(addr); }
  // Return the list of addresses that call this function.  Wes defined this to return a copy
  // of the set, and it appears that is currently needed?
  CallTargetSet get_callers() const { return callers; }

  void set_stack_parameters(StackDelta sd) { stack_parameters = sd; }
  StackDelta get_stack_parameters() const { return stack_parameters; }
  // Cory wants to isolate this better.  Maybe with friend, or by moving defuse code into funcs?
  ParameterList& get_rw_parameters() { return parameters; }
  const ParameterList& get_parameters() const { return parameters; }

  void set_returns_this_pointer(bool r) { returns_this_pointer = r; }
  bool get_returns_this_pointer() const { return returns_this_pointer; }
  void set_never_returns(bool n) { never_returns = n; }
  bool get_never_returns() const { return never_returns; }

  // return the computed PDG for this function
  PDG * get_pdg(spTracker *sp = NULL);
  void free_pdg();

  // Get the number of stack delta analysis failures.
  size_t get_stack_analysis_failures() const { return stack_analysis_failures; }

  // Compute the exact & PIC bytes & hashes simultaneously.  If extra pointer is not null,
  // compute extra hash types and return in that struct.
  void compute_function_hashes(ExtraFunctionHashData *extra=NULL);

  // Get the weighted PDG hash.
  std::string get_pdg_hash(unsigned int num_hash_funcs = 4);

  // The bytes of the function in the order described by the function hashing specification.
  // This is the value hashed to produce the exact hash.  This value is pretty close to
  // correct, but probably still doesn't follow the exact specification.
  const std::string& get_exact_bytes();
  // Get the exact hash for the function.
  const std::string& get_exact_hash();
  // The bytes of the function in the order described by the function hashing specification,
  // with the non position independent parts replaced with zeros.  This is the value hashed to
  // produce the PIC hash.
  const std::string& get_pic_bytes();
  const std::list< uint32_t > & get_pic_offsets(); // which bytes in the PIC bytes were PICed out?
  // Get the PIC hash.
  const std::string& get_pic_hash();
  // Get the CPIC (tries to account for simple CFG changes):
  const std::string& get_composite_pic_hash();

  inline unsigned int get_num_blocks() { return num_blocks; };
  inline unsigned int get_num_blocks_in_cfg() { return num_blocks_in_cfg; };
  inline unsigned int get_num_instructions() { return num_instructions; };
  inline unsigned int get_num_bytes() { return num_bytes; };

  // A couple of methods that perhaps should be on the function, but we'll put it on the
  // function descriptor for now.
  CFG& get_rose_cfg();
  CFG& get_pharos_cfg();
  Rose::BinaryAnalysis::ControlFlow& get_cfg_analyzer();
  BlockSet& get_return_blocks();
  SgAsmInstruction* get_insn(const rose_addr_t) const;
  X86InsnVector get_insns_addr_order() const;

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
  void merge(FunctionDescriptor *other);

  // Propagate is called when a call has multiple targets.  After merging all of the targets
  // into a unified description, that description is propagated back to each of the individual
  // targets to see if improved guesses can be made.
  void propagate(FunctionDescriptor *merged);

  // Validate the function description, complaining about any unusual.
  void validate(std::ostream &o);

  // Read and write from property tree config files.
  void read_config(const boost::property_tree::ptree& tree);
  void write_config(boost::property_tree::ptree* tree);
  void set_api(const APIDefinition& fdata);

  // Merge the important fields from the export descriptor loaded from a DLL config file.
  void merge_export_descriptor(const FunctionDescriptor *dfd);

  // Check for various problems in the function related to disconnected basic blocks, strange
  // basic block types, etc.  Return true if anything unusual was found.
  bool check_for_disconnected_blocks();

  // Is this insn address "in" this function? (Regardless of it's flow-control status)
  bool contains_insn_at(rose_addr_t);

  // Provide access to the register usage object.
  const RegisterUsage& get_register_usage() const { return register_usage; }

  // Lookup a stack variable by its offset
  StackVariable* get_stack_variable(int64_t offset) const;

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

typedef std::vector<FunctionDescriptor *> FuncDescVector;

class FunctionDescriptorMap: public std::map<rose_addr_t, FunctionDescriptor> {

public:

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
