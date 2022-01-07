// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Calls_H
#define Pharos_Calls_H

#include <boost/format.hpp>
#include <boost/property_map/property_map.hpp>
#include <boost/iterator/filter_iterator.hpp> // for filter_iterator

#include "funcs.hpp"
#include "imports.hpp"
#include "state.hpp"
#include "convention.hpp"
#include "typedb.hpp"
#include "vcall.hpp"
#include "threads.hpp"

namespace pharos {

class PDG;

enum CallType {
  CallImmediate,
  CallRegister,
  CallImport,
  CallGlobalVariable,
  CallVirtualFunction,
  CallUnknown,
  CallUnspecified
};

enum CallTargetLocation {
  CallInternal,
  CallExternal,
  CallLocationUnknown
};

// Added to quickly extract calls where the target is known/unknown
enum TargetSetCardinality {
  TargetSizeUnspecified,
  TargetSizeZero,
  TargetSizeOne,
  TargetSizeMany
};

// this forward declaration is needed to create a filtered iterator on the call descriptor map
class CallDescMapPredicate;
class VirtualFunctionCallAnalyzer;

class CallDescriptor : private Immobile {

  // The predicate class must be a friend to access class members. Alternatively, we could
  // define additional get/set methods.
  friend class CallDescMapPredicate;

  mutable shared_mutex mutex;

  // The address of the call instruction.  This can refer to address that does not yet have a
  // call instruction, or it can be an invalid address (typically zero).
  rose_addr_t address = 0;

  // The SgAsmX86Instruction object for the call instruction.  This can be NULL if the
  // instruction has not been found yet.
  SgAsmX86Instruction* insn = nullptr;

  // The function descriptor that describes the aspects of this call that are specific to the
  // call target.  In many calls, this will point directly to the descriptor for the actual
  // function that is called.  But if there are multiple targets, we will allocate a new
  // descriptor that merges the results from all of the targets.  If the call target is a
  // single import, this pointer will point to the function descriptor associated with the
  // import.
  FunctionDescriptor* function_descriptor = nullptr;

  // If the FunctionDescriptor pointed to by function_descriptor is owned (allocated) by this
  // object, it is managed here.
  std::unique_ptr<FunctionDescriptor> owned_function_descriptor;

  // The addresses that the call can transfer control to.  This list could be empty if we don't
  // know the answers.  If could have multiple answers if the call is to a register which could
  // contain multiple values.  Typically the set contains a single value.  For imports, the
  // address of the import itself is added to represent the address that the loader would
  // supply dynamically when it resolved the import.  There's still some ambiguity here about
  // whether there's any simplification via thunks being done on this list, but Cory's
  // unconfirmed belief is that this list only contains direct targets, although it does
  // contain virtual call resolutions and other kinds of simplification, which is perhaps an
  // inconsistent design choice.
  CallTargetSet targets;

  // The symbolic state at the time of the call (useful for getting the values of parameters).
  SymbolicStatePtr state;

  // How confident are we in the target list being complete and correct?  One one extreme we
  // know conclusively that the list is correct.  At the other, we know that it's actively
  // wrong (e.g. empty).  In between, we may be confident or just guessing.
  GenericConfidence confidence = ConfidenceNone;

  // A variable to represent the stack delta when then delta is unknown (missing)
  mutable LeafNodePtr stack_delta_variable;

  // Is the call internal, external, or unknown?
  CallTargetLocation call_location = CallLocationUnknown;

  // What type is this call?  e.g. Is it a call to an immediate value, a register?
  CallType call_type = CallUnknown;

  // What is the import descriptor for this call, if it is external?
  ImportDescriptor* import_descriptor = nullptr;

  // The overridden function from the user config file.
  std::unique_ptr<FunctionDescriptor> function_override;

  // The function that contains this call descriptor.
  FunctionDescriptor* containing_function = nullptr;

  // The parameters for this call.
  ParameterList parameters;

  // The symbolic return value.
  SymbolicValuePtr return_value;

  // For calls that indeterminate targets, we may want to record the "expected" stack delta for
  // the call, without any rigorous knowledge of where we call to.  This stack delta contains
  // that information.
  StackDelta stack_delta;

  // The resolution details for virtual function calls.
  VirtualFunctionCallVector virtual_calls;

  void analyze();

  void _update_connections();

  void _print(std::ostream &o) const;

  struct self { CallDescriptor & self; };

  friend std::ostream& operator<<(std::ostream &o, const self &cd) {
    cd.self._print(o);
    return o;
  }

 public:

  DescriptorSet& ds;

  CallDescriptor(DescriptorSet& d) : ds(d) {}

  CallDescriptor(DescriptorSet& d, SgAsmX86Instruction* i)
    : insn(i), ds(d)
  {
    analyze();
  }

  void update_connections() {
    write_guard<decltype(mutex)> guard{mutex};
    _update_connections();
  }

  SgAsmInstruction* get_insn() const {
    return insn;
  }
  rose_addr_t get_address() const {
    return address;
  }
  CallTargetLocation get_target_location() const {
    return call_location;
  }

  // Add a new address to the targets list, recompute the merged descriptions, and update
  // connections with the affected function descriptor.
  void add_target(rose_addr_t taddr);
  // Return the set of target addresses.
  auto get_targets() const {
    return make_read_locked_range(targets, mutex);
  }

  std::string address_string() const {
    return str(boost::format("0x%08X") % address);
  }

  // One spot needs read/write access to update the callers.
  FunctionDescriptor* get_rw_function_descriptor() { return function_descriptor; }

  // Provide read-only access to the function descriptor and import descriptor.
  const FunctionDescriptor* get_function_descriptor() const { return function_descriptor; }
  const ImportDescriptor* get_import_descriptor() const { return import_descriptor; }

  // Get and set the return value.
  const SymbolicValuePtr & get_return_value() const {
    read_guard<decltype(mutex)> guard{mutex};
    return return_value;
  }
  void set_return_value(SymbolicValuePtr r) {
    write_guard<decltype(mutex)> guard{mutex};
    return_value = r;
  }

  void add_import_target(ImportDescriptor* id);

  void update_call_type(CallType ct, GenericConfidence conf);

  // Are we a tail-call optimized JMP instruction?
  bool is_tail_call() const {
    return insn_is_jmp(insn);
  }

  // Add virtual call resolutions
  void add_virtual_resolution(VirtualFunctionCallInformation& vci, GenericConfidence conf);
  // Available only if object oriented analysis has been performed, empty otherwise.
  auto get_virtual_calls() const {
    return make_read_locked_range(virtual_calls, mutex);
  }

  CallType get_call_type() const  {
    read_guard<decltype(mutex)> guard{mutex};
    return call_type;
  }

  StackDelta get_stack_delta() const;
  LeafNodePtr get_stack_delta_variable() const;
  StackDelta get_stack_parameters() const;

  // Cory wants to isolate this better.  Maybe with friend, or by moving defuse code into funcs?
  ParameterList& get_rw_parameters() { return parameters; }
  const ParameterList& get_parameters() const { return parameters; }

  // Return the function that contains this call.
  FunctionDescriptor* get_containing_function() const { return containing_function; }

  void print(std::ostream &o) const {
    read_guard<decltype(mutex)> guard{mutex};
    _print(o);
  }
  // Return the "real" call targets, e.g. with thunks removed.
  // CallTargetSet get_real_targets();

  // Does the call never return (because all of the targets never return, e.g. exits).
  bool get_never_returns() const;

  // Get the state at the time of the call.
  const SymbolicStatePtr get_state() const { return state; }
  // Set the state for this call (called while building the PDG).
  void set_state(SymbolicStatePtr s) {
    // Clone the state so that we get an unchanging copy?  In theory the reference counted
    // pointer should protect against deallocation.  Do we really need a clone?  Cory thinks
    // this is only set in defuse.cpp evaluate bblock, and then never used?
    state = s->sclone();
  }
  // Discard the state, freeing memory by releasing references to the smart pointers.
  void discard_state() {
    state.reset();
  }

  // Validate the call description, complaining about any unusual.
  void validate(std::ostream &o, const FunctionDescriptorMap& fdmap) const;

  // Unused?
  bool operator<(const CallDescriptor& other) {
    return (address < other.get_address());
  }

  friend std::ostream& operator<<(std::ostream &o, const CallDescriptor &cd) {
    cd.print(o);
    return o;
  }
};

class CallDescriptorMap: public std::map<rose_addr_t, CallDescriptor>, private Immobile {

 public:

  CallDescriptorMap() = default;

  template<typename... T>
  CallDescriptor * add(rose_addr_t addr, T &&... cd_args) {
    auto it = find(addr);
    if (it != end()) {
      erase(it);
    }
    auto result = emplace(std::piecewise_construct, std::forward_as_tuple(addr),
                          std::forward_as_tuple(std::forward<T>(cd_args)...));
    assert(result.second);
    return &result.first->second;
  }

  const CallDescriptor* get_call(rose_addr_t addr) const {
    CallDescriptorMap::const_iterator it = this->find(addr);
    if (it != this->end())
      return &(it->second);
    else
      return NULL;
  }

  CallDescriptor* get_call(rose_addr_t addr) {
    CallDescriptorMap::iterator it = this->find(addr);
    if (it != this->end())
      return &(it->second);
    else
      return NULL;
  }
};

//
// Predicate for filtered iterators on CallDescriptors. There are two configuration parameters
// to carve the CallDescriptorMap: call type and confidence.  The predicate determines which
// values are included during iteration. Currently, the included values are a conjunction. That
// is, they are "and'd" together
class CallDescMapPredicate {
 public:

  // The default values for predicate parameters are unspecified, which is different than
  // unknown.
  CallDescMapPredicate(CallType ct = CallUnspecified, GenericConfidence gc =
                       ConfidenceUnspecified, TargetSetCardinality tc = TargetSizeUnspecified):
    call_type(ct), conf(gc), target_card(tc) {
  }

  // evaluate whether CallDescriptorMap value should be included in the iterator
  // unspecified values are ignored
  bool operator()(CallDescriptorMap::value_type & c) const {

    bool ct_match = true, gc_match = true, tc_match = true;

    if (call_type != CallUnspecified) {
      ct_match = (c.second.call_type == call_type);
    }

    if (conf != ConfidenceUnspecified) {
      gc_match = (c.second.confidence == conf);
    }

    if (target_card != TargetSizeUnspecified) {
      if (target_card == TargetSizeZero) {
        tc_match = c.second.targets.isEmpty();
      } else if (target_card == TargetSizeOne) {
        tc_match = (c.second.targets.size() == 1);
      } else if (target_card == TargetSizeMany) {
        tc_match = (c.second.targets.size() > 1);
      }
    }

    // Currently This is a conjunction. In the future it may support different logic
    return (ct_match && gc_match && tc_match);
  }

 private:

  CallType call_type;
  GenericConfidence conf;
  TargetSetCardinality target_card;
};


using ValueList = std::vector<typedb::Value>;

class CallParamInfoBuilder;

class CallParamInfo {
 private:
  CallDescriptor const & cd;
  ValueList const val;
  CallParamInfo(CallDescriptor const & cd_, ValueList && val_)
    : cd(cd_), val(std::move(val_))
  {}
  friend class CallParamInfoBuilder;

  static typedb::TypeRef type_from_value(typedb::Value const & val) {
    return val.get_type();
  }
  static std::string const & name_from_param(ParameterDefinition const & pd) {
    return pd.get_name();
  }
  static std::string const & type_name_from_param(ParameterDefinition const & pd) {
    return pd.get_type();
  }

 public:
  CallDescriptor const & descriptor() const {
    return cd;
  }
  ValueList const & values() const {
    return val;
  }
  auto params() const {
    return cd.get_parameters().get_params();
  }

  auto types() const {
    return values() | boost::adaptors::transformed(type_from_value);
  }

  auto names() const {
    return params() | boost::adaptors::transformed(name_from_param);
  }

  auto type_names() const {
    return params() | boost::adaptors::transformed(type_name_from_param);
  }
};

class CallParamInfoBuilder {
 private:
  typedb::DB db;
  Memory const & memory;
 public:
  CallParamInfoBuilder(typedb::DB && db_, Memory const & mem) : db(db_), memory(mem) {}
  CallParamInfoBuilder(ProgOptVarMap const & vm, Memory const & mem) :
    db(typedb::DB::create_standard(vm)), memory(mem) {}

  CallParamInfo create(CallDescriptor const & cd) const;
  CallParamInfo operator()(CallDescriptor const & cd) const {
    return create(cd);
  }
};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
