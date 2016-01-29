// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Calls_H
#define Pharos_Calls_H

#include <boost/format.hpp>
#include <boost/property_map/property_map.hpp>
#include <boost/iterator/filter_iterator.hpp> // for filter_iterator
#include <rose.h>

class PDG;

#include "masm.hpp"
#include "funcs.hpp"
#include "imports.hpp"
#include "state.hpp"
#include "convention.hpp"

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

// CallInformation is the abstract base class for all call types. Each specific call type should
// extend and define specific call information. There cannot be any generic call information
// hence the pure virtual destructor.
class CallInformation {
public:
  virtual ~CallInformation()=0;
};
// despite being a pure virtual destructor, an implementation is needed.
inline CallInformation::~CallInformation() { }

typedef boost::shared_ptr<CallInformation> CallInformationPtr;

class CallDescriptor {

  // The predicate class must be a friend to access class members. Alternatively, we could
  // define additional get/set methods.
  friend class CallDescMapPredicate;

  // The address of the call instruction.  This can refer to address that does not yet have a
  // call instruction, or it can be an invalid address (typically zero).
  rose_addr_t address;

  // The SgAsmx86Instruction object for the call instruction.  This can be NULL if the
  // instruction has not been found yet.
  SgAsmx86Instruction* insn;

  // The function descriptor that describes the aspects of this call that are specific to the
  // call target.  In many calls, this will point directly to the descriptor for the actual
  // function that is called.  But if there are multiple targets, we will allocate a new
  // descriptor that merges the results from all of the targets.  If the call target is a
  // single import, this pointer will point to the functuon descriptor associated with the
  // import.
  FunctionDescriptor* function_descriptor;

  // Did we dynamically allocate the function descriptor?
  bool function_allocated;

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

  // The thing Jeff Gennari created for tracking virtual function pointers.
  CallInformationPtr call_info;

  // The symbolic state at the time of the call (useful for getting the values of parameters).
  SymbolicStatePtr state;

  // How confident are we in the target list being complete and correct?  One one extreme we
  // know conclusively that the list is correct.  At the other, we know that it's actively
  // wrong (e.g. empty).  In between, we may be confident or just guessing.
  GenericConfidence confidence;

  // Is the call internal, external, or unknown?
  CallTargetLocation call_location;

  // What type is this call?  e.g. Is it a call to an immediate value, a register?
  CallType call_type;

  // What is the import descriptor for this call, if it is external?
  ImportDescriptor* import_descriptor;

  // The overridden function from the user config file.
  FunctionDescriptor* function_override;

  // The function that contains this call descriptor.
  FunctionDescriptor* containing_function;

  // The parameters for this call.
  ParameterList parameters;

  // The symbolic return value.
  SymbolicValuePtr return_value;

public:

  CallDescriptor() {
    address = 0;
    insn = NULL;
    function_descriptor = NULL;
    function_allocated = false;
    import_descriptor = NULL;
    confidence = ConfidenceNone;
    call_type = CallUnknown;
    call_location = CallLocationUnknown;
    function_override = NULL;
    containing_function = NULL;
    return_value = SymbolicValue::instance();
  }

  CallDescriptor(SgAsmx86Instruction* i) {
    address = 0;
    insn = i;
    function_descriptor = NULL;
    function_allocated = false;
    import_descriptor = NULL;
    confidence = ConfidenceNone;
    call_type = CallUnknown;
    call_location = CallLocationUnknown;
    function_override = NULL;
    containing_function = NULL;
    analyze();
    return_value = SymbolicValue::instance();
  }

  ~CallDescriptor() {

    // destroy the call information associated with this call if it is not referenced
    call_info.reset();

    if (function_allocated)
      delete function_descriptor;

    if (function_override != NULL)
      delete function_override;

  }

  void analyze();
  SgAsmInstruction* get_insn() const {
    return insn;
  }
  rose_addr_t get_address() const {
    return address;
  }

  // Add a new address to the targets list, recompute the merged descriptions, and update
  // connections with the affected function descriptor.
  void add_target(rose_addr_t taddr);
  // Return the set of target addresses.
  const CallTargetSet& get_targets() const { return targets; }

  std::string address_string() const {
    return str(boost::format("0x%08X") % address);
  }

  // Provide read-only access to the function descriptor and import descriptor.
  FunctionDescriptor* get_function_descriptor() const { return function_descriptor; }
  ImportDescriptor* get_import_descriptor() const { return import_descriptor; }

  // Get and set the return value.
  SymbolicValuePtr get_return_value() { return return_value; }
  void set_return_value(SymbolicValuePtr r) { return_value = r; }

  void update_connections();
  void add_import_target(ImportDescriptor* id);

  bool check_virtual(PDG *pdg);

  void update_call_type(CallType ct, GenericConfidence conf);

  CallType get_call_type() const  {
    return call_type;
  }

  StackDelta get_stack_delta();
  StackDelta get_stack_parameters();

  // Cory wants to isolate this better.  Maybe with friend, or by moving defuse code into funcs?
  ParameterList& get_rw_parameters() { return parameters; }
  const ParameterList& get_parameters() const { return parameters; }

  // Return the function that contains this call.
  FunctionDescriptor* get_containing_function() const { return containing_function; }

  // Read and write from property tree config files.
  void read_config(const boost::property_tree::ptree& tree, ImportNameMap* import_names);
  void write_config(boost::property_tree::ptree* tree);

  void print(std::ostream &o) const;
  // Return the "real" call targets, e.g. with thunks removed.
  // CallTargetSet get_real_targets();

  CallInformationPtr get_call_info() const {
    return call_info;
  }

  // Get the state at the time of the call.
  const SymbolicStatePtr get_state() const { return state; }
  // Set the state for this call (called while building the PDG).
  void set_state(SymbolicStatePtr s) {
    // Clone the state so that we get an unchanging copy?  In theory the reference counted
    // pointer should protect against deallocation.  Do we really need a clone?  Cory thinks
    // this is only set in defuse.cpp evaluate bblock, and then never used?
    state = s->sclone();
  }

  // Validate the call description, complaining about any unusual.
  void validate(std::ostream &o, FunctionDescriptorMap& fdmap);

  // Unused?
  bool operator<(const CallDescriptor& other) {
    return (address < other.get_address());
  }

  friend std::ostream& operator<<(std::ostream &o, const CallDescriptor &cd) {
    cd.print(o);
    return o;
  }
};

class CallDescriptorMap: public std::map<rose_addr_t, CallDescriptor> {

public:

  CallDescriptor* get_call(rose_addr_t addr) {
    CallDescriptorMap::iterator it = this->find(addr);
    if (it != this->end())
      return &(it->second);
    else
      return NULL;
  }

  // definition of a filter descriptor
  typedef boost::filter_iterator<CallDescMapPredicate, CallDescriptorMap::iterator> filtered_iterator;
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
  bool operator()(std::pair<rose_addr_t, CallDescriptor> c) const {

    bool ct_match = true, gc_match = true, tc_match = true;

    if (call_type != CallUnspecified) {
      ct_match = (c.second.call_type == call_type);
    }

    if (conf != ConfidenceUnspecified) {
      gc_match = (c.second.confidence == conf);
    }

    if (target_card != TargetSizeUnspecified) {
      if (target_card == TargetSizeZero) {
        tc_match = c.second.targets.empty();
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

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
