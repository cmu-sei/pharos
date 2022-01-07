// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Imports_H
#define Pharos_Imports_H

#include <boost/format.hpp>

namespace pharos {

// Forward declaration of mport descriptor for recursive includes.
class ImportDescriptor;
// Import name map (names to import descriptors).
// There's no global map of this form currently, only local variables. :-(
using ImportNameMap = std::map<std::string, ImportDescriptor*>;

} // namespace pharos

#include "util.hpp"
#include "funcs.hpp"
#include "delta.hpp"
#include "semantics.hpp"
#include "threads.hpp"

namespace pharos {

class ImportDescriptor : private Immobile {
  static constexpr auto unknown_name = "*INVALID*";

  mutable shared_mutex mutex;

  // The address of the import descriptor.  This can be NULL or invalid if the import
  // descriptor has not been found yet.
  rose_addr_t address = 0;

  // This is a private function descriptor that records the stack delta, calling convention,
  // etc. for the function that the import ultimately calls out to.  This information can not
  // be obtained from the program being analyzed, and must be supplied by the user or guessed
  // at by heuristics.
  FunctionDescriptor function_descriptor;

  // The name of the import as it appears in the import table.
  std::string name;
  // The name of the DLL as it appears in the import directory.
  std::string dll;
  // The import by ordinal number.
  size_t ordinal = 0;

  // A set of call instructions that call to this import.
  CallTargetSet callers;

  // The symbolic value of the dword of memory at the address of the import.  For a while Cory
  // was returning the address of the import itself, but this can be a little confusing and
  // potentially incorrect in unusual scenarios.  Chuck pointed out that we could create a
  // symbolic value and store it here, and be closer to a correct implementation.  This value
  // is simply created when the import is constructed, and it's used by RiscOps::readMemory()
  // to return a consistent value whenever [address] is read initially.  We can also check it
  // to see if it matches at the time the call is made.  This would be the value filled in by
  // the loader when the import is resolved at load time.
  SymbolicValuePtr loader_variable;

 public:

  ImportDescriptor(DescriptorSet& ds_) : function_descriptor(ds_) {
    name = unknown_name;
    dll = unknown_name;
    loader_variable = SymbolicValue::loader_defined();
  }

  ImportDescriptor(DescriptorSet& ds_, rose_addr_t addr_, std::string dll_, std::string name_, size_t ord_ = 0);

  auto get_callers() const { return make_read_locked_range(callers, mutex); }
  bool is_name_valid() const {
    read_guard<decltype(mutex)> guard{mutex};
    return name != unknown_name;
  }
  bool is_dll_valid() const {
    read_guard<decltype(mutex)> guard{mutex};
    return dll != unknown_name;
  }
  const std::string & get_name() const {
    read_guard<decltype(mutex)> guard{mutex};
    return name;
  }
  size_t get_ordinal() const {
    read_guard<decltype(mutex)> guard{mutex};
    return ordinal;
  }
  const std::string & get_dll_name() const {
    read_guard<decltype(mutex)> guard{mutex};
    return dll;
  }
  std::string get_long_name() const {
    read_guard<decltype(mutex)> guard{mutex};
    return dll + ":" + name;
  }
  std::string get_normalized_name() const;
  std::string get_best_name() const;
  std::string get_ordinal_name() const {
    read_guard<decltype(mutex)> guard{mutex};
    return to_lower(dll) + ":" + str(boost::format("%d") % ordinal);
  }
  rose_addr_t get_address() const { return address; }
  std::string address_string() const { return str(boost::format("0x%08X") % address); }
  FunctionDescriptor* get_rw_function_descriptor() { return &function_descriptor; }
  const FunctionDescriptor* get_function_descriptor() const { return &function_descriptor; }
  std::string get_dll_root() const;
  SymbolicValuePtr get_loader_variable() const { return loader_variable; }
  StackDelta get_stack_delta() const { return function_descriptor.get_stack_delta(); }
  LeafNodePtr get_stack_delta_variable() const {
    return function_descriptor.get_stack_delta_variable();
  }
  StackDelta get_stack_parameters() const { return function_descriptor.get_stack_parameters(); }

  void add_caller(rose_addr_t addr) {
    write_guard<decltype(mutex)> guard{mutex};
    callers.insert(addr);
  }

  // Validate the function description, complaining about any unusual.
  void validate(std::ostream &o) const;

  // Merge a DLL export descriptor with ourself.
  void merge_api_definition(APIDefinition const & def);

  void print(std::ostream &o) const;
  friend std::ostream& operator<<(std::ostream &o, const ImportDescriptor &id) {
    id.print(o);
    return o;
  }
};

class ImportDescriptorMap: public std::map<rose_addr_t, ImportDescriptor> {

 public:

  const ImportDescriptor* get_import(rose_addr_t addr) const {
    ImportDescriptorMap::const_iterator it = this->find(addr);
    if (it != this->end())
      return &(it->second);
    else
      return NULL;
  }

  ImportDescriptor* get_import(rose_addr_t addr) {
    ImportDescriptorMap::iterator it = this->find(addr);
    if (it != this->end())
      return &(it->second);
    else
      return NULL;
  }

  // Find the one descriptor matching a specific DLL and name?
  const ImportDescriptor* find_name(const std::string & dll,
                                    const std::string & name) const;
  // Find all descriptors with a given name.
  std::set<const ImportDescriptor*> find_name(
    const std::string & name) const;
};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
