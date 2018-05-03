// Copyright 2015, 2016, 2017 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Imports_H
#define Pharos_Imports_H

#include <boost/format.hpp>
#include <boost/property_tree/ptree.hpp>

#include <rose.h>

namespace pharos {

// Forward declaration of mport descriptor for recursive includes.
class ImportDescriptor;
// Import name map (names to import descriptors).
// There's no global map of this form currently, only local variables. :-(
typedef std::map<std::string, ImportDescriptor*> ImportNameMap;
// A set of import descriptors.
typedef std::set<ImportDescriptor*> ImportDescriptorSet;

} // namespace pharos

#include "util.hpp"
#include "masm.hpp"
#include "funcs.hpp"
#include "delta.hpp"
#include "semantics.hpp"

namespace pharos {

class ImportDescriptor {
  static constexpr auto unknown_name = "*INVALID*";

  // The address of the import descriptor.  This can be NULL or invalid if the import
  // descriptor has not been found yet.
  rose_addr_t address;

  // The SgAsmImportItem object.  This member call be NULL if the import descriptor was created
  // by the user or resolved from so kind of import obfucsation technique.
  SgAsmPEImportItem* item;

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
  size_t ordinal;

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

  // Our whole approach to marking methods as new, delete and purecall is getting messier and
  // messier.   It's probably getting to be time for a new strategy involving the API database.
  bool new_method;
  bool delete_method;
  bool purecall_method;

 public:

  ImportDescriptor() {
    address = 0;
    item = NULL;
    name = unknown_name;
    dll = unknown_name;
    ordinal = 0;
    new_method = false;
    delete_method = false;
    purecall_method = false;
    loader_variable = SymbolicValue::loader_defined();
  }

  ImportDescriptor(const APIDefinition &func);

  ImportDescriptor(std::string d, SgAsmPEImportItem *i);

  CallTargetSet get_callers() const { return callers; }
  bool is_name_valid() const { return name != unknown_name; }
  bool is_dll_valid() const { return dll != unknown_name; }
  const std::string & get_name() const { return name; }
  size_t get_ordinal() const { return ordinal; }
  const std::string & get_dll_name() const { return dll; }
  std::string get_long_name() const { return dll + ":" + name; }
  std::string get_normalized_name() const;
  std::string get_best_name() const;
  std::string get_ordinal_name() const {
    return to_lower(dll) + ":" + str(boost::format("%d") % ordinal); }
  rose_addr_t get_address() const { return address; }
  void add_caller(rose_addr_t addr) { callers.insert(addr); }
  std::string address_string() const { return str(boost::format("0x%08X") % address); }
  FunctionDescriptor* get_rw_function_descriptor() { return &function_descriptor; }
  const FunctionDescriptor* get_function_descriptor() const { return &function_descriptor; }
  std::string get_dll_root() const;
  SymbolicValuePtr get_loader_variable() const { return loader_variable; }

  void set_names_hack(std::string compund_name);

  StackDelta get_stack_delta() const { return function_descriptor.get_stack_delta(); }
  const LeafNodePtr & get_stack_delta_variable() const {
    return function_descriptor.get_stack_delta_variable();
  }
  StackDelta get_stack_parameters() const { return function_descriptor.get_stack_parameters(); }

  // Validate the function description, complaining about any unusual.
  void validate(std::ostream &o);

  // Read and write from property tree config files.
  void read_config(const boost::property_tree::ptree& tree);
  void write_config(boost::property_tree::ptree* tree);

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

  // Merge a DLL export descriptor with ourself.
  void merge_export_descriptor(ImportDescriptor* did);

  void print(std::ostream &o) const;
  friend std::ostream& operator<<(std::ostream &o, const ImportDescriptor &id) {
    id.print(o);
    return o;
  }
};

class ImportDescriptorMap: public std::map<rose_addr_t, ImportDescriptor> {

 public:

  ImportDescriptor* get_import(rose_addr_t addr) {
    ImportDescriptorMap::iterator it = this->find(addr);
    if (it != this->end())
      return &(it->second);
    else
      return NULL;
  }

  // Find the one descriptor matching a specific DLL and name?
  ImportDescriptor* find_name(const std::string & dll, const std::string & name);
  // Find all descriptors with a given name.
  ImportDescriptorSet find_name(const std::string & name);
};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
