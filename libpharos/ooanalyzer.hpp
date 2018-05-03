// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

// This code represents the new Prolog based approach!

#ifndef Pharos_OOAnalyzer_H
#define Pharos_OOAnalyzer_H

#include <chrono>

#include "descriptors.hpp"
#include "options.hpp"
#include "defuse.hpp"
#include "method.hpp"
#include "usage.hpp"
#include "ooclass.hpp"

namespace pharos {

typedef std::map<rose_addr_t, bool> ProcessedAddresses;
typedef std::map<rose_addr_t, VirtualTableInstallationPtr> VirtualTableInstallationMap;

class OOAnalyzer : public BottomUpAnalyzer {
private:
  using clock = std::chrono::steady_clock;
  using time_point = std::chrono::time_point<clock>;
  using duration = std::chrono::duration<double>;

  ProcessedAddresses virtual_tables;

  // A list of hashes known to be new() methods.  This should really be read from a JSON config
  // file or something, but for now, we'll just initialize it manually.
  StringSet new_hashes;

  // A list of addresses of known new() methods.  This list can be supplemented by the user by
  // address. It does _not_ include all known new methods, wihch is stored on a property on the
  // FunctionDescriptor via set_new_method(), and accessed via is_new_method().
  AddrSet new_addrs;

  // The number of new() methods found.  Just for reporting whether we've found any new methods.
  int new_methods_found;

  // A comparable set of variables for tracking delete() methods.
  StringSet delete_hashes;
  StringSet free_hashes;
  AddrSet delete_addrs;
  int delete_methods_found;

  // A comparable set of variables for tracking _purecall methods.
  StringSet purecall_hashes;
  AddrSet purecall_addrs;
  int purecall_methods_found;

  // Yet another hacked up magic list of method hashes, this time for non-returning functions.
  StringSet nonreturn_hashes;

  time_point start_ts;

  // Analyze possible virtual table at a specified address.
  bool analyze_possible_vtable(rose_addr_t address, bool allow_base = true);
  // Find possible virtual tables in a given function.
  void find_vtable_installations(FunctionDescriptor *fd);

  // Initialize the list of known methods with some well-known hashes.
  void initialize_known_method_hashes();
  // Find new() methods by examining imports.
  void find_imported_new_methods();
  // Find delete() methods by examining imports.
  void find_imported_delete_methods();
  // Find purecall() methods by examining imports.
  void find_imported_purecall_methods();

  // Find heap allocations?
  void find_heap_allocs();
  // Handlethem by adding them to the previously global map?
  void handle_heap_allocs(const rose_addr_t saddr);


  bool identify_new_method(FunctionDescriptor* fd);
  bool identify_delete_method(FunctionDescriptor* fd);
  bool identify_purecall_method(FunctionDescriptor* fd);
  bool identify_nonreturn_method(FunctionDescriptor* fd);

  std::vector<OOClassDescriptorPtr> ooclasses;

public:

  // Virtual table installations.
  VirtualTableInstallationMap virtual_table_installations;

  // A map of object uses.  Populated in analyze_functions_for_object_uses().
  ObjectUseMap object_uses;

  OOAnalyzer(DescriptorSet* ds_, ProgOptVarMap& vm_, AddrSet& new_addrs_);

  std::vector<OOClassDescriptorPtr> get_result_classes();
  void visit(FunctionDescriptor* fd);
  void finish();
};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
