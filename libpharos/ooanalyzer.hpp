// Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.

// This code represents the new Prolog based approach!

#ifndef Pharos_OOAnalyzer_H
#define Pharos_OOAnalyzer_H

#include <chrono>
#include <atomic>

#include "descriptors.hpp"
#include "options.hpp"
#include "defuse.hpp"
#include "method.hpp"
#include "usage.hpp"
#include "ooclass.hpp"
#include "vftable.hpp"
#include "vcall.hpp"
#include "bua.hpp"
#include "threads.hpp"

namespace pharos {

using ProcessedAddresses = std::map<rose_addr_t, bool>;
using VirtualTableInstallationMap = std::map<rose_addr_t, VirtualTableInstallationPtr>;
using VirtualFunctionCallMap = std::map<rose_addr_t, VirtualFunctionCallVector>;
using MethodMap = std::map<rose_addr_t, std::unique_ptr<ThisCallMethod>>;

class OOAnalyzer : public BottomUpAnalyzer {
private:
  using clock = std::chrono::steady_clock;
  using time_point = std::chrono::time_point<clock>;
  using duration = std::chrono::duration<double>;

  mutable std_mutex mutex;

  VFTableAddrMap vftables;
  VBTableAddrMap vbtables;
  VirtualFunctionCallMap vcalls;
  MethodMap methods;

  // Map of call addresses to the symbolic values of the this-pointers at the time of the call.
  std::map<rose_addr_t, SymbolicValuePtr> callptrs;

  ProcessedAddresses virtual_tables;

  // This entire new/delete/purecall system needs a major rewrite.  The new design is to have a
  // FunctionFinder() class that get initialized with some properties (names, hashes, etc.),
  // finds all the functions matching the critria, and then provides the interface to query
  // which functions match which criteria.  In the meantime let's just get the properties off
  // the FunctionDescriptor, which seemed like a good idea when there was only one property,
  // but now is bad for multiple reasons including that it requires inappropriate update access.

  // The transition plan is to just add the addresses of the matches functions to the address
  // sets.

  // A list of hashes known to be new() methods.  This should really be read from a JSON config
  // file or something, but for now, we'll just initialize it manually.
  std::set<std::string> new_hashes;

  // A list of addresses of known new() methods.  This list can be supplemented by the user by
  // address. It does _not_ include all known new methods, wihch is stored on a property on the
  // FunctionDescriptor via set_new_method(), and accessed via is_new_method().
  AddrSet new_addrs;

  // The number of new() methods found.  Just for reporting whether we've found any new methods.
  std::atomic<int> new_methods_found;

  // A comparable set of variables for tracking delete() methods.
  std::set<std::string> delete_hashes;
  std::set<std::string> free_hashes;
  AddrSet delete_addrs;
  std::atomic<int> delete_methods_found;

  // A comparable set of variables for tracking _purecall methods.
  std::set<std::string> purecall_hashes;
  AddrSet purecall_addrs;
  std::atomic<int> purecall_methods_found;

  // Yet another hacked up magic list of method hashes, this time for non-returning functions.
  std::set<std::string> nonreturn_hashes;

  time_point start_ts;

  // Analyze possible virtual table at a specified address.
  bool analyze_possible_vtable(rose_addr_t address, bool allow_base = true);
  // Find possible virtual tables in a given function.
  void find_vtable_installations(FunctionDescriptor const & fd);

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

  // Record this-pointers in a map more efficiently than in call descriptor states.
  void record_this_ptrs_for_calls(FunctionDescriptor* fd);

  bool identify_new_method(FunctionDescriptor const & fd);
  bool identify_delete_method(FunctionDescriptor const & fd);
  bool identify_purecall_method(FunctionDescriptor const & fd);
  bool identify_nonreturn_method(FunctionDescriptor & fd);

  std::vector<OOClassDescriptorPtr> ooclasses;

  // Mark methods as new(), delete(), and purecall() respectively.
  void set_new_method(rose_addr_t addr) {
      write_guard<decltype(mutex)> guard{mutex};
      new_addrs.insert(addr);
  }
  void set_delete_method(rose_addr_t addr) {
    {
      write_guard<decltype(mutex)> guard{mutex};
      delete_addrs.insert(addr);
    }
    // This update only works if the function descriptor is a "normal" one.  It's needed
    // because there are still two places that require access from the function descriptor
    // using the old API. :-(
    FunctionDescriptor *fd = ds.get_rw_func(addr); // set_delete_method()
    if (fd) fd->set_delete_method(true);
  }
  void set_purecall_method(rose_addr_t addr) { purecall_addrs.insert(addr); }

public:

  OOAnalyzer(DescriptorSet& ds_, const ProgOptVarMap& vm_, AddrSet& new_addrs_);

  // External classes need to inspect the tables that we found.
  const VFTableAddrMap& get_vftables() const { return vftables; }
  const VBTableAddrMap& get_vbtables() const { return vbtables; }
  const VirtualFunctionCallMap& get_vcalls() const { return vcalls; }

  // Is the provided address a new(), delete(), or purecall() method?
  bool is_new_method(rose_addr_t addr) const {
    return (new_addrs.find(addr) != new_addrs.end());
  }
  bool is_delete_method(rose_addr_t addr) const {
    return (delete_addrs.find(addr) != delete_addrs.end());
  }
  bool is_purecall_method(rose_addr_t addr) const {
    return (purecall_addrs.find(addr) != purecall_addrs.end());
  }

  ThisCallMethod* get_method_rw(rose_addr_t addr) {
    MethodMap::const_iterator it = methods.find(addr);
    if (it == methods.end()) return nullptr;
    return (*it).second.get();
  }

  const ThisCallMethod* get_method(rose_addr_t addr) const {
    MethodMap::const_iterator it = methods.find(addr);
    if (it == methods.end()) return nullptr;
    return (*it).second.get();
  }

  const MethodMap& get_methods() const { return methods; }

  // Once the this-pointers have been recorded for each call, e.g. during visit(), then this
  // method can be used to access them again during finish(), even though the states from the
  // call descriptors have been freed.
  const SymbolicValuePtr get_this_ptr_for_call(rose_addr_t addr) const {
    if (callptrs.find(addr) == callptrs.end()) return SymbolicValuePtr();
    return callptrs.at(addr);
  }

  const ThisCallMethod* follow_thunks(rose_addr_t addr) const {
    const FunctionDescriptor* fd = ds.get_func(addr);
    if (fd == nullptr) return nullptr;
    bool endless = false;
    rose_addr_t final_addr = fd->follow_thunks(&endless);
    if (endless) return nullptr;
    return get_method(final_addr);
  }

  // Virtual table installations.
  VirtualTableInstallationMap virtual_table_installations;

  // A map of object uses.  Populated in analyze_functions_for_object_uses().
  ObjectUseMap object_uses;

  std::vector<OOClassDescriptorPtr> get_result_classes();
  void visit(FunctionDescriptor* fd) override;
  void start() override;
  void finish() override;
};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
