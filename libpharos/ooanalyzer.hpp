// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

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
#include "vftable.hpp"
#include "vcall.hpp"
#include "bua.hpp"
#include "threads.hpp"

namespace pharos {

using ProcessedAddresses = std::map<rose_addr_t, bool>;
using VirtualTableInstallationMap = std::map<rose_addr_t, VirtualTableInstallationPtr>;
using VirtualFunctionCallMap = std::map<rose_addr_t, VirtualFunctionCallVector>;
using MethodMap = std::map<rose_addr_t, std::unique_ptr<ThisCallMethod>>;
// An Itanium ABI virtual table table (VTT), mapping its address to the vftable address points
// that it references, in table order.
using ItaniumVTTMap = std::map<rose_addr_t, std::vector<rose_addr_t>>;

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

  ProcessedAddresses virtual_tables;

  // The Itanium ABI virtual table tables, which are how the construction vtables get found.
  ItaniumVTTMap itanium_vtts;

  // The Itanium ABI type information records.  One record serves every table of its class, and
  // the record of a non-polymorphic base class belongs to no table at all, so the finder is
  // per-program rather than per-table.
  ItaniumTypeInfoFinder itanium_typeinfo;

  // This entire new/delete/purecall system needs a major rewrite.  The new design is to have a
  // FunctionFinder() class that get initialized with some properties (names, hashes, etc.),
  // finds all the functions matching the critria, and then provides the interface to query
  // which functions match which criteria.  In the meantime let's just get the properties off
  // the FunctionDescriptor, which seemed like a good idea when there was only one property,
  // but now is bad for multiple reasons including that it requires inappropriate update access.


  // The transition plan is to just add the addresses of the matches functions to the address
  // sets.
  enum call_type { NEW, DELETE, FREE, CANDIDATE_DELETE, PURECALL };
  std::map<rose_addr_t, call_type> call_addrs;

  // The list of new addresses specified on the command line by the user.
  AddrSet user_new_addrs;
  // The list of delete addresses specified on the command line by the user.
  AddrSet user_delete_addrs;
  // The list of purecall addresses specified on the command line by the user.
  AddrSet user_purecall_addrs;

  time_point start_ts;

  // Analyze possible virtual table at a specified address.
  bool analyze_possible_vtable(rose_addr_t address, bool allow_base = true);
  // Find possible virtual tables in a given function.
  void find_vtable_installations(FunctionDescriptor const & fd);
  // Find the Itanium ABI VTTs, and through them the vtables that no instruction names.
  void find_itanium_vtts();

  // Find heap allocations?
  void find_heap_allocs();
  // Handlethem by adding them to the previously global map?
  void handle_heap_allocs(const rose_addr_t saddr);

  // Release call states after all per-function analyses have consumed them.
  void discard_call_states(FunctionDescriptor* fd);

  bool identify_new_method(FunctionDescriptor const & fd);
  bool identify_free_method(FunctionDescriptor const & fd);
  bool identify_delete_method(FunctionDescriptor const & fd);
  bool identify_purecall_method(FunctionDescriptor const & fd);
  bool identify_nonreturn_method(FunctionDescriptor & fd);

  // Mark methods as new(), delete(), and purecall() respectively.
  void set_new_method(rose_addr_t addr) {
    write_guard<decltype(mutex)> guard{mutex};
    call_addrs.emplace(addr, NEW);
  }
  void set_delete_method(rose_addr_t addr) {
    write_guard<decltype(mutex)> guard{mutex};
    call_addrs.emplace(addr, DELETE);
  }
  void set_candidate_delete_method(rose_addr_t addr) {
    write_guard<decltype(mutex)> guard{mutex};
    call_addrs.emplace(addr, CANDIDATE_DELETE);
  }
  void set_free_method(rose_addr_t addr) {
    write_guard<decltype(mutex)> guard{mutex};
    call_addrs.emplace(addr, FREE);
  }
  void set_purecall_method(rose_addr_t addr) {
    write_guard<decltype(mutex)> guard{mutex};
    call_addrs.emplace(addr, PURECALL);
  }

  using check_method_t = bool (OOAnalyzer::*)(rose_addr_t) const;
  using set_method_t   = void (OOAnalyzer::*)(rose_addr_t);

  // Helper function to unify identifying various special methods.
  bool identify_method(
    FunctionDescriptor const & fd,
    AddrSet const * user_addrs,
    check_method_t check,
    set_method_t set,
    std::string const & tag);

 public:

  OOAnalyzer(DescriptorSet& ds_, const ProgOptVarMap& vm_);

  // External classes need to inspect the tables that we found.
  const VFTableAddrMap& get_vftables() const { return vftables; }
  const VBTableAddrMap& get_vbtables() const { return vbtables; }
  const VirtualFunctionCallMap& get_vcalls() const { return vcalls; }
  const ItaniumVTTMap& get_itanium_vtts() const { return itanium_vtts; }
  const ItaniumTypeInfoMap& get_itanium_typeinfo() const {
    return itanium_typeinfo.get_records();
  }

  // Is the provided address a new(), delete(), or purecall() method?
  bool is_new_method(rose_addr_t addr) const {
    read_guard<decltype(mutex)> guard{mutex};
    auto i = call_addrs.find(addr);
    return i != call_addrs.end() && i->second == NEW;
  }
  bool is_delete_method(rose_addr_t addr) const {
    read_guard<decltype(mutex)> guard{mutex};
    auto i = call_addrs.find(addr);
    return i != call_addrs.end() && i->second == DELETE;
  }
  // Free, delete, or delete candidate.
  bool is_free_like_method(rose_addr_t addr) const {
    read_guard<decltype(mutex)> guard{mutex};
    auto i = call_addrs.find(addr);
    if (i == call_addrs.end()) return false;
    if (i->second == DELETE) return true;
    if (i->second == FREE) return true;
    if (i->second == CANDIDATE_DELETE) return true;
    return false;
  }
  // Either delete or candidate delete.
  bool is_candidate_delete_method(rose_addr_t addr) const {
    read_guard<decltype(mutex)> guard{mutex};
    auto i = call_addrs.find(addr);
    if (i == call_addrs.end()) return false;
    if (i->second == DELETE) return true;
    if (i->second == CANDIDATE_DELETE) return true;
    return false;
  }
  bool is_free_method(rose_addr_t addr) const {
    read_guard<decltype(mutex)> guard{mutex};
    auto i = call_addrs.find(addr);
    return i != call_addrs.end() && i->second == FREE;
  }
  bool is_purecall_method(rose_addr_t addr) const {
    read_guard<decltype(mutex)> guard{mutex};
    auto i = call_addrs.find(addr);
    return i != call_addrs.end() && i->second == PURECALL;
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
