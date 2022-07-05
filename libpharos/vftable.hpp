// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_VFTable_H
#define Pharos_VFTable_H

#include "delta.hpp"
#include "funcs.hpp"
#include "datatypes.hpp"

namespace pharos {

// Forward declarations of the virtual table classes for the maps.
class VirtualFunctionTable;
class VirtualBaseTable;
// Maps of addresses to the virtual function tables and virtual base tables.
using VFTableAddrMap = std::map<rose_addr_t, std::unique_ptr<VirtualFunctionTable>>;
using VBTableAddrMap = std::map<rose_addr_t, std::unique_ptr<VirtualBaseTable>>;

// An instruction that possibly installs a virtual table.
class VirtualTableInstallation {
 public:
  // The instruction that installed the table somewhere.
  SgAsmInstruction* insn;
  // The function that the instruction is in.
  FunctionDescriptor const * fd;
  // The constant address of the table.
  rose_addr_t table_address;
  // The variable portion of the symbolic value that the table was written into.
  TreeNodePtr written_to;
  // The constant offset into the symbolic value.
  int64_t offset;
  // The expanded version of the entire ptr; so we can create thisPtrDefinition facts
  TreeNodePtr expanded_ptr;
  // True if the table is virtual base table, and false it is a virtual function table.
  bool base_table;

  VirtualTableInstallation(SgAsmInstruction* i, FunctionDescriptor const *f,
                           rose_addr_t a, TreeNodePtr w, int64_t o, TreeNodePtr pe, bool b);
};

using VirtualTableInstallationPtr = std::shared_ptr<VirtualTableInstallation>;
using ConstVirtualTableInstallationPtr = std::shared_ptr<const VirtualTableInstallation>;

class VirtualBaseTable {

  const DescriptorSet& ds;

  bool valid() const;

 public:

  // The address in memory where the virtual base table is located.
  rose_addr_t addr;

  // A best guess size for the table.
  size_t size;

  VirtualBaseTable(const DescriptorSet& ds_, rose_addr_t a) : ds(ds_) {
    addr = a;
    size = 0;
  }

  // Analyzes the vitrual base table.  Returns true if the table is valid, and false if it is
  // not.
  bool analyze();

  // Limit sizes based on overlaps with other tables and data structures.
  void analyze_overlaps(const VFTableAddrMap& vftables, const VBTableAddrMap& vbtables);

  // Read an entry from the table.
  signed int read_entry(unsigned int entry) const;
};

using TypeRTTICompleteObjectLocatorPtr = std::shared_ptr<TypeRTTICompleteObjectLocator>;

class VirtualFunctionTable {

  const DescriptorSet& ds;

  bool valid() const;

 public:

  // The address in memory where the virtual function table is located.
  rose_addr_t addr;

  // Known minimum size, in entries (not bytes)
  size_t min_size;
  // Known maximum size, in entries (not bytes)
  size_t max_size;
  // Non-function pointers found.  This field was added because legitimate virtual function
  // tables were being rejected because none of the pointers were to recognized functions.
  unsigned int non_function;
  // Best guess at size given current information, in entries (not bytes)
  size_t best_size;
  // Confidence in the best guess at size
  GenericConfidence size_confidence;

  // RTTI information is stored directly above the virtual function table. It can be saved here
  // for later usage (if it is present).
  TypeRTTICompleteObjectLocatorPtr rtti;

  // the address of the rtti structures
  rose_addr_t rtti_addr;

  // The confidence is based on the technique used to identify RTTI.
  GenericConfidence rtti_confidence;

  // This constructor should be deprecated in favor of the one that requires an address if
  // that's not a problem.
  VirtualFunctionTable(const DescriptorSet& ds_) : ds(ds_) {
    addr = 0;
    min_size = 0;
    max_size = 0;
    non_function = 0;
    best_size = 0;
    size_confidence = ConfidenceNone;
    rtti_confidence = ConfidenceNone;
  }

  VirtualFunctionTable(const DescriptorSet& ds_, rose_addr_t a) : ds(ds_) {
    addr = a;
    min_size = 0;
    max_size = 0;
    non_function = 0;
    best_size = 0;
    size_confidence = ConfidenceNone;
    rtti_confidence = ConfidenceNone;
  }

  // Determine if RTTI is present with this virtual function table
  void analyze_rtti(const rose_addr_t address);

  // This method updates the minimum size of the table based on new information (typically a
  // known virtual function call using the table).  This value always grows, because we're
  // supposed to be making sound assertions about the minimum size.
  void update_minimum_size(size_t new_size);

  // This method updates the maximum size of the table based on new information (typically by
  // walking the memory of the vtable looking for valid function pointers).  This value always
  // shrinks, because we're supposed to be making sound assertions about the maximum size.
  void update_maximum_size(size_t new_size);

  void update_best_size(size_t besty);

  // Take a "guess" at the correct table size, and update our confidence appropriately.
  void update_size_guess();

  // Read an entry from the table.
  rose_addr_t read_entry(unsigned int entry) const;

  // A convenience version of the above interface when you expect a fully valid function
  // descriptor object pointer.
  const FunctionDescriptor * read_entry_fd(unsigned int entry) const;

  // This method updates the fields describing the virtual function table based on analyzing
  // the contents of the memory at the address of the table.  Returns true if the table is
  // valid, and false if it is not.  Requires a list of existing tables to check for overlaps,
  // and becuse of some complexity with finding the next vftable unsolicited, it also needs
  // update access.  More cleanup is required.
  bool analyze(VFTableAddrMap& vftables);
};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
