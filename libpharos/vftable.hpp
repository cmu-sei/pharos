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

TypeRTTICompleteObjectLocatorPtr read_msvc_rtti(const DescriptorSet& ds, rose_addr_t addr);

using ItaniumTypeInfoMap = std::map<rose_addr_t, TypeItaniumTypeInfo>;

// The Itanium ABI counterpart of read_msvc_rtti(), which has to be a class rather than a
// function because it answers a question no single record can: which of the three __cxxabiv1
// classes a record is an instance of decides its layout, and the record does not say.
//
// Three things can answer it, in descending order of reliability.  A relocation on the
// record's own vtable word names the __cxxabiv1 class, which is what a binary that gets the
// class from libstdc++ has.  A symbol names one of the three type_info vtables, which is what
// a binary carrying its own copy has.  Failing both, the record's own shape decides, and that
// answer is remembered per type_info vtable rather than per record, because it cannot stand on
// its own: two adjacent 16-byte __class_type_info records are laid out exactly like one
// __si_class_type_info naming the other.
//
// Records are memoized by address, since one record serves every table of its class and the
// record of a non-polymorphic base class belongs to no table at all.
class ItaniumTypeInfoFinder {
 public:
  ItaniumTypeInfoFinder(const DescriptorSet& ds_);

  // Read the record at an address, and the records of its base classes.  Returns nullptr if
  // there is no type information record there.  The returned pointer is stable.
  const TypeItaniumTypeInfo* read(rose_addr_t addr);

  // Is this the two word header that precedes a virtual table's address point?  True when the
  // second word names a type information record and the first is a plausible offset-to-top.
  // This is what ends the walk of the table that precedes the header.
  bool is_address_point_header(rose_addr_t addr);

  const ItaniumTypeInfoMap& get_records() const { return records; }

 private:
  const DescriptorSet& ds;
  size_t arch_bytes;

  ItaniumTypeInfoMap records;
  // The addresses that hold no record, so that a base class pointer into another shared
  // object is only diagnosed once.
  AddrSet rejected;
  // The kind of each type_info vtable, keyed by the address point that a record's vtable word
  // holds.  Seeded from the ELF symbols, extended as records are classified structurally.
  std::map<rose_addr_t, ItaniumTypeInfoKind> vtable_kinds;

  // Seed vtable_kinds from the ELF symbols for the three __cxxabiv1 type_info vtables.
  void find_abi_vtables();
  // Is there a plausible mangled type name at this address?
  bool is_name(rose_addr_t addr) const;
  // Decide which of the three classes the record at an address is an instance of.
  ItaniumTypeInfoKind classify(rose_addr_t addr, rose_addr_t vptr);
  // Do the words after the name parse as an __vmi_class_type_info base class array?
  bool reads_as_vmi(rose_addr_t addr) const;
};

// Demangle an Itanium ABI type name, as type_info::name() reports it.  Returns an empty string
// if the name does not demangle.
std::string demangle_itanium_type(std::string const & name);

class VirtualFunctionTable {

  const DescriptorSet& ds;

  bool valid() const;

 public:

  // The address in memory where the virtual function table is located.
  rose_addr_t addr;

  // Non-function pointers found.  This field was added because legitimate virtual function
  // tables were being rejected because none of the pointers were to recognized functions.
  unsigned int non_function;

  // Whether analyze() got as far as one entry.  This is not the same question as valid(), since
  // a table made entirely of pointers that we could not identify as functions has no entries but
  // is still accepted.  How many entries a table really has is decided in OOSolver, which is the
  // only place that needs to know.
  bool has_entries;

  // RTTI information is stored directly above the virtual function table. It can be saved here
  // for later usage (if it is present).
  TypeRTTICompleteObjectLocatorPtr msvc_rtti;

  // the address of the rtti structures
  rose_addr_t msvc_rtti_addr;

  // The confidence is based on the technique used to identify RTTI.
  GenericConfidence msvc_rtti_confidence;

  // Under the Itanium ABI the word above the table points at the type information of the class
  // the table serves, and the word above that says where in the object the subobject it serves
  // begins.  The record is owned by the finder, which outlives every table.
  const TypeItaniumTypeInfo* itanium_rtti;
  int64_t offset_to_top;

  VirtualFunctionTable(const DescriptorSet& ds_, rose_addr_t a) : ds(ds_) {
    addr = a;
    non_function = 0;
    has_entries = false;
    msvc_rtti_confidence = ConfidenceNone;
    itanium_rtti = nullptr;
    offset_to_top = 0;
  }

  // Determine if RTTI is present with this virtual function table
  void analyze_msvc_rtti(const rose_addr_t address);

  // The Itanium ABI equivalent, reading the type information record that the word above the
  // table names, and the offset-to-top beside it.
  void analyze_itanium_rtti(ItaniumTypeInfoFinder& typeinfo);

  // Read an entry from the table.
  rose_addr_t read_entry(unsigned int entry) const;

  // This method updates the fields describing the virtual function table based on analyzing
  // the contents of the memory at the address of the table.  Returns true if the table is
  // valid, and false if it is not.  Requires a list of existing tables to check for overlaps,
  // and becuse of some complexity with finding the next vftable unsolicited, it also needs
  // update access.  More cleanup is required.  The type information finder is needed because
  // under the Itanium ABI it is what says where the table ends: the next component of the
  // group announces itself with the two word header below its own address point.
  bool analyze(VFTableAddrMap& vftables, ItaniumTypeInfoFinder& typeinfo);
};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
