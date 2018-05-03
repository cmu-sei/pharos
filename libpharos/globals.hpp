// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Globals_H
#define Pharos_Globals_H

#include <boost/format.hpp>
#include <rose.h>
#include "state.hpp"
#include "semantics.hpp"
#include "delta.hpp"

namespace pharos {

// duplicative...
typedef std::set<SgAsmInstruction*> InsnSet;

// A procedural method that's defined here and used in several places.  This hack is not
// related to initializing ESP to zero, but rather sorting out which constants are likely to be
// addresses and which are not.  It should be replaced with a method that properly inspects the
// memory map.
inline bool possible_global_address(rose_addr_t addr) {
  if (addr > 0x00000ffff && addr < 0x7fffffff) return true;
  return false;
}

// This is still a fairly horrid way of doing this.  We should really have some kind of
// interpreted data-driven mechanism for loading the definitions of structures.  In the mean
// time, this will get the job done.
enum DataType {
  DTypeNone,
  DTypeByte,
  DTypeWord,
  DTypeWordInt,
  DTypeWordSignedInt,
  DTypeDword,
  DTypeDwordInt,
  DTypeDwordSignedInt,
  DTypeDwordAddr,
  DTypeQword,
  DTypeChar,
  DTypeWideChar,
  DTypeString,
  DTypeUnicodeString,
  DTypeLen8String,
  DTypeLen16String,
  DTypeLen32String,
  DTypeLen16UnicodeString,
  DTypeLen32UnicodeString,
  DTypeSEH3ExceptionRegistration,
  DTypeSEH4ScopeTableRecord,
  DTypeSEH4ScopeTable,
  DTypeSEH4TryBlockMapEntry,
  DTypeSEH4HandlerType,
  DTypeSEH4UnwindMapEntry,
  DTypeSEH4FuncInfo,
  DTypeRTCFrameDesc,
  DTypeRTCVarDesc,
  DTypeRTTITypeDescriptor,
  DTypeRTTICompleteObjectLocator,
  DTypeRTTIClassHierarchyDescriptor,
  DTypeRTTIBaseClassArray,
  DTypeRTTIBaseClassDescriptor,
};

// I'd like to be able to use extern here to reduce compilation dependencies.
// Declared extern here just to reduce compile dependencies.
// The real definition is in datatypes.hpp.
//extern enum DataType;

class GlobalMemoryDescriptor {
  // The address of the global memory.  This is where the data or code
  // is at during execution.
  rose_addr_t address;

  // The instructions which refefence the constant address.
  InsnSet refs;

  // The instructions known to read and write the global
  // memory address.
  InsnSet reads;
  InsnSet writes;

  // Is the memory address defined in the PE header?
  bool in_image;
  // Is the memory address initialized at program load?
  bool initialized;

  // Our confidence in the data type.
  GenericConfidence confidence;
  // The data type as an enumeration.
  DataType type;

  // The list of abstract value associated with this global variable
  std::vector<SymbolicValuePtr> values;

  // The address of the global
  SymbolicValuePtr memory_address;

  // The total size of contiguous data at this address.  Zero means we don't currently know.
  size_t size;
  // The initial access size (operand size of the intruction).  This will be zero if we don't
  // know, and -1 if we have mutiple accesses with conflicting initial sizes.
  int access_size;

  // Whether the address is known to be a data or code reference.

  // The type of the global memory reference.  e.g. Virtual function table, compiler data
  // struct, jump table, etc.

public:

  GlobalMemoryDescriptor();

  GlobalMemoryDescriptor(rose_addr_t addr);

  SymbolicValuePtr get_memory_address() { return memory_address; }

  const std::vector<SymbolicValuePtr>& get_values() { return values; }

  rose_addr_t get_address() const { return address; }

  std::string address_string() const { return str(boost::format("0x%08X") % address); }

  void add_ref(SgAsmInstruction* insn) { refs.insert(insn); }
  void add_read(SgAsmInstruction* insn, int asize);
  void add_write(SgAsmInstruction* insn, int asize);
  void add_value(SymbolicValuePtr new_val);

  std::string to_string() const;

  const InsnSet& get_writes();
  const InsnSet& get_reads();
  const InsnSet& get_refs();

  // Are all known memory accesses reads?
  bool read_only() const;
  // Are there both read and write memory accesses?
  bool read_write() const;
  // Is the descriptor known to be used in memory accesses?
  bool known_memory() const;
  // Is the descriptor "suspicious"?  (One of several unlikely cases?)
  bool suspicious() const;

  bool get_initialized() const { return initialized; }
  bool get_in_image() const { return in_image; }

  size_t get_size() const { return size; }
  void set_size(size_t s) { size = s; }
  size_t get_access_size() const { return access_size; }

  void analyze(rose_addr_t addr);

  void short_print(std::ostream &o) const;
  void print(std::ostream &o) const;
  friend std::ostream& operator<<(std::ostream &o, const GlobalMemoryDescriptor &gd) {
    gd.print(o);
    return o;
  }
};

class GlobalMemoryDescriptorMap: public std::map<rose_addr_t, GlobalMemoryDescriptor> {

public:

  GlobalMemoryDescriptor* get_global(rose_addr_t addr) {
    GlobalMemoryDescriptorMap::iterator it = this->find(addr);
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
