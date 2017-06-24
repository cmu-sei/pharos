// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_VFTable_H
#define Pharos_VFTable_H

#include <rose.h>

#include "delta.hpp"
#include "funcs.hpp"
#include "datatypes.hpp"

namespace pharos {

class VirtualBaseTable {

 public:

  // The address in memory where the virtual base table is located.
  rose_addr_t addr;

  // A best guess size for the table.
  size_t size;

  VirtualBaseTable(rose_addr_t a) {
    addr = a;
    size = 0;
  }

  void analyze();

  // Limit sizes based on overlaps with other tables and data structures.
  void analyze_overlaps();

  // Read an entry from the table.
  signed int read_entry(unsigned int entry) const;
};


class VirtualFunctionTable {

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
  TypeRTTICompleteObjectLocator *rtti;

  // the address of the rtti structures
  rose_addr_t rtti_addr;

  // The confidence is based on the technique used to identify RTTI.
  GenericConfidence rtti_confidence;

  // This constructor should be deprecated in favor of the one that requires an address if
  // that's not a problem.
  VirtualFunctionTable() {
    addr = 0;
    rtti = NULL;
    min_size = 0;
    max_size = 0;
    non_function = 0;
    best_size = 0;
    size_confidence = ConfidenceNone;
    rtti_confidence = ConfidenceNone;
  }

  VirtualFunctionTable(rose_addr_t a) {
    addr = a;
    rtti = NULL;
    min_size = 0;
    max_size = 0;
    non_function = 0;
    best_size = 0;
    size_confidence = ConfidenceNone;
    rtti_confidence = ConfidenceNone;
  }

  ~VirtualFunctionTable() {
    if (rtti!=NULL) delete rtti;
    rtti = NULL;
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
  FunctionDescriptor * read_entry_fd(unsigned int entry);

  // This method updates the fields describing the virtual function table based on analyzing
  // the contents of the memory at the address of the table.
  void analyze();
};

// This class accumulates "evidence" about the existence of a virtual function table based on
// instructions that write the virtual function table pointer into a specific offset in an
// object.  Because of inlined constructors, we sometimes need additional information to be
// able to decide which virtual function tables are associated with which classes.

// Poorly named right now (still deciding how to handle base verus function tables).
class VFTEvidence {

public:

  // The instruction that installed the pointer into the object.
  SgAsmInstruction* insn;
  // The function that contains the instruction.
  FunctionDescriptor* fd;
  // Our class representing the virtual function table.
  VirtualFunctionTable* vftable;
  // Our class representing the virtual base table.
  VirtualBaseTable* vbtable;

  // We'll probably also want a this-pointer value here in the future.

  VFTEvidence(SgAsmInstruction* i, FunctionDescriptor* f,
              VirtualFunctionTable* vft, VirtualBaseTable* vbt) {
    insn = i;
    fd = f;
    vftable = vft;
    vbtable = vbt;
    // The instruction and the function descriptor pointers must be valid.
    assert(insn != NULL);
    assert(fd != NULL);
  }
};

// Members contain a set of VFTEvidence objects.  Memory allocation for the evidence objects is
// managed by the set.
struct VFTEvidenceCompare {
  bool operator()(const VFTEvidence x, const VFTEvidence y) const {
    return (x.insn->get_address() < y.insn->get_address()) ? true : false;
  }
};
typedef std::set<VFTEvidence, VFTEvidenceCompare> VFTEvidenceSet;

// Map addresses in the program to virtual function tables.
typedef std::map<rose_addr_t, VirtualFunctionTable*> VFTableAddrMap;
typedef std::map<rose_addr_t, VirtualBaseTable*> VBTableAddrMap;

// Global table for tracking unique virtual function tables.  This allow us to prevent
// duplicated effort, by re-using earlier analysis of the same table.  Should perhaps be part
// of the global descriptor set.
extern VFTableAddrMap global_vftables;

// A global tables for tracking virtual base tables.
extern VBTableAddrMap global_vbtables;

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
