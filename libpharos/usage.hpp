// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Usage_H
#define Pharos_Usage_H

#include "funcs.hpp"
#include "method.hpp"

namespace pharos {

// Maps the call instructions to the methods they call.  This is another way of representing
// the method set above, but is needed (at least temporarily) for dominance analysis.
typedef std::map<SgAsmInstruction* , ThisCallMethodSet> MethodEvidenceMap;

// Don't forget to update the EnumStrings in usage.cpp as well...
enum AllocType {
  AllocUnknown,
  AllocLocalStack,
  AllocHeap,
  AllocGlobal,
  AllocParameter
};

// Allow others to use our utility function to pick a this-pointer out of an ITE expression.
SymbolicValuePtr pick_this_ptr(SymbolicValuePtr& sv);

// Track the usage of a specific this-pointer.  This class is now clearly the one that tracks a
// specific object while it has a given symbolic value for its this-pointer.  There was also
// some confusion about the ObjectUse class, which was basically just a set of ThisPtrUsages
// for a given function.  We're going to continue tearing down that distinction by storing the
// FunctionDescriptor in the ThisPtrUsage class, since there can only be one function for a
// given usage given the way we propagate symbolic values.
class ThisPtrUsage {

  // The function that this usage appears in.
  FunctionDescriptor* fd;

  // This is an unordered set of all of the methods sharing the same this-pointer.
  MethodEvidenceMap method_evidence;

public:

  // The symbolic value of the this-pointer.  In at least some cases, this (used to be?) the
  // allocated memory pointer following a call to new(), which is not really the this-pointer.
  SymbolicValuePtr this_ptr;

  // How was this object allocated?
  AllocType alloc_type;
  // The size of the memory allocation for this object if dynamically allocated.  This value is
  // set to zero if the object was not dynamically allocated, or the size is unknown.
  uint32_t alloc_size;

  // The instruction that best represents the allocation.
  SgAsmInstruction* alloc_insn;

  ThisPtrUsage(FunctionDescriptor* f, SymbolicValuePtr tptr,
               ThisCallMethod* tcm, SgAsmInstruction* call_insn);

  // Add a method to both the methods set and the method evidence map.
  void add_method(ThisCallMethod* tcm, SgAsmInstruction* call_insn) {
    // The semantics of the square brackets actually appear to be correct here.  If there's no
    // entry yet for call_insn, create an empty set.  Hooray, it worked like I wanted!
    method_evidence[call_insn].insert(tcm);
  }

  const MethodEvidenceMap& get_method_evidence() const { return method_evidence; }

  FunctionDescriptor* get_fd() const { return fd; }

  void analyze_alloc();

  // Prolog mode constructor destructor test based on call order.
  void update_ctor_dtor() const;
};

// The ThisPtrUsage map is keyed by the get_hash() of the TreeNode, which is a 64-bit hash of
// the expression.
typedef std::map<SVHash, ThisPtrUsage> ThisPtrUsageMap;

// Cory's experimenting here.  This class will define the use of an object in a function,
// regardless of whether that function is itself an object-oriented method itself.
class ObjectUse {

public:
  // This is the function that contains the object uses.
  FunctionDescriptor* fd;
  // This is the list of ThisPtrUsages which records the this-pointer and the OO methods called
  // on each of them.
  ThisPtrUsageMap references;

  // Analyze the function and populate the references member.
  ObjectUse(FunctionDescriptor* f);

  // Analyze function to find object uses.
  void analyze_object_uses();

  // Prolog mode constructor destructor test based on call order.
  void update_ctor_dtor() const;

};

// Typedef for global map recording the use of various objects.
typedef std::map<rose_addr_t, ObjectUse> ObjectUseMap;

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
