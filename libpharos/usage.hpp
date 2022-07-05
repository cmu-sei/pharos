// Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Usage_H
#define Pharos_Usage_H

#include "funcs.hpp"
#include "method.hpp"

namespace pharos {

// Forward declaration of OOAnalyzer in lieu of including ooanalyzer.hpp
class OOAnalyzer;

// Maps the call instructions to the methods they call.  This is another way of representing
// the method set above, but is needed (at least temporarily) for dominance analysis.
using MethodEvidenceMap = std::map<SgAsmInstruction*, ThisCallMethodSet>;

// Don't forget to update the EnumStrings in usage.cpp as well...
enum AllocType {
  AllocUnknown,
  AllocLocalStack,
  AllocHeap,
  AllocGlobal,
  AllocParameter
};
extern template std::string Enum2Str<AllocType>(AllocType);

// Allow others to use our utility function to pick a this-pointer out of an ITE expression.
SymbolicValuePtr pick_this_ptr(const SymbolicValuePtr& sv);

// Track the usage of a specific this-pointer.  This class is now clearly the one that tracks a
// specific object while it has a given symbolic value for its this-pointer.  There was also
// some confusion about the ObjectUse class, which was basically just a set of ThisPtrUsages
// for a given function.  We're going to continue tearing down that distinction by storing the
// FunctionDescriptor in the ThisPtrUsage class, since there can only be one function for a
// given usage given the way we propagate symbolic values.
class ThisPtrUsage {

  // The function that this usage appears in.
  const FunctionDescriptor* fd;

  // This is an unordered set of all of the methods sharing the same this-pointer.
  MethodEvidenceMap method_evidence;

 public:

  // The symbolic value of the this-pointer.  In at least some cases, this (used to be?) the
  // allocated memory pointer following a call to new(), which is not really the this-pointer.
  SymbolicValuePtr this_ptr;

  // The symbolic expression of the this-pointer expanded to include unknown memory reads as
  // expressions.  This is used later to export more complete representations of the thisptr in
  // prolog.  This has to be done before the PDG is released, because otherwise the variables
  // representing unknown memory will not match the recorded thisptrs.
  TreeNodePtr expanded_this_ptr;

  // How was this object allocated?
  AllocType alloc_type;
  // The size of the memory allocation for this object if dynamically allocated.  This value is
  // set to zero if the object was not dynamically allocated, or the size is unknown.
  uint32_t alloc_size;

  // The instruction that best represents the allocation.
  SgAsmInstruction* alloc_insn;

  ThisPtrUsage(const FunctionDescriptor* f, SymbolicValuePtr tptr,
               const ThisCallMethod* tcm, SgAsmInstruction* call_insn);

  // Add a method to both the methods set and the method evidence map.
  void add_method(const ThisCallMethod* tcm, SgAsmInstruction* call_insn) {
    // The semantics of the square brackets actually appear to be correct here.  If there's no
    // entry yet for call_insn, create an empty set.  Hooray, it worked like I wanted!
    method_evidence[call_insn].insert(tcm);
  }

  const MethodEvidenceMap& get_method_evidence() const { return method_evidence; }

  const FunctionDescriptor* get_fd() const { return fd; }

  void analyze_alloc();

  // Prolog mode constructor destructor test based on call order.
  void update_ctor_dtor(OOAnalyzer& ooa) const;

  // Ed is not sure this really belongs here
  static TreeNodePtr expand_thisptr(const FunctionDescriptor *fd, SgAsmInstruction*, const SymbolicValuePtr tptr);
};

// The ThisPtrUsage map is keyed by the get_hash() of the TreeNode, which is a 64-bit hash of
// the expression.
using ThisPtrUsageMap = std::map<SVHash, ThisPtrUsage>;

// Cory's experimenting here.  This class will define the use of an object in a function,
// regardless of whether that function is itself an object-oriented method itself.
class ObjectUse {

 public:
  // This is the function that contains the object uses.
  const FunctionDescriptor* fd;
  // This is the list of ThisPtrUsages which records the this-pointer and the OO methods called
  // on each of them.
  ThisPtrUsageMap references;

  // Analyze the function and populate the references member.
  // The ooanalyzer is non-const because of ooa.follow_thunks()
  ObjectUse(OOAnalyzer& ooa, const FunctionDescriptor* f);

  // Analyze function to find object uses.
  void analyze_object_uses(OOAnalyzer const & ooa);

  // Prolog mode constructor destructor test based on call order.
  void update_ctor_dtor(OOAnalyzer& ooa) const;

};

// Typedef for global map recording the use of various objects.
using ObjectUseMap = std::map<rose_addr_t, ObjectUse>;


TreeNodePtr pick_non_null_expr(const TreeNodePtr& expr);

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
