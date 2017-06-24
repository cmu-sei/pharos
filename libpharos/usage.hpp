// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Usage_H
#define Pharos_Usage_H

#include "funcs.hpp"
#include "oo.hpp"

namespace pharos {

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
// specific object while it has a given symbolic value for its this-pointer.  The
// ClassDescriptor class tracks the existance of a class involving all of the this-pointer
// usages.  There was also some confusion about the ObjectUse class, which was basically just a
// set of ThisPtrUsages for a given function.  We're going to continue tearing down that
// distinction by storing the FunctionDescriptor in the ThisPtrUsage class, since there can
// only be one function for a given usage given the way we propagate symbolic values.
class ThisPtrUsage {

  // The function that this usage appears in.
  FunctionDescriptor* fd;

  // This is the first method we encountered when creating the this-pointer usage group.  This
  // comment is a reminder to consider making ThisPtrUsage start with the unordered set of
  // methods, and then call a pick_ctor() method that uses several approaches to identify the
  // best candidate ctor from the set.  This shuold be replaced the proper dominance rule.
  ThisCallMethod* first_method;

  // This is the best available constructor chosen by pick_ctor().  It is often the same as
  // first_method, but not always.
  ThisCallMethod* ctor;

  // The list of the classes that might "own" this usage.  In the source code, each usage is
  // associated with one and only one class.  But until we have complete knowledge about the
  // classes, we instead have a list of candidate classes.
  ClassDescriptorSet calling_classes;

  // This is an unordered set of all of the methods sharing the same this-pointer, including
  // the first one.  We used to store this as an ordered vector, but that caused some
  // unpleasant looking code, so this way is probably better.
  ThisCallMethodSet methods;

  // Turns out that what we really need long term includes the instruction that did the calling
  // as well. :-(  So here's another way of representing the methods set above. :-( Cory
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
    methods.insert(tcm);
    // The semantics of the square brackets actually appear to be correct here.  If there's no
    // entry yet for call_insn, create an empty set.  Hooray, it worked like I wanted!
    method_evidence[call_insn].insert(tcm);
  }

  const ThisCallMethodSet& get_methods() const { return methods; }
  const MethodEvidenceMap& get_method_evidence() const { return method_evidence; }

  FunctionDescriptor* get_fd() const { return fd; }

  void analyze_alloc();

  // Add a class that calls this method.
  void add_class(ClassDescriptor* cls) { calling_classes.insert(cls); }

  // Get the classes that call this method.
  const ClassDescriptorSet& get_classes() const { return calling_classes; }

  // Every method in the usage after the dominant method must NOT be a constructor.
  void apply_constructor_dominance_rule();

  // Report a unique identifier for this usage in a human readable way.
  std::string identifier() const;

  // Pick a constructor from the list of possible constructors.
  void pick_ctor();

  // Now permitted to return NULL when we couldn't pick a constructor.
  ThisCallMethod* get_ctor() const { return ctor; }

  // This verison is old.  It probably makes more sense to call through ObjectUse::debug() now.
  void debug_methods() const;

  void debug() const;
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

  void debug() const;

  // Analyze function to find object uses.
  void analyze_object_uses();

  // Apply the constructor dominance rule (which is incorrect and has to be done later).
  void apply_constructor_dominance_rule();
};

// Typedef for global map recording the use of various objects.
typedef std::map<rose_addr_t, ObjectUse> ObjectUseMap;

// A global map of object uses.  Populated in analyze_functions_for_object_uses().
extern ObjectUseMap object_uses;

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
