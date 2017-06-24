// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Method_H
#define Pharos_Method_H

#include <rose.h>

#include "delta.hpp"
#include "funcs.hpp"
#include "oo.hpp"

// Full declarations for members are required because methods allocate the members in a MemberMap.
#include "member.hpp"

namespace pharos {

// Assuming Visual Studio
#define THIS_PTR_STR "ecx"

// This class describes the passing of object pointers from a __thiscall method to another
// __thiscall method.  This includes objects embedded in the current object.
class FuncOffset {

public:

  // This is the method being called.
  ThisCallMethod* tcm;

  // This is the offset into the object from the caller that is passed to the target.  Or in
  // other words, the offset of the embedded object the type of which corresponds to the called
  // method.
  int64_t offset;

  // The call instruction that does the call in question.
  SgAsmx86Instruction* insn;

  FuncOffset(ThisCallMethod *t, int64_t o, SgAsmx86Instruction* i) {
    tcm = t;
    assert(tcm != NULL);
    offset = o;
    insn = i;
    assert(insn != NULL);
  }
};

// A map of functions to their offsets in something related to passing this-pointers.
typedef std::map<rose_addr_t, FuncOffset> FuncOffsetMap;

// Provided by method.cpp and used in usage.cpp as well.  Messy design. :-(
SymbolicValuePtr get_this_ptr_for_call(const CallDescriptor* cd);

// This class is for tracking all object oriented methods, regardless of whether they're
// constructors, destructors, or just normal methods.
class ThisCallMethod {

  bool find_this_pointer();
  void test_for_constructor();
  void find_members();
  void analyze_vftables();

  // The symbolic value of the this-pointer in this function.  This value cannot be NULL in a
  // ThisCallMethod that was accepted as __thiscall.
  SymbolicValuePtr thisptr;

  // We also seem very interested in confirming that the symbolic value above is in fact a
  // LeafNodePtr, and extracting the variable ID from it.  I'm not sure which is more
  // convenient right now, so let's keep both.  It appears that for all(?) analysis, we reject
  // non-leaf pointers...
  LeafNodePtr leaf;

  // Is this method a constructor?
  bool constructor;
  // Our confidence in our determination of whether this method is a constructor.
  GenericConfidence constructor_confidence;

  // Is this method a destructor?
  bool destructor;
  // Our confidence in our determination of whether this method is a destructor.
  GenericConfidence destructor_confidence;

  // Is this method a deleting destructor?
  bool deleting_destructor;
  // Our confidence in our determination of whether this method is a deleting destructor.
  GenericConfidence deleting_destructor_confidence;

  // The list of the classes that might "own" this method.  In the source code, each method is
  // associated with one and only one class.  But until we have complete knowledge about the
  // classes, we instead have a list of candidate classes.
  ClassDescriptorSet calling_classes;

public:

  // The function that corresponds to this method.
  FunctionDescriptor* fd;

  // List data members accessed in this particular method.  The map is keyed by the offset in
  // the object, and the value is a Member class instance.
  MemberMap data_members;

  // This map is populated by find_passed_func_offsets(), which is the second phase of
  // find_this_call_methods().  It's read in analyze_passed_func_offsets(), where the
  // information is transferred to classes.
  FuncOffsetMap passed_func_offsets;

  // This is a list of all the methods called on the same object (belonging to either this
  // class or it's ancestors) that is implied by this method.  For example, if this method is
  // on some class, and the same this-pointer is passed to method X, which in turn passes the
  // same object to method Y, then this list would contain X and Y.  It's a step in the
  // algorithm for finding which methods are associated with which class.  See
  // update_recursive_methods() for how this field is populated.
  ThisCallMethodSet recursive_methods;

  // FunctionDescriptor should probably be a reference so that we don't have to keep checking
  // it for NULL.
  ThisCallMethod(FunctionDescriptor *f);

  bool is_this_call() const { return (thisptr != NULL); }
  bool is_constructor() const { return constructor; }
  bool is_destructor() const { return destructor; }
  bool is_deleting_destructor() const { return deleting_destructor; }
  std::string address_string() const { return fd->address_string(); }
  rose_addr_t get_address() const { return fd->get_address(); }

  // Add a class that calls this method.
  void add_class(ClassDescriptor* cls) { calling_classes.insert(cls); }

  // Get the classes that call this method.
  const ClassDescriptorSet& get_classes() const { return calling_classes; }

  // Populate the recursive methods set by examining each known object instance, and updating
  // the list.  This algorithm references other ThisCallMethods, and so needs to be called
  // repeatedly until we converge on an answer.  Returns true if the internal list of recursive
  // methods was updated.
  bool update_recursive_methods();

  // Mark the method as a destructor (or not) with a specified confidence.
  void set_destructor(bool b, GenericConfidence conf);

  // Mark the method as a deleting destructor (or not) with a specified confidence.
  void set_deleting_destructor(bool b, GenericConfidence conf);

  // Mark the method as a constructor (or not) with a specified confidence.
  void set_constructor(bool b, GenericConfidence conf);

  // Test whether the method has apparently uninitialized reads of the object.
  bool test_for_uninit_reads() const;

  // Most analysis methods in ThisCallMethod are private, but this one has to be called after
  // the global this_call_methods map has been populated.  It updates the passed_func_offsets
  // map with the stack offsets of passed this-pointers.
  void find_passed_func_offsets();

  // Given an expression, return true if the expression contains a reference to our
  // this-pointer and false if it does not.  This logic still requires that our this-pointer be
  // represented as a leaf node, which is kindof unfortunate.  Perhaps we can fix this later.
  bool refs_leaf_ptr(const TreeNodePtr& tn) {
    assert(leaf != NULL);
    LeafNodePtrSet vars = tn->getVariables();
    if (vars.size() > 0 && vars.find(leaf) != vars.end()) return true;
    return false;
  }

  // Given an expression, substitute the current this-pointer with zero, returning an
  // expression that will often be a constant offset into the object.  This routine is now
  // ready to handle arbitrary (non-leaf) object pointers as well.
  TreeNodePtr remove_this_ptr_expr(const TreeNodePtr& tn) {
    assert(leaf != NULL);
    size_t nbits = leaf->nBits();
    return tn->substitute(leaf, LeafNode::createInteger(nbits, 0, "thisptr"));
  }

  // Is the expression out this-pointer plus an offset?
  boost::optional<int64_t> get_offset(const TreeNodePtr& tn);

  // Get the "leaf" version of the this-pointer.  Having this be separate from the
  // get_this_ptr() method is not the most efficient way of doing this, but Cory's exploring
  // different access patterns, and it's helps to know which code is using which pattern.
  LeafNodePtr get_leaf_ptr() const { return leaf; }
  SymbolicValuePtr get_this_ptr() const { return thisptr; }

  void debug() const;

  // So that we can put this call methods in a set...
  bool operator<(const ThisCallMethod& other) const {
    return (fd->get_address() < other.fd->get_address());
  }

  // This method is duplicated in ClassDescriptor... That's probably not really right.  The
  // additional warnings are uncovering some interesting cases however.
  void add_data_member(Member m);

};

typedef std::map<rose_addr_t, ThisCallMethod> ThisCallMethodMap;
typedef std::vector<ThisCallMethod *> ThisCallMethodVector;

// Let everyone know that methods.cpp has a global variable listing all OO methods.
extern ThisCallMethodMap this_call_methods;

// This function seems most related to ThisCallMethods...
ThisCallMethod* follow_oo_thunks(rose_addr_t addr);

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
