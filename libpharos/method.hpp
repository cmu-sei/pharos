// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Method_H
#define Pharos_Method_H

#include "delta.hpp"
#include "funcs.hpp"
#include "vftable.hpp"

namespace pharos {

// This class is just so that we could eliminate maps of pairs, and be clear about what
// represents a "member".  This should probably be replaced with a class that we've given some
// thought to -- in particular Jeff Gennari made some progress in this area I think.
class Member {

 public:
  // This is the offset in the current object where the member is located.
  unsigned int offset;

  // This is the size of the member in bytes.
  unsigned int size;

  // Is this member believed to be a base table?
  bool base_table;

  // This is the set of instructions that access this member, thus providing evidence for it's
  // existence, and documenting the places where we use the member.  Surprisingly(?), it
  // includes the uses of the member where the "use" is as a parameter to a call for offset
  // zero, and any embedded objects.  This is probably good because it causes this field to
  // also provide the evidence for the embedded ctors list below.
  X86InsnSet using_instructions;

  Member(unsigned int o, unsigned int s, SgAsmX86Instruction* i, bool b);

  void merge(Member& m);
};

using MemberMap = std::map<unsigned int, Member>;

// This class is for tracking all object oriented methods, regardless of whether they're
// constructors, destructors, or just normal methods.
class ThisCallMethod {

  bool find_this_pointer();
  bool find_this_pointer_from_stack();
  void test_for_constructor();
  void find_members();

  // The symbolic value of the this-pointer in this function.  This value cannot be NULL in a
  // ThisCallMethod that was accepted as __thiscall.
  SymbolicValuePtr thisptr;

  // We also seem very interested in confirming that the symbolic value above is in fact a
  // LeafNodePtr, and extracting the variable ID from it.  I'm not sure which is more
  // convenient right now, so let's keep both.  It appears that for all(?) analysis, we reject
  // non-leaf pointers...
  LeafNodePtr leaf;

 public:

  bool returns_self;
  bool no_calls_before;
  bool no_calls_after;
  bool uninitialized_reads;

  // The function that corresponds to this method.
  FunctionDescriptor* fd;

  // List data members accessed in this particular method.  The map is keyed by the offset in
  // the object, and the value is a Member class instance.
  MemberMap data_members;

  // FunctionDescriptor should probably be a reference so that we don't have to keep checking
  // it for NULL.
  ThisCallMethod(FunctionDescriptor *f);

  void stage2();

  bool is_this_call() const { return (thisptr != NULL); }
  std::string address_string() const { return fd->address_string(); }
  rose_addr_t get_address() const { return fd->get_address(); }

  // Test whether the method has apparently uninitialized reads of the object.
  bool test_for_uninit_reads() const;

  // Do late stage validation of virtual table pointers.
  bool validate_vtable(ConstVirtualTableInstallationPtr install);

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
    return tn->substitute(leaf, SymbolicExpr::makeIntegerConstant(nbits, 0, "thisptr"));
  }

  // Is the expression out this-pointer plus an offset?
  boost::optional<int64_t> get_offset(const TreeNodePtr& tn);

  SymbolicValuePtr get_this_ptr() const { return thisptr; }

  // So that we can put this call methods in a set...
  bool operator<(const ThisCallMethod& other) const {
    return (fd->get_address() < other.fd->get_address());
  }

  void add_data_member(Member m);

};

// This is to keep members in the ThisCallMethodSet in a consistent address order.
struct ThisCallMethodCompare {
  bool operator()(const ThisCallMethod *x, const ThisCallMethod *y) const;
};

// Specifically, the class description needs a set of methods associate with the class.
using ThisCallMethodSet = std::set<const ThisCallMethod*, ThisCallMethodCompare>;

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
