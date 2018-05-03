// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Method_H
#define Pharos_Method_H

#include <rose.h>

#include "delta.hpp"
#include "funcs.hpp"
#include "vftable.hpp"

namespace pharos {

// Forward declaration.
class ThisCallMethod;

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

  Member(unsigned int o, unsigned int s, SgAsmx86Instruction* i, bool b);

  // Member (in)equality is determined by comparing size and offset for two different members
  friend bool operator== (Member &m1, Member &m2) {
    return (m1.offset == m2.offset && m1.size == m2.size);
    // Cory's unclear on when we added vftable to the comparison, and whether we should have.
    // When changing how vftables worked, he removed: m1.get_vftable() == m2.get_vftable()
  }

  friend bool operator!= (Member &m1, Member &m2) {
    return !(m1 == m2);
  }

  void merge(Member& m);
};

typedef std::map<unsigned int, Member> MemberMap;

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

  // This map is populated by find_passed_func_offsets(), which is the second phase of
  // find_this_call_methods().  It's read in analyze_passed_func_offsets(), where the
  // information is transferred to classes.
  FuncOffsetMap passed_func_offsets;

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
  bool validate_vtable(VirtualTableInstallationPtr install);

  // Most analysis methods in ThisCallMethod are private, but this one has to be called after
  // we've updated the oo_properties member on the function descriptors.  It updates the
  // passed_func_offsets map with the stack offsets of passed this-pointers.
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
typedef std::set<ThisCallMethod*, ThisCallMethodCompare> ThisCallMethodSet;

typedef std::map<rose_addr_t, ThisCallMethod> ThisCallMethodMap;
typedef std::vector<ThisCallMethod *> ThisCallMethodVector;

// This function seems most related to ThisCallMethods...
ThisCallMethod* follow_oo_thunks(rose_addr_t addr);

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
