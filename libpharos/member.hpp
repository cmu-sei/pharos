// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Member_H
#define Pharos_Member_H

#include "vftable.hpp"
#include "oo.hpp"

// This class is just so that we could eliminate maps of pairs, and be clear about what
// represents a "member".  This should probably be replaced with a class that we've given some
// thought to -- in particular Jeff Gennari made some progress in this area I think.
class Member {

  // This set provides a list of the instructions that assigned possible virtual function table
  // pointers to this member.  It references a virtual function table object that contains more
  // details about the table.  To support arbitrary inheritance, with multiple parents all
  // having inlined constructors, this must be a set of evidence descriptions, not just a
  // single value.
  VFTEvidenceSet vftables;

  // In cases where only a single vftable is allowed for this member (e.g. a correct class
  // definition), this field contains a pointer to the "best" choice for the vftable for the
  // current class.  For a while this was the last entry in an ordered vftables vector, but an
  // unordered set with additional evidence and an algorithm for picking the best choice was
  // determined to be a better approach.
  VirtualFunctionTable* best_vftable;

public:
  // This is the offset in the current object where the member is located.
  unsigned int offset;

  // This is the size of the member in bytes.
  unsigned int size;

  // This is the set of instructions that access this member, thus providing evidence for it's
  // existence, and documenting the places where we use the member.  Surprisingly(?), it
  // includes the uses of the member where the "use" is as a parameter to a call for offset
  // zero, and any embedded objects.  This is probably good because it causes this field to
  // also provide the evidence for the embedded ctors list below.
  X86InsnSet using_instructions;

  // If there's an embedded object, this is a list of the addresses of the methods that the
  // embedded object was passed to.  In the common case, these will be constructors, but they
  // can also be ordinary methods if we call methods after constructing the object.  This isn't
  // exactly the generic class pointer that we'd like here, but at least we can actually
  // populate it. :-)
  AddrSet embedded_ctors;

  // if this member is an embedded object, keep a pointer to its instance.
  ClassDescriptor *object;

  Member(unsigned int o, unsigned int s, rose_addr_t ec,
         SgAsmx86Instruction* i, const VFTEvidence* v);

  // Member (in)equality is determined by comparing size and offset for two different members
  friend bool operator== (Member &m1, Member &m2) {
    return (m1.offset == m2.offset && m1.size == m2.size);
    // Cory's unclear on when we added vftable to the comparison, and whether we should have.
    // When changing how vftables worked, he removed: m1.get_vftable() == m2.get_vftable()
  }

  friend bool operator!= (Member &m1, Member &m2) {
    return !(m1 == m2);
  }

  bool is_virtual() const {
    // We're virtual only if there's a "best" virtual function table.
    return (best_vftable != NULL);
  }

  void pick_best_vftable();

  VirtualFunctionTable* get_vftable() const { return best_vftable; }
  const VFTEvidenceSet& get_vftable_evidence() const { return vftables; }

  // This is a BAD API.  Do not use it.  Cory included it only to ease transition to
  // pick_best_vftable() which is still not correctly implemented.
  void set_best_vftable(VirtualFunctionTable* t) { best_vftable = t; }

  bool is_embedded_object() const { return (embedded_ctors.size() != 0); }

  bool is_parent() const { return (is_virtual() && is_embedded_object()); }

  void merge(Member& m, rose_addr_t loc);

  void debug() const;
};

typedef std::map<unsigned int, Member> MemberMap;

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
