#ifndef Pharos_OOClass_H
#define Pharos_OOClass_H

#include "ooelement.hpp"
#include "oovftable.hpp"
#include "oomember.hpp"
#include "oomethod.hpp"

namespace pharos {

// finalClass(ClassID, VFTable, CSize, LSize, RealDestructor, MethodList)
//
//   This result defines the existance of a class.  It is intended to be the first query to
//   Prolog, which could drive all other required queries.  The ClassID field is a unique
//   identifier for a class.
//
//   VFTable is the address of the primary virtual function table associated with this class.
//   This is the table that contains the derived class' newly declared virtual methods, and
//   typically contains the method of the class' primary parent as well.  It is typically the
//   table at offset zero in the object.  The VFTable will have the value zero if no VFTable was
//   associated with the class.  In the case of multiple inheritance, additional tables may be
//   associated with this class through the inheritance result described below.
//
//   Csize is minimum certain size of the class.  Lsize is the likely maximum size of the class.
//   The likely size is guaranteed to be greater than or equal to the certain size.  Classes are
//   explicitly permitted to have a certain size of zero, but they may not have likely sizes of
//   zero.  Classes are explicitly permitted to have certain and likely sizes that match exactly.
//   Classes are explicitly permitted to have certain and likely sizes that exceed the member
//   definitions reported as separate results, but member definitions that exceed the likely size
//   are not permitted.
//
//   The RealDestructor field is the address of the real destructor associated with the class if
//   one was identified, and zero otherwise.
//
//   The MethodList field contains all methods associated with the class regardless of their
//   confidence levels or status as constructors, destructors, etc.  This list should include only
//   those methods actually implemented on the class.  Thus all methods in the list should
//   reference the same class name in their symbols.  Listing methods in this way is partially a
//   convenience and optimization for importing class definitions into C++, since it allows the
//   association with the class to be made simply and early in the import.
//
// based on the finalClass result:
// finalClass(ClassID, VFTable, CSize, LSize, RealDestructor, MethodList)
//
class OOClassDescriptor : public OOElement {

 private:

  rose_addr_t cid_;

  OOMethodPtr dtor_;

  OOMethodPtrList methods_;

  // members (of any type are keyed by an offset
  OOElementPtrMap members_;

  OOParentPtrMap parents_;

  OOVirtualFunctionTablePtr primary_vftable_;

  OOVirtualFunctionTablePtrList vftables_;

  virtual void generate_name();

 public:

  OOClassDescriptor(rose_addr_t cid,
                    rose_addr_t vft,
                    size_t csize,
                    rose_addr_t dtor,
                    std::vector<rose_addr_t> method_list);

  OOClassDescriptor();

  // JSG thinks the default will suffice because every pointer is a
  // shared pointer
  OOClassDescriptor(const OOClassDescriptor&) = default;

  virtual ~OOClassDescriptor() = default;

  OOClassDescriptor& operator=(const OOClassDescriptor&) = default;

  bool operator==(const OOClassDescriptor& other) const;

  rose_addr_t get_id();

  OOVirtualFunctionTablePtr get_primary_vftable();

  void add_vftable(size_t off, OOVirtualFunctionTablePtr v);

  void add_vftable(size_t off, rose_addr_t vftable_addr);

  OOVirtualFunctionTablePtrList& get_vftables();

  OOMethodPtr get_dtor();

  OOMethodPtrList get_methods();

  void add_member(size_t off, OOElementPtr e);

  void add_method(OOMethodPtr m);

  void add_parent(size_t off, OOClassDescriptorPtr p);

  OOParentPtrMap& get_parents();

  OOElementPtrMap& get_members();

  OOElementPtr member_at(size_t o);

}; // end OOClassDescriptor

} // end namespace pharos


#endif
