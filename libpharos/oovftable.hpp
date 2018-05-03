#ifndef Pharos_OOVFTable_H
#define Pharos_OOVFTable_H

#include "ooelement.hpp"
#include "calls.hpp"
#include "oomember.hpp"
#include "datatypes.hpp"

// The OOVvirtualFunctionTable is based on the following prolog query:
//
// finalVFTable(VFTable, CertainSize, LikelySize, RTTIAddress, RTTIName)
//
//   The virtual function table at the address specified by VFTable is associated with the RTTI
//   object locator at address RTTIAddress.  If there is no object locator, this value will be
//   zero.  The certain size is the minimum certain size of the table (there are certain to be at
//   least this many valid entries).  The likely size is the maximum likely size of the table (it
//   is very unlikely that there are more than this number of valid entries).  The likely size is
//   guaranteed to be greater than or equal to the certain size.  Tables are explicitly permitted
//   to have a certain size of zero, but they may not have likely sizes of zero.  Possible virtual
//   function tables that did not meet minimum standards are not reported at all.  The RTTIName
//   field extracts the name of the class from the TypeDescriptor implied by the RTTIAddress,
//   which simplifies debugging as as duplicative of the RTTIAddress field.
//
namespace pharos {

typedef std::shared_ptr<TypeRTTICompleteObjectLocator> TypeRTTICompleteObjectLocatorPtr;

class OOVirtualFunctionTable {
 private:

  rose_addr_t address_;

  size_t size_;

  // RTTI information is stored directly above the virtual function
  // table. It can be saved here for later usage (if it is
  // present). Both the address and the COL are stored. The COL is the
  // initial RTTI structure in the chain, so saving it should be
  // enough. Unfortunately, the address of the COL is not stored in
  // the COL class itself
  rose_addr_t rtti_address_;

  TypeRTTICompleteObjectLocatorPtr rtti_col_;

  // virtual function calls made through this virtual function table
  std::vector<CallDescriptor*> vcalls_;

  // virtual functions in this table and their offsets within the table
  OOVirtualMethodMap vfuncs_;

  void load_rtti_col();

 public:

  OOVirtualFunctionTable() : address_(INVALID), size_(0), rtti_address_(INVALID),rtti_col_(nullptr) { }

  OOVirtualFunctionTable(rose_addr_t a, size_t s, rose_addr_t ra);

  OOVirtualFunctionTable(rose_addr_t a);

  ~OOVirtualFunctionTable();

  OOVirtualFunctionTable& operator=(const OOVirtualFunctionTable& other) = default;

  rose_addr_t get_address() const;

  void set_address(rose_addr_t a);

  rose_addr_t get_rtti_address() const;

  void set_rtti_address(rose_addr_t rtti);

  size_t get_size() const;

  void set_size(size_t s);

  void add_virtual_call(CallDescriptor *vcd);

  const std::vector<CallDescriptor*>& get_virtual_calls();

  void add_virtual_function(OOVirtualFunctionTableEntry entry);

  const OOVirtualMethodMap& get_virtual_functions();

};

// A virtual function pointer is a special kind of member
class OOVfptr : public OOMember {

 private:

  OOVirtualFunctionTablePtr vftable_;

 public:

  OOVfptr();

  OOVfptr(size_t s, size_t o, OOVirtualFunctionTablePtr vft);

  OOVfptr(OOVirtualFunctionTablePtr vft);

  OOVfptr& operator=(const OOVfptr&) = default;

  virtual ~OOVfptr();

  virtual void set_default_name();

  OOVirtualFunctionTablePtr get_vftable() const;
};

} // end pharos

#endif
