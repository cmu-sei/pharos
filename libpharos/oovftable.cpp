// Copyright 2017-2020 Carnegie Mellon University.  See LICENSE file for terms.

#include "oovftable.hpp"
#include "oomethod.hpp"
#include "descriptors.hpp"

namespace pharos {

rose_addr_t
OOVirtualFunctionTable::get_address() const {
  return address_;
}

void
OOVirtualFunctionTable::set_address(rose_addr_t a) {
  address_ = a;
}

OOVirtualFunctionTable::OOVirtualFunctionTable(rose_addr_t a, size_t s, size_t b, rose_addr_t ra,
                                               TypeRTTICompleteObjectLocatorPtr rc)
{
  address_ = a;
  arch_bytes_ = b;
  size_ = s;
  rtti_address_ = ra;
  rtti_col_ = rc;
}

TypeRTTICompleteObjectLocatorPtr
read_RTTI(const DescriptorSet& ds, rose_addr_t addr)
{
  // Try reading an RTTI complete object locatot at the specified address.
  try {
    rose_addr_t rptr = ds.memory.read_address(addr);
    TypeRTTICompleteObjectLocatorPtr rtti =
      std::make_shared<TypeRTTICompleteObjectLocator>(ds.memory, rptr);
    if (rtti) {
      // essentially, the memory must look like RTTI structures - are both signatures 0?
      if (rtti->signature.value == 0 && rtti->class_desc.signature.value == 0) {
        return rtti;
      }
    }
  }
  catch (...) {
    GDEBUG << "RTTI was bad at " << addr_str(addr) << LEND;
    // not RTTI
  }

  return nullptr;
}

OOVirtualFunctionTable::OOVirtualFunctionTable(rose_addr_t a, size_t b) {
  address_ = a;
  arch_bytes_ = b;
  size_ = 0;
  rtti_address_ = INVALID;
}

OOVirtualFunctionTable::~OOVirtualFunctionTable() { }

rose_addr_t
OOVirtualFunctionTable::get_rtti_address() const {
  return rtti_address_;
}

void
OOVirtualFunctionTable::set_rtti(rose_addr_t ra, TypeRTTICompleteObjectLocatorPtr rc) {
  rtti_address_ = ra;
  rtti_col_ = rc;
}

size_t
OOVirtualFunctionTable::get_size() const {
  return size_;
}

void
OOVirtualFunctionTable::set_size(size_t s) {
  size_ = s;
}

const std::vector<const CallDescriptor*>&
OOVirtualFunctionTable::get_virtual_calls() const {
  return vcalls_;
}

const OOVirtualFunctionTable::CallDescriptorAddressMap
OOVirtualFunctionTable::get_virtual_call_targets() const {
  return vcall_targets_;
}

void
OOVirtualFunctionTable::add_virtual_call(const CallDescriptor *vcd, rose_addr_t target) {
  vcalls_.push_back(vcd);
  // Since we don't want to write the targets back into the call descriptor, until the caller
  // asks us to, lets store them in a map from call descriptor to target address.
  vcall_targets_[vcd].insert(target);
}

const OOVirtualMethodMap&
OOVirtualFunctionTable::get_virtual_functions() {
  return vfuncs_;
}

void
OOVirtualFunctionTable::add_virtual_function(OOVirtualFunctionTableEntry entry) {
  OOMethodPtr vf = entry.second;
  vf->set_virtual(true);
  vfuncs_.insert(entry);
}

// ==================================================================================
// OOVfptr methods

OOVfptr::OOVfptr() : vftable_(NULL) {
  set_name("vfptr");
  set_type(OOElementType::VFPTR);
}

OOVfptr::OOVfptr(size_t s, OOVirtualFunctionTablePtr vft) : OOMember(s) {
  set_name("vfptr");
  vftable_ = vft;
  set_type(OOElementType::VFPTR);
}

OOVfptr::~OOVfptr() { }

OOVirtualFunctionTablePtr
OOVfptr::get_vftable() const {
  return vftable_;
}

} // end namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
