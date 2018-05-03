
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

OOVirtualFunctionTable::OOVirtualFunctionTable(rose_addr_t a, size_t s, rose_addr_t ra) {
  address_ = a;
  size_ = s;
  rtti_address_ = ra;

  load_rtti_col();
}

void
OOVirtualFunctionTable::load_rtti_col() {
  // Try reading an RTTI complete object locatot at the specified address.
  try {
    rose_addr_t rptr = global_descriptor_set->read_addr(rtti_address_);
    rtti_col_ = std::make_shared<TypeRTTICompleteObjectLocator>(rptr);
    if (rtti_col_) {
      // essentially, the memory must look like RTTI structures - are both signatures 0?
      if (rtti_col_->signature.value == 0 && rtti_col_->class_desc.signature.value == 0) {
        rtti_col_ = nullptr;
      }
    }
  }
  catch (...) {
    GDEBUG << "RTTI was bad at " << addr_str(rtti_address_) << LEND;
    // not RTTI
  }
}

OOVirtualFunctionTable::OOVirtualFunctionTable(rose_addr_t a) {
  address_ = a;
  size_ = 0;
  rtti_address_ = INVALID;
}

OOVirtualFunctionTable::~OOVirtualFunctionTable() { }

rose_addr_t
OOVirtualFunctionTable::get_rtti_address() const {
  return rtti_address_;
}

void
OOVirtualFunctionTable::set_rtti_address(rose_addr_t rtti) {
  rtti_address_ = rtti;
  if (!rtti_col_) {
    load_rtti_col();
  }
}

size_t
OOVirtualFunctionTable::get_size() const {
  return size_;
}

void
OOVirtualFunctionTable::set_size(size_t s) {
  size_ = s;
}

const std::vector<CallDescriptor*>&
OOVirtualFunctionTable::get_virtual_calls() {
  return vcalls_;
}

void
OOVirtualFunctionTable::add_virtual_call(CallDescriptor *vcd) {
  vcalls_.push_back(vcd);
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
  set_type(OOElementType::VFPTR);
}

OOVfptr::OOVfptr(size_t s, size_t o, OOVirtualFunctionTablePtr vft) : OOMember(s, o) {
  set_default_name();
  vftable_ = vft;
  set_type(OOElementType::VFPTR);
}

OOVfptr::~OOVfptr() { }

OOVirtualFunctionTablePtr
OOVfptr::get_vftable() const {
  return vftable_;
}

void
OOVfptr::set_default_name() {

  std::stringstream name_ss;
  name_ss << "vfptr_" << std::hex << std::noshowbase << offset_ << std::showbase << std::dec;
  std::string s = name_ss.str();
  set_name(s);
}


} // end namespace pharos
