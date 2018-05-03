
#include "ooclass.hpp"
#include "demangle.hpp"
#include "descriptors.hpp"

namespace pharos {

OOClassDescriptor::OOClassDescriptor() : cid_(INVALID), dtor_(nullptr), primary_vftable_(nullptr) {
  set_type(OOElementType::STRUC);
}


OOClassDescriptor::OOClassDescriptor(rose_addr_t cid,
                                     rose_addr_t vft,
                                     size_t csize,
                                     rose_addr_t dtor,
                                     std::vector<rose_addr_t> method_list) : OOElement(csize) {
  cid_ = cid;
  generate_name();
  set_type(OOElementType::STRUC);

  // Process each method. Create the method list based on addresses
  // Other properties will be filled in later
  for (rose_addr_t m : method_list) {
    OOMethodPtr meth = std::make_shared<OOMethod>(m);
    if (meth->get_address() == dtor) {
      meth->set_type(OOMethodType::DTOR);
      dtor_ = meth;
    }
    GDEBUG << "Adding method " << meth->get_name() << LEND;
    add_method(meth);
  }

  // Add the nearly empty primary vftable, which is at offset 0
  primary_vftable_ = std::make_shared<OOVirtualFunctionTable>(vft);
  add_vftable(0, primary_vftable_);
}

// create a default name
void
OOClassDescriptor::generate_name() {

  // The class must have an ID to be named
  assert(cid_ != INVALID);

  std::stringstream name_ss;
  name_ss << "cls_" << std::hex << std::noshowbase << cid_ << std::showbase << std::dec;
  std::string s = name_ss.str();
  set_name(s);
}

bool
OOClassDescriptor::operator==(const OOClassDescriptor& other) const {
  return cid_ == other.cid_;
}

OOMethodPtr
OOClassDescriptor::get_dtor() {
  return dtor_;
}

OOElementPtrMap&
OOClassDescriptor::get_members() {
  return members_;
}

OOElementPtr
OOClassDescriptor::member_at(size_t o) {

  OOElementPtrMap::iterator mi = members_.find(o);
  if (mi != members_.end()) {
    return mi->second;
  }
  return nullptr;
}

OOParentPtrMap&
OOClassDescriptor::get_parents() {
  return parents_;
}

OOVirtualFunctionTablePtrList&
OOClassDescriptor::get_vftables() {
  return vftables_;
}

OOMethodPtrList
OOClassDescriptor::get_methods() {
  return methods_;
}

OOVirtualFunctionTablePtr
OOClassDescriptor::get_primary_vftable() {
  return primary_vftable_;
}

void
OOClassDescriptor::add_vftable(size_t off, rose_addr_t vftable_addr) {

  // Add the nearly empty primary vftable
  add_vftable(off, std::make_shared<OOVirtualFunctionTable>(vftable_addr));
}

void
OOClassDescriptor::add_vftable(size_t off, OOVirtualFunctionTablePtr v) {

  vftables_.push_back(v);

  size_t ptr_width = global_descriptor_set->get_arch_bits() >> 2;

  // add the virtual function table pointer at offset 0 for the primary vftable
  std::shared_ptr<OOElement> vfptr = std::make_shared<OOVfptr>(ptr_width, off, v);
  add_member(off, vfptr);
}

rose_addr_t
OOClassDescriptor::get_id() {
  return cid_;
}

void
OOClassDescriptor::add_member(size_t off, OOElementPtr e) {
  members_.insert(OOMemberEntry(off, e));
}

void
OOClassDescriptor::add_method(OOMethodPtr m) {

  if (m->is_import()) {

    // if this is an import, then it may have a mangled name for the
    // owning class. There is no way to get the mangled class name right now, so
    const ImportDescriptor* id = m->get_import_descriptor();
    try {

      auto dtype = demangle::visual_studio_demangle(id->get_name());
      if (dtype) {

        // go with the imported method class name
        std::string current_name = get_name();
        if (current_name != dtype->get_class_name()) {
          set_name(dtype->get_class_name());
        }
      }
    }

    catch (const demangle::Error &) {
      // It doesn't matter what the error was.  We might not have even
      // been a mangled name.
    }

    // Could not demangle class name, so go with the default name;
    set_name(id->get_name());
  }
  methods_.push_back(m);
}

void
OOClassDescriptor::add_parent(size_t off, OOClassDescriptorPtr p) {
  parents_.insert(OOParentPtrEntry(off,p));
}

} // end namespace pharos
