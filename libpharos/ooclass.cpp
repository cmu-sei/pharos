// Copyright 2017-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "ooclass.hpp"
#include "demangle.hpp"
#include "descriptors.hpp"

namespace pharos {

#if 0
OOClassDescriptor::OOClassDescriptor() : cid_(INVALID), dtor_(nullptr), primary_vftable_(nullptr) {
  set_type(OOElementType::STRUC);
}
#endif

OOClassDescriptor::OOClassDescriptor(rose_addr_t cid,
                                     rose_addr_t vft,
                                     size_t csize,
                                     rose_addr_t dtor,
                                     std::vector<rose_addr_t> method_list,
                                     const DescriptorSet& d) : OOElement(csize), ds(d) {
  cid_ = cid;


  std::stringstream name_ss;
  name_ss << "cls_0x" << std::hex << cid_ << std::dec;
  set_name(name_ss.str());

  set_type(OOElementType::STRUC);

  // Process each method. Find the function or import while we have the descriptor set.
  for (rose_addr_t m : method_list) {

    OOMethodPtr meth;

    const FunctionDescriptor* fd = ds.get_func(m);
    if (fd) {
      meth = std::make_shared<OOMethod>(fd);
    }
    else {
      const ImportDescriptor* id = ds.get_import(m);
      if (id) {
        meth = std::make_shared<OOMethod>(id);
      }
    }

    if (!meth) {
      GERROR << "Method address " << addr_str(m) << " was not a function or import." << LEND;
      continue;
    }

    if (meth->get_address() == dtor) {
      meth->set_type(OOMethodType::DTOR);
      dtor_ = meth;
    }
    GDEBUG << "Adding method " << meth->get_name() << LEND;
    add_method(meth);
  }

  if (vft!=0) {
    // Add the nearly empty primary vftable, which is at offset 0
    primary_vftable_ = std::make_shared<OOVirtualFunctionTable>(vft, ds.get_arch_bytes());
    add_vftable(0, primary_vftable_);
  }
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
  add_vftable(off, std::make_shared<OOVirtualFunctionTable>(vftable_addr, ds.get_arch_bytes()));
}

void
OOClassDescriptor::add_vftable(size_t off, OOVirtualFunctionTablePtr v) {

  vftables_.push_back(v);

  // add the virtual function table pointer at offset 0 for the primary vftable
  std::shared_ptr<OOElement> vfptr = std::make_shared<OOVfptr>(ds.get_arch_bytes(), v);
  add_member(off, vfptr);
}

rose_addr_t
OOClassDescriptor::get_id() {
  return cid_;
}

void
OOClassDescriptor::add_member(size_t off, OOElementPtr e) {

  members_.emplace(off, e);
}

void
OOClassDescriptor::add_method(OOMethodPtr m) {

  if (m->is_import()) {

    bool name_set = false;

    // if this is an import, then it may have a mangled name for the
    // owning class. There is no way to get the mangled class name right now, so
    const ImportDescriptor* id = m->get_import_descriptor();
    try {

      auto dtype = demangle::visual_studio_demangle(id->get_name());
      if (dtype) {

        // go with the imported method class name
        std::string current_name = get_name();
        if (current_name != dtype->get_class_name()) {
          set_demangled_name(dtype->get_class_name());

          // We can't easily get the mangled name of the class, so we will _not_ set the
          // mangled name.
          name_set = true;
        }
      }
    }

    catch (const demangle::Error &) {
      // It doesn't matter what the error was.  We might not have even
      // been a mangled name.
    }

    if (!name_set) {
      // If the method is imported, but we couldn't demangle the class
      // name, what should we do?  We do know the imported DLL name, and
      // the symbol or ordinal.  We were previously naming the class
      // after the imported method, but this doesn't seem quite right,
      // so I'm going to turn it off for now.
#if 0
      set_name(id->get_best_name());
#endif
    }
  }
  methods_.push_back(m);
}

void
OOClassDescriptor::add_parent(size_t off, OOClassDescriptorPtr p) {
  parents_.emplace(off,p);
}

} // end namespace pharos
