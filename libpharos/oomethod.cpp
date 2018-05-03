
#include "oomethod.hpp"
#include "descriptors.hpp"

namespace pharos {

OOMethod::OOMethod(rose_addr_t a, OOMethodType t, bool v) {

  address_ = a;
  name_ = "";
  type_ = t;
  is_virtual_ = v;
  set_descriptors();

}

OOMethod::OOMethod(rose_addr_t a) {

  address_ = a;
  name_ = "";
  type_ = OOMethodType::UNKN;
  is_virtual_ = false;
  set_descriptors();
}

OOMethod::OOMethod(const FunctionDescriptor* fd) {

  function_ = fd;
  name_ = "";
  address_ = fd->get_address();
  import_ = nullptr;
  type_ = OOMethodType::UNKN;
  is_virtual_ = false;
}

void
OOMethod::set_descriptors() {

  function_ = nullptr;
  import_ = nullptr;

  const FunctionDescriptor* fd = global_descriptor_set->get_func(address_);
  if (!fd) {
    GDEBUG << "Detected imported method " << addr_str(address_) << LEND;
    const ImportDescriptor* id = global_descriptor_set->get_import(address_);
    if (id) {
      import_ = id;
      function_ = id->get_function_descriptor();
      set_name(id->get_name());
    }
  }
  else {
    function_ = fd;
  }
   if (!function_) {
    OWARN << "There is no function descriptor for " << addr_str(address_) << LEND;
  }
}

void
OOMethod::generate_name() {
  std::stringstream name_ss;

  if (type_ == OOMethodType::CTOR) {
    name_ss << "ctor_";
  }
  else {
    name_ss << ((is_virtual_) ? "virt_" : "");

    if (type_ == OOMethodType::DTOR) {
      name_ss << "dtor_";
    }
    else if (type_ == OOMethodType::DELDTOR) {
      name_ss << "deldtor_";
    }
    else {
      name_ss << "meth_";
    }
  }

  name_ss << std::hex << std::noshowbase << address_ << std::showbase << std::dec;
  std::string s = name_ss.str();
  set_name(s);
}

void
OOMethod::set_name(std::string n) {
  name_ = n;
}

std::string
OOMethod::get_name() {
  if (name_ == "") generate_name();
  return name_;
}

const FunctionDescriptor*
OOMethod::get_function_descriptor() {
  return function_;
}

void
OOMethod::set_function_descriptor(const FunctionDescriptor* fd) {
  function_ = fd;
}

const ImportDescriptor*
OOMethod::get_import_descriptor() {
  return import_;
}

void
OOMethod::set_import_descriptor(const ImportDescriptor* id) {
  import_ = id;
}

rose_addr_t
OOMethod::get_address() const {
  return address_;
}

bool
OOMethod::is_import() const {
  return (import_ != nullptr);
}

bool
OOMethod::is_constructor() const {
  return (type_ == OOMethodType::CTOR);
}

bool
OOMethod::is_destructor() const {
  return (type_ == OOMethodType::DTOR);
}

bool
OOMethod::is_deleting_destructor() const {
  return (type_ == OOMethodType::DELDTOR);
}

void
OOMethod::set_type(OOMethodType new_type) {
  type_ = new_type;
}

bool
OOMethod::is_virtual() const {
  return is_virtual_;
}

void
OOMethod::set_virtual(bool v) {
  is_virtual_ = v;
}

}
