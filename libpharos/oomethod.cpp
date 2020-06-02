// Copyright 2017-2018 Carnegie Mellon University.  See LICENSE file for terms.

#include "oomethod.hpp"
#include "descriptors.hpp"

namespace pharos {

OOMethod::OOMethod(const FunctionDescriptor* fd) {

  function_ = fd;
  import_ = nullptr;
  address_ = fd->get_address();
  name_ = "";
  type_ = OOMethodType::UNKN;
  is_virtual_ = false;
}

OOMethod::OOMethod(const ImportDescriptor* id) {

  function_ = nullptr;
  import_ = id;
  address_ = id->get_address();
  type_ = OOMethodType::UNKN;
  is_virtual_ = false;
  function_ = id->get_function_descriptor();

  // ejs: If the import is an ordinal, we do want to note that.  But all the naming functions
  // (i.e., get_best_name) that handle ordinals also include the DLL name, which we do not
  // normally want for non-ordinals.
  if (id->is_name_valid())
    set_name(id->get_name());
  else if (id->get_ordinal() != 0)
    set_name(id->get_best_name());
  else {
    GWARN << "Unsure how to name imported method " << address_ << " " << id->get_best_name() << LEND;
    set_name(id->get_name());
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

  name_ss << "0x" << std::hex << address_ << std::dec;
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
