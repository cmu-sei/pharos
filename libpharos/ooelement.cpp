// Copyright 2017-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "ooelement.hpp"

namespace pharos {

OOElement::OOElement()  {

  // everything is default
  set_size(0);
  // set_offset(INVALID);
  set_type(OOElementType::UNKN);
  set_name("");
}

OOElement::OOElement(size_t s, OOElementType t) {
  set_size(s);
  set_type(t);

  // defaults
  // set_offset(INVALID);
  set_name("");
}

OOElement::OOElement(size_t s) {
  set_size(s);
  // set_offset(INVALID);
  set_type(OOElementType::UNKN);
  set_name("");
}

// elements should know how to name themselves
void
OOElement::set_name(std::string n) {
  name_ = n;
}

std::string
OOElement::get_name() const {
  return name_;
}

// size_t
// OOElement::get_offset() const {
//   return offset_;
// }

// void
// OOElement::set_offset(size_t o) {
//   offset_=o;
// }

size_t
OOElement::get_size() const { return size_; }

void
OOElement::set_size(size_t s) {
  size_=s;
}

OOElementType
OOElement::get_type() const {
  return type_;
}

void
OOElement::set_type(OOElementType t) {
  type_=t;

  // update size based on type
  if (type_ == OOElementType::BYTE) {
    size_ = 1;
  }
  else if (type_ == OOElementType::WORD) {
    size_ = 2;
  }
  else if (type_ == OOElementType::DWORD || type_ == OOElementType::VFPTR) {
    size_ = 4;
  }
}

const InsnSet&
OOElement::get_evidence() {
  return evidence_;
}

void
OOElement::add_evidence(InsnSet new_evidence) {
  for (auto e : new_evidence) {
    evidence_.insert(e);
  }
}

} // end namespace pharos
