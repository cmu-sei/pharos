
#include "ooelement.hpp"

namespace pharos {

OOElement::OOElement() : size_(0), offset_(INVALID), type_(OOElementType::UNKN), name_("") { }

OOElement::OOElement(size_t s, OOElementType t) : size_(s), offset_(INVALID), type_(t), name_("") { }

OOElement::OOElement(size_t s) : size_(s), offset_(INVALID), type_(OOElementType::UNKN), name_("") { }

// elements should know how to name themselves
void
OOElement::set_name(std::string n) {
  name_ = n;
}

std::string
OOElement::get_name() const {
  return name_;
}

size_t
OOElement::get_offset() const {
  return offset_;
}

void
OOElement::set_offset(size_t o) {
  offset_=o;
}

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
