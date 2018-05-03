#include "oomember.hpp"

namespace pharos {

void
OOMember::generate_name() {
  std::stringstream name_ss;
  name_ss << "mbr_" << std::hex << std::noshowbase << offset_ << std::showbase << std::dec;
  std::string s = name_ss.str();
  set_name(s);
}

OOMember::OOMember(size_t s) : OOElement(s) {
  generate_name();
  assess_type_from_size();
}

OOMember::OOMember(size_t s, size_t o) : OOElement(s) {
  set_offset(o);
  generate_name();
  assess_type_from_size();
}

OOMember::OOMember(size_t s, size_t o, InsnSet e) : OOElement(s) {
  set_offset(o);
  add_evidence(e);
  generate_name();
  assess_type_from_size();
}

void
OOMember::assess_type_from_size() {

  // initial type is based on size
  if (size_ == 1) {
    type_ = OOElementType::BYTE;
  }
  else if (size_ == 2) {
    type_ = OOElementType::WORD;
  }
  else if (size_ == 4) {
    type_ = OOElementType::DWORD;
  }
  else {
    type_ = OOElementType::UNKN;
  }
}

} // end namespace pharos
