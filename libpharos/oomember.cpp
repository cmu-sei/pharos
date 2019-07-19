// Copyright 2017-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "oomember.hpp"

namespace pharos {

OOMember::OOMember(size_t s) : OOElement(s) {
  set_name("mbr");
  assess_type_from_size();
}

OOMember::OOMember(size_t s, InsnSet e) : OOElement(s) {
  add_evidence(e);
  set_name("mbr");
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
