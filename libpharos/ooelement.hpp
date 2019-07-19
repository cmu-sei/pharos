// Copyright 2017-2019 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_OOElement_H
#define Pharos_OOElement_H

#include <rose.h>
#include "globals.hpp" // for typedef of InsnSet

namespace pharos {

const size_t INVALID = (size_t) -1;

enum class OOElementType {
  UNKN,
  DWORD,
  WORD,
  BYTE,
  ASCI,
  QWORD,
  STRUC,
  VFPTR
};

// template <>
// const char *pharos::EnumStrings<OOElementType>::data[] = {
//   "UNKN",
//   "DWORD",
//   "WORD",
//   "BYTE",
//   "ASCI",
//   "QWORD",
//   "STRUC",
//   "VFPTR"
// };

// The common parent for all members
class OOElement {

 protected:

  // All elements have a size, offset within a class, and type
  size_t size_;

  // size_t offset_;

  OOElementType type_;

  std::string name_;

  // JSG wonders if evidence should be in OOElement instead of
  // OOMember - can all elements have evidence or just true class
  // members? Cory says that embedded object members have evidence, so
  // the answer is probaly yes
  InsnSet evidence_;

 public:

  OOElement();

  OOElement(size_t s);

  OOElement(size_t s, OOElementType t);

  // allow default move semantics. JSG hopes this works for InsnSets (it should)
  OOElement& operator=(const OOElement&) = default;

  virtual ~OOElement() = default;

  virtual void set_name(std::string n);

  virtual std::string get_name() const;

  virtual size_t get_size() const;

  virtual void set_size(size_t s);

  virtual OOElementType get_type() const;

  virtual void set_type(OOElementType t);

  virtual void add_evidence(InsnSet new_evidence);

  virtual const InsnSet& get_evidence();
};

// OO elements will be able to output themselves, but they must know how

using OOElementPtr = std::shared_ptr<OOElement>;
using OOElementPtrMap = std::map<size_t, OOElementPtr>;

class OOMember;
using OOMemberPtr = std::shared_ptr<OOMember>;

class OOMethod;
using OOMethodPtr = std::shared_ptr<OOMethod>;
using OOMethodPtrList = std::vector<OOMethodPtr>;

using OOVirtualFunctionTableEntry = std::pair<rose_addr_t, OOMethodPtr>;
using OOVirtualMethodMap = std::map<size_t, OOMethodPtr>;

class OOVirtualFunctionTable;
using OOVirtualFunctionTablePtr = std::shared_ptr<OOVirtualFunctionTable>;
using OOVirtualFunctionTablePtrList = std::vector<OOVirtualFunctionTablePtr>;

class OOClassDescriptor;
using OOClassDescriptorPtr = std::shared_ptr<OOClassDescriptor>;
using OOParentPtrMap = std::map<size_t, OOClassDescriptorPtr>;


} // end namespace pharos

#endif
