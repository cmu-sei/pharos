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

  size_t offset_;

  OOElementType type_;

  std::string name_;

  // JSG wonders if evidence should be in OOElement instead of
  // OOMember - can all elements have evidence or just true class
  // members? Cory says that embedded object members have evidence, so
  // the answer is probaly yes
  InsnSet evidence_;

 public:

  // All elements should generate a deafult name
  virtual void generate_name()=0;

  OOElement();

  OOElement(size_t s);

  OOElement(size_t s, OOElementType t);

  // allow default move semantics. JSG hopes this works for InsnSets (it should)
  OOElement& operator=(const OOElement&) = default;

  virtual ~OOElement() = default;

  virtual void set_name(std::string n);

  virtual std::string get_name() const;

  virtual size_t get_offset() const;

  virtual void set_offset(size_t o);

  virtual size_t get_size() const;

  virtual void set_size(size_t s);

  virtual OOElementType get_type() const;

  virtual void set_type(OOElementType t);

  virtual void add_evidence(InsnSet new_evidence);

  virtual const InsnSet& get_evidence();
};

// OO elements will be able to output themselves, but they must know how

typedef std::shared_ptr<OOElement> OOElementPtr;
typedef std::pair<size_t, OOElementPtr> OOMemberEntry;
typedef std::map<size_t, OOElementPtr> OOElementPtrMap;

class OOMember;
typedef std::shared_ptr<OOMember> OOMemberPtr;

class OOMethod;
typedef std::shared_ptr<OOMethod> OOMethodPtr;
typedef std::vector<OOMethodPtr> OOMethodPtrList;

typedef std::pair<rose_addr_t, OOMethodPtr> OOVirtualFunctionTableEntry;
typedef std::map<size_t, OOMethodPtr> OOVirtualMethodMap;

class OOVirtualFunctionTable;
typedef std::shared_ptr<OOVirtualFunctionTable> OOVirtualFunctionTablePtr;
typedef std::vector<OOVirtualFunctionTablePtr> OOVirtualFunctionTablePtrList;

class OOClassDescriptor;
typedef std::shared_ptr<OOClassDescriptor> OOClassDescriptorPtr;
typedef std::pair<size_t, OOClassDescriptorPtr> OOParentPtrEntry;
typedef std::map<size_t, OOClassDescriptorPtr> OOParentPtrMap;


} // end namespace pharos

#endif
