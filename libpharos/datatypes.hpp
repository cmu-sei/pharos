// Copyright 2015-2023 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_DataTypes_H
#define Pharos_DataTypes_H

#include <boost/format.hpp>

#include "globals.hpp"

namespace pharos {

class Memory;

class TypeBase {
 public:
  Memory const & memory;
  rose_addr_t address;
  size_t size ;
  TypeBase(Memory const & mem, rose_addr_t a=0, size_t s=0) :
    memory(mem), address(a), size(s) {}
  virtual ~TypeBase() { };
  virtual void read(void *b);
  // Exposes arbitrary read capability
  void read(rose_addr_t a, void *b, size_t s);
  virtual DataType type() const { return DTypeNone; }
};

class TypeByte: public TypeBase {
 public:
  uint8_t value;
  TypeByte(Memory const & mem): TypeBase(mem, 0, 1) { }
  TypeByte(Memory const & mem, rose_addr_t a): TypeBase(mem, a, 1) { read(); }
  using TypeBase::read;
  inline uint8_t read() { TypeBase::read(&value); return value; }
  inline uint8_t read(rose_addr_t a) { address = a; return read(); }
  inline std::string str() const { return boost::str(boost::format("0x%02X") % value); }
  inline DataType type() const { return DTypeByte; }
};

class TypeWord: public TypeBase {
 public:
  uint16_t value;
  TypeWord(Memory const & mem): TypeBase(mem, 0, 2) { }
  TypeWord(Memory const & mem, rose_addr_t a): TypeBase(mem, a, 2) { read(); }
  using TypeBase::read;
  inline uint16_t read() { TypeBase::read(&value); return value; }
  inline uint16_t read(rose_addr_t a) { address = a; return read(); }
  inline std::string str() const { return boost::str(boost::format("0x%04X") % value); }
  inline DataType type() const { return DTypeWord; }
};

class TypeWordInt: public TypeWord {
 public:
  TypeWordInt(Memory const & mem): TypeWord(mem) { }
  TypeWordInt(Memory const & mem, rose_addr_t a): TypeWord(mem, a) { }
  inline std::string str() const { return boost::str(boost::format("%d") % value); }
  inline DataType type() const { return DTypeWordInt; }
};

class TypeWordSignedInt: public TypeWord {
 public:
  TypeWordSignedInt(Memory const & mem): TypeWord(mem) { }
  TypeWordSignedInt(Memory const & mem, rose_addr_t a): TypeWord(mem, a) { }
  inline std::string str() const { return boost::str(boost::format("%d") % (int16_t)value); }
  inline DataType type() const { return DTypeWordSignedInt; }
};

class TypeDword: public TypeBase {
 public:
  uint32_t value;
  TypeDword(Memory const & mem): TypeBase(mem, 0, 4) { }
  TypeDword(Memory const & mem, rose_addr_t a): TypeBase(mem, a, 4) { read(); }
  using TypeBase::read;
  inline uint32_t read() { TypeBase::read(&value); return value; }
  inline uint32_t read(rose_addr_t a) { address = a; return read(); }
  inline std::string str() const { return boost::str(boost::format("0x%08X") % value); }
  inline DataType type() const { return DTypeDword; }
};

class TypeDwordInt: public TypeDword {
 public:
  TypeDwordInt(Memory const & mem): TypeDword(mem) { }
  TypeDwordInt(Memory const & mem, rose_addr_t a): TypeDword(mem, a) { read(); }
  inline std::string str() const { return boost::str(boost::format("%d") % value); }
  inline DataType type() const { return DTypeDwordInt; }
};

class TypeDwordSignedInt: public TypeDword {
 public:
  TypeDwordSignedInt(Memory const & mem): TypeDword(mem) { }
  TypeDwordSignedInt(Memory const & mem, rose_addr_t a): TypeDword(mem, a) { read(); }
  inline std::string str() const { return boost::str(boost::format("%d") % (int32_t)value); }
  inline DataType type() const { return DTypeDwordSignedInt; }
};

// TypeDwordAddr implies a 32-bit analysis architecture. :-(
class TypeDwordAddr: public TypeDword {
 public:
  TypeDwordAddr(Memory const & mem): TypeDword(mem) { }
  TypeDwordAddr(Memory const & mem, rose_addr_t a): TypeDword(mem, a) { read(); }
  inline DataType type() const { return DTypeDwordAddr; }
};

class TypeQword: public TypeBase {
 public:
  uint64_t value;
  TypeQword(Memory const & mem): TypeBase(mem, 0, 8) { }
  TypeQword(Memory const & mem, rose_addr_t a): TypeBase(mem, a, 8) { TypeBase::read(&value); }
  using TypeBase::read;
  inline uint64_t read() { TypeBase::read(&value); return value; }
  inline std::string str() const { return boost::str(boost::format("0x%16X") % value); }
  inline DataType type() const { return DTypeQword; }
};

class TypeChar: public TypeByte {
 public:
  char value;
  TypeChar(Memory const & mem, rose_addr_t a): TypeByte(mem, a) { read(); }
  using TypeByte::read;
  inline char read() { TypeByte::read(); return value; }
  inline char read(rose_addr_t a) { address = a; return read(); }
  inline std::string str() const { return boost::str(boost::format("'%c'") % value); }
  inline DataType type() const { return DTypeChar; }
};

class TypeWideChar: public TypeWord {
 public:
  wchar_t value;
  TypeWideChar(Memory const & mem, rose_addr_t a): TypeWord(mem, a) { read(); }
  using TypeWord::read;
  inline wchar_t read() { TypeWord::read(); return value; }
  inline wchar_t read(rose_addr_t a) { address = a; return read(); }
  inline std::string str() const { return boost::str(boost::format("'%c'") % value); }
  inline DataType type() const { return DTypeWideChar; }
};

class TypeString: public TypeBase {
 public:
  std::string value;
  TypeString(Memory const & mem): TypeBase(mem) { }
  TypeString(Memory const & mem, rose_addr_t a) : TypeBase(mem) { read(a); }
  using TypeBase::read;
  void read(rose_addr_t a);
  inline std::string str() const { return value; }
  inline DataType type() const { return DTypeString; }
};

class TypeUnicodeString: public TypeBase {
 public:
  std::wstring value;
  TypeUnicodeString(Memory const & mem, rose_addr_t a);
  inline std::wstring str() const { return value; }
  inline DataType type() const { return DTypeUnicodeString; }
};

class TypeLen8String: public TypeString {
 public:
  TypeLen8String(Memory const & mem, rose_addr_t a);
  inline DataType type() const { return DTypeLen8String; }
};

class TypeLen16String: public TypeString {
 public:
  TypeLen16String(Memory const & mem, rose_addr_t a);
  inline DataType type() const { return DTypeLen16String; }
};

class TypeLen32String: public TypeString {
 public:
  TypeLen32String(Memory const & mem, rose_addr_t a);
  inline DataType type() const { return DTypeLen32String; }
};

// _EH4_SCOPETABLE_RECORD
class TypeSEH4ScopeTableRecord: public TypeBase {
 public:
  TypeDwordSignedInt EnclosingLevel{memory};
  TypeDwordAddr FilterFunc{memory};
  TypeDwordAddr HandleFunc{memory};
  TypeSEH4ScopeTableRecord(Memory const & mem): TypeBase(mem) {}
  TypeSEH4ScopeTableRecord(Memory const & mem, rose_addr_t a) : TypeBase(mem) { read(a); }
  using TypeBase::read;
  void read(rose_addr_t a);
  std::string str() const;
  inline DataType type() const { return DTypeSEH4ScopeTableRecord; }
};

// _EH4_SCOPETABLE
class TypeSEH4ScopeTable: public TypeBase {
 public:
  TypeDwordSignedInt GSCookieOffset{memory};
  TypeDword GSCookieXOROffset{memory};
  TypeDwordSignedInt EHCookieOffset{memory};
  TypeDword EHCookieXOROffset{memory};
  std::vector<TypeSEH4ScopeTableRecord> ScopeRecord;
  TypeSEH4ScopeTable(Memory const & mem) : TypeBase(mem) {}
  TypeSEH4ScopeTable(Memory const & mem, rose_addr_t a): TypeBase(mem) { read(a); }
  using TypeBase::read;
  void read(rose_addr_t a);
  std::string str() const;
  inline DataType type() const { return DTypeSEH4ScopeTable; }
};

class TypeSEH3ExceptionRegistration: public TypeBase {
 public:
  TypeDwordAddr Next{memory};
  TypeDwordAddr ExceptionHandler{memory};
  TypeSEH4ScopeTable ScopeTable{memory};
  TypeDwordSignedInt TryLevel{memory};
  TypeSEH3ExceptionRegistration(Memory const & mem): TypeBase(mem) {}
  TypeSEH3ExceptionRegistration(Memory const & mem, rose_addr_t a): TypeBase(mem) { read(a); }
  using TypeBase::read;
  void read(rose_addr_t a);
  std::string str() const;
  inline DataType type() const { return DTypeSEH3ExceptionRegistration; }
};

// _s_HandlerType
class TypeSEH4HandlerType: public TypeBase {
 public:
  TypeDwordInt adjectives{memory};
  TypeDwordAddr pType{memory};
  TypeDwordInt dispatchObj{memory};
  TypeDwordAddr addressOfHandler{memory};
  TypeSEH4HandlerType(Memory const & mem) : TypeBase(mem) {}
  TypeSEH4HandlerType(Memory const & mem, rose_addr_t a) : TypeBase(mem) { read(a); }
  using TypeBase::read;
  void read(rose_addr_t a);
  std::string str() const;
  inline DataType type() const { return DTypeSEH4HandlerType; }
};

// _s_TryBlockMapEntry
class TypeSEH4TryBlockMapEntry: public TypeBase {
 public:
  TypeDwordInt tryLow{memory};
  TypeDwordInt tryHigh{memory};
  TypeDwordInt catchHigh{memory};
  TypeDwordInt nCatches{memory};
  TypeDwordAddr pHandlerArray{memory};
  std::vector<TypeSEH4HandlerType> handlers;
  TypeSEH4TryBlockMapEntry(Memory const & mem): TypeBase(mem) {}
  TypeSEH4TryBlockMapEntry(Memory const & mem, rose_addr_t a) : TypeBase(mem) { read(a); }
  using TypeBase::read;
  void read(rose_addr_t a);
  std::string str() const;
  inline DataType type() const { return DTypeSEH4TryBlockMapEntry; }
};

// _s_UnwindMapEntry
class TypeSEH4UnwindMapEntry: public TypeBase {
 public:
  TypeDwordSignedInt toState{memory};
  TypeDwordAddr action{memory};
  TypeSEH4UnwindMapEntry(Memory const & mem): TypeBase(mem) {}
  TypeSEH4UnwindMapEntry(Memory const & mem, rose_addr_t a) : TypeBase(mem) { read(a); }
  using TypeBase::read;
  void read(rose_addr_t a);
  std::string str() const;
  inline DataType type() const { return DTypeSEH4UnwindMapEntry; }
};

// _s_FuncInfo
class TypeSEH4FuncInfo: public TypeBase {
 public:
  TypeDword magicNumber{memory};
  TypeDwordInt maxState{memory};
  TypeDwordAddr pUnwindMap{memory};
  std::vector<TypeSEH4UnwindMapEntry> unwind_map;
  TypeDwordInt nTryBlocks{memory};
  TypeDwordAddr pTryBlocksMap{memory};
  std::vector<TypeSEH4TryBlockMapEntry> try_block_map;
  TypeDwordInt nIPMapEntries{memory};
  TypeDwordAddr pIPtoStateMap{memory};
  TypeDwordAddr pESTypeList{memory};
  TypeDword EHFlags{memory};
  TypeSEH4FuncInfo(Memory const & mem): TypeBase(mem) {}
  TypeSEH4FuncInfo(Memory const & mem, rose_addr_t a) : TypeBase(mem) { read(a); }
  using TypeBase::read;
  void read(rose_addr_t a);
  std::string str() const;
  void dump();
  inline DataType type() const { return DTypeSEH4FuncInfo; }
};

// _RTC_vardesc
class TypeRTCVarDesc: public TypeBase {
 public:
  TypeDwordSignedInt var_offset{memory}; // named addr in _RTC_vardesc
  TypeDwordInt var_size{memory}; // named size in _RTV_vardesc
  TypeDwordAddr var_name_addr{memory};
  TypeString var_name{memory};
  TypeRTCVarDesc(Memory const & mem): TypeBase(mem) { }
  TypeRTCVarDesc(Memory const & mem, rose_addr_t a) : TypeBase(mem) { read(a); }
  using TypeBase::read;
  void read(rose_addr_t a);
  std::string str() const;
  inline DataType type() const { return DTypeRTCVarDesc; }
};

// _RTC_framedesc
class TypeRTCFrameDesc: public TypeBase {
 public:
  TypeDwordInt varCount{memory};
  TypeDwordAddr variables{memory};
  std::vector<TypeRTCVarDesc> vars;
  TypeRTCFrameDesc(Memory const & mem): TypeBase(mem) { }
  TypeRTCFrameDesc(Memory const & mem, rose_addr_t a) : TypeBase(mem) { read(a); }
  using TypeBase::read;
  void read(rose_addr_t a);
  std::string str() const;
  void dump();
  inline DataType type() const { return DTypeRTCFrameDesc; }
};

// 'RTTI Type Descriptor'
class TypeRTTITypeDescriptor: public TypeBase {
 public:
  TypeDwordAddr pVFTable{memory};
  TypeDword spare{memory};
  TypeString name{memory};
  TypeRTTITypeDescriptor(Memory const & mem): TypeBase(mem) { }
  TypeRTTITypeDescriptor(Memory const & mem, rose_addr_t a) : TypeBase(mem) { read(a); }
  virtual ~TypeRTTITypeDescriptor() {};
  using TypeBase::read;
  void read(rose_addr_t a);
  std::string str() const;
  inline DataType type() const { return DTypeRTTITypeDescriptor; }
};

// 'RTTI Base Class Array'
class TypeRTTIBaseClassArray: public TypeBase {
 public:
  TypeRTTIBaseClassArray(Memory const & mem): TypeBase(mem) { }
  TypeRTTIBaseClassArray(Memory const & mem, rose_addr_t a) : TypeBase(mem) { read(a); }
  using TypeBase::read;
  void read(rose_addr_t a);
  std::string str() const;
  inline DataType type() const { return DTypeRTTIBaseClassArray; }
};

// 'RTTI Base Class Descriptor'
class TypeRTTIBaseClassDescriptor: public TypeBase {
 public:
  TypeDwordAddr pTypeDescriptor{memory};
  TypeDwordInt numContainedBases{memory};
  // Really a _PMD structure for next three dwords.
  TypeDwordSignedInt where_mdisp{memory};
  TypeDwordSignedInt where_pdisp{memory};
  TypeDwordSignedInt where_vdisp{memory};
  TypeDword attributes{memory};
  // The pClass(Hierarchy)Descriptor is optional, and is only present if attributes & 0x40.
  TypeDwordAddr pClassDescriptor{memory};

  TypeRTTITypeDescriptor type_desc{memory};
  TypeRTTIBaseClassDescriptor(Memory const & mem): TypeBase(mem) { }
  TypeRTTIBaseClassDescriptor(Memory const & mem, rose_addr_t a) : TypeBase(mem) { read(a); }
  using TypeBase::read;
  void read(rose_addr_t a);
  std::string str() const;
  inline DataType type() const { return DTypeRTTIBaseClassDescriptor; }
};

// 'RTTI Class Hierarchy Descriptor'
class TypeRTTIClassHierarchyDescriptor: public TypeBase {
 public:
  TypeDword signature{memory};
  TypeDword attributes{memory};
  TypeDwordInt numBaseClasses{memory};
  TypeDwordAddr pBaseClassArray{memory};
  std::vector<TypeRTTIBaseClassDescriptor> base_classes;
  TypeRTTIClassHierarchyDescriptor(Memory const & mem): TypeBase(mem) { }
  TypeRTTIClassHierarchyDescriptor(Memory const & mem, rose_addr_t a) : TypeBase(mem)
  { read(a); }
  using TypeBase::read;
  void read(rose_addr_t a);
  std::string str() const;
  inline DataType type() const { return DTypeRTTIClassHierarchyDescriptor; }
};

// 'RTTI Complete Object Locator'
class TypeRTTICompleteObjectLocator: public TypeBase {
 public:
  TypeDword signature{memory};
  TypeDword offset{memory};
  TypeDword cdOffset{memory};
  TypeDwordAddr pTypeDescriptor{memory};
  TypeDwordAddr pClassDescriptor{memory};

  TypeRTTITypeDescriptor type_desc{memory};
  TypeRTTIClassHierarchyDescriptor class_desc{memory};

  TypeRTTICompleteObjectLocator(Memory const & mem): TypeBase(mem) { }
  TypeRTTICompleteObjectLocator(Memory const & mem, rose_addr_t a) : TypeBase(mem) { read(a); }
  virtual ~TypeRTTICompleteObjectLocator() {};
  using TypeBase::read;
  void read(rose_addr_t a);
  std::string str() const;
  void dump();
  inline DataType type() const { return DTypeRTTICompleteObjectLocator; }
};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
