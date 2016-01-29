// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_DataTypes_H
#define Pharos_DataTypes_H

#include <boost/format.hpp>

#include <rose.h>

#include "globals.hpp"

class TypeBase {
public:
  rose_addr_t address;
  size_t size;
  TypeBase() { address = 0; size = 0; }
  TypeBase(rose_addr_t a) { address = a; size = 0; }
  TypeBase(rose_addr_t a, size_t s) { address = a; size = s; }
  virtual ~TypeBase() { };
  virtual void read(void *b);
  // Exposes arbitrary read capability
  void read(rose_addr_t a, void *b, size_t s);
  virtual DataType type() { return DTypeNone; }
};

class TypeByte: public TypeBase {
public:
  uint8_t value;
  TypeByte(): TypeBase(0, 1) { }
  TypeByte(rose_addr_t a): TypeBase(a, 1) { read(); }
  inline uint8_t read() { TypeBase::read(&value); return value; }
  inline uint8_t read(rose_addr_t a) { address = a; return read(); }
  inline std::string str() { return boost::str(boost::format("0x%02X") % value); }
  inline DataType type() { return DTypeByte; }
};

class TypeWord: public TypeBase {
public:
  uint16_t value;
  TypeWord(): TypeBase(0, 2) { }
  TypeWord(rose_addr_t a): TypeBase(a, 2) { read(); }
  inline uint16_t read() { TypeBase::read(&value); return value; }
  inline uint16_t read(rose_addr_t a) { address = a; return read(); }
  inline std::string str() { return boost::str(boost::format("0x%04X") % value); }
  inline DataType type() { return DTypeWord; }
};

class TypeWordInt: public TypeWord {
public:
  TypeWordInt(): TypeWord() { }
  TypeWordInt(rose_addr_t a): TypeWord(a) { }
  inline std::string str() { return boost::str(boost::format("%d") % value); }
  inline DataType type() { return DTypeWordInt; }
};

class TypeWordSignedInt: public TypeWord {
public:
  TypeWordSignedInt(): TypeWord() { }
  TypeWordSignedInt(rose_addr_t a): TypeWord(a) { }
  inline std::string str() { return boost::str(boost::format("%d") % (int16_t)value); }
  inline DataType type() { return DTypeWordSignedInt; }
};

class TypeDword: public TypeBase {
public:
  uint32_t value;
  TypeDword(): TypeBase(0, 4) { }
  TypeDword(rose_addr_t a): TypeBase(a, 4) { read(); }
  inline uint32_t read() { TypeBase::read(&value); return value; }
  inline uint32_t read(rose_addr_t a) { address = a; return read(); }
  inline std::string str() { return boost::str(boost::format("0x%08X") % value); }
  inline DataType type() { return DTypeDword; }
};

class TypeDwordInt: public TypeDword {
public:
  TypeDwordInt(): TypeDword() { }
  TypeDwordInt(rose_addr_t a): TypeDword(a) { read(); }
  inline std::string str() { return boost::str(boost::format("%d") % value); }
  inline DataType type() { return DTypeDwordInt; }
};

class TypeDwordSignedInt: public TypeDword {
public:
  TypeDwordSignedInt(): TypeDword() { }
  TypeDwordSignedInt(rose_addr_t a): TypeDword(a) { read(); }
  inline std::string str() { return boost::str(boost::format("%d") % (int32_t)value); }
  inline DataType type() { return DTypeDwordSignedInt; }
};

class TypeDwordAddr: public TypeDword {
public:
  TypeDwordAddr(): TypeDword() { }
  TypeDwordAddr(rose_addr_t a): TypeDword(a) { read(); }
  inline DataType type() { return DTypeDwordAddr; }
};

class TypeQword: public TypeBase {
public:
  uint64_t value;
  TypeQword(): TypeBase(0, 8) { }
  TypeQword(rose_addr_t a): TypeBase(a, 8) { TypeBase::read(&value); }
  inline uint64_t read() { TypeBase::read(&value); return value; }
  inline std::string str() { return boost::str(boost::format("0x%16X") % value); }
  inline DataType type() { return DTypeQword; }
};

class TypeChar: public TypeByte {
public:
  char value;
  TypeChar(rose_addr_t a): TypeByte(a) { read(); }
  inline char read() { TypeByte::read(); return value; }
  inline char read(rose_addr_t a) { address = a; return read(); }
  inline std::string str() { return boost::str(boost::format("'%c'") % value); }
  inline DataType type() { return DTypeChar; }
};

class TypeWideChar: public TypeWord {
public:
  wchar_t value;
  TypeWideChar(rose_addr_t a): TypeWord(a) { read(); }
  inline wchar_t read() { TypeWord::read(); return value; }
  inline wchar_t read(rose_addr_t a) { address = a; return read(); }
  inline std::string str() { return boost::str(boost::format("'%c'") % value); }
  inline DataType type() { return DTypeWideChar; }
};

class TypeString: public TypeBase {
public:
  std::string value;
  TypeString(): TypeBase(0, 0) { }
  TypeString(rose_addr_t a) { read(a); }
  void read(rose_addr_t a);
  inline std::string str() { return value; }
  inline DataType type() { return DTypeString; }
};

class TypeUnicodeString: public TypeBase {
public:
  std::wstring value;
  TypeUnicodeString(rose_addr_t a);
  inline std::wstring str() { return value; }
  inline DataType type() { return DTypeUnicodeString; }
};

class TypeLen8String: public TypeString {
public:
  TypeLen8String(rose_addr_t a);
  inline DataType type() { return DTypeLen8String; }
};

class TypeLen16String: public TypeString {
public:
  TypeLen16String(rose_addr_t a);
  inline DataType type() { return DTypeLen16String; }
};

class TypeLen32String: public TypeString {
public:
  TypeLen32String(rose_addr_t a);
  inline DataType type() { return DTypeLen32String; }
};

// _EH4_SCOPETABLE_RECORD
class TypeSEH4ScopeTableRecord: public TypeBase {
public:
  TypeDwordSignedInt EnclosingLevel;
  TypeDwordAddr FilterFunc;
  TypeDwordAddr HandleFunc;  
  TypeSEH4ScopeTableRecord(): TypeBase() { }
  TypeSEH4ScopeTableRecord(rose_addr_t a) { read(a); }
  void read(rose_addr_t a);
  std::string str();
  inline DataType type() { return DTypeSEH4ScopeTableRecord; }
};

// _EH4_SCOPETABLE
class TypeSEH4ScopeTable: public TypeBase {
public:
  TypeDwordSignedInt GSCookieOffset;
  TypeDword GSCookieXOROffset;
  TypeDwordSignedInt EHCookieOffset;
  TypeDword EHCookieXOROffset;
  std::vector<TypeSEH4ScopeTableRecord> ScopeRecord;
  TypeSEH4ScopeTable(): TypeBase() { }
  TypeSEH4ScopeTable(rose_addr_t a) { read(a); }
  void read(rose_addr_t a);
  std::string str();
  inline DataType type() { return DTypeSEH4ScopeTable; }
};

class TypeSEH3ExceptionRegistration: public TypeBase {
public:
  TypeDwordAddr Next; 
  TypeDwordAddr ExceptionHandler;
  TypeSEH4ScopeTable ScopeTable;  
  TypeDwordSignedInt TryLevel;
  TypeSEH3ExceptionRegistration(): TypeBase() { }
  TypeSEH3ExceptionRegistration(rose_addr_t a) { read(a); }
  void read(rose_addr_t a);
  std::string str();
  inline DataType type() { return DTypeSEH3ExceptionRegistration; }
};

// _s_HandlerType
class TypeSEH4HandlerType: public TypeBase {
public:
  TypeDwordInt adjectives;
  TypeDwordAddr pType;
  TypeDwordInt dispatchObj;
  TypeDwordAddr addressOfHandler;
  TypeSEH4HandlerType(): TypeBase() { }
  TypeSEH4HandlerType(rose_addr_t a) { read(a); }
  void read(rose_addr_t a);
  std::string str();
  inline DataType type() { return DTypeSEH4HandlerType; }
};

// _s_TryBlockMapEntry
class TypeSEH4TryBlockMapEntry: public TypeBase {
public:
  TypeDwordInt tryLow;
  TypeDwordInt tryHigh;
  TypeDwordInt catchHigh;
  TypeDwordInt nCatches;
  TypeDwordAddr pHandlerArray;
  std::vector<TypeSEH4HandlerType> handlers;
  TypeSEH4TryBlockMapEntry(): TypeBase() { }
  TypeSEH4TryBlockMapEntry(rose_addr_t a) { read(a); }
  void read(rose_addr_t a);
  std::string str();
  inline DataType type() { return DTypeSEH4TryBlockMapEntry; }
};

// _s_UnwindMapEntry
class TypeSEH4UnwindMapEntry: public TypeBase {
public:
  TypeDwordSignedInt toState;
  TypeDwordAddr action;
  TypeSEH4UnwindMapEntry(): TypeBase() { }
  TypeSEH4UnwindMapEntry(rose_addr_t a) { read(a); }
  void read(rose_addr_t a);
  std::string str();
  inline DataType type() { return DTypeSEH4UnwindMapEntry; }
};

// _s_FuncInfo
class TypeSEH4FuncInfo: public TypeBase {
public:
  TypeDword magicNumber;
  TypeDwordInt maxState;
  TypeDwordAddr pUnwindMap;
  std::vector<TypeSEH4UnwindMapEntry> unwind_map;
  TypeDwordInt nTryBlocks;
  TypeDwordAddr pTryBlocksMap;
  std::vector<TypeSEH4TryBlockMapEntry> try_block_map;
  TypeDwordInt nIPMapEntries;
  TypeDwordAddr pIPtoStateMap;
  TypeDwordAddr pESTypeList;
  TypeDword EHFlags;
  TypeSEH4FuncInfo(): TypeBase() { }
  TypeSEH4FuncInfo(rose_addr_t a) { read(a); }
  void read(rose_addr_t a);
  std::string str();
  void dump();
  inline DataType type() { return DTypeSEH4FuncInfo; }
};

// _RTC_vardesc
class TypeRTCVarDesc: public TypeBase {
public:
  TypeDwordSignedInt var_offset; // named addr in _RTC_vardesc
  TypeDwordInt var_size; // named size in _RTV_vardesc
  TypeDwordAddr var_name_addr;
  TypeString var_name;
  TypeRTCVarDesc(): TypeBase() { }
  TypeRTCVarDesc(rose_addr_t a) { read(a); }
  void read(rose_addr_t a);
  std::string str();
  inline DataType type() { return DTypeRTCVarDesc; }
};

// _RTC_framedesc
class TypeRTCFrameDesc: public TypeBase {
public:
  TypeDwordInt varCount;
  TypeDwordAddr variables;  
  std::vector<TypeRTCVarDesc> vars;
  TypeRTCFrameDesc(): TypeBase() { }
  TypeRTCFrameDesc(rose_addr_t a) { read(a); }
  void read(rose_addr_t a);
  std::string str();
  void dump();
  inline DataType type() { return DTypeRTCFrameDesc; }
};

// 'RTTI Type Descriptor'
class TypeRTTITypeDescriptor: public TypeBase {
public:
  TypeDwordAddr pVFTable;
  TypeDword spare;
  TypeString name;
  TypeRTTITypeDescriptor(): TypeBase() { }
  TypeRTTITypeDescriptor(rose_addr_t a) { read(a); }
  virtual ~TypeRTTITypeDescriptor() {};
  void read(rose_addr_t a);
  std::string str();
  inline DataType type() { return DTypeRTTITypeDescriptor; }
};

// 'RTTI Base Class Array'
class TypeRTTIBaseClassArray: public TypeBase {
public:
  TypeRTTIBaseClassArray(): TypeBase() { }
  TypeRTTIBaseClassArray(rose_addr_t a) { read(a); }
  void read(rose_addr_t a);
  std::string str();
  inline DataType type() { return DTypeRTTIBaseClassArray; }
};

// 'RTTI Base Class Descriptor'
class TypeRTTIBaseClassDescriptor: public TypeBase {
public:
  TypeDwordAddr pTypeDescriptor;
  TypeDwordInt numContainedBases;
  // Really a _PMD structure for next three dwords.
  TypeDwordSignedInt where_mdisp;
  TypeDwordSignedInt where_pdisp;
  TypeDwordSignedInt where_vdisp;
  TypeDword attributes;
  TypeRTTIBaseClassDescriptor(): TypeBase() { }
  TypeRTTIBaseClassDescriptor(rose_addr_t a) { read(a); }
  void read(rose_addr_t a);
  std::string str();
  inline DataType type() { return DTypeRTTIBaseClassDescriptor; }
};

// 'RTTI Class Hierarchy Descriptor'
class TypeRTTIClassHierarchyDescriptor: public TypeBase {
public:
  TypeDwordAddr signature;
  TypeDword attributes;
  TypeDwordInt numBaseClasses;
  TypeDwordAddr pBaseClassArray;
  std::vector<TypeRTTIBaseClassDescriptor> base_classes; 
  TypeRTTIClassHierarchyDescriptor(): TypeBase() { }
  TypeRTTIClassHierarchyDescriptor(rose_addr_t a) { read(a); }
  void read(rose_addr_t a);
  std::string str();
  inline DataType type() { return DTypeRTTIClassHierarchyDescriptor; }
};

// 'RTTI Complete Object Locator'
class TypeRTTICompleteObjectLocator: public TypeBase {
public:
  TypeDword signature;
  TypeDword offset;
  TypeDword cdOffset;
  TypeDwordAddr pTypeDescriptor;
  TypeDwordAddr pClassDescriptor;

  TypeRTTITypeDescriptor type_desc;
  TypeRTTIClassHierarchyDescriptor class_desc;

  TypeRTTICompleteObjectLocator(): TypeBase() { }
  TypeRTTICompleteObjectLocator(rose_addr_t a) { read(a); }
  virtual ~TypeRTTICompleteObjectLocator() {};
  void read(rose_addr_t a);
  std::string str();
  void dump();
  inline DataType type() { return DTypeRTTICompleteObjectLocator; }
};

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
