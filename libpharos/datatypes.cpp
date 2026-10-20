// Copyright 2015-2019, 2021, 2026 Carnegie Mellon University.  See LICENSE file for terms.

#include "globals.hpp"
#include "descriptors.hpp"
#include "datatypes.hpp"
#include "util.hpp"

namespace pharos {


// This is here primarily because I don't want to reference the global descriptor set in the
// globals header file.
void TypeBase::read(void *b) {
  // This is a BUG!  We need to thow an exception here, for now just report the problem.  Cory
  // moved this back to the DEBUG level as part of an effort to enable GWARN level messages by
  // default, and while this is a serious TODO fot the developers, there's nothing that the
  // end-user can do about the message (or even that it's actually a problem in most cases).
  if (address == 0 || size == 0) {
    GDEBUG << "Bad read of address and size. address=0x" << std::hex
           << address << " size=0x" << size << std::dec << LEND;
    return;
  }
  memory.read_bytes_strict(address, (char *)b, Bytes(size));
}

void TypeBase::read(rose_addr_t a, void *b, size_t s) {
  memory.read_bytes_strict(a, (char *)b, Bytes(s));
}

void TypeString::read(rose_addr_t a) {
  size = 0;
  value.clear();
  TypeByte ch(memory, a);
  while (ch.read(a + size) != 0) {
    size += 1;
    value += ch.value;
  }
  // The NULL is counted in the size.
  size += 1;
}

TypeUnicodeString::TypeUnicodeString(Memory const & mem, rose_addr_t a): TypeBase(mem, a, 0) {
  size = 0;
  value.clear();
  TypeWideChar ch(memory, a);
  while (ch.read(a + size) != 0) {
    size += 2;
    value += ch.value;
  }
  // The NULL is counted in the size.
  size += 1;
}

TypeLen8String::TypeLen8String(Memory const & mem, rose_addr_t a): TypeString(mem, a) {
  TypeByte len(memory, a);
  char buffer[257];
  TypeBase::read(a + 1, buffer, len.value);
  size = len.value + 1;
  value = buffer;
}

TypeLen16String::TypeLen16String(Memory const & mem, rose_addr_t a): TypeString(mem, a) {
  TypeWord len(memory, a);
  char* buffer = (char *)alloca(len.value);
  TypeBase::read(a + 2, buffer, len.value);
  size = len.value + 2;
  value = buffer;
}

TypeLen32String::TypeLen32String(Memory const & mem, rose_addr_t a): TypeString(mem, a) {
  TypeDword len(memory, a);
  if (len.value <= 0x1000000) {
    char* buffer = (char *)alloca(len.value);
    TypeBase::read(a + 2, buffer, len.value);
    size = len.value + 4;
    value = buffer;
  }
  else {
    GERROR << "Over-sized string ignored." << LEND;
    // We should probably be throwing an error here as well.
  }
}

// This structure may not get used much, because it's typically on the stack, and is
// constructed from several push instructions in the code.
// This is defined in the Microsoft source code as: _EH3_EXCEPTION_REGISTRATION
void TypeSEH3ExceptionRegistration::read(rose_addr_t a) {
  address = a;
  size = 16;
  Next.read(a);
  ExceptionHandler.read(a + 4);
  ScopeTable.read(a + 8);
  TryLevel.read(a + 12);
}

std::string TypeSEH3ExceptionRegistration::str() const {
  return boost::str(boost::format("<next=%s ehfunc=%s scopetable=%s lvl=%s>") %
                    Next.str() % ExceptionHandler.str() %
                    ScopeTable.str() % TryLevel.str());
}

// This is defined in the Microsoft source code as:
void TypeSEH4ScopeTableRecord::read(rose_addr_t a) {
  address = a;
  size = 12;
  EnclosingLevel.read(a);
  FilterFunc.read(a + 4);
  HandleFunc.read(a + 8);
}

std::string TypeSEH4ScopeTableRecord::str() const {
  return boost::str(boost::format("<lvl=%s filter=%s handler=%s>") %
                    EnclosingLevel.str() % FilterFunc.str() % HandleFunc.str());
}

// This is defined in the Microsoft source code as:
void TypeSEH4ScopeTable::read(rose_addr_t a) {
  address = a;
  size = 16;
  GSCookieOffset.read(a);
  GSCookieXOROffset.read(a + 4);
  EHCookieOffset.read(a + 8);
  EHCookieXOROffset.read(a + 12);

  TypeSEH4ScopeTableRecord scope{memory};
  do {
    scope.read(a + size);
    ScopeRecord.push_back(scope);
    size += scope.size;
  } while ((int32_t)scope.EnclosingLevel.value != -2);
  // Negative two appears to be the magic value for EH4.
  // Negative one is reported to be the approprioate value for EH3.
}

std::string TypeSEH4ScopeTable::str() const {
  std::string base = boost::str(boost::format("<gsc=%s gscx=%s ehc=%s ehcx=%s>") %
                                GSCookieOffset.str() %
                                GSCookieXOROffset.str() %
                                EHCookieOffset.str() %
                                EHCookieXOROffset.str());
  base += "recs=[ ";
  for (const TypeSEH4ScopeTableRecord & scope : ScopeRecord) {
    base += scope.str();
  }
  base += " ]";
  return base;
}

void TypeSEH4TryBlockMapEntry::read(rose_addr_t a) {
  address = a;
  size = 20;
  tryLow.read(a);
  tryHigh.read(a + 4);
  catchHigh.read(a + 8);
  nCatches.read(a + 12);
  pHandlerArray.read(a + 16);

  //rose_addr_t handler_pointer = pHandlerArray.value;
  //for (int i = 0; i < maxState.value; i++) {
  //  TypeSEH4UnwindMapEntry entry(memory, unwind_map_pointer);
  //  unwind_map.push_back(entry);
  //  GINFO << entry.str() << LEND;
  //  unwind_map_pointer += entry.size;
  //}
}

std::string TypeSEH4TryBlockMapEntry::str() const {
  return boost::str(boost::format("<trylow=%s tryhigh=%s catchhigh=%s ncatches=%s handlers=%s>") %
                    tryLow.str() % tryHigh.str() % catchHigh.str() %
                    nCatches.str() % pHandlerArray.str());
}

void TypeSEH4HandlerType::read(rose_addr_t a) {
  adjectives.read(a);
  pType.read(a + 4);
  dispatchObj.read(a + 8);
  addressOfHandler.read(a + 12);
}

std::string TypeSEH4HandlerType::str() const {
  return boost::str(boost::format("<adj=%s type=%s obj=%s handler=%s>") %
                    adjectives.str() % pType.str() %
                    dispatchObj.str() % addressOfHandler.str());
}

void TypeSEH4UnwindMapEntry::read(rose_addr_t a) {
  address = a;
  size = 8;
  toState.read(a);
  action.read(a + 4);
}

std::string TypeSEH4UnwindMapEntry::str() const {
  return boost::str(boost::format("<tostate=%s action=%s>") % toState.str() % action.str());
}

// _s_FuncInfo
void TypeSEH4FuncInfo::read(rose_addr_t a) {
  address = a;
  size = 34;
  magicNumber.read(a);
  if (magicNumber.value < 0x19930520 || magicNumber.value > 0x19930522) {
    GERROR << "Invalid magic number for TypeSEH4FuncInfo magic=" << magicNumber.str() << LEND;
    // We should also be throwing an exception here...
    return;
  }

  maxState.read(a + 4);
  pUnwindMap.read(a + 8);
  rose_addr_t unwind_map_pointer = pUnwindMap.value;
  for (unsigned int i = 0; i < maxState.value; i++) {
    TypeSEH4UnwindMapEntry entry(memory, unwind_map_pointer);
    unwind_map.push_back(entry);
    unwind_map_pointer += entry.size;
  }

  nTryBlocks.read(a + 12);
  pTryBlocksMap.read(a + 16);

  rose_addr_t try_block_map_pointer = pTryBlocksMap.value;
  for (unsigned int i = 0; i < nTryBlocks.value; i++) {
    TypeSEH4TryBlockMapEntry entry(memory, try_block_map_pointer);
    try_block_map.push_back(entry);
    try_block_map_pointer += entry.size;
  }
  // Add contiguos block to memory map

  // These two fields are reportedly only used in x64.
  nIPMapEntries.read(a + 20);
  pIPtoStateMap.read(a + 24);
  if (magicNumber.value > 0x19930520) {
    pESTypeList.read(a + 28);
  }
  if (magicNumber.value > 0x19930521) {
    EHFlags.read(a + 32);
  }
}

std::string TypeSEH4FuncInfo::str() const {
  return boost::str(
    boost::format(
      "<magic=%s states=%s unwind=%s ntries=%s trymap=%s nip=%s ipm=%s estypes=%s flags=%s>") %
    magicNumber.str() %
    maxState.str() % pUnwindMap.str() %
    nTryBlocks.str() % pTryBlocksMap.str() %
    nIPMapEntries.str() % pIPtoStateMap.str() %
    pESTypeList.str() % EHFlags.str());
}

void TypeSEH4FuncInfo::dump() {
  GINFO << "SEH4FuncInfo @0x" << std::hex << address << std::dec << ": " << str() << LEND;
  for (const TypeSEH4UnwindMapEntry & entry : unwind_map) {
    GINFO << "  " << entry.str() << LEND;
  }
  for (const TypeSEH4TryBlockMapEntry & entry : try_block_map) {
    GINFO << "  " << entry.str() << LEND;
  }
}

void TypeRTCVarDesc::read(rose_addr_t a) {
  address = a;
  size = 12;
  var_offset.read(a);
  var_size.read(a + 4);
  var_name_addr.read(a + 8);

  var_name.read(var_name_addr.value);
}

std::string TypeRTCVarDesc::str() const {
  return boost::str(boost::format("<offset=%s size=%s name='%s'>") %
                    var_offset.str() % var_size.str() % var_name.str());
}

void TypeRTCFrameDesc::read(rose_addr_t a) {
  address = a;
  size = 8;
  varCount.read(a);
  variables.read(a + 4);

  rose_addr_t var_desc = variables.value;
  for (unsigned int i = 0; i < varCount.value; i++) {
    TypeRTCVarDesc var(memory, var_desc);
    vars.push_back(var);
    var_desc += var.size;
  }
}

std::string TypeRTCFrameDesc::str() const {
  return boost::str(boost::format("<count=%s>") % varCount.str());
}

void TypeRTCFrameDesc::dump() {
  GINFO << "RTCFrameDesc @0x" << std::hex << address << std::dec << ": " << str() << LEND;
  for (const TypeRTCVarDesc & var : vars) {
    GINFO << "  " << var.str() << LEND;
  }
}

void TypeRTTITypeDescriptor::read(rose_addr_t a) {
  address = a;
  pVFTable.read(a);
  spare.read(a + 4);
  name.read(a + 8);
  size = 8 + name.size;
}

std::string TypeRTTITypeDescriptor::str() const {
  return boost::str(boost::format("<vftable=%s name='%s'>") % pVFTable.str() % name.str());
}

void TypeRTTICompleteObjectLocator::read(rose_addr_t a) {
  address = a;
  size = 20;
  signature.read(a);
  offset.read(a + 4);
  cdOffset.read(a + 8);
  pTypeDescriptor.read(a + 12);
  pClassDescriptor.read(a + 16);

  type_desc.read(pTypeDescriptor.value);
  class_desc.read(pClassDescriptor.value);
}

std::string TypeRTTICompleteObjectLocator::str() const {
  return boost::str(boost::format("<sig=%s offset=%s cdo=%s type=%s class=%s>")
                    % signature.str() % offset.str() % cdOffset.str() %
                    pTypeDescriptor.str() % pClassDescriptor.str());
}

void TypeRTTICompleteObjectLocator::dump() {
  GINFO << "RTTI Object @0x" << std::hex << address << std::dec << ": " << str() << LEND;
  GINFO << "  Type: " << type_desc.str() << LEND;
  GINFO << "  Class: " << class_desc.str() << LEND;
  for (const TypeRTTIBaseClassDescriptor & bcd : class_desc.base_classes) {
    GINFO << "    Base Class: " << bcd.str() << LEND;
  }
}

void TypeRTTIClassHierarchyDescriptor::read(rose_addr_t a) {
  address = a;
  size = 16;
  signature.read(a);
  attributes.read(a + 4);
  numBaseClasses.read(a + 8);
  pBaseClassArray.read(a + 12);

  rose_addr_t base_class_array = pBaseClassArray.value;
  for (unsigned int i = 0; i < numBaseClasses.value; i++) {
    TypeDwordAddr bcaddr(memory, base_class_array);
    TypeRTTIBaseClassDescriptor bcd(memory, bcaddr.value);
    base_classes.push_back(bcd);
    base_class_array += bcaddr.size;
  }
}

std::string TypeRTTIClassHierarchyDescriptor::str() const {
  return boost::str(boost::format("<sig=%s attr=%s numbases=%s>") %
                    signature.str() % attributes.str() % numBaseClasses.str());
}

void TypeRTTIBaseClassArray::read(UNUSED rose_addr_t a) {
}

std::string TypeRTTIBaseClassArray::str() const {
  return boost::str(boost::format("<incomplete>"));
}

void TypeRTTIBaseClassDescriptor::read(rose_addr_t a) {
  address = a;
  size = 28;
  pTypeDescriptor.read(a);
  numContainedBases.read(a + 4);
  where_mdisp.read(a + 8);
  where_pdisp.read(a + 12);
  where_vdisp.read(a + 16);
  attributes.read(a + 20);
  pClassDescriptor.read(a + 24);

  type_desc.read(pTypeDescriptor.value);

  // This quickly turns into a recursive relationship, and could even be a cycle, so we'll need
  // to give some more thought to whether we ought to be doing this.  A visited list is
  // probably required, and we definitely don't want to store the whole tree inside each object
  // as we would do if this were a member variable instead of a discarded local.  I was trying
  // to read it here because I wanted it to throw if there's a problem during reading, but it
  // turns out that even normal files have endless loops.

  //TypeRTTIClassHierarchyDescriptor chd{memory};
  //chd.read(pClassDescriptor.value);
}

std::string TypeRTTIBaseClassDescriptor::str() const {
  return boost::str(boost::format("<type=%s numbase=%s pmd=(%s,%s,%s) attr=%s>") %
                    pTypeDescriptor.str() % numContainedBases.str() %
                    where_mdisp.str() % where_pdisp.str() % where_vdisp.str() %
                    attributes.str());
}

TypeAddr::TypeAddr(Memory const & mem): TypeBase(mem, 0, global_arch_bytes) { }

TypeAddr::TypeAddr(Memory const & mem, rose_addr_t a): TypeBase(mem, a, global_arch_bytes) {
  read();
}

rose_addr_t TypeAddr::read() {
  // Zero first, because on a 32-bit architecture the read only fills half of the value.
  value = 0;
  TypeBase::read(&value);
  return value;
}

int64_t TypeAddr::signed_value() const {
  return IntegerOps::signExtend2(value, 8 * size, 64);
}

std::string TypeAddr::str() const {
  return addr_str(value);
}

void TypeItaniumBaseTypeInfo::read(rose_addr_t a) {
  address = a;
  pTypeInfo.read(a);
  offset_flags.read(a + pTypeInfo.size);
  size = pTypeInfo.size + offset_flags.size;
}

void TypeItaniumBaseTypeInfo::read_single(rose_addr_t a) {
  address = a;
  pTypeInfo.read(a);
  size = pTypeInfo.size;

  // An __si_class_type_info has no offset_flags word, and does not need one: its base is
  // always public, non-virtual and at offset zero, which is the condition for the compiler to
  // have used the smaller record at all.  Fill in what an __vmi_class_type_info would have
  // spelled out, so that every base reads the same way.  The address is left at zero to show
  // that the value did not come from memory.
  offset_flags.address = 0;
  offset_flags.value = 0x2;
}

std::string TypeItaniumBaseTypeInfo::str() const {
  return boost::str(boost::format("<type=%s offset=%d%s%s>") %
                    pTypeInfo.str() % offset() %
                    (is_virtual() ? " virtual" : "") % (is_public() ? " public" : ""));
}

void TypeItaniumTypeInfo::read(rose_addr_t a, ItaniumTypeInfoKind k) {
  address = a;
  kind = k;
  base_classes.clear();

  pVTable.read(a);
  pName.read(a + pVTable.size);
  name.read(pName.value);
  size = pVTable.size + pName.size;

  switch (kind) {
    case ItaniumTypeInfoKind::Class:
      break;

    case ItaniumTypeInfoKind::SIClass: {
      TypeItaniumBaseTypeInfo base{memory};
      base.read_single(address + size);
      size += base.size;
      base_classes.push_back(base);
      break;
    }

    case ItaniumTypeInfoKind::VMIClass: {
      flags.read(address + size);
      numBaseClasses.read(address + size + flags.size);
      size += flags.size + numBaseClasses.size;

      // The caller is expected to have rejected an implausible count already, since reading
      // the array is what makes a wrong one expensive.
      for (unsigned int i = 0; i < numBaseClasses.value; i++) {
        TypeItaniumBaseTypeInfo base{memory, address + size};
        size += base.size;
        base_classes.push_back(base);
      }
      break;
    }
  }
}

std::string TypeItaniumTypeInfo::str() const {
  return boost::str(boost::format("<%s vtable=%s name='%s' bases=%d>") %
                    kind_str(kind) % pVTable.str() % name.str() % base_classes.size());
}

void TypeItaniumTypeInfo::dump() {
  GINFO << "Itanium Type Information @" << addr_str(address) << ": " << str() << LEND;
  for (const TypeItaniumBaseTypeInfo & base : base_classes) {
    GINFO << "  Base Class: " << base.str() << LEND;
  }
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
