// Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include <cxxabi.h>

#include <boost/range/adaptor/map.hpp>

#include "vftable.hpp"
#include "descriptors.hpp"

namespace pharos {

TypeRTTICompleteObjectLocatorPtr
read_msvc_rtti(const DescriptorSet& ds, rose_addr_t addr)
{
  try {
    rose_addr_t rptr = ds.memory.read_address(addr);
    TypeRTTICompleteObjectLocatorPtr rtti =
      std::make_shared<TypeRTTICompleteObjectLocator>(ds.memory, rptr);
    if (rtti && rtti->signature.value == 0 && rtti->class_desc.signature.value == 0) {
      return rtti;
    }
  }
  catch (...) {
    GDEBUG << "RTTI was bad at " << addr_str(addr) << LEND;
  }

  return nullptr;
}

// No object is this large, and no subobject begins this far into one.  Only here to keep a
// word that happens to hold a huge number from reading as a plausible offset.
constexpr int64_t max_object_size = 1 << 24;
// A class with more direct base classes than this is not something a compiler emitted.
constexpr uint32_t max_base_classes = 256;
// A mangled name longer than this is a runaway read rather than a name.
constexpr size_t max_name_length = 4096;

// The type_info vtables of the three __cxxabiv1 classes that describe a class type.  The
// number in each name is the length of the class name that follows it, which is how the
// Itanium ABI mangles a nested name.
static const std::pair<const char *, ItaniumTypeInfoKind> abi_vtables[] = {
  {"_ZTVN10__cxxabiv117__class_type_infoE",     ItaniumTypeInfoKind::Class},
  {"_ZTVN10__cxxabiv120__si_class_type_infoE",  ItaniumTypeInfoKind::SIClass},
  {"_ZTVN10__cxxabiv121__vmi_class_type_infoE", ItaniumTypeInfoKind::VMIClass},
};

std::string demangle_itanium_type(std::string const & name) {
  // __cxa_demangle takes a type mangling as readily as a symbol, which is what makes the
  // typeid(x).name() idiom work, and a type mangling is what a name field holds.
  int status = 0;
  auto free_char = [](char *v) { std::free(v); };
  std::unique_ptr<char, decltype(free_char)> demangled(
    abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status), free_char);
  if (status != 0 || !demangled) return std::string();
  return std::string(demangled.get());
}

ItaniumTypeInfoFinder::ItaniumTypeInfoFinder(const DescriptorSet& ds_)
  : ds(ds_), arch_bytes(ds_.get_arch_bytes())
{
  find_abi_vtables();
}

// A file that instantiates a class of its own defines the type_info vtables, and so does one
// that gets them from libstdc++ through a copy relocation, since the copy is made into the
// file's own memory and the symbol names where.  Either way the vtable word of a record holds
// the vtable's address point, which is two pointers past the symbol.
void ItaniumTypeInfoFinder::find_abi_vtables() {
  for (auto const & abi_vtable : abi_vtables) {
    if (auto symbol = ds.get_symbol_address(abi_vtable.first)) {
      vtable_kinds[*symbol + 2 * arch_bytes] = abi_vtable.second;
      GDEBUG << "Found " << abi_vtable.first << " at " << addr_str(*symbol) << LEND;
    }
  }
}

bool ItaniumTypeInfoFinder::is_name(rose_addr_t addr) const {
  if (addr == 0 || !ds.memory.is_mapped(addr)) return false;

  // Bounded, unlike the read that TypeString does, because this is the test that decides
  // whether there is a name here at all.
  std::string chars = ds.memory.read_string(addr, Bytes(max_name_length));
  size_t end = chars.find('\0');
  if (end == std::string::npos || end == 0) return false;
  chars.resize(end);

  // A mangled type name is built from the characters of the Itanium ABI's mangling grammar,
  // and starts with the length of a name, the 'N' of a nested one, or the letter of a builtin
  // type.  A leading '*' marks a type compared by address rather than by name.
  size_t start = chars[0] == '*' ? 1 : 0;
  if (start == chars.size()) return false;
  if (!std::isalnum(static_cast<unsigned char>(chars[start]))) return false;
  return std::all_of(chars.begin() + start, chars.end(), [](char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' || c == '$';
  });
}

bool ItaniumTypeInfoFinder::reads_as_vmi(rose_addr_t addr) const {
  uint32_t words[2];
  if (ds.memory.read_bytes(addr, words, Bytes(sizeof(words))) != sizeof(words)) return false;
  uint32_t flags = words[0];
  uint32_t base_count = words[1];

  // Only four flag bits are defined, and a record with no base classes would not have been
  // emitted as a vmi in the first place.  Two pointers do not read this way, which is what
  // makes this test worth anything.
  if (flags > 0xf) return false;
  if (base_count == 0 || base_count > max_base_classes) return false;

  rose_addr_t base = addr + 2 * sizeof(uint32_t);
  for (uint32_t i = 0; i < base_count; i++) {
    if (!ds.memory.is_mapped(base) || !ds.memory.is_mapped(base + arch_bytes)) return false;

    // The base's own record.  Its vtable word may well be an unresolved relocation, so the
    // name is the only part worth testing.
    rose_addr_t typeinfo = ds.memory.read_address(base, Bytes(arch_bytes));
    if (typeinfo != 0
        && !is_name(ds.memory.read_address(typeinfo + arch_bytes, Bytes(arch_bytes)))) {
      return false;
    }

    // Sign extend into a signed type before shifting.  A virtual base's offset is negative,
    // and shifting it as an unsigned value turns it into an enormous positive one.
    int64_t offset_flags = IntegerOps::signExtend2(
      ds.memory.read_address(base + arch_bytes, Bytes(arch_bytes)), 8 * arch_bytes, 64);
    int64_t offset = offset_flags >> 8;
    if (offset > max_object_size || offset < -max_object_size) return false;

    base += 2 * arch_bytes;
  }

  return true;
}

ItaniumTypeInfoKind ItaniumTypeInfoFinder::classify(rose_addr_t addr, rose_addr_t vptr) {
  // The relocation that writes the record's vtable word, which names the __cxxabiv1 class
  // outright.  This is the only evidence available in a binary that gets the class from
  // libstdc++, where the word itself reads as zero.
  if (auto symbol = ds.get_reloc_symbol(addr)) {
    for (auto const & abi_vtable : abi_vtables) {
      // A substring test, because the name may carry a version suffix.
      if (symbol->find(abi_vtable.first) != std::string::npos) return abi_vtable.second;
    }
  }

  auto known = vtable_kinds.find(vptr);
  if (known != vtable_kinds.end()) return known->second;

  // Nothing named it, so the shape decides.  The vmi test goes first because it is the one
  // that cannot be fooled by an adjacent record.
  ItaniumTypeInfoKind kind = ItaniumTypeInfoKind::Class;
  rose_addr_t rest = addr + 2 * arch_bytes;
  if (reads_as_vmi(rest)) {
    kind = ItaniumTypeInfoKind::VMIClass;
  }
  else if (ds.memory.is_mapped(rest)) {
    rose_addr_t base = ds.memory.read_address(rest, Bytes(arch_bytes));
    if (base != 0 && base != addr
        && is_name(ds.memory.read_address(base + arch_bytes, Bytes(arch_bytes)))) {
      kind = ItaniumTypeInfoKind::SIClass;
    }
  }

  // Only worth remembering when the vtable word holds a real value.  It reads as zero for
  // every unresolved record in the program regardless of kind.
  if (vptr != 0) vtable_kinds[vptr] = kind;
  return kind;
}

const TypeItaniumTypeInfo* ItaniumTypeInfoFinder::read(rose_addr_t addr) {
  auto existing = records.find(addr);
  if (existing != records.end()) return &existing->second;
  if (rejected.find(addr) != rejected.end()) return nullptr;

  // A record begins with its vtable word and the pointer to its name.  The vtable word is not
  // required to be a usable pointer, since it is a relocation against libstdc++ in most
  // binaries, but the name has to be there: it is what makes this a type information record
  // rather than any two words of data.
  if (addr == 0 || !ds.memory.is_mapped(addr) || !ds.memory.is_mapped(addr + arch_bytes)
      || !is_name(ds.memory.read_address(addr + arch_bytes, Bytes(arch_bytes))))
  {
    rejected.insert(addr);
    return nullptr;
  }

  rose_addr_t vptr = ds.memory.read_address(addr, Bytes(arch_bytes));
  ItaniumTypeInfoKind kind = classify(addr, vptr);

  // Reading the base class array is what makes a wrong count expensive, so check it before
  // the record is read rather than inside it.
  if (kind == ItaniumTypeInfoKind::VMIClass && !reads_as_vmi(addr + 2 * arch_bytes)) {
    rejected.insert(addr);
    return nullptr;
  }

  TypeItaniumTypeInfo ti{ds.memory};
  try {
    ti.read(addr, kind);
  }
  catch (...) {
    GDEBUG << "Itanium type information was bad at " << addr_str(addr) << LEND;
    rejected.insert(addr);
    return nullptr;
  }

  GDEBUG << "Found Itanium type information at " << addr_str(addr) << ": " << ti.str() << LEND;

  // Insert before recursing, so that a record reaching itself through a malformed base class
  // pointer terminates.
  const TypeItaniumTypeInfo* result = &records.emplace(addr, std::move(ti)).first->second;
  for (const TypeItaniumBaseTypeInfo & base : result->base_classes) {
    read(base.pTypeInfo.value);
  }

  return result;
}

// The two words below an address point are the offset-to-top of the subobject the table serves
// and the pointer to the type information of its class.  Recognizing the pair is what tells the
// walk of the preceding table that it has reached the next component of the group.
bool ItaniumTypeInfoFinder::is_address_point_header(rose_addr_t addr) {
  if (!ds.memory.is_mapped(addr) || !ds.memory.is_mapped(addr + arch_bytes)) return false;

  // Zero for a primary table, and negative for a secondary one, since the subobject it serves
  // begins somewhere after the top of the object.  Sign extend before comparing, or every
  // secondary table in a 32-bit binary reads as a large positive number.
  int64_t offset_to_top = IntegerOps::signExtend2(
    ds.memory.read_address(addr, Bytes(arch_bytes)), 8 * arch_bytes, 64);
  if (offset_to_top > 0 || offset_to_top < -max_object_size) return false;

  return read(ds.memory.read_address(addr + arch_bytes, Bytes(arch_bytes))) != nullptr;
}

VirtualTableInstallation::VirtualTableInstallation(
  SgAsmInstruction* i, FunctionDescriptor const * f, rose_addr_t a,
  TreeNodePtr w, int64_t o, TreeNodePtr pe, bool b) {
  insn = i;
  fd = f;
  table_address = a;
  written_to = w;
  offset = o;
  expanded_ptr = pe;
  base_table = b;
}

bool VirtualBaseTable::analyze() {
  // Set the size to zero to indicate that we're not a valid virtual base table.
  size = 0;

  // If we don't have a vbtable address yet, there's nothing to analyze.
  if (addr == 0) return false;

  size_t arch_bytes = ds.get_arch_bytes();

  while (true) {
    // Get the address of an entry in table.
    rose_addr_t taddr = addr + (size * arch_bytes);

    // If the table itself has passed into invalid memory, then this is our last entry.
    if (!ds.memory.is_mapped(taddr)) {
      GWARN << "Failed to read invalid virtual base table address " << addr_str(addr) << LEND;
      break;
    }

    // Read the function pointer in that memory location.
    rose_addr_t fptr = ds.memory.read_address(taddr);

    // GDEBUG << "Read possible virtual base table entry " << size << " at " << addr_str(taddr)
    //       << " with value " << addr_str(fptr) << LEND;

    // If the value point to a valid image addreses, then this entry is NOT a valid virtual
    // base table entry.  Unless coincidentally the object is so large that progam image
    // addresses are also valid object offsets, which is very unlikely.
    if (ds.memory.is_mapped(fptr)) break;

    // This is hackish and ugly, but it eliminates a lot of cases (including strings) by
    // requiring that the high byte be FF or 00 (rather than an ASCII character for example).
    int64_t signed_val = (int64_t)fptr;
    if (signed_val < -16000000 || signed_val > 16000000) {
      //GDEBUG << "Rejected possible virtual base pointer entry based on object size." << LEND;
      break;
    }

    // Unlike virtual function tables which are very likely to run into a non-pointer, we could
    // reads lots of non-pointers before failing, and virtual inheritance heirarchies are
    // rarely this deep, so it probably makes more sense to just fail early.
    if (size >= 9) break;

    // Advance to the next entry.
    size++;
  }

  GDEBUG << "Virtual base table " << addr_str(addr) << " has " << size << " valid entries." << LEND;
  return valid();
}

void VirtualBaseTable::analyze_overlaps(const VFTableAddrMap& vftables, const VBTableAddrMap& vbtables) {
  unsigned int limit;
  size_t arch_bytes = ds.get_arch_bytes();
  for (auto const & vft : boost::adaptors::values(vftables)) {
    if (vft->addr > addr) {
      // Don't bound ourselves by other vftables if we know that they are invalid.
      if (!vft->has_entries) continue;

      if (vft->msvc_rtti != NULL) {
        limit = ((vft->addr - 4) - addr) / arch_bytes;
      }
      else {
        limit = (vft->addr - addr) / arch_bytes;
      }

      if (limit < size) {
        //GDEBUG << "Reducing size of vbtable " << addr_str(addr) << " to " << limit
        //       << " because it overlaps with vftable " << addr_str(vft->addr) << LEND;
        size = limit;
      }
    }
  }

  for (auto const & vbt : boost::adaptors::values(vbtables)) {
    if (vbt->addr > addr) {
      // Don't bound ourselves by other vbtables if we know that they are invalid.
      if (vbt->size < 2) continue;

      limit = (vbt->addr - addr) / arch_bytes;
      if (limit < size) {
        //GDEBUG << "Reducing size of vbtable " << addr_str(addr) << " to " << limit
        //       << " because it overlaps with vbtable " << addr_str(vbt->addr) << LEND;
        size = limit;
      }
    }
  }
}

signed int VirtualBaseTable::read_entry(unsigned int entry) const {
  // Get the address of an entry in table.
  size_t arch_bytes = ds.get_arch_bytes();
  rose_addr_t taddr = addr + (entry * arch_bytes);
  // Read the function address value in that memory location...
  rose_addr_t object_offset = ds.memory.read_address(taddr);
  return (signed int)object_offset;
}

bool VirtualBaseTable::valid() const {
  if (size > 1) {
    return true;
  }
  return false;
}

bool VirtualFunctionTable::valid() const {
  // The address can only truly be a virtual function table if it passes some basic tests,
  // such as having at least one function pointer.
  if (!has_entries) {
    // If there were no pointer at all, just reject the table outright.
    if (non_function == 0) {
      GDEBUG << "Possible virtual function table at " << addr_str(addr)
             << " rejected because no valid pointers were found." << LEND;
      return false;
    }
  }
  return true;
}

// Cory's not convinced that a "map" is the right data structure to store the mapping.  It
// seems like it would be better for this to be more dynamic at a very slight performance
// loss for reading the memory image each time.
rose_addr_t VirtualFunctionTable::read_entry(unsigned int entry) const {
  // Get the address of an entry in table.
  size_t arch_bytes = ds.get_arch_bytes();
  rose_addr_t taddr = addr + (entry * arch_bytes);
  // Read the function address value in that memory location...
  rose_addr_t fptr = ds.memory.read_address(taddr);
  return fptr;
}

// Look for RTTI structures, which should be situated directly above the vtable start
void VirtualFunctionTable::analyze_msvc_rtti(const rose_addr_t address) {
  msvc_rtti = read_msvc_rtti(ds, address);
  if (msvc_rtti) {
    GINFO << "RTTI was found at " << addr_str(address)
          << " with a class name: " << msvc_rtti->type_desc.name.value << LEND;
    // checking the signatures is not a proven method
    msvc_rtti_confidence = ConfidenceGuess;
  }
}

// The Itanium ABI puts the same information in a different place: the word above the table
// points at the class' type information record, and the word above that is the offset-to-top.
// Unlike the MSVC case there is no signature to check, so the record parsing is what decides
// whether this really is RTTI.  The pointer is zero in a binary built with -fno-rtti, which is
// legal and leaves the header in place.
void VirtualFunctionTable::analyze_itanium_rtti(ItaniumTypeInfoFinder& typeinfo) {
  size_t arch_bytes = ds.get_arch_bytes();
  if (!ds.memory.is_mapped(msvc_rtti_addr)) return;

  itanium_rtti = typeinfo.read(ds.memory.read_address(msvc_rtti_addr, Bytes(arch_bytes)));
  if (!itanium_rtti) return;

  rose_addr_t offset_addr = addr - 2 * arch_bytes;
  if (ds.memory.is_mapped(offset_addr)) {
    offset_to_top = IntegerOps::signExtend2(
      ds.memory.read_address(offset_addr, Bytes(arch_bytes)), 8 * arch_bytes, 64);
  }

  GINFO << "Itanium RTTI was found at " << addr_str(itanium_rtti->address)
        << " for the table at " << addr_str(addr) << " with a class name: "
        << itanium_rtti->name.value << LEND;
}

// This method updates the fields describing the virtual function table based on analyzing
// the contents of the memory at the address of the table.
bool VirtualFunctionTable::analyze(VFTableAddrMap& vftables, ItaniumTypeInfoFinder& typeinfo) {
  unsigned int failures = 0;
  unsigned int entry = 0;

  // If we don't have a vtable address yet, there's nothing to analyze.
  if (addr == 0) return false;

  // Before determining the size of the vftable, check to see if there is RTTI associated with
  // it.  The RTTI pointer will be located immediately before the table, and because it's a
  // pointer, its size varies with the architecture.  Both ABIs put it there.
  size_t arch_bytes = ds.get_arch_bytes();
  msvc_rtti_addr = addr - arch_bytes;
  if (ds.is_itanium_abi()) {
    analyze_itanium_rtti(typeinfo);
  }
  else {
    analyze_msvc_rtti(msvc_rtti_addr);
  }

  while (true) {
    // Perhaps we should call read_entry() here, but we need taddr as well...

    // Get the address of an entry in table.
    rose_addr_t taddr = addr + (entry * arch_bytes);

    // If the address is not legit, there's no way we're reading a valid function pointer
    // from it. (I think...  Is this dependent on faulty memory mapping logic?
    if (!ds.memory.is_mapped(taddr)) {
      GERROR << "Failed to read invalid virtual function table address " << addr_str(taddr) << LEND;
      // There is no virtual function table if the address is invalid.
      break;
    }

    // The next component of an Itanium vtable group announces itself with the two word header
    // below its own address point, and a header is never an entry of the table before it.
    // This is an exact answer where the tolerance below is only a guess, and it matters most
    // for the zeroed destructor slots of a construction vtable, which the tolerance cannot
    // tell from the end of the table.
    if (entry != 0 && ds.is_itanium_abi() && typeinfo.is_address_point_header(taddr)) {
      break;
    }

    // Read the function pointer in that memory location.
    rose_addr_t fptr = ds.memory.read_address(taddr);

    // The first case is that we read a NULL pointer, although it could be a memory mapping
    // error as mentioned above.  Perhaps we should change the API for read_addr to make this
    // clearer?
    if (fptr == 0) {
      // Under the Itanium ABI a NULL is not the end of the table.  A construction vtable has
      // zeroed destructor slots, because a base-object destructor is never dispatched virtually
      // while the base subobject is under construction, and the ABI orders virtual functions by
      // declaration, so those slots can sit anywhere in the table.  Without this a construction
      // vtable would be rejected outright rather than merely mismeasured.  Treat the slot as a
      // miss instead; the tolerance below still ends a run of them.  They deliberately do not
      // count towards non_function, so that a region of nothing but zeros still fails valid().
      if (ds.is_itanium_abi()) {
        entry++;
        failures++;
        if (failures >= 3) break;
        continue;
      }

      // Reading a NULL value is expected, just so long as it's not the first entry.
      if (entry == 0) {
        GTRACE << "Read NULL function pointer in first entry of vftable at "
               << addr_str(taddr) << LEND;
      }

      // Regardless, we're at the end of the virtual function table.
      break;
    }

    // The second case is that the address of the entry in the table was a valid address, but
    // that the virtual function pointer points to an invalid address.
    if (!ds.memory.is_mapped(fptr)) {
      // Cory says: In our test programs, this dword is routinely 0x20646162 " @ab" or
      // 0x6e6b6e55 "nknU".  I had hoped this would lead to a useful heuristic, but Jeff
      // G. seems to think it's just coincidence.
      GTRACE << "Virtual function pointer is invalid at "
             << addr_str(taddr) << ", points to " << addr_str(fptr) << LEND;
      // An invalid function pointer always marks the end of a vitrual function table
      // unless we're having serious memory mapping problems.

      break;
    }

    // It's pretty common to find RTTI complete object locators in the
    //OINFO << "Looking for RTTI at " << addr_str(taddr) << LEND;
    // There are none under the Itanium ABI, where the equivalent split between adjacent
    // components of a vtable group is made by the header test above.
    TypeRTTICompleteObjectLocatorPtr embedded_rtti =
      ds.is_itanium_abi() ? nullptr : read_msvc_rtti(ds, taddr);
    // If it is, then there's most likely a VFTable just pass that, and we should probably
    // analyze that table (even though we haven't found any other references to it yet).
    // This will prevent us from assigning functions found in the later VFTable to this
    // VFTable incorrectly.
    if (embedded_rtti) {
      //OINFO << "Found an embedded RTTI at " << addr_str(taddr) << LEND;
      // The address of the next VFTable is right after the RTTI pointer.
      rose_addr_t next_taddr = taddr + arch_bytes;
      // Have we already processsed this vftable?  If so, don't do it again.
      if (vftables.find(next_taddr) == vftables.end()) {
        // Create a new table, analyze it, and then add it to the global map.
        auto next_vftable = make_unique<VirtualFunctionTable>(ds, taddr + arch_bytes);
        // This call could be recursive, but it's not obvious that's a problem.
        next_vftable->analyze(vftables, typeinfo);
        //OINFO << "Found an new VFTable at " << addr_str(next_taddr)
        //      << " with " << next_vftable->non_function << " non-functions." << LEND;
        vftables[next_taddr] = std::move(next_vftable);
      }
      // An RTTI data structure is never a valid entry in a VFTable.
      break;
    }

    // Advance to the next entry in the table.  We're going to keep trying unles the number of
    // failures becomes too great, and if it has, we want entry to already be incremented.
    entry++;

    bool valid_entry = false;

    // If the address found points to a known function, that's a valid entry.
    if (ds.get_func(fptr) != NULL) valid_entry = true;
    // If the address found points to an import, that's also a valid entry.
    if (ds.get_import(fptr) != NULL) valid_entry = true;

    // The pointer is a pointer to a function that we recognize.
    if (valid_entry) {
      // A success resets the failure counter.  Cory's theory here is that we might
      // occasionally miss a function or two, but we're less likely to miss several in a row.
      // Further, a bad table pointer is going to point to way more than a few bad function
      // pointers (nearly all fptrs should fail the test).
      failures = 0;

      // A little debugging to report our success...
      GDEBUG << "Validated virtual function at " << addr_str(taddr)
             << " points to function at " << addr_str(fptr) << LEND;

    }
    // It's unclear if our disassembly is accurate enough currently to require this for every
    // entry.  For right now, we're going to only going to break after several adjacent
    // failures.
    else {
      // Report every entry that we do not recognize as a function.  This is mildly useful to
      // the end-user since as part of the OOAnalyzer output, but I'm not sure it's a warning,
      // because it's a common side effect of partitioning failures, and OOAnalyzer should cope
      // with the condition acceptably.
      GINFO << "Virtual function table at " << addr_str(addr) << " entry " << entry
            << ", has a non-function pointer " << addr_str(fptr)
            << " at address " << addr_str(taddr) << LEND;

      // Record that we found a valid pointer, but that it was not recognized as a function.
      non_function++;
      // Also increase the "failure" count, which is a temporary version of non_function.
      failures++;
      // More than three failures in adjacent addresses probably means we should give up.

      if (failures >= 3) {
        break;
      }
    }
  }

  // At this point we've finished walking through memory for one of several reasons.  How many
  // entries the table really has is not decided here -- OOSolver works that out when it exports
  // the entries, because that is the only place that needs an answer.  All we record is whether
  // the walk got as far as a single entry, which is the question the virtual base table trimmer
  // asks.  Trailing failures do not count, since there's no reason to believe they're legitimate.
  unsigned int msize = entry - failures;
  has_entries = (msize > 0);

  if (!has_entries) {
    GTRACE << "Virtual function table at " << addr_str(addr)
           << " failed to validate at least one function pointer." << LEND;
  }
  else {
    GINFO << "Virtual function table at " << addr_str(addr) << " has at most "
          << msize << " entries." << LEND;
    GINFO << "The entries are:";
    for (unsigned int x = 0; x < msize; x++) GINFO << " " << addr_str(read_entry(x));
    GINFO << LEND;
  }

  return valid();
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
