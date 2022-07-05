// Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/range/adaptor/map.hpp>

#include "vftable.hpp"
#include "descriptors.hpp"
#include "oovftable.hpp" // For the new read_RTTI

namespace pharos {


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
      if (vft->best_size < 1) continue;

      if (vft->rtti != NULL) {
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
  if (max_size < 1) {
    // If there were no pointer at all, just reject the table outright.
    if (non_function == 0) {
      GDEBUG << "Possible virtual function table at " << addr_str(addr)
             << " rejected because no valid pointers were found." << LEND;
      return false;
    }
  }
  return true;
}

// This method updates the minimum size of the vtable based on new information (typically a
// known virtual function call using the table).  This value always grows, because we're
// supposed to be making sound assertions about the minimum size.
void VirtualFunctionTable::update_minimum_size(size_t new_size) {
  if (new_size > max_size && max_size != 0) {
    GERROR << "Confusion about the minimum size of vtable at " << addr_str(addr)
           << ", " << new_size << ">" << max_size << LEND;
  }
  else if (min_size < new_size) min_size = new_size;
}

// This method updates the maximum size of the vtable based on new information (typically by
// walking the memory of the vtable looking for valid function pointers).  This value always
// shrinks, because we're supposed to be making sound assertions about the maximum size.
void VirtualFunctionTable::update_maximum_size(size_t new_size) {
  if (new_size < min_size) {
    GERROR << "Confusion about the maximum size of vtable at " << addr_str(addr)
           << ", " << new_size << "<" << min_size << LEND;
  }
  else if (max_size == 0 || max_size > new_size) max_size = new_size;
}

// directly update the best size
void VirtualFunctionTable::update_best_size(size_t besty) {
  best_size = besty;
}

// Take a "guess" at the correct vtable size, and update our confidence appropriately.
void VirtualFunctionTable::update_size_guess() {

  // if the confidence is set by the user, then trust it. Currently, this will only happen when
  // applying the RTTI structures *appears* to make sense.
  if (size_confidence == ConfidenceUser) {
    return;
  }
  // Cory's not sure what the correct logic is here, but this seems like a reasonable first
  // attempt.  If the minimum and maximum match, I figure we're pretty confident.
  if (min_size == max_size && min_size != 0) {
    best_size = min_size;
    size_confidence = ConfidenceConfident;
  }
  // Otherwise use the maximum possible value, and set the confidence to "Guess".
  else {
    best_size = max_size;
    size_confidence = ConfidenceGuess;
  }
  // There are probably some other heuristics to use here, but this is a start.  In
  // particular, the complete lack of code to increase the minimum beyond one will ensure
  // that only the second heuristic has any significance currently.
}

// Cory's not convinced that a "map" is the right data structure to store the mapping.  It
// seems like it would be better for this to be more dynamic at a very slight performance
// loss for reading the memory image each time.  Thus I propose the following (currently
// unused) interface:
rose_addr_t VirtualFunctionTable::read_entry(unsigned int entry) const {
  // Get the address of an entry in table.
  size_t arch_bytes = ds.get_arch_bytes();
  rose_addr_t taddr = addr + (entry * arch_bytes);
  // Read the function address value in that memory location...
  rose_addr_t fptr = ds.memory.read_address(taddr);
  return fptr;
}

// A convenience version of the above interface when you expect a fully valid function
// descriptor object pointer.
const FunctionDescriptor * VirtualFunctionTable::read_entry_fd(unsigned int entry) const {
  rose_addr_t fptr = read_entry(entry);
  return ds.get_func(fptr);
}

// Look for RTTI structures, which should be situated directly above the vtable start
void VirtualFunctionTable::analyze_rtti(const rose_addr_t address) {
  rtti = read_RTTI(ds, address);
  if (rtti) {
    GINFO << "RTTI was found at " << addr_str(address)
          << " with a class name: " << rtti->type_desc.name.value << LEND;
    // checking the signatures is not a proven method
    rtti_confidence = ConfidenceGuess;
  }
}

// This method updates the fields describing the virtual function table based on analyzing
// the contents of the memory at the address of the table.
bool VirtualFunctionTable::analyze(VFTableAddrMap& vftables) {
  unsigned int failures = 0;
  unsigned int entry = 0;

  // If we don't have a vtable address yet, there's nothing to analyze.
  if (addr == 0) return false;

  // Before determining the size of the vftable, check to see if there is RTTI associated with
  // it.  The RTTI pointer will be located immediately before the table, and because it's a
  // pointer, its size varies with the architecture.
  size_t arch_bytes = ds.get_arch_bytes();
  rtti_addr = addr - arch_bytes;
  analyze_rtti(rtti_addr);

  while (true) {
    // Perhaps we should call read_entry() here, but we need taddr as well...

    // Get the address of an entry in table.
    rose_addr_t taddr = addr + (entry * arch_bytes);

    // If the address is not legit, there's no way we're reading a valid function pointer
    // from it. (I think...  Is this dependent on faulty memory mapping logic?
    if (!ds.memory.is_mapped(taddr)) {
      GERROR << "Failed to read invalid virtual function table address " << addr_str(taddr) << LEND;
      // There is no virtual function table if the address is invalid.
      // Reinforce this by setting size confidence to wrong.
      size_confidence = ConfidenceWrong;
      break;
    }

    // Read the function pointer in that memory location.
    rose_addr_t fptr = ds.memory.read_address(taddr);

    // The first case is that we read a NULL pointer, although it could be a memory mapping
    // error as mentioned above.  Perhaps we should change the API for read_addr to make this
    // clearer?
    if (fptr == 0) {
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
    TypeRTTICompleteObjectLocatorPtr embedded_rtti = read_RTTI(ds, taddr);
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
        next_vftable->analyze(vftables);
        //OINFO << "Found an new VFTable at " << addr_str(next_taddr)
        //      << " with " << next_vftable->best_size << " entries." << LEND;
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

      // As a special case, finding a valid function pointer at entry zero confirms that we
      // are in fact a virtual function table, and moves our minimum size to one.  The same
      // cannot be said for finding entries at entry greater than zero because they might
      // not be part of THIS virtual function table, but instead an adjacent one.
      if (entry == 0) {
        update_minimum_size(1);
      }

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

  // At this point, we've finished walking through memory for one of several reasons.  We
  // should attempt to update the size limits on the table based on what we've learned.

  // The maximum size can't possibly be more than the current offset, but we also ought to
  // subtract any trailing failures, since there's no reason to believe that they're
  // legitimate.
  unsigned int msize = entry - failures;

  if (msize < 1) {
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

  // Avoid passing ridiculously small values of maximum, since that won't help anybody.
  if (msize > 0) {
    update_maximum_size(msize);

    // If we've got a reasonable maximum, we should also use that to update our best guess.
    update_size_guess();
  }

  return valid();
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
