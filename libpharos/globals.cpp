// Copyright 2015-2019, 2021 Carnegie Mellon University.  See LICENSE file for terms.

#include "globals.hpp"
#include "masm.hpp"
#include "descriptors.hpp"
#include "datatypes.hpp"
#include "util.hpp"
#include "types.hpp"
#include "typedb.hpp"

namespace pharos {

GlobalMemoryDescriptor::GlobalMemoryDescriptor(rose_addr_t addr, size_t bits) {
  address = addr;
  confidence = ConfidenceNone;
  type = DTypeNone;
  size = 0;
  access_size = 0;

  memory_address = SymbolicValue::constant_instance(bits, addr);
  values.push_back(SymbolicValue::variable_instance(bits));
}

std::string
GlobalMemoryDescriptor::to_string() const {
  std::stringstream ostr;

  ostr << "Global variable at " << address_string();
  if (memory_address) {
    TreeNodePtr global_addr_tnp = memory_address->get_expression();
    if (global_addr_tnp) {

      // TODO: This is useful for this when done debugging
      int64_t addr_raw = reinterpret_cast<int64_t>(&*global_addr_tnp);
      ostr << ", " << "raw=(" << addr_str(addr_raw) << ")";

      TypeDescriptorPtr addr_td = fetch_type_descriptor(global_addr_tnp);
      ostr << " addr=" << *global_addr_tnp << " addr td=(" << addr_td->to_string() << ")";
    }
    else {
      ostr << " address=(invalid)";
    }
  }

  auto global_values = values;
  if (global_values.empty() == false) {

    size_t i = 0;
    ostr << " values=({";

    for (auto gv : global_values) {
      TreeNodePtr val_tnp = gv->get_expression();
      if (val_tnp) {
        ostr << "(exp=(" << *val_tnp << ")";
      }
      else {
        ostr << "<unknown>";
      }
      TypeDescriptorPtr global_value_tdp = fetch_type_descriptor(gv);
      ostr << " td=";
      if (global_value_tdp) {
        ostr << "(" << global_value_tdp->to_string() << ")";
      }
      else {
        ostr << "<unknown>";
      }
      ostr << ")";

      if (i+1 < global_values.size())  ostr << ", ";

      ++i;
    }
    ostr << "})";
  }
  else {
    std::cout << " values=(invalid)";
  }
  return ostr.str();
}

void GlobalMemoryDescriptor::add_value(SymbolicValuePtr new_val) {
  write_guard<decltype(mutex)> guard{mutex};

  // We should probably implement a std::set<SymbolicValuePtr> under some comparison operation
  // that used to be can_be_equal(), and is now must_be_equal().
  auto gvi = std::find_if(
    values.begin(), values.end(),
    [new_val](SymbolicValuePtr sv)
    {
      if (sv->get_width() != new_val->get_width()) return false;
      return sv->mustEqual(new_val);
    });

  if (gvi == values.end()) {
    values.push_back(new_val);
  }
}

void GlobalMemoryDescriptor::short_print(std::ostream &o) const {
  read_guard<decltype(mutex)> guard{mutex};

  o << "Global: addr=" << address_string()
    << " asize=" << access_size << " tsize=" << size;

  o << " refs=[";
  for (const SgAsmInstruction* insn : refs) {
    o << boost::str(boost::format(" 0x%08X") % insn->get_address());
  }
  o << " ]";

  o << " reads=[";
  for (const SgAsmInstruction* insn : reads) {
    o << boost::str(boost::format(" 0x%08X") % insn->get_address());
  }
  o << " ]";

  o << " writes=[";
  for (const SgAsmInstruction* insn : writes) {
    o << boost::str(boost::format(" 0x%08X") % insn->get_address());
  }
  o << " ]";
}

void GlobalMemoryDescriptor::print(std::ostream &o) const {
  read_guard<decltype(mutex)> guard{mutex};

  o << "Global: addr=" << address_string()
    << " asize=" << access_size << " tsize=" << size << LEND;

  for (const SgAsmInstruction* insn : refs) {
    o << "   Ref: " << debug_instruction(insn) << LEND;
  }
  for (const SgAsmInstruction* insn : reads) {
    o << "  Read: " << debug_instruction(insn) << LEND;
  }
  for (const SgAsmInstruction* insn : writes) {
    o << " Write: " << debug_instruction(insn) << LEND;
  }
}

// Are all known memory accesses reads?
bool GlobalMemoryDescriptor::read_only() const {
  read_guard<decltype(mutex)> guard{mutex};
  if (writes.size() == 0 && reads.size() > 0) return true;
  return false;
}

// Are there both read and write memory accesses?
bool GlobalMemoryDescriptor::read_write() const {
  read_guard<decltype(mutex)> guard{mutex};
  if (writes.size() > 0 && reads.size() > 0) return true;
  return false;
}

// Is the descriptor known to be used in memory accesses?
bool GlobalMemoryDescriptor::known_memory() const {
  read_guard<decltype(mutex)> guard{mutex};
  if (writes.size() > 0 || reads.size() > 0) return true;
  return false;
}

// Is the descriptor "suspicious"?  (One of several unlikely cases?)
bool GlobalMemoryDescriptor::suspicious() const {
  read_guard<decltype(mutex)> guard{mutex};
  // If we've got no reads, we're probably just missing them.
  if (reads.size() == 0) return true;
  return false;
}

void GlobalMemoryDescriptor::add_read(SgAsmInstruction* insn, int asize) {
  write_guard<decltype(mutex)> guard{mutex};
  // Add the instruction to the reads list.
  reads.insert(insn);

  SDEBUG << "Global memory read of " << address_string()
         << " by " << debug_instruction(insn) << LEND;

  // Remove the instruction from refs now that we know that it's really a read.
  InsnSet::iterator it = refs.find(insn);
  if (it != refs.end()) refs.erase(it);

  // Update the access size appropriately.
  if (access_size == 0) access_size = asize;
  if (access_size != asize) access_size = -1;
}

void GlobalMemoryDescriptor::add_write(SgAsmInstruction* insn, int asize) {
  write_guard<decltype(mutex)> guard{mutex};
  // Add the instruction to the writes list.
  writes.insert(insn);

  SDEBUG << "Global memory write of " << address_string()
         << " by " << debug_instruction(insn) << LEND;

  // Remove the instruction from refs now that we know that it's really a read.
  InsnSet::iterator it = refs.find(insn);
  if (it != refs.end()) refs.erase(it);

  // Update the access size appropriately.
  if (access_size == 0) access_size = asize;
  if (access_size != asize) access_size = -1;
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
