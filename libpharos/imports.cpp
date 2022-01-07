// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/optional.hpp>

#include "imports.hpp"
#include "masm.hpp"
#include "util.hpp"
#include "apidb.hpp"
#include "descriptors.hpp"

namespace pharos {

// Construct and import given an address, dll/so name, function name, and optionally an import.
ImportDescriptor::ImportDescriptor(DescriptorSet& ds_, rose_addr_t addr_,
                                   std::string dll_, std::string name_, size_t ord_)
  : function_descriptor(ds_)
{
  address = addr_;
  dll = dll_;
  if (name_.size() == 0) {
    name = unknown_name;
  }
  else {
    name = name_;
  }
  ordinal = ord_;
  if (ordinal != 0) {
    GTRACE << "Import by ordinal at: " << addr_str(address)
           << " to " << get_normalized_name() << LEND;
  }

  // Create a new variable value to represent the memory initialized by the loader.
  loader_variable = SymbolicValue::loader_defined();
}

std::string ImportDescriptor::get_dll_root() const {
  auto & dll_name = get_dll_name();
  auto dot = dll_name.find_first_of('.');
  return dll_name.substr(0, dot);
}

// Merge the important fields from the export descriptor loaded from a DLL config file.
void ImportDescriptor::merge_api_definition(APIDefinition const & def) {
  write_guard<decltype(mutex)> guard{mutex};

  // Probably the most important case, where the input file tried to be sneaky and import by
  // ordinal, but we've figured out what the corrsponding name is?
  if (name == unknown_name) name = def.get_name();
  // Not possible because we must have a DLL name in the input file and have reached here?
  if (dll == unknown_name) dll = def.dll_name;
  // Pretty common, but not very useful?  (We now know the ordinal that was not specified?)
  if (ordinal == 0) ordinal = def.ordinal;

  // Here's the real call that does most of the work.
  function_descriptor.set_api(def);
}

std::string ImportDescriptor::get_normalized_name() const {
  read_guard<decltype(mutex)> guard{mutex};

  // Return the name if we have one.
  if (name != unknown_name) {
    return to_lower(dll) + ":" + name;
  }
  // Then try by ordinal.
  if (ordinal != 0) {
    return to_lower(dll) + ":" + str(boost::format("%d") % ordinal);;
  }
  // Fall back to the name, even if it's invalid.
  return to_lower(dll) + ":" + name;
}

// Report the "best available" name.  This is the case sensitive version of the name if it
// exists, and the ordinal pseudo-name if it doesn't.
std::string ImportDescriptor::get_best_name() const {
  read_guard<decltype(mutex)> guard{mutex};

  // Return the name if we have one.
  if (name != unknown_name) {
    return dll + ":" + name;
  }
  // Then try by ordinal.
  if (ordinal != 0) {
    return dll + ":" + str(boost::format("%d") % ordinal);
  }
  // Fall back to the name, even if it's invalid.
  return dll + ":" + name;
}

void ImportDescriptor::print(std::ostream &o) const {
  o << "Import: addr=" << std::hex << get_address() << std::dec
    << " name='" << get_long_name() << "'"
    << function_descriptor.debug_deltas()
    << " callers=[" << std::hex;
  read_guard<decltype(mutex)> guard{mutex};
  for (auto & c : callers.values()) {
    o << str(boost::format(" 0x%08X") % c);
  }
  o << " ]" << std::dec;
}

void ImportDescriptor::validate(std::ostream &o) const {
  read_guard<decltype(mutex)> guard{mutex};
  if (callers.size() == 0)
    o << "No callers for " << *this << LEND;
}

const ImportDescriptor*
ImportDescriptorMap::find_name(const std::string & dll,
                               const std::string & name) const
{
  std::string normed = to_lower(dll) + ":" + name;

  for (const ImportDescriptorMap::value_type& pair : *this) {
    const ImportDescriptor& id = pair.second;
    if (id.get_normalized_name() == normed) {
      return &id;
    }
  }
  return NULL;
}

std::set<const ImportDescriptor*>
ImportDescriptorMap::find_name(const std::string & name) const
{
  std::set<const ImportDescriptor*>ids;

  for (const ImportDescriptorMap::value_type& pair : *this) {
    const ImportDescriptor& id = pair.second;
    if (id.get_name() == name) {
      ids.insert(&id);
    }
  }

  return ids;
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
