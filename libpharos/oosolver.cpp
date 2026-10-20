// Copyright 2016-2022 Carnegie Mellon University.  See LICENSE file for terms.
// Author: Cory Cohen

#include <boost/range/adaptor/map.hpp>

#include "oosolver.hpp"
#include "ooanalyzer.hpp"
#include "method.hpp"
#include "usage.hpp"
#include "vcall.hpp"
#include "pdg.hpp"
#include "vftable.hpp"
#include "demangle.hpp"
#include "bua.hpp"
#include "demangle.hpp"
#include "prolog_symexp.hpp"

namespace bf = boost::filesystem;

namespace pharos {

using namespace prolog;

// Place enum declartion here because no-one else needs it, and if we delcare it here we can
// allocate the strings in the same place.
enum prolog_method_property_enum {
  Constructor,
  DeletingDestructor,
  RealDestructor,
  Virtual
};

template <>
const char *pharos::EnumStrings<prolog_method_property_enum>::data[] = {
  "constructor",
  "deletingDestructor",
  "realDestructor",
  "virtual"
};

std::unique_ptr<OOSolver::ProgressBar> OOSolver::progress_bar;

// Construct a new Object Oriented Prolog solver.
OOSolver::OOSolver(DescriptorSet & ds_, const ProgOptVarMap& vm) : ds(ds_)
{
  // We're nt actually going to perform analysis unless requested.
  perform_analysis = false;

  if (vm.count("prolog-facts")) {
    facts_filename = vm["prolog-facts"].as<bf::path>().native();
  }

  tracing_enabled = false;
  if (vm.count("prolog-trace")) {
    tracing_enabled = true;
  }

  int logging_level;
  auto loglevel = vm.get<int>("prolog-loglevel", "prolog-loglevel");
  if (loglevel) {
    logging_level = *loglevel;
    if (logging_level < 1 || logging_level > 7) {
      OWARN << "Illegal prolog-loglevel, setting to 6" << LEND;
      logging_level = 6;
    }
    switch (logging_level) {
     case 7:
      plog[Sawyer::Message::DEBUG].enable();
      // fallthrough
     case 6:
      plog[Sawyer::Message::TRACE].enable();
      // fallthrough
     case 5:
      plog[Sawyer::Message::WHERE].enable();
      // fallthrough
     case 4:
      plog[Sawyer::Message::INFO].enable();
      // fallthrough
     case 3:
      plog[Sawyer::Message::WARN].enable();
      // fallthrough
     case 2:
      plog[Sawyer::Message::ERROR].enable();
      // fallthrough
     case 1:
      plog[Sawyer::Message::FATAL].enable();
      // fallthrough
     default:
      break;
    }
  } else {
    if (plog[Sawyer::Message::DEBUG]) {
      logging_level = 7;
    } else if (plog[Sawyer::Message::TRACE]) {
      logging_level = 6;
    } else if (plog[Sawyer::Message::WHERE]) {
      logging_level = 5;
    } else if (plog[Sawyer::Message::INFO]) {
      logging_level = 4;
    } else if (plog[Sawyer::Message::WARN]) {
      logging_level = 3;
    } else if (plog[Sawyer::Message::ERROR]) {
      logging_level = 2;
    } else {
      logging_level = 1;
    }
  }

  ignore_rtti = false;
  if (vm.count("ignore-rtti")) {
    ignore_rtti = true;
  }

  no_guessing = false;
  if (vm.count("no-guessing")) {
    no_guessing = true;
  }

  if (vm.count("prolog-results")) {
    results_filename = vm["prolog-results"].as<bf::path>().native();
    perform_analysis = true;
  }

  if (vm.count("json")) {
    json_path = vm["json"].as<bf::path>().native();
    perform_analysis = true;
  }

  try {
    session = std::make_shared<Session>(vm);
    if (tracing_enabled) {
      session->set_debug_log(std::cout);
    }
    auto stack_limit = vm.get<std::size_t>("prolog_stack_limit");
    if (stack_limit) {
      session->command("set_prolog_flag", "stack_limit", *stack_limit);
    }
    auto table_space = vm.get<std::size_t>("prolog_table_space");
    if (table_space) {
      session->command("set_prolog_flag", "table_space", *table_space);
    }
    session->add_fact("logLevel", logging_level);
    session->consult("oorules/progress_oosolver");
    session->consult("oorules/setup");
    if (json_path) {
      session->consult("oorules/oojson");
    }
  } catch (const Error& error) {
    GFATAL << "Unable to start Prolog session." << LEND;
    GFATAL << error.what() << LEND;
    session.reset();
  }
  if (progress_bar) {
    GFATAL << "More than one OOSolver in existence" << LEND;
    session.reset();
  }
  progress_bar.reset(new ProgressBar(olog[Sawyer::Message::MARCH], "Prolog facts"));
  session->register_predicate("progress", 1, progress, "oosolver");
}

OOSolver::~OOSolver()
{
  progress_bar.reset();
}

bool OOSolver::progress(Args args)
{
  assert(progress_bar);
  auto val = args.as<size_t>(0);
  progress_bar->value(val);
  return true;
}

// The public interface to adding facts.  It's wrapped in a try/catch for more graceful
// handling of unexpected conditions.
bool
OOSolver::add_facts(const OOAnalyzer& ooa) {
  if (!session) return false;
  try {
    if (!ignore_rtti) {
      session->add_fact("rTTIEnabled");
    }
    if (no_guessing) {
      session->add_fact("guessingDisabled");
    }
    static const auto abi_name = [](DescriptorSet::ABI a) -> std::string {
      switch (a) {
        case DescriptorSet::ABI::MSVC_32: return "MSVC_32";
        case DescriptorSet::ABI::MSVC_64: return "MSVC_64";
        case DescriptorSet::ABI::SYSV_32: return "SYSV_32";
        case DescriptorSet::ABI::SYSV_64: return "SYSV_64";
        default:                          return "UNKNOWN";
      }
    };
    session->add_fact("fileInfo", ds.get_filemd5(), ds.get_filename(), abi_name(ds.get_abi()),
                      ds.get_arch_bytes());
    add_method_facts(ooa);
    add_vftable_facts(ooa);
    add_usage_facts(ooa);
    add_call_facts(ooa);
    add_thisptroffset_facts();
    add_thisptrdefinition_facts();
    add_function_facts(ooa);
    add_import_facts(ooa);
  }
  catch (const Error& error) {
    GFATAL << error.what() << LEND;
    return false;
  }
  return true;
}

bool
OOSolver::solve() {
  if (!session) return false;
  try {
    GINFO << "Analyzing object oriented data structures..." << LEND;
    auto query = session->query("solve", "ooanalyzer_tool");
    if (query->done()) {
      GERROR << "The solution found is not internally consistent and may have significant errors!" << LEND;
    }
  }
  catch (const Error& error) {
    GFATAL << error.what() << LEND;
    return false;
  }
  return true;
}

// The main analysis call.  It adds facts, invokes the analysis, and reports the results.
bool
OOSolver::analyze(const OOAnalyzer& ooa) {
  if (!session) return false;
  if (!add_facts(ooa)) return false;
  if (facts_filename.size() != 0) {
    if (!dump_facts()) return false;
  }

  if (perform_analysis) {
    if (!solve()) {
      GERROR << "Failed to analyze object oriented data structures." << LEND;
      return false;
    }

    if (results_filename.size() != 0) {
      if (!dump_results()) return false;
    }

    if (json_path) {
      session->command("exportJSONTo", *json_path);
    }

  }

  return true;
}

// Dump facts primarily associated with a this call method.  This currently includes object
// offsets passed to otehr methods, member accesses, and possible vftable writes.
void
OOSolver::add_method_facts(const OOAnalyzer& ooa)
{
  for (auto const & tcm : boost::adaptors::values(ooa.get_methods())) {
    std::string thisptr_term = "invalid";
    const SymbolicValuePtr& this_ptr = tcm->get_this_ptr();
    if (this_ptr) {
      thisptr_term = "sv_" + std::to_string(this_ptr->get_hash());
    }

    // Hackish forced exporting of "thisptr" arguments when no calling convention was detected.
    // There's a difference between how the thisptr symbolic values are being determined for
    // thiscall methods, and how it's being determined for function calling conventions in
    // general.  By exporting the facts related to this defect in a way that draws more
    // attention to the real problem than the old thisCallMethod facts, we can narrow in on the
    // real problem gradually.  It's also not acceptable to export a normal callingConvention
    // fact and normal funcParameter fact, as this results in non-OO functions.
    auto conventions = tcm->fd->get_calling_conventions();
    if (conventions.size() == 0) {
      session->add_fact("callingConvention", tcm->get_address(), "genericthisptr");
      auto reg_name = tcm->fd->ds.get_this_ptr_reg_name();
      if (reg_name) {
        session->add_fact("funcParameter", tcm->get_address(), *reg_name, thisptr_term);
      } else {
        // System V 32-bit: this-pointer is the first stack argument (parameter position 0).
        session->add_fact("funcParameter", tcm->get_address(), 0, thisptr_term);
      }
    }

    // These facts are getting closer to correct, but should still be reviewed once more.
    if (tcm->returns_self) {
      session->add_fact("returnsSelf", tcm->get_address());
    }
    if (tcm->no_calls_before) {
      session->add_fact("noCallsBefore", tcm->get_address());

      // Uninitialized reads are only meaningful for methods that have no calls before.  This
      // helps cut down on the number of exported facts.
      if (tcm->uninitialized_reads) {
        session->add_fact("uninitializedReads", tcm->get_address());
      }
    }

    if (tcm->no_calls_after) {
      session->add_fact("noCallsAfter", tcm->get_address());
    }

    // We used to report funcOffsets here, but they're no longer needed.

    for (const Member& member : boost::adaptors::values(tcm->data_members)) {
      for (const SgAsmX86Instruction* insn : member.using_instructions) {
        session->add_fact("methodMemberAccess", insn->get_address(),
                          tcm->get_address(), member.offset, member.size);
      }
    }
  }
}

// Dump facts primarily associated with virtual function tables (the entries and the RTTI
// information).
void
OOSolver::add_vftable_facts(const OOAnalyzer& ooa)
{
  const VirtualTableInstallationMap& installs = ooa.virtual_table_installations;
  for (const VirtualTableInstallationPtr & vti : boost::adaptors::values(installs)) {
    GDEBUG << "Considering VFTable Install " << addr_str(vti->insn->get_address()) << LEND;

    std::string thisptr_term = "invalid";
    if (vti->written_to) {
      thisptr_term = "sv_" + std::to_string(vti->written_to->hash());
    }

    std::string expanded_thisptr_term = "sv_" + std::to_string(vti->expanded_ptr->hash());

    std::string fact_name = "possibleVFTableWrite";
    if (vti->base_table) fact_name = "possibleVBTableWrite";

    // Only export VTableWrites with non-negative offsets to reduce false positives?
    if (vti->offset >= 0) {
      session->add_fact(fact_name, vti->insn->get_address(), vti->fd->get_address(),
                        thisptr_term, vti->offset, expanded_thisptr_term, vti->table_address);

      // Add the ptr so we make a thisPtrDefinition
      expanded_thisptrs.insert(ExpandedTreeNodePtr{vti->expanded_ptr, vti->insn->get_address(), vti->fd->get_address()});
    }
  }

  std::set<rose_addr_t> exported;

  size_t arch_bytes = ooa.ds.get_arch_bytes();
  const VFTableAddrMap& vftables = ooa.get_vftables();
  const ItaniumVTTMap& vtts = ooa.get_itanium_vtts();

  // How far a table extends is decided here rather than during analysis, because this is the only
  // place that needs the answer.  Two knobs, both fixed by the ABI: what counts as a table entry,
  // and how many consecutive slots may fail that test before the table has ended.
  //
  // MSVC keeps its long standing rule, where any mapped value is an entry and the first unmapped
  // one ends the table.  Being generous here is deliberate: reasonVFTableSizeGTE and
  // reasonVFTableSizeLTE work out the real size in Prolog, and they can only do that from entries
  // we exported.
  //
  // The Itanium ABI cannot use that rule.  A construction vtable has zeroed destructor slots in
  // the middle of it, so an unmapped value cannot end a table; and the type information records
  // that follow the last table alternate unmapped and mapped words, so a tolerance counted over
  // unmapped values never runs out.  Requiring an entry to be a function pointer solves both,
  // because the zeroed slots are covered by the tolerance while the pointers into those records
  // are not functions and do end the walk.  Three is the right tolerance because the next table's
  // header is always at least that many non-function words: the virtual call and base offsets, the
  // offset to the top of the object, and the type information pointer, which is itself zero when
  // the binary was built without RTTI.
  //
  // "Function pointer" has to mean any address in executable memory, not just one we successfully
  // partitioned into a function.  Requiring a known function loses the last entry of a table
  // whenever its target went unpartitioned, which is what happens in the stripped builds: the
  // adjusting thunk for the final method of five separate tables goes unrecognized, lands as a
  // trailing failure and is trimmed away.  Nothing that has to end a walk is executable -- the
  // offsets in the next table's header are small integers, and the type information pointers are
  // in read only data -- so accepting all of .text costs nothing.
  const bool itanium = ooa.ds.is_itanium_abi();
  auto is_entry = [&ooa, itanium](rose_addr_t value) {
    if (!itanium) return ooa.ds.memory.is_mapped(value);
    if (ooa.ds.get_func(value) != NULL || ooa.ds.get_import(value) != NULL) return true;
    uint8_t byte;
    return ooa.ds.memory.get_memmap()->at(value).limit(1)
      .require(MemoryMap::EXECUTABLE).read(&byte).size() == size_t(1);
  };
  const size_t tolerance = itanium ? 3 : 0;

  // The next component of a vtable group announces itself with the two word header below its
  // address point: the offset-to-top of the subobject it serves, which is zero for a primary
  // table and negative for a secondary one, and the pointer to the type information of its
  // class.  That header is never an entry of the table before it, so recognizing it ends the
  // walk exactly where the tolerance above can only guess.  Every record has been read by the
  // time facts are exported, so the map is all that is needed to recognize one.
  const ItaniumTypeInfoMap& typeinfo = ooa.get_itanium_typeinfo();
  auto is_next_component = [&ooa, &typeinfo, arch_bytes](rose_addr_t addr) {
    if (!ooa.ds.memory.is_mapped(addr) || !ooa.ds.memory.is_mapped(addr + arch_bytes)) {
      return false;
    }
    int64_t offset_to_top = IntegerOps::signExtend2(
      ooa.ds.memory.read_address(addr, Bytes(arch_bytes)), 8 * arch_bytes, 64);
    if (offset_to_top > 0) return false;
    return typeinfo.count(
      ooa.ds.memory.read_address(addr + arch_bytes, Bytes(arch_bytes))) != 0;
  };

  for (auto const & vft : boost::adaptors::values(vftables)) {
    // Collect before emitting, because a slot that failed the test can still turn out to be inside
    // the table.  Only the failures the table ends on should be dropped.
    std::vector<rose_addr_t> slots;
    size_t entries = 0;
    size_t strikes = 0;
    for (size_t e = 0; ; e++) {
      rose_addr_t eaddr = vft->addr + (e * arch_bytes);
      if (!ooa.ds.memory.is_mapped(eaddr)) break;

      // Another table starts here, so this one has ended.  Only the starting address has to be
      // right for Prolog's benefit: possibleVFTableEntry/3 refuses to step onto the start of
      // another table and works out the extent for itself.  A VTT bounds a table the same way,
      // and while the tolerance below would usually stop the walk anyway, a two entry VTT
      // followed by the next table's two word header is exactly at the limit.
      if (e != 0 && (vftables.find(eaddr) != vftables.end()
                     || vtts.find(eaddr) != vtts.end())) break;

      // Skip this entry if it's already been proccessed.
      if (exported.find(eaddr) != exported.end()) break;

      if (e != 0 && itanium && is_next_component(eaddr)) break;

      rose_addr_t value = vft->read_entry(e);
      if (is_entry(value)) strikes = 0;
      else if (++strikes > tolerance) break;

      slots.push_back(value);
      if (strikes == 0) entries = slots.size();
    }
    slots.resize(entries);

    // We used to follow thunks and export the dethunked entry, but it turns out that thunks
    // sometimes play an important role if differentiating functions, especially in vftable
    // entries.  A common scenario is for the compiler to create two different thunks jumping
    // to the same method implementation, and to put the distinct thunks in the vftable.  If
    // we've exported thunk facts to Prolog, we can sort that out correctly, and identify
    // that the single implementation is a shared implementation.

    for (size_t e = 0; e < slots.size(); e++) {
      rose_addr_t eaddr = vft->addr + (e * arch_bytes);
      exported.insert(eaddr);
      session->add_fact("initialMemory", eaddr, slots[e]);
    }

    if (vft->msvc_rtti) {
      add_msvc_rtti_facts(vft.get());
    }
    else if (vft->itanium_rtti) {
      add_itanium_rtti_facts(ooa, vft.get());
    }
  }

  const VBTableAddrMap& vbtables = ooa.get_vbtables();
  for (auto const & vbt : boost::adaptors::values(vbtables)) {
    for (size_t e = 0; e < vbt->size; e++) {
      signed int value = vbt->read_entry(e);
      rose_addr_t eaddr = vbt->addr + (e * arch_bytes);

      // Skip this entry if it's already been proccessed.
      auto finder = exported.find(eaddr);
      if (finder != exported.end()) break;
      exported.insert(eaddr);

      session->add_fact("initialMemory", eaddr, value);
    }
  }

  // The tables a VTT names have already been exported above, since discovering a VTT is what
  // put them in vftables.  What is left is the shape of the VTT itself, which is what says
  // which tables belong to the same construction sequence.  Its slots are deliberately not
  // also reported as initialMemory: a VTT sits adjacent to the tables it describes, and
  // possibleVFTableEntry/3 would walk out of the end of the preceding table and absorb them as
  // though they were virtual function pointers.
  for (auto const & vtt : vtts) {
    for (size_t e = 0; e < vtt.second.size(); e++) {
      session->add_fact("possibleVTTEntry", vtt.first, e * arch_bytes, vtt.second[e]);
    }
  }
}

void
OOSolver::add_msvc_rtti_facts(const VirtualFunctionTable* vft)
{
  if (vft->msvc_rtti_confidence == ConfidenceNone) return;

  const TypeRTTICompleteObjectLocatorPtr rtti = vft->msvc_rtti;

  // Check for --ignore-rtti option?
  if (rtti->signature.value != 0) return;
  if (rtti->class_desc.signature.value != 0) return;

  if (visited.find(vft->msvc_rtti_addr) == visited.end()) {
    session->add_fact("rTTIMSVCCompleteObjectLocator", vft->msvc_rtti_addr, rtti->address,
                      rtti->pTypeDescriptor.value, rtti->pClassDescriptor.value,
                      rtti->offset.value, rtti->cdOffset.value);
    visited.insert(vft->msvc_rtti_addr);
  }

  if (visited.find(rtti->pTypeDescriptor.value) == visited.end()) {
    std::string demangled_name;
    demangle::DemangledTypePtr demangled;

    try {
      demangled = demangle::visual_studio_demangle(rtti->type_desc.name.value);
    } catch (demangle::Error &e) {
      GWARN << "Unable to demangle type " << rtti->type_desc.name.value << ": " << e.what () << LEND;
    }

    if (demangled) {
      demangled_name = demangled->get_class_name();
    }
    session->add_fact("rTTITypeDescriptor", rtti->pTypeDescriptor.value,
                      rtti->type_desc.pVFTable.value, rtti->type_desc.name.value,
                      demangled_name);
    visited.insert(rtti->pTypeDescriptor.value);
  }

  if (visited.find(rtti->pClassDescriptor.value) == visited.end()) {
    add_msvc_rtti_chd_facts(rtti->pClassDescriptor.value);
  }
}

void
OOSolver::add_msvc_rtti_chd_facts(const rose_addr_t addr)
{
  visited.insert(addr);
  try {
    TypeRTTIClassHierarchyDescriptor chd{ds.memory};
    chd.read(addr);

    std::vector<uint32_t> base_addresses;
    for (const TypeRTTIBaseClassDescriptor& base : chd.base_classes) {
      if (visited.find(base.address) == visited.end()) {
        session->add_fact("rTTIMSVCBaseClassDescriptor", base.address,
                          base.pTypeDescriptor.value, base.numContainedBases.value,
                          base.where_mdisp.value, base.where_pdisp.value,
                          base.where_vdisp.value, base.attributes.value,
                          base.pClassDescriptor.value);
        visited.insert(base.address);

        // This is where we read and export facts for the undocumented "sub-chd", but only if
        // the base.attributes flag has bit 0x40 set, which indicates that optional pointer is
        // present.
        if (base.attributes.value & 0x40 &&
            visited.find(base.pClassDescriptor.value) == visited.end()) {
          add_msvc_rtti_chd_facts(base.pClassDescriptor.value);
        }
      }

      if (visited.find(base.pTypeDescriptor.value) == visited.end()) {
        std::string demangled_name;
        demangle::DemangledTypePtr demangled;

        try {
          demangled = demangle::visual_studio_demangle(base.type_desc.name.value);
        } catch (demangle::Error &e) {
          GWARN << "Unable to demangle type " << base.type_desc.name.value << ": " << e.what () << LEND;
        }

        if (demangled) {
          demangled_name = demangled->get_class_name();
        }
        session->add_fact("rTTITypeDescriptor", base.pTypeDescriptor.value,
                          base.type_desc.pVFTable.value, base.type_desc.name.value,
                          demangled_name);
        visited.insert(base.pTypeDescriptor.value);
      }

      base_addresses.push_back(base.address);
    }

    session->add_fact("rTTIMSVCClassHierarchyDescriptor", addr,
                      chd.attributes.value, base_addresses);
  }
  catch (std::exception &e) {
    GERROR << "RTTI Class Hierarchy Descriptor was bad at " << addr_str(addr) << ": " << e.what () << LEND;
  }
  catch (...) {
    GERROR << "RTTI Class Hierarchy Descriptor was bad at " << addr_str(addr) << LEND;
  }
}

// The Itanium ABI counterpart of add_msvc_rtti_facts().  The type information record takes the
// place of both the complete object locator and the class hierarchy descriptor: it names the
// class and lists its direct base classes, and the table points at it directly rather than
// through a locator.  Bases are followed recursively the way add_msvc_rtti_chd_facts() follows
// base class descriptors, because a base class' record is reported even when the base has no
// virtual function table of its own to reach it from.
void
OOSolver::add_itanium_rtti_facts(const OOAnalyzer& ooa, const VirtualFunctionTable* vft)
{
  session->add_fact("rTTIItaniumVFTableTypeInfo", vft->addr, vft->itanium_rtti->address,
                    vft->offset_to_top);

  add_itanium_typeinfo_facts(ooa, vft->itanium_rtti->address);
}

void
OOSolver::add_itanium_typeinfo_facts(const OOAnalyzer& ooa, const rose_addr_t addr)
{
  if (visited.find(addr) != visited.end()) return;

  // A base class whose record is in another shared object, where the pointer to it is a
  // relocation that the dynamic linker was going to fill in.  There is nothing to report.
  const ItaniumTypeInfoMap& records = ooa.get_itanium_typeinfo();
  auto found = records.find(addr);
  if (found == records.end()) return;
  const TypeItaniumTypeInfo& ti = found->second;
  visited.insert(addr);

  std::string demangled_name = demangle_itanium_type(ti.name.value);
  if (demangled_name.empty()) {
    GWARN << "Unable to demangle type " << ti.name.value << LEND;
  }

  // The same fact the MSVC path asserts, because the record describes the same thing: the
  // type_info vtable, the mangled name of the class, and its demangling.
  session->add_fact("rTTITypeDescriptor", ti.address, ti.pVTable.value,
                    ti.name.value, demangled_name);
  session->add_fact("rTTIItaniumTypeInfo", ti.address, kind_str(ti.kind));

  for (const TypeItaniumBaseTypeInfo & base : ti.base_classes) {
    session->add_fact("rTTIItaniumBaseTypeInfo", ti.address, base.pTypeInfo.value,
                      base.offset(), base.is_virtual() ? "true" : "false",
                      base.is_public() ? "true" : "false");
    add_itanium_typeinfo_facts(ooa, base.pTypeInfo.value);
  }
}

// Dump facts primarily associated with object usage, which are effectively grouped by the
// function that they occur in.  Dominace relationships are also dumped here because we're only
// dumping dominance information for instructions involved in method evidence.  That might
// result in duplicate assertions and further it might be insufficient for some advanced
// reasoning about vtable reads and writes.   Changes may be required in the future.
void
OOSolver::add_usage_facts(const OOAnalyzer& ooa)
{
  for (const ObjectUse& obj_use : boost::adaptors::values(ooa.object_uses)) {
    rose_addr_t func_addr = obj_use.fd->get_address();

    for (const ThisPtrUsage& tpu : boost::adaptors::values(obj_use.references)) {
      // Report relationships for the this-pointer later.
      thisptrs.insert(tpu.this_ptr->get_expression());
      const rose_addr_t defaddr = tpu.this_ptr->has_definers() ? (*tpu.this_ptr->get_defining_instructions().begin())->get_address () : 0;
      expanded_thisptrs.insert(ExpandedTreeNodePtr{tpu.expanded_this_ptr, defaddr, func_addr});

      // Report where this object was allocated.
      if (tpu.alloc_insn != NULL) {
        // Report the allocation fact now though.
        std::string thisptr_term = "sv_" + std::to_string(tpu.this_ptr->get_hash());
        session->add_fact("thisPtrAllocation", tpu.alloc_insn->get_address(), func_addr,
                          thisptr_term, "type_" + Enum2Str(tpu.alloc_type), tpu.alloc_size);
      }
    }
  }
}

// Is Address one of the slots of a VTT we found?  Under the Itanium ABI a complete-object
// constructor hands each base-object constructor a slice of its VTT to load a vptr from, and the
// slice address is the only evidence of which construction vtable the callee installs.  Empty for
// MSVC, which has no VTTs.
static bool
on_vtt_slot(const ItaniumVTTMap& vtts, size_t arch_bytes, rose_addr_t address)
{
  // The greatest VTT at or below the address, if there is one.
  auto vtt = vtts.upper_bound(address);
  if (vtt == vtts.begin()) return false;
  --vtt;
  rose_addr_t offset = address - vtt->first;
  return (offset % arch_bytes) == 0 && (offset / arch_bytes) < vtt->second.size();
}

// Dump facts primarily associated with each call instruction in the program.
void
OOSolver::add_call_facts(const OOAnalyzer& ooa)
{
  const ItaniumVTTMap& vtts = ooa.get_itanium_vtts();
  size_t arch_bytes = ooa.ds.get_arch_bytes();

  const CallDescriptorMap& call_map = ooa.ds.get_call_map();
  for (const CallDescriptor& cd : boost::adaptors::values(call_map)) {

    FunctionDescriptor* callfunc = cd.get_containing_function();
    if (!callfunc) continue;
    // For each target of the call, consider whether it calls operator delete().
    for (rose_addr_t target : cd.get_targets()) {

      // This code should really be implemented as cd.get_real_targets(), but that's going to
      // require an iterator or something like that.  Instead I've implemented an example of
      // how to do it here.
      // bool endless;
      // rose_addr_t real_target = target;
      // FunctionDescriptor* tfd = ooa.ds.get_func(target);
      // if (tfd) real_target = tfd->follow_thunks(&endless);

      if (cd.get_address() == callfunc->get_address()
          && callfunc->is_thunk() && callfunc->get_jmp_addr() == target) {
        // If the callTarget is just for a thunk, don't export the callTarget fact.
      }
      else {
        session->add_fact("callTarget", cd.get_address(), callfunc->get_address(), target);
      }

      bool isdelete = ooa.is_candidate_delete_method(target);
      std::string thisptr_term = "invalid";
      if (isdelete) {
        auto params = cd.get_parameters().get_params();
        if (params.size() > 0) {
          const ParameterDefinition& param = *params.begin();
          const SymbolicValuePtr& value = param.get_value();
          if (value) thisptr_term = "sv_" + std::to_string(value->get_hash());
          GTRACE << "Parameter to delete at " << cd.address_string() << " was: "
                 << thisptr_term << " tn=" << *(value->get_expression()) << LEND;
        }
        session->add_fact("insnCallsDelete", cd.get_address(),
                          callfunc->get_address(), thisptr_term);
      }

      bool isnew = ooa.is_new_method(target);
      thisptr_term = "invalid";
      if (isnew) {
        const SymbolicValuePtr& value = cd.get_return_value();
        if (value) thisptr_term = "sv_" + std::to_string(value->get_hash());
        session->add_fact("insnCallsNew", cd.get_address(),
                          callfunc->get_address(), thisptr_term);
      }
    }

    // Report all parameters for every call (in the future we'll try using an OO subset)
    const ParameterList& call_params = cd.get_parameters();
    auto cparams = call_params.get_params();
    for (const ParameterDefinition& cpd : cparams) {
      if (!cpd.get_value()) continue;
      TreeNodePtr expr = cpd.get_expression();
      if (!expr) continue;
      // If the expression is a constant and not a global variable we do not want to export it.
      // A VTT slice is neither, but it names the construction vtable a base-object constructor
      // installs, which nothing else records, so let that one kind of constant through too.
      bool vtt_slice = false;
      if (expr->isIntegerConstant()) {
        if (expr->nBits() > 64) continue;
        vtt_slice = on_vtt_slot(vtts, arch_bytes, *expr->toUnsigned());
        if (!vtt_slice && ooa.ds.get_global(*expr->toUnsigned()) == NULL) continue;
      }

      // If the expression is of the form ite(cond value 0), extract just the non-NULL part of
      // the value.  See additional commentary in usage.cpp for more background.
      expr = pick_non_null_expr(expr);

      // Prolog needs the slice's value, not just its identity, to work out which VTT entry the
      // callee loads.  callParameter carries only a hash, so report the expression through
      // thisPtrDefinition as well, where an integer constant is exported as an integer.
      if (vtt_slice) {
        expanded_thisptrs.insert(
          ExpandedTreeNodePtr{expr, cd.get_address(), callfunc->get_address()});
      }

      std::string term = "sv_" + std::to_string(expr->hash());
      if (cpd.is_reg()) {
        std::string regname = unparseX86Register(cpd.get_register(), {});
        session->add_fact("callParameter", cd.get_address(),
                          callfunc->get_address(), regname, term);
      }
      else {
        session->add_fact("callParameter", cd.get_address(),
                          callfunc->get_address(), cpd.get_num(), term);
      }
    }

    // From here on, we're only interested in virtual calls.
    const VirtualFunctionCallMap& vcalls = ooa.get_vcalls();
    if (vcalls.find(cd.get_address()) == vcalls.end()) continue;

    for (const VirtualFunctionCallInformation& vci : vcalls.at(cd.get_address())) {
      // If there's no object pointer, we can't export?
      if (!(vci.obj_ptr)) continue;

      // XXX: Should we add these to expanded_thisptrs too? Probably.
      thisptrs.insert(vci.obj_ptr->get_expression());

      const FunctionDescriptor* fd = cd.get_function_descriptor();
      rose_addr_t funcaddr = fd ? fd->get_address() : 0;
      expanded_thisptrs.insert(ExpandedTreeNodePtr{vci.expanded_obj_ptr, cd.get_address (), funcaddr});

      // Report the virtual call fact now.
      std::string thisptr_term = "sv_" + std::to_string(vci.obj_ptr->get_hash());
      session->add_fact("possibleVirtualFunctionCall", cd.get_address(),
                        callfunc->get_address(), thisptr_term,
                        vci.vtable_offset, vci.vfunc_offset);
    }
  }
}

// Report relationships between this-pointers.
void
OOSolver::add_thisptroffset_facts()
{
  for (const TreeNodePtr& thisptr : thisptrs) {
    AddConstantExtractor ace(thisptr);
    // Signed integer conversion, because we want to exclude unreasonably large offsets.
    int constant = ace.constant_portion();
    if (constant > 0 && ace.well_formed()) {
      std::string thisptr_term = "sv_" + std::to_string(thisptr->hash());
      const TreeNodePtr& varptr = ace.variable_portion();
      std::string variable_term = "sv_" + std::to_string(varptr->hash());
      session->add_fact("thisPtrOffset", variable_term, constant, thisptr_term);
    }
  }
}

// Report definitions of this-pointers.
void
OOSolver::add_thisptrdefinition_facts()
{
  for (const ExpandedTreeNodePtr& thisptr : expanded_thisptrs) {
    std::string thisptr_term = "sv_" + std::to_string(thisptr.ptr->hash());
    session->add_fact("thisPtrDefinition", thisptr_term, thisptr.ptr, thisptr.defaddr, thisptr.funcaddr);
  }
}

// Returns true if a calling convention is appropriate for the detected ABI.  Conventions tagged
// ABI::UNKNOWN are always permitted.  This prevents e.g. __sysv32call from being emitted as a
// fact for a PE/MSVC binary.
static bool
abi_matches_convention(DescriptorSet::ABI binary_abi, const CallingConvention& cc)
{
  auto cc_abi = cc.get_abi();
  if (cc_abi == CallingConvention::ABI::UNKNOWN) return true;
  return cc_abi == binary_abi;
}

// Report facts about functions (like purecall).
void
OOSolver::add_function_facts(const OOAnalyzer& ooa)
{
  const FunctionDescriptorMap& fdmap = ooa.ds.get_func_map();
  for (const FunctionDescriptor& fd : boost::adaptors::values(fdmap)) {
    rose_addr_t fdaddr = fd.get_address();
    if (ooa.is_purecall_method(fdaddr)) {
      session->add_fact("purecall", fdaddr);
    }

    // Turns out that we need to export thunk data to Prolog, because the presence or absence
    // of thunks can affect our logic.  For example, thunk1 and thunk2 can be assigned to
    // different classes, even if they jump to the same function.  The third argument reports
    // how the thunk adjusts the this-pointer, which is what distinguishes an ordinary thunk
    // from an adjustor stub that retargets the callee onto a different subobject.
    if (fd.is_thunk()) {
      auto adjustment = fd.get_thunk_adjustment();
      int64_t fixed = adjustment ? adjustment->fixed_delta : 0;
      if (adjustment && adjustment->virtual_adjustment) {
        // The two ABIs read the run-time part of the adjustment from different places and
        // combine it with opposite signs, so each gets its own functor rather than a shared
        // one that would mean different things on different binaries.
        auto const & virt = *adjustment->virtual_adjustment;
        const char* name = virt.kind == ThunkAdjustment::VirtualKind::vcall_offset
          ? "virtual" : "vtordisp";
        session->add_fact("thunk", fdaddr, fd.get_jmp_addr(),
                          functor(name, fixed, virt.slot));
      }
      else {
        session->add_fact("thunk", fdaddr, fd.get_jmp_addr(), fixed);
      }
    }

    // Report all calling conventions for all functions, filtered by the detected ABI so that
    // e.g. __sysv32call is not emitted for PE binaries or __thiscall for ELF binaries.
    auto conventions = fd.get_calling_conventions();
    for (const CallingConvention* cc: conventions) {
      if (!abi_matches_convention(ooa.ds.get_abi(), *cc)) continue;
      session->add_fact("callingConvention", fdaddr, cc->get_name());
    }

    // Report all parameters for every function (in the future we'll try using an OO subset)
    const ParameterList& func_params = fd.get_parameters();
    auto fparams = func_params.get_params();
    for (const ParameterDefinition& fpd : fparams) {
      if (!fpd.get_value()) continue;
      TreeNodePtr expr = fpd.get_expression();
      if (!expr) continue;
      // If the expression is a constant and not a global variable we do not want to export it.
      // Is it possible to have _function_ parameters that are constants, or only on calls?
      if (expr->isIntegerConstant()) {
        if (expr->nBits() > 64) continue;
        if (ooa.ds.get_global(*expr->toUnsigned()) == NULL) continue;
      }
      std::string term = "sv_" + std::to_string(expr->hash());
      if (fpd.is_reg()) {
        std::string regname = unparseX86Register(fpd.get_register(), {});
        session->add_fact("funcParameter", fdaddr, regname, term);
      }
      else {
        session->add_fact("funcParameter", fdaddr, fpd.get_num(), term);
      }
    }

  }
}

// Report facts about functions (like purecall).
void
OOSolver::add_import_facts(const OOAnalyzer& ooa)
{
  const ImportDescriptorMap& idmap = ooa.ds.get_import_map();
  for (const ImportDescriptor& id : boost::adaptors::values(idmap)) {
    try {
      demangle::DemangledTypePtr dtype;

      if (!id.get_name().empty()
          && (id.get_name().front() == '?' || id.get_name().front() == '.'))
      {
        try {
          dtype = demangle::visual_studio_demangle(id.get_name());
        } catch (demangle::Error &e) {
          GWARN << "Unable to demangle import " << id.get_name() << ": " << e.what () << LEND;
        }
      }

      if (!dtype) continue;

      // Emit something for imported global objects.  I don't know what to do with this yet,
      // but we should emit something as a reminder.
      if (dtype->symbol_type == demangle::SymbolType::GlobalObject ||
          dtype->symbol_type == demangle::SymbolType::StaticClassMember) {

        std::string clsname = dtype->get_class_name();
        std::string varname = dtype->str_name_qualifiers(dtype->instance_name, false);

        session->add_fact("symbolGlobalObject", id.get_address(), clsname, varname);

        // And we're done with this import.
        continue;
      }

      // From this point forward, we're only interested in class methods.
      if (dtype->symbol_type != demangle::SymbolType::ClassMethod) continue;

      std::string clsname = dtype->get_class_name();
      std::string method_name = dtype->get_method_name();

      if (clsname.size() > 0) {
        assert(!dtype->name.empty());

        session->add_fact("symbolClass", id.get_address(), id.get_name(), clsname, method_name);

        // Add calling convention for imported functions, filtered by ABI.
        auto conventions = id.get_function_descriptor()->get_calling_conventions();
        for (const CallingConvention* cc: conventions) {
          if (!abi_matches_convention(ooa.ds.get_abi(), *cc)) continue;
          session->add_fact("callingConvention", id.get_address(), cc->get_name());
        }
        if (dtype->name.front()->is_ctor) {
          session->add_fact("symbolProperty", id.get_address(), Constructor);
        }

        if (dtype->name.front()->is_dtor) {
          session->add_fact("symbolProperty", id.get_address(), RealDestructor);
        }

        // Obviously would could do much better here, since we can identify a wide variety of
        // special purpose methods (e.g. operators) by inspecting the names.  I propose that we
        // should add those features only if they're in support of figuring out comparable facts
        // without symbols (as we have for deleting destructors).
        auto method = dtype->get_method_name();
        if (method == "`vector deleting destructor'"
            || method == "`scalar deleting destructor'")
        {
          session->add_fact("symbolProperty", id.get_address(), DeletingDestructor);
        }

        if (dtype->method_property == demangle::MethodProperty::Virtual) {
          session->add_fact("symbolProperty", id.get_address(), Virtual);
        }
      }
    }
    catch (const demangle::Error &) {
      // It doesn't matter what the error was.  We might not have even been a mangled name.
      continue;
    }
  }
}

// Wrap the private API to dump the Prolog facts in a try/catch wrapper.
bool
OOSolver::dump_facts()
{
  try {
    dump_facts_private();
  }
  catch (const Error& error) {
    GFATAL << error.what() << LEND;
    return false;
  }
  return true;
}

// Dump all of the OO related facts in the Prolog database.  Hopefully there will be an easier,
// more general way to do this in the future.  Dumping the facts in Prolog form as ASCII
// strings is required for the cases in which something goes wrong during analysis and we fail
// to detect an object in the presence of complicated real-world facts.  In that case, we'll
// need to be able to add a line or two of debugging statements to the C++ code and do the
// heavy lifting for the debugging in the interactive Prolog interpreter.  In the meantime,
// this is implementation is both useful and serves as a test of the Prolog query interface.
void
OOSolver::dump_facts_private()
{
  // This method should take a filename to write the facts to!
  std::ofstream facts_file;
  facts_file.open(facts_filename);
  if (!facts_file.is_open()) {
    GERROR << "Unable to open prolog facts file '" << facts_filename << "'." << LEND;
    return;
  }
  facts_file << "% Prolog facts autogenerated by OOAnalyzer." << std::endl;

  size_t exported = 0;

  exported += session->print_predicate(facts_file, "fileInfo", 4);
  exported += session->print_predicate(facts_file, "returnsSelf", 1);
  exported += session->print_predicate(facts_file, "noCallsBefore", 1);
  exported += session->print_predicate(facts_file, "noCallsAfter", 1);
  exported += session->print_predicate(facts_file, "uninitializedReads", 1);
  exported += session->print_predicate(facts_file, "insnCallsDelete", 3);
  exported += session->print_predicate(facts_file, "insnCallsNew", 3);
  exported += session->print_predicate(facts_file, "purecall", 1);
  exported += session->print_predicate(facts_file, "methodMemberAccess", 4);
  exported += session->print_predicate(facts_file, "possibleVFTableWrite", 6);
  exported += session->print_predicate(facts_file, "possibleVBTableWrite", 6);
  exported += session->print_predicate(facts_file, "possibleVTTEntry", 3);
  exported += session->print_predicate(facts_file, "initialMemory", 2);
  exported += session->print_predicate(facts_file, "rTTIMSVCCompleteObjectLocator", 6);
  exported += session->print_predicate(facts_file, "rTTITypeDescriptor", 4);
  exported += session->print_predicate(facts_file, "rTTIMSVCClassHierarchyDescriptor", 3);
  exported += session->print_predicate(facts_file, "rTTIMSVCBaseClassDescriptor", 8);
  exported += session->print_predicate(facts_file, "rTTIItaniumTypeInfo", 2);
  exported += session->print_predicate(facts_file, "rTTIItaniumVFTableTypeInfo", 3);
  exported += session->print_predicate(facts_file, "rTTIItaniumBaseTypeInfo", 5);
  exported += session->print_predicate(facts_file, "thisPtrAllocation", 5);
  exported += session->print_predicate(facts_file, "possibleVirtualFunctionCall", 5);
  exported += session->print_predicate(facts_file, "thisPtrDefinition", 4);
  exported += session->print_predicate(facts_file, "thisPtrOffset", 3);
  exported += session->print_predicate(facts_file, "symbolGlobalObject", 3);
  exported += session->print_predicate(facts_file, "symbolClass", 4);
  exported += session->print_predicate(facts_file, "symbolProperty", 2);
  exported += session->print_predicate(facts_file, "thunk", 3);
  exported += session->print_predicate(facts_file, "callingConvention", 2);
  exported += session->print_predicate(facts_file, "funcParameter", 3);
  exported += session->print_predicate(facts_file, "callParameter", 4);
  exported += session->print_predicate(facts_file, "callTarget", 3);

  facts_file << "% Object fact exporting complete." << std::endl;
  facts_file.close();

  GINFO << "Exported " << exported << " Prolog facts to '" << facts_filename << "'." << LEND;
}

// Wrap the private API to dump the Prolog results in a try/catch wrapper.
bool
OOSolver::dump_results()
{
  try {
    dump_results_private();
  }
  catch (const Error& error) {
    GFATAL << error.what() << LEND;
    return false;
  }
  return true;
}

void
OOSolver::dump_results_private()
{
  // This method should take a filename to write the facts to!
  std::ofstream results_file;
  results_file.open(results_filename);
  if (!results_file.is_open()) {
    GERROR << "Unable to open prolog results file '" << results_filename << "'." << LEND;
    return;
  }
  results_file << "% Prolog results autogenerated by OOAnalyzer." << std::endl;

  size_t exported = 0;

  //  session->command("break");
  exported += session->print_predicate(results_file, "finalFileInfo", 2);
  exported += session->print_predicate(results_file, "finalVFTable", 5);
  exported += session->print_predicate(results_file, "finalVFTableEntry", 3);
  exported += session->print_predicate(results_file, "finalVBTable", 4);
  exported += session->print_predicate(results_file, "finalVBTableEntry", 3);
  exported += session->print_predicate(results_file, "finalClass", 6);
  exported += session->print_predicate(results_file, "finalResolvedVirtualCall", 3);
  exported += session->print_predicate(results_file, "finalInheritance", 5);
  exported += session->print_predicate(results_file, "finalEmbeddedObject", 4);
  exported += session->print_predicate(results_file, "finalMember", 4);
  exported += session->print_predicate(results_file, "finalMemberAccess", 4);
  exported += session->print_predicate(results_file, "finalMethodProperty", 3);
  exported += session->print_predicate(results_file, "finalThunk", 2);
  exported += session->print_predicate(results_file, "finalDemangledName", 4);

  results_file << "% Object detection reporting complete." << std::endl;
  results_file.close();

  GINFO << "Exported " << exported << " Prolog results to '" << results_filename << "'." << LEND;

}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
