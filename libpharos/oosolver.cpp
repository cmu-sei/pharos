// Copyright 2016-2017 Carnegie Mellon University.  See LICENSE file for terms.
// Author: Cory Cohen

#include <boost/range/adaptor/map.hpp>

#include <rose.h>

#include "oosolver.hpp"
#include "ooanalyzer.hpp"
#include "method.hpp"
#include "usage.hpp"
#include "vcall.hpp"
#include "pdg.hpp"
#include "vftable.hpp"
#include "demangle.hpp"

namespace pharos {

using namespace prolog;

// Place enum declartion here because no-one else needs it, and if we delcare it here we can
// allocate the strings in the same place.
enum prolog_certainty_enum {
  Certain,
  Likely
};

template <>
const char *pharos::EnumStrings<prolog_certainty_enum>::data[] = {
  "certain",
  "likely"
};

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
OOSolver::OOSolver(ProgOptVarMap& vm)
{
  // Only invoke Prolog if the user specifically requested it.
  bool initialize = false;

  // This ensure that if they didn't specify
  if (vm.count("prolog-facts")) {
    facts_filename = vm["prolog-facts"].as<std::string>();
    initialize = true;
  }
  if (vm.count("prolog-results")) {
    results_filename = vm["prolog-results"].as<std::string>();
    initialize = true;
  }
  if (!initialize) return;

  try {
    session = std::make_shared<Session>(vm);
    session->consult("oorules/progress_oosolver");
    session->consult("oorules/setup");
  } catch (const Error& error) {
    OFATAL << "Unable to start Prolog session." << LEND;
    OFATAL << error.what() << LEND;
    session.reset();
  }
  if (progress_bar) {
    OFATAL << "More than one OOSolver in existence" << LEND;
    session.reset();
  }
  progress_bar.reset(new ProgressBar(olog[Sawyer::Message::MARCH], "Prolog facts"));
  session->register_predicate("progress", 1, progress, "oosolver");
}

OOSolver::~OOSolver()
{
  progress_bar.reset();
}

int OOSolver::progress()
{
  assert(progress_bar);
  using pharos::prolog::impl::arg;
  auto val = arg<size_t>(0);
  progress_bar->value(val);
  return true;
}

// The public interface to adding facts.  It's wrapped in a try/catch for more graceful
// handling of unexpected conditions.
bool
OOSolver::add_facts() {
  if (!session) return false;
  try {
    add_method_facts();
    add_vftable_facts();
    add_usage_facts();
    add_call_facts();
    add_thisptr_facts();
    add_function_facts();
    add_import_facts();
  }
  catch (const Error& error) {
    OFATAL << error.what() << LEND;
    return false;
  }
  return true;
}

// The main analysis call.  It adds facts, invokes the anlaysis, and reports the results.
bool
OOSolver::analyze() {
  if (!session) return false;
  if (!add_facts()) return false;
  if (facts_filename.size() != 0) {
    if (!dump_facts()) return false;
  }
  // The Prolog analysis will "run" as a consequence of us making queries.
  if (!import_results()) return false;
  if (results_filename.size() != 0) {
    if (!dump_results()) return false;
  }
  return true;
}

// Dump facts primarily associated with a this call method.  This currently includes object
// offsets passed to otehr methods, member accesses, and possible vftable writes.
void
OOSolver::add_method_facts()
{
  for (const ThisCallMethod& tcm : boost::adaptors::values(this_call_methods)) {
    // These aren't really correct and should be replaced with something lower level.
    if (tcm.is_constructor()) {
      session->add_fact("possibleConstructor", tcm.get_address());

      if (tcm.test_for_uninit_reads()) {
        session->add_fact("uninitializedReads", tcm.get_address());
      }
    }

    for (const FuncOffset& fo : boost::adaptors::values(tcm.passed_func_offsets)) {
      session->add_fact("funcOffset", fo.insn->get_address(),
                        tcm.get_address(), fo.tcm->get_address(), fo.offset);
    }

    for (const Member& member : boost::adaptors::values(tcm.data_members)) {
      for (const SgAsmx86Instruction* insn : member.using_instructions) {
        session->add_fact("methodMemberAccess", insn->get_address(),
                          tcm.get_address(), member.offset, member.size);
      }

      for (const VFTEvidence& vfte : member.get_vftable_evidence()) {
        rose_addr_t eaddr = vfte.insn->get_address();
        if (vfte.vftable != NULL) {
          VirtualFunctionTable* vftab = vfte.vftable;
          session->add_fact("possibleVFTableWrite", eaddr, tcm.get_address(),
                            member.offset, vftab->addr);
        }
        if (vfte.vbtable != NULL) {
          VirtualBaseTable* vbtab = vfte.vbtable;
          session->add_fact("possibleVBTableWrite", eaddr, tcm.get_address(),
                            member.offset, vbtab->addr);
        }
      }
    }
  }
}

// Dump facts primarily associated with virtual function tables (the entries and the RTTI
// information).
void
OOSolver::add_vftable_facts()
{
  size_t arch_bytes = global_descriptor_set->get_arch_bytes();
  for (const VirtualFunctionTable* vft : boost::adaptors::values(global_vftables)) {
    size_t e = 0;
    while (true) {
      rose_addr_t eaddr = vft->read_entry(e);
      if (!(global_descriptor_set->memory_in_image(eaddr))) {
        break;
      }
      size_t offset = e * arch_bytes;

      // Convert the entry in the vftable to the end of the thunk chain (if the chain ends in a
      // real function), otherwise just leave the address that actually appeared in the table.
      // It unclear if this is really the correct thing to do.  There are occasionally cases
      // where a function gets optimized to a thunk (not because of debugging or incremental
      // linking).  For example 0x401940 in 10/Lite/ooex7 _Yarn::~_Yarn() becomes a thunk to
      // _Yarn::_Tidy().  If these cases turn out to be important for proper reasoning about
      // vftables, we'll probably have to export thunk facts -- which would be a nuisance.

      // First get the function descriptor for the function at the entry address.
      FunctionDescriptor* efd = global_descriptor_set->get_func(eaddr);
      if (efd != NULL) {
        // And then the function that we eventually jump to.
        FunctionDescriptor* epfd = efd->get_jmp_fd();
        // And if all of that went smoothly, replace the eaddr with this function.
        if (epfd != NULL) eaddr = epfd->get_address();
      }

      session->add_fact("possibleVFTableEntry", vft->addr, offset, eaddr);
      e++;
    }

    if (vft->rtti != NULL) {
      add_rtti_facts(vft);
    }
  }

  for (const VirtualBaseTable* vbt : boost::adaptors::values(global_vbtables)) {
    for (size_t e = 0; e < vbt->size; e++) {
      signed int value = vbt->read_entry(e);
      size_t offset = e * arch_bytes;
      session->add_fact("possibleVBTableEntry", vbt->addr, offset, value);
    }
  }
}

void
OOSolver::add_rtti_facts(const VirtualFunctionTable* vft)
{
  if (vft->rtti_confidence == ConfidenceNone) return;

  const TypeRTTICompleteObjectLocator *rtti = vft->rtti;

  // Check for --ignore-rtti option?
  if (rtti->signature.value != 0) return;
  if (rtti->class_desc.signature.value != 0) return;

  if (visited.find(vft->rtti_addr) == visited.end()) {
    session->add_fact("rTTICompleteObjectLocator", vft->rtti_addr, rtti->address,
                      rtti->pTypeDescriptor.value, rtti->pClassDescriptor.value,
                      rtti->offset.value, rtti->cdOffset.value);
    visited.insert(vft->rtti_addr);
  }

  if (visited.find(rtti->pTypeDescriptor.value) == visited.end()) {
    session->add_fact("rTTITypeDescriptor", rtti->pTypeDescriptor.value,
                      rtti->type_desc.pVFTable.value, rtti->type_desc.name.value);
    visited.insert(rtti->pTypeDescriptor.value);
  }

  if (visited.find(rtti->pClassDescriptor.value) == visited.end()) {
    add_rtti_chd_facts(rtti->pClassDescriptor.value);
  }
}

void
OOSolver::add_rtti_chd_facts(const rose_addr_t addr)
{
  visited.insert(addr);
  try {
    TypeRTTIClassHierarchyDescriptor chd;
    chd.read(addr);

    std::vector<uint32_t> base_addresses;
    for (const TypeRTTIBaseClassDescriptor& base : chd.base_classes) {
      if (visited.find(base.address) == visited.end()) {
        session->add_fact("rTTIBaseClassDescriptor", base.address,
                          base.pTypeDescriptor.value, base.numContainedBases.value,
                          base.where_mdisp.value, base.where_pdisp.value,
                          base.where_vdisp.value, base.attributes.value,
                          base.pClassDescriptor.value);
        visited.insert(base.address);

        // This is where we read and export facts for the undocumented "sub-chd".
        if (visited.find(base.pClassDescriptor.value) == visited.end()) {
          add_rtti_chd_facts(base.pClassDescriptor.value);
        }
      }

      if (visited.find(base.pTypeDescriptor.value) == visited.end()) {
        session->add_fact("rTTITypeDescriptor", base.pTypeDescriptor.value,
                          base.type_desc.pVFTable.value, base.type_desc.name.value);
        visited.insert(base.pTypeDescriptor.value);
      }

      base_addresses.push_back(base.address);
    }

    session->add_fact("rTTIClassHierarchyDescriptor", addr,
                      chd.attributes.value, base_addresses);
  }
  catch (...) {
    GDEBUG << "RTTI Class Hierarchy Descriptor was bad at " << addr_str(addr) << LEND;
  }
}

// Dump facts primarily associated with object usage, which are effectively grouped by the
// function that they occur in.  Dominace relationships are also dumped here because we're only
// dumping dominance information for instructions involved in method evidence.  That might
// result in duplicate assertions and further it might be insufficient for some advanced
// reasoning about vtable reads and writes.   Changes may be required in the future.
void
OOSolver::add_usage_facts()
{
  AddrSet cfgs;

  for (const ObjectUse& obj_use : boost::adaptors::values(object_uses)) {
    rose_addr_t func_addr = obj_use.fd->get_address();

    for (const ThisPtrUsage& tpu : boost::adaptors::values(obj_use.references)) {
      // Report where this object was allocated.
      if (tpu.alloc_insn != NULL) {
        // Report relationships for the this-pointer later.
        thisptrs.insert(tpu.this_ptr->get_expression());
        // Report the allocation fact now though.
        std::string thisptr_term = "thisptr_" + std::to_string(tpu.this_ptr->get_hash());
        session->add_fact("thisPtrAllocation", tpu.alloc_insn->get_address(), func_addr,
                          thisptr_term, "type_" + Enum2Str(tpu.alloc_type), tpu.alloc_size);
      }

      // Export facts for the the control flow graph if we haven't already.
      rose_addr_t faddr = obj_use.fd->get_address();
      if (cfgs.find(faddr) == cfgs.end()) {
        CFG& cfg = obj_use.fd->get_cfg();

        // For each vertex in the control flow graph.
        for (const CFGVertex& vertex : cfg_vertices(cfg)) {
          SgAsmBlock *bb = get(boost::vertex_name, cfg, vertex);
          const SgAsmInstruction* lastinsn = last_insn_in_block(bb);
          if (!lastinsn) continue;

          // For each vertex connected via an out edge...
          for (const SgAsmBlock *sbb : cfg_out_bblocks(cfg, vertex)) {
            const SgAsmInstruction* slastinsn = last_insn_in_block(sbb);
            if (!slastinsn) continue;

            // Export a fact saying the last instruction in the outer loop preceeds the last
            // instruction in the inner loop.  We use the last instruction rather than the
            // first instruction beacuse it makes it easier to correlate these facts with the
            // call instructons (that are always last in the block?)
            session->add_fact("preceeds", lastinsn->get_address(), slastinsn->get_address());
          }
        }

        // Mark the function as having an exported control flow graph.
        cfgs.insert(faddr);
      }

      for (const MethodEvidenceMap::value_type& mepair : tpu.get_method_evidence()) {
        SgAsmInstruction* meinsn = mepair.first;
        rose_addr_t meaddr = meinsn->get_address();

        // Report relationships for the this-pointer later.
        thisptrs.insert(tpu.this_ptr->get_expression());
        // Each instruction references multiple methods, since the call have multiple targets.
        for (const ThisCallMethod* called : mepair.second) {
          std::string thisptr_term = "thisptr_" + std::to_string(tpu.this_ptr->get_hash());
          session->add_fact("thisPtrUsage", meaddr, func_addr,
                            thisptr_term, called->get_address());
        }
      }
    }
  }
}

// Dump facts primarily associated with each call instruction in the program.
void
OOSolver::add_call_facts()
{
  CallDescriptorMap& call_map = global_descriptor_set->get_call_map();
  for (const CallDescriptor& cd : boost::adaptors::values(call_map)) {

    // For each target of the call, consider whether it calls operator delete().
    for (rose_addr_t target : cd.get_targets()) {
      FunctionDescriptor* tfd = global_descriptor_set->get_func(target);
      if (tfd && tfd->is_delete_method()) {
        session->add_fact("insnCallsDelete", cd.get_address());
      }
      ImportDescriptor* id = global_descriptor_set->get_import(target);
      if (id && id->is_delete_method()) {
        session->add_fact("insnCallsDelete", cd.get_address());
      }
    }

    // We're only interested in virtual calls.
    if (cd.get_call_type() != CallVirtualFunction) continue;

    CallInformationPtr ci = cd.get_call_info();
    VirtualFunctionCallInformationPtr vci =
      boost::dynamic_pointer_cast<VirtualFunctionCallInformation>(ci);

    FunctionDescriptor* inside = cd.get_containing_function();

    // Report relationships for the this-pointer later.
    thisptrs.insert(vci->obj_ptr->get_expression());
    // Report the virtual call fact now.
    std::string thisptr_term = "thisptr_" + std::to_string(vci->obj_ptr->get_hash());
    session->add_fact("possibleVirtualFunctionCall", cd.get_address(),
                      inside->get_address(), thisptr_term,
                      vci->vtable_offset, vci->vfunc_offset);
  }
}

// Report relationships between this-pointers.
void
OOSolver::add_thisptr_facts()
{
  for (const TreeNodePtr& thisptr : thisptrs) {
    AddConstantExtractor ace(thisptr);
    // Signed integer conversion, because we want to exclude unreasonably large offsets.
    int constant = ace.constant_portion();
    if (constant > 0 && ace.well_formed()) {
      std::string thisptr_term = "thisptr_" + std::to_string(thisptr->hash());
      const TreeNodePtr& varptr = ace.variable_portion();
      std::string variable_term = "thisptr_" + std::to_string(varptr->hash());
      session->add_fact("thisPtrOffset", variable_term, constant, thisptr_term);
    }
  }
}

// Report facts about functions (like purecall).
void
OOSolver::add_function_facts()
{
  FunctionDescriptorMap& fdmap = global_descriptor_set->get_func_map();
  for (FunctionDescriptor& fd : boost::adaptors::values(fdmap)) {
    if (fd.is_purecall_method()) {
      session->add_fact("purecall", fd.get_address());
    }
  }
}

// Report facts about functions (like purecall).
void
OOSolver::add_import_facts()
{
  ImportDescriptorMap& idmap = global_descriptor_set->get_import_map();
  for (ImportDescriptor& id : boost::adaptors::values(idmap)) {
    try {
      DemangledTypePtr dtype = visual_studio_demangle(id.get_name());
      if (!dtype) continue;

      // Emit something for imported global objects.  I don't know what to do with this yet,
      // but we should emit something as a reminder.
      if (dtype->symbol_type == SymbolType::GlobalObject ||
          dtype->symbol_type == SymbolType::StaticClassMember) {

        std::string clsname = dtype->get_class_name();
        std::string varname = dtype->str_name_qualifiers(dtype->instance_name);

        session->add_fact("symbolGlobalObject", id.get_address(), clsname, varname);

        // And we're done with this import.
        continue;
      }

      // From this point forward, we're only interested in class methods.
      if (dtype->symbol_type != SymbolType::ClassMethod) continue;

      std::string clsname = dtype->get_class_name();
      std::string method_name = dtype->get_method_name();

      if (clsname.size() > 0) {
        session->add_fact("symbolClass", id.get_address(), clsname, method_name);

        if (dtype->is_ctor) {
          session->add_fact("symbolProperty", id.get_address(), Constructor);
        }

        if (dtype->is_dtor) {
          session->add_fact("symbolProperty", id.get_address(), RealDestructor);
        }

        // Obviously would could do much better here, since we can identify a wide variety of
        // special purpose methods (e.g. operators) by inspecting the names.  I propose that we
        // should add those features only if they're in support of figuring out comparable facts
        // without symbols (as we have for deleting destructors).
        if (dtype->method_name == "`vector deleting destructor'" ||
            dtype->method_name == "`scalar deleting destructor'") {
          session->add_fact("symbolProperty", id.get_address(), DeletingDestructor);
        }

        if (dtype->method_property == MethodProperty::Virtual) {
          session->add_fact("symbolProperty", id.get_address(), Virtual);
        }
      }
    }
    catch (const DemanglerError & e) {
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
    OFATAL << error.what() << LEND;
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
    OERROR << "Unable to open prolog facts file '" << facts_filename << "'." << LEND;
    return;
  }
  facts_file << "% Prolog facts autogenerated by Objdigger." << std::endl;

  size_t exported = 0;

  exported += session->print_predicate(facts_file, "possibleConstructor", 1);
  exported += session->print_predicate(facts_file, "uninitializedReads", 1);
  exported += session->print_predicate(facts_file, "insnCallsDelete", 1);
  exported += session->print_predicate(facts_file, "purecall", 1);
  exported += session->print_predicate(facts_file, "funcOffset", 4);
  exported += session->print_predicate(facts_file, "methodMemberAccess", 4);
  exported += session->print_predicate(facts_file, "possibleVFTableWrite", 4);
  exported += session->print_predicate(facts_file, "possibleVFTableEntry", 3);
  exported += session->print_predicate(facts_file, "possibleVBTableWrite", 4);
  exported += session->print_predicate(facts_file, "possibleVBTableEntry", 3);
  exported += session->print_predicate(facts_file, "rTTICompleteObjectLocator", 6);
  exported += session->print_predicate(facts_file, "rTTITypeDescriptor", 3);
  exported += session->print_predicate(facts_file, "rTTIClassHierarchyDescriptor", 3);
  exported += session->print_predicate(facts_file, "rTTIBaseClassDescriptor", 8);
  exported += session->print_predicate(facts_file, "thisPtrAllocation", 5);
  exported += session->print_predicate(facts_file, "thisPtrUsage", 4);
  exported += session->print_predicate(facts_file, "possibleVirtualFunctionCall", 5);
  exported += session->print_predicate(facts_file, "thisPtrOffset", 3);
  exported += session->print_predicate(facts_file, "preceeds", 2);
  exported += session->print_predicate(facts_file, "symbolGlobalObject", 3);
  exported += session->print_predicate(facts_file, "symbolClass", 3);
  exported += session->print_predicate(facts_file, "symbolProperty", 2);

  facts_file << "% Object fact exporting complete." << std::endl;
  facts_file.close();

  OINFO << "Exported " << exported << " Prolog facts to '" << facts_filename << "'." << LEND;
}

// Wrap the private API to dump the Prolog results in a try/catch wrapper.
bool
OOSolver::dump_results()
{
  try {
    dump_results_private();
  }
  catch (const Error& error) {
    OFATAL << error.what() << LEND;
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
    OERROR << "Unable to open prolog results file '" << results_filename << "'." << LEND;
    return;
  }
  results_file << "% Prolog results autogenerated by Objdigger." << std::endl;

  size_t exported = 0;

  OINFO << "Analyzing object oriented data structures..." << LEND;
#if ENABLE_PROLOG_DEBUGGING
  session->command("assert(debuggingEnabled).");
#endif
#if ENABLE_PROLOG_TRACING
  session->command("debug_ctl(profile, on).");
  session->command("debug_ctl(prompt, off).");
  session->command("debug_ctl(leash, []).");
  session->command("debug_ctl(hide, [rootint/2]).");
  session->command("trace");
#endif
  auto query = session->query("solve");
  if (query->done()) {
    OERROR << "The solution found is not internally consistent and may have significant errors!" << LEND;
  }
#if ENABLE_PROLOG_TRACING
  session->command("notrace");
#endif

  //  session->command("break");
  exported += session->print_predicate(results_file, "finalVFTable", 5);
  exported += session->print_predicate(results_file, "finalClass", 6);
  exported += session->print_predicate(results_file, "finalResolvedVirtualCall", 3);
  exported += session->print_predicate(results_file, "finalInheritance", 5);
  exported += session->print_predicate(results_file, "finalEmbeddedObject", 4);
  exported += session->print_predicate(results_file, "finalMember", 4);
  exported += session->print_predicate(results_file, "finalMemberAccess", 4);
  exported += session->print_predicate(results_file, "finalMethodProperty", 3);
  exported += session->print_predicate(results_file, "finalUncertainName", 1);

  results_file << "% Object detection reporting complete." << std::endl;
  results_file.close();

  OINFO << "Exported " << exported << " Prolog results to '" << results_filename << "'." << LEND;
}

// The public interface to importing results back into C++ classes.  It's wrapped in a
// try/catch for more graceful handling of unexpected conditions.
bool
OOSolver::import_results() {
  if (!session) return false;
  try {
    // This is where multiple calls to real mehtods to import results will go.
  }
  catch (const Error& error) {
    OFATAL << error.what() << LEND;
    return false;
  }
  return true;
}


} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
