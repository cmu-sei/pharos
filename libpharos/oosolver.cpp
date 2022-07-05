// Copyright 2016-2021 Carnegie Mellon University.  See LICENSE file for terms.
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

// C++ data structures
#include "ooelement.hpp"
#include "ooclass.hpp"
#include "oomethod.hpp"
#include "oomember.hpp"
#include "oovftable.hpp"

namespace bf = boost::filesystem;

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
    session->add_fact("fileInfo", ds.get_filemd5(), ds.get_filename());
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

// The main analysis call.  It adds facts, invokes the anlaysis, and reports the results.
bool
OOSolver::analyze(const OOAnalyzer& ooa) {
  if (!session) return false;
  if (!add_facts(ooa)) return false;
  if (facts_filename.size() != 0) {
    if (!dump_facts()) return false;
  }

  if (perform_analysis) {
    // The Prolog analysis will "run" as a consequence of us making queries.
    if (!import_results()) {
      GERROR << "Failed to import object oriented results into Pharos." << LEND;
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

    // Hackish forced exporting of "thisptr" arguments as register "ECX".  There's a difference
    // between how the thisptr symbolic values are being determined for thiscall methods, and
    // how it's being determined for function calling conventions in general.  By exporting the
    // facts related to this defect in a way that draws more attention to the real problem that
    // then old thisCallMethod facts, we can narrow in on the real problem gradually.  It's
    // also not accetpable to export a normal callingConvention fact and normal funcParameter
    // fact, as this results in non-OO functions
    auto conventions = tcm->fd->get_calling_conventions();
    if (conventions.size() == 0) {
      session->add_fact("callingConvention", tcm->get_address(), "invalid");
      session->add_fact("funcParameter", tcm->get_address(), "ecx", thisptr_term);
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
  for (auto const & vft : boost::adaptors::values(vftables)) {
    size_t e = 0;
    while (true) {
      rose_addr_t value = vft->read_entry(e);
      if (!(ooa.ds.memory.is_mapped(value))) {
        break;
      }
      rose_addr_t eaddr = vft->addr + (e * arch_bytes);

      // Skip this entry if it's already been proccessed.
      auto finder = exported.find(eaddr);
      if (finder != exported.end()) break;
      exported.insert(eaddr);

      // We used to follow thunks and export the dethunked entry, but it turns out that thunks
      // sometimes play an important role if differentiating functions, especially in vftable
      // entries.  A common scenario is for the compiler to create two different thunks jumping
      // to the same method implementation, and to put the distinct thunks in the vftable.  If
      // we've exported thunk facts to Prolog, we can sort that out correctly, and identify
      // that the single implementation is a shared implementation.

      session->add_fact("initialMemory", eaddr, value);
      e++;
    }

    if (vft->rtti) {
      add_rtti_facts(vft.get());
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
}

void
OOSolver::add_rtti_facts(const VirtualFunctionTable* vft)
{
  if (vft->rtti_confidence == ConfidenceNone) return;

  const TypeRTTICompleteObjectLocatorPtr rtti = vft->rtti;

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
    add_rtti_chd_facts(rtti->pClassDescriptor.value);
  }
}

void
OOSolver::add_rtti_chd_facts(const rose_addr_t addr)
{
  visited.insert(addr);
  try {
    TypeRTTIClassHierarchyDescriptor chd{ds.memory};
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

        // This is where we read and export facts for the undocumented "sub-chd", but only if
        // the base.attributes flag has bit 0x40 set, which indicates that optional pointer is
        // present.
        if (base.attributes.value & 0x40 &&
            visited.find(base.pClassDescriptor.value) == visited.end()) {
          add_rtti_chd_facts(base.pClassDescriptor.value);
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

    session->add_fact("rTTIClassHierarchyDescriptor", addr,
                      chd.attributes.value, base_addresses);
  }
  catch (std::exception &e) {
    GERROR << "RTTI Class Hierarchy Descriptor was bad at " << addr_str(addr) << ": " << e.what () << LEND;
  }
  catch (...) {
    GERROR << "RTTI Class Hierarchy Descriptor was bad at " << addr_str(addr) << LEND;
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

// Dump facts primarily associated with each call instruction in the program.
void
OOSolver::add_call_facts(const OOAnalyzer& ooa)
{
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
      if (expr->isIntegerConstant()) {
        if (expr->nBits() > 64) continue;
        if (ooa.ds.get_global(*expr->toUnsigned()) == NULL) continue;
      }

      // If the expression is of the form ite(cond value 0), extract just the non-NULL part of
      // the value.  See additional commentary in usage.cpp for more background.
      expr = pick_non_null_expr(expr);

      std::string term = "sv_" + std::to_string(expr->hash());
      if (cpd.is_reg()) {
        std::string regname = unparseX86Register(cpd.get_register(), NULL);
        session->add_fact("callParameter", cd.get_address(),
                          callfunc->get_address(), regname, term);
      }
      else {
        session->add_fact("callParameter", cd.get_address(),
                          callfunc->get_address(), cpd.get_num(), term);
      }
    }

    // Report all parameters for every function (in the future we'll try using an OO subset)
    auto creturns = call_params.get_returns();
    for (const ParameterDefinition& cpd : creturns) {
      if (!cpd.get_value()) continue;
      TreeNodePtr expr = cpd.get_value()->get_expression();
      if (!expr) continue;
      // If the expression is a constant and not a global variable we do not want to export it.
      if (expr->isIntegerConstant()) {
        if (expr->nBits() > 64) continue;
        if (ooa.ds.get_global(*expr->toUnsigned()) == NULL) continue;
      }
      std::string term = "sv_" + std::to_string(expr->hash());
      if (cpd.is_reg()) {
        std::string regname = unparseX86Register(cpd.get_register(), NULL);
        session->add_fact("callReturn", cd.get_address(), callfunc->get_address(), regname, term);
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
    // different classes, even if they jump to the same function.
    if (fd.is_thunk()) {
      session->add_fact("thunk", fdaddr, fd.get_jmp_addr());
    }

    // Report all calling conventions for all functions.
    auto conventions = fd.get_calling_conventions();
    for (const CallingConvention* cc: conventions) {
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
        std::string regname = unparseX86Register(fpd.get_register(), NULL);
        session->add_fact("funcParameter", fdaddr, regname, term);
      }
      else {
        session->add_fact("funcParameter", fdaddr, fpd.get_num(), term);
      }
    }

    // Report all parameters for every function (in the future we'll try using an OO subset)
    auto freturns = func_params.get_returns();
    for (const ParameterDefinition& fpd : freturns) {
      if (!fpd.get_value()) continue;
      TreeNodePtr expr = fpd.get_value()->get_expression();
      if (!expr) continue;
      // If the expression is a constant and not a global variable we do not want to export it.
      if (expr->isIntegerConstant()) {
        if (expr->nBits() > 64) continue;
        if (ooa.ds.get_global(*expr->toUnsigned()) == NULL) continue;
      }
      std::string term = "sv_" + std::to_string(expr->hash());
      if (fpd.is_reg()) {
        std::string regname = unparseX86Register(fpd.get_register(), NULL);
        session->add_fact("funcReturn", fdaddr, regname, term);
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

  exported += session->print_predicate(facts_file, "fileInfo", 2);
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
  exported += session->print_predicate(facts_file, "initialMemory", 2);
  exported += session->print_predicate(facts_file, "rTTICompleteObjectLocator", 6);
  exported += session->print_predicate(facts_file, "rTTITypeDescriptor", 4);
  exported += session->print_predicate(facts_file, "rTTIClassHierarchyDescriptor", 3);
  exported += session->print_predicate(facts_file, "rTTIBaseClassDescriptor", 8);
  exported += session->print_predicate(facts_file, "thisPtrAllocation", 5);
  exported += session->print_predicate(facts_file, "possibleVirtualFunctionCall", 5);
  exported += session->print_predicate(facts_file, "thisPtrDefinition", 4);
  exported += session->print_predicate(facts_file, "thisPtrOffset", 3);
  exported += session->print_predicate(facts_file, "symbolGlobalObject", 3);
  exported += session->print_predicate(facts_file, "symbolClass", 4);
  exported += session->print_predicate(facts_file, "symbolProperty", 2);
  exported += session->print_predicate(facts_file, "thunk", 2);
  exported += session->print_predicate(facts_file, "callingConvention", 2);
  exported += session->print_predicate(facts_file, "funcParameter", 3);
  exported += session->print_predicate(facts_file, "funcReturn", 3);
  exported += session->print_predicate(facts_file, "callParameter", 4);
  exported += session->print_predicate(facts_file, "callReturn", 4);
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

std::vector<OOClassDescriptorPtr>&
OOSolver::get_classes() {
  return classes;
}

std::string
OOSolverAnalysisPass::get_name() {
  return pass_name_;
}

void
OOSolverAnalysisPass::set_name(std::string n) {
  pass_name_ = n;
}

void
OOSolverAnalysisPassRunner::add_pass(std::shared_ptr<OOSolverAnalysisPass> p) {
  passes_.push_back(p);
}

void
OOSolverAnalysisPassRunner::run() {

  if (solver_) {
    std::vector<OOClassDescriptorPtr>& classes = solver_->get_classes();
    for (auto pass : passes_) {
      GDEBUG << "Running pass: " << pass->get_name() << " ... " << LEND;
      if (!pass->solve(classes)) GWARN << " Pass failed" << LEND;
      else GDEBUG << "Pass completeed successfully" << LEND;
    }
  }
}

bool
SolveClassesFromProlog::solve(std::vector<OOClassDescriptorPtr>& classes) {

  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
  // finalClass(ClassID, VFTable, CSize, LSize, RealDestructor, MethodList)
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
  rose_addr_t cid, vft, dtor;
  size_t csize;
  std::vector<rose_addr_t> method_list;

  auto class_query = session_->query("finalClass",
                                     var(cid),
                                     var(vft),
                                     var(csize),
                                     any(), // we'll use the certain size for now
                                     var(dtor),
                                     var(method_list));
  // populate the master class list
  while (!class_query->done()) {
    OOClassDescriptorPtr new_cls = std::make_shared<OOClassDescriptor>(
      cid, vft, csize, dtor, method_list, ds);
    classes.push_back(new_cls);
    GDEBUG << "Adding class: " << new_cls->get_name() << LEND;
    class_query->next();
  }
  GDEBUG << "generated class list with " << classes.size() << " entries." << LEND;

  return true;
}


bool
SolveInheritanceFromProlog::solve(std::vector<OOClassDescriptorPtr>& classes) {

  // Add inheritance relationship elements ... we have to do it this way because of prolog
  // restrictions on how many queries can be run simultaneously (spoiler alert: the answer is
  // one)

  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
  // finalInheritance(DerivedClassID, BaseClassID, ObjectOffset, VFTable, Virtual)
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

  rose_addr_t derived_id, base_id, derived_vft;
  size_t obj_offset;

  auto parent_query = session_->query("finalInheritance",
                                      var(derived_id),
                                      var(base_id),
                                      var(obj_offset),
                                      var(derived_vft),
                                      any() // disregard virtual property because it's new?
    );

  while (!parent_query->done()) {

    OOClassDescriptorPtr derived=NULL, base=NULL;

    auto dit = std::find_if(classes.begin(), classes.end(),
                            [derived_id](OOClassDescriptorPtr cls)
                            { return cls->get_id() == derived_id; });
    if (dit != classes.end()) {
      derived = *dit;
    }

    auto bit = std::find_if(classes.begin(), classes.end(),
                            [base_id](OOClassDescriptorPtr cls)
                            { return cls->get_id() == base_id; });
    if (bit != classes.end()) {
      base = *bit;
    }

    if (derived && base) {
      // Add the parent as a shared pointer
      derived->add_parent(obj_offset, base);

      GDEBUG << "Adding parent: Derived="
             << derived->get_name() << ", Base=" << base->get_name()
             << " @ " << addr_str(obj_offset) << LEND;

      // To quote Cory: "If the base class is not the first base class (non-zero offset) and the
      // base class has a virtual function table, the VFTable field will contain the derived
      // class instance of that virtual function table."

      if (derived_vft && obj_offset!=0) {
        derived->add_vftable(obj_offset, derived_vft);
      }
    }
    parent_query->next();
  }

  return true;
}

bool
SolveVFTableFromProlog::solve(std::vector<OOClassDescriptorPtr>& classes) {

  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
  // finalVFTable(VFTable, CertainSize, LikelySize, RTTIAddress, RTTIName)
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

  // Now fill in the details for the virtual function tables via prolog
  rose_addr_t vft_addr, rtti_addr;
  size_t vft_size;
  std::string rtti_name;
  auto vft_query = session_->query("finalVFTable",
                                   var(vft_addr),
                                   var(vft_size),
                                   any(),
                                   var(rtti_addr),
                                   var(rtti_name));

  while (!vft_query->done()) {
    GDEBUG << "Prolog returned VFTable " << addr_str(vft_addr) << " with size " << addr_str(vft_size) << LEND;

    bool found = false;
    for (OOClassDescriptorPtr cls : classes) {
      for (OOVirtualFunctionTablePtr v : cls->get_vftables()) {
        if (v->get_address() == vft_addr) {
          found = true;

          GDEBUG << "Assigned " << addr_str(vft_addr) << " to class " << addr_str(cls->get_id()) << LEND;
          v->set_size(vft_size);

          v->set_rtti(rtti_addr, read_RTTI(ds, rtti_addr));

          // If the class ID is not the vftable address, then either the vftable is not the
          // primary one OR it is claimed by multiple classes and we should not use its name.
          // Without this check we can get duplicate json keys.
          if (cls->get_id() == v->get_address()) {

            // set the class name based on RTTI
            if (rtti_name.size() > 0) {
              GDEBUG << "Renaming " << cls->get_name() << " to " << rtti_name << LEND;
              cls->set_name(rtti_name);

              // Attempt to set the demangled name too
              try {
                auto dtype = demangle::visual_studio_demangle(rtti_name);
                cls->set_demangled_name(dtype->get_class_name());
              } catch (const demangle::Error &e) {
                GWARN << "Unable to demangle RTTI Class name " << rtti_name
                      << ": " << e.what () << LEND;
              }

              GDEBUG << "Found RTTI name for "
                     <<  addr_str(cls->get_id()) << " = " << cls->get_name() << LEND;
            }
          }
          // We won't find the same vftable twice in a class
          break;
        }
      }
    }

    if (!found) {
      GDEBUG << "Unable to find VFTable " << addr_str(vft_addr) << " in imported classes." << LEND;
    }

    vft_query->next();
  }
  return true;
}

bool
SolveMemberAccessFromProlog::solve(std::vector<OOClassDescriptorPtr>& classes) {

  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
  // finalMemberAccess(Class, Offset, Size, EvidenceList)
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

  size_t mbr_cid, mbr_off, mbr_size;
  std::vector<rose_addr_t> mbr_evidence;

  // Add tradtional (primative) class members
  auto mbr_access_query = session_->query("finalMemberAccess",
                                          var(mbr_cid),
                                          var(mbr_off),
                                          var(mbr_size),
                                          var(mbr_evidence));
  while (!mbr_access_query->done()) {

    auto mit = std::find_if(classes.begin(), classes.end(),
                            [mbr_cid](OOClassDescriptorPtr cls)
                            { return cls->get_id() == mbr_cid; });

    if (mit != classes.end()) {
      OOClassDescriptorPtr cls = *mit;

      // ingest the new member evidence as a set of instructions, not addresses
      InsnSet insn_evidence;
      std::stringstream ss;

      // convert evidence from instructions to addresses
      for (rose_addr_t a : mbr_evidence) {
        SgAsmInstruction* i = ds.get_insn(a);
        if (i) {
          insn_evidence.insert(i);
          ss << addr_str(i->get_address()) << " ";
        }
      }

      // If the member doesn't exist, we need to create it.  There are "member accesses" for
      // members that are not explicitly on the class.  This occurs because there can be
      // derived methods that access members in the base class.
      OOElementPtr existing_elm = cls->member_at(mbr_off);
      if (!existing_elm) {
        OOElementPtr elm = std::make_shared<OOMember>(mbr_size, insn_evidence);
        // Mark the member as being on a base/embedded class.
        elm->set_exactly(false);
        cls->add_member(mbr_off, elm);
      }
      else {
        // this is a traditional member because that is what prolog reports for this query
        // OOMemberPtr existing_mbr = std::dynamic_pointer_cast<OOMember>(existing_elm);

        existing_elm->add_evidence(insn_evidence);

        // Only override the size if it is less than what is previously reported. In other
        // words, the biggest size wins
        if (existing_elm->get_size() < mbr_size) {

          GDEBUG << "Class member: "<< cls->get_name() << " @ " << addr_str(mbr_off)
                 << " has a conflicting size with access, previous size=" << existing_elm->get_size()
                 << " access size=" << mbr_size << LEND;

          existing_elm->set_size(mbr_size);
        }
        GDEBUG << "Updating member on " << cls->get_name() << " @ " << addr_str(mbr_off)
               << " as " << existing_elm->get_name() << " evidence=" << ss.str() << LEND;
      }
    }
    mbr_access_query->next();
  }
  return true;
}

bool
SolveMemberFromProlog::solve(std::vector<OOClassDescriptorPtr>& classes) {

  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
  // finalMember(Class, Offset, Size, EvidenceList)
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

  size_t mbr_cid, mbr_off;
  std::vector<size_t>mbr_sizes;

  // Add tradtional (primative) class members
  auto mbr_query = session_->query("finalMember",
                                   var(mbr_cid),
                                   var(mbr_off),
                                   var(mbr_sizes),
                                   any());
  while (!mbr_query->done()) {

    auto mit = std::find_if(classes.begin(), classes.end(),
                            [mbr_cid](OOClassDescriptorPtr cls)
                            { return cls->get_id() == mbr_cid; });

    if (mit != classes.end()) {
      OOClassDescriptorPtr cls = *mit;

      // for now, we will just use the biggest size. I'm sure this will change
      auto sit = max_element(mbr_sizes.begin(), mbr_sizes.end());
      size_t selected_size = *sit;

      // Embedded object and inherited bases are not listed again as finalMembers.  Instead
      // they are list in the finalEmbeddedObject and finalInheritance results.
      OOElementPtr elm = std::make_shared<OOMember>(selected_size);

      cls->add_member(mbr_off, elm);

      GDEBUG << "Adding new member to " << cls->get_name() << " @ " << addr_str(mbr_off)
             << " as " << elm->get_name() << LEND;
    }
    mbr_query->next();
  }
  return true;
}

bool
SolveEmbeddedObjFromProlog::solve(std::vector<OOClassDescriptorPtr>& classes) {

  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
  // finalEmbeddedObject(OuterClass, Offset, EmbeddedClass, likely)
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

  rose_addr_t out_cid, emb_cid;
  size_t emb_off;

  OOClassDescriptorPtr outer=NULL, embedded=NULL;
  auto emb_obj_query = session_->query("finalEmbeddedObject",
                                       var(out_cid),
                                       var(emb_off),
                                       var(emb_cid),
                                       any());
  while (!emb_obj_query->done()) {

    // look up the outer class by id
    auto oit = std::find_if(classes.begin(),
                            classes.end(),
                            [out_cid](OOClassDescriptorPtr cls)
                            { return out_cid == cls->get_id(); });

    if (oit != classes.end()) {
      outer = *oit;
    }

    // look up the embedded class by id
    auto eit = std::find_if(classes.begin(),
                            classes.end(),
                            [emb_cid](OOClassDescriptorPtr cls)
                            { return emb_cid == cls->get_id(); });

    if (eit != classes.end()) {
      embedded = *eit;
    }

    if (outer && embedded) {
      OOElementPtr emb_elm = embedded;
      emb_elm->set_size(embedded->get_size());
      outer->add_member(emb_off, emb_elm);

      GDEBUG << "Adding embedded object member " << emb_elm->get_name()
             << " to " << outer->get_name() << "@ " << addr_str(emb_off) << LEND;
    }
    emb_obj_query->next();
  }
  return true;
}

bool
SolveMethodPropertyFromProlog::solve(std::vector<OOClassDescriptorPtr>& classes) {

  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
  // finalMethodProperty(Method, constructor|deletingDestructor|realDestructor|virtual, certain)
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-


  // This query should not add new methods to the class, rather it should update existing
  // methods on a class

  for (OOClassDescriptorPtr cls : classes) {
    for (OOMethodPtr meth : cls->get_methods()) {

      std::string meth_prop;
      auto meth_query = session_->query("finalMethodProperty",
                                        meth->get_address(),
                                        var(meth_prop),
                                        any());
      while (!meth_query->done()) {

        if (meth_prop == "virtual") {
          meth->set_virtual(true);

          // find the vftable that this virtual function resides in, and add it at the right
          // offset
          for (OOVirtualFunctionTablePtr vftbl : cls->get_vftables()) {

            GDEBUG << "Processing vftable " << addr_str(vftbl->get_address()) << LEND;

            size_t arch_bytes = ds.get_arch_bytes();
            size_t table_size = vftbl->get_size() / ds.get_arch_bytes();
            for (size_t offset=0; offset<table_size; offset++) {

              rose_addr_t faddr = ds.memory.read_address(
                vftbl->get_address()+(offset*arch_bytes));

              // Handle thunks ... sigh
              const FunctionDescriptor *f = ds.get_func(faddr);
              if (f) {
                if (f->is_thunk()) faddr = f->get_jmp_addr();

                GDEBUG << "faddr=" << addr_str(faddr)
                       << ", meth->get_address()="
                       << addr_str(meth->get_address()) << LEND;

                if (faddr == meth->get_address() ) {
                  vftbl->add_virtual_function(OOVirtualFunctionTableEntry(offset, meth));

                  GDEBUG << "Added virtual function " << addr_str(meth->get_address())
                          << " to vftable " << addr_str(vftbl->get_address())
                          << " @ " << offset << LEND;

                  // Just because we found the method in a table doesn't mean that we can't
                  //find it again (even in the same table), so don't break here...
                }
              }
            }
          }
        }
        if (meth_prop == "constructor") {
          meth->set_type(OOMethodType::CTOR);
        }
        else if (meth_prop == "realDestructor") {
          meth->set_type(OOMethodType::DTOR);
        }
        else if (meth_prop == "deletingDestructor") {
          meth->set_type(OOMethodType::DELDTOR);
        }

        GDEBUG << "Updating method for " << cls->get_name()
               << " Method=" << addr_str(meth->get_address())
               << ", Virtual=" << ((meth->is_virtual()) ? "yes" : "no")
               << ", CTOR=" << ((meth->is_constructor()) ? "yes" : "no")
               << ", DTOR=" << ((meth->is_destructor()) ? "yes" : "no")
               << ", Del DTOR=" << ((meth->is_deleting_destructor()) ? "yes" : "no") << LEND;

        meth_query->next();
      }
    }
  }
  return true;
}

bool
SolveResolvedVirtualCallFromProlog::solve(std::vector<OOClassDescriptorPtr>& classes) {

  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
  // finalResolvedVirtualCall(Insn, VFTable, Target)
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
  rose_addr_t to_addr, vfcall_id, from_addr;
  auto vcall_query = session_->query("finalResolvedVirtualCall",
                                     var(from_addr),
                                     var(vfcall_id),
                                     var(to_addr));
  while (!vcall_query->done()) {
    for (OOClassDescriptorPtr cls : classes) {
      for (OOVirtualFunctionTablePtr vftcall : cls->get_vftables()) {
        if (vftcall->get_address() == vfcall_id) {
          const CallDescriptor* vcall_cd = ds.get_call(from_addr);

          if (vcall_cd) {
            vftcall->add_virtual_call(vcall_cd, to_addr);

            GDEBUG << "Added virtual function call for " << cls->get_name()
                   << " in vftable " << addr_str(vftcall->get_address())
                   << " from=" << addr_str(vcall_cd->get_address())
                   << ", to=" << addr_str(to_addr) << LEND;
          } else {
            GDEBUG << "Could not add virtual function call from="
                   << addr_str(from_addr)
                   << ", to=" << addr_str(to_addr)
                   << " due to invalid call descriptor" << LEND;
          }
        }
      }
    }
    vcall_query->next();
  }
  return true;
}

// Because the entire OO analysis is read-only with respect to the descriptor set until we
// discover some new targets for some virtual function calls, we need a separate method (this
// one) to _update_ a descriptor set with the the new call targets.
void OOSolver::update_virtual_call_targets() {
  for (OOClassDescriptorPtr cls : classes) {
    for (OOVirtualFunctionTablePtr vftcall : cls->get_vftables()) {
      for (auto& pair : vftcall->get_virtual_call_targets()) {
        const CallDescriptor* vcall_cd = pair.first;
        CallDescriptor* vcall_rw_cd = ds.get_rw_call(vcall_cd->get_address());
        for (rose_addr_t target : pair.second) {
          vcall_rw_cd->add_target(target);
        }
      }
    }
  }
}

// The public interface to importing results back into C++ classes.  It's wrapped in a
// try/catch for more graceful handling of unexpected conditions.
bool
OOSolver::import_results() {
  if (!session) return false;
  try {
    GINFO << "Analyzing object oriented data structures..." << LEND;
    {
      auto query = session->query("solve", "ooanalyzer_tool");
      if (query->done()) {
        GERROR << "The solution found is not internally consistent and may have significant errors!" << LEND;
      }
    }
    // Populate the C++ data structures with the prolog results
    OOSolverAnalysisPassRunner runner(this);

    std::shared_ptr<OOSolverAnalysisPass> final_class
      = std::make_shared<SolveClassesFromProlog>(session, ds);
    runner.add_pass(final_class);

    // Inheritance relationships must be loaded before VFTables so that tables from multiple
    // inheritance are created before they're updated in the VFTable import step.
    std::shared_ptr<OOSolverAnalysisPass> final_inheritance
      = std::make_shared<SolveInheritanceFromProlog>(session, ds);
    runner.add_pass(final_inheritance);

    // VFTables importing must come after inheritance importing so that the VFTables can be
    // found in the correct classes.
    std::shared_ptr<OOSolverAnalysisPass> final_vftable
      = std::make_shared<SolveVFTableFromProlog>(session, ds);
    runner.add_pass(final_vftable);

    // Not importing virtual base tables (yet)...

    std::shared_ptr<OOSolverAnalysisPass> final_mem
      = std::make_shared<SolveMemberFromProlog>(session, ds);
    runner.add_pass(final_mem);

    std::shared_ptr<OOSolverAnalysisPass> final_emb_obj
      = std::make_shared<SolveEmbeddedObjFromProlog>(session, ds);
    runner.add_pass(final_emb_obj);

    std::shared_ptr<OOSolverAnalysisPass> final_mem_access
      = std::make_shared<SolveMemberAccessFromProlog>(session, ds);
    runner.add_pass(final_mem_access);

    std::shared_ptr<OOSolverAnalysisPass> final_method
      = std::make_shared<SolveMethodPropertyFromProlog>(session, ds);
    runner.add_pass(final_method);

    std::shared_ptr<OOSolverAnalysisPass> final_vcall
      = std::make_shared<SolveResolvedVirtualCallFromProlog>(session, ds);
    runner.add_pass(final_vcall);

    GINFO << "Ingesting prolog results ... " << LEND;
    runner.run();
    GINFO << "Done!" << LEND;

  }
  catch (const Error& error) {
    GFATAL << error.what() << LEND;
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
