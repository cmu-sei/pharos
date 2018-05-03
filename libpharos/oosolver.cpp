// Copyright 2016-2018 Carnegie Mellon University.  See LICENSE file for terms.
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

// C++ data structures
#include "ooelement.hpp"
#include "ooclass.hpp"
#include "oomethod.hpp"
#include "oomember.hpp"
#include "oovftable.hpp"

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
  // We're nt actually going to perform analysis unless requested.
  perform_analysis = false;

  if (vm.count("prolog-facts")) {
    facts_filename = vm["prolog-facts"].as<std::string>();
  }

  debug_sv_facts = false;
  if (vm.count("prolog-debug-sv")) {
    debug_sv_facts = true;
  }

  debugging_enabled = false;
  if (vm.count("prolog-debug")) {
    debugging_enabled = true;
  }

  tracing_enabled = false;
  if (vm.count("prolog-trace")) {
    tracing_enabled = true;
  }

  low_level_tracing_enabled = false;
  if (vm.count("prolog-low-level-tracing")) {
    low_level_tracing_enabled = true;
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
    results_filename = vm["prolog-results"].as<std::string>();
    perform_analysis = true;
  }

  if (vm.count("json")) {
    perform_analysis = true;
  }

  try {
    session = std::make_shared<Session>(vm);
    if (tracing_enabled) {
      session->set_debug_log(std::cout);
    }
    if (low_level_tracing_enabled) {
      session->command("debug_ctl(profile, on).");
      session->command("debug_ctl(prompt, off).");
      session->command("debug_ctl(leash, []).");
      session->command("debug_ctl(hide, [rootint/2]).");
      session->command("trace");
    }
    session->consult("oorules/progress_oosolver");
    session->consult("oorules/setup");
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
OOSolver::add_facts(OOAnalyzer& ooa) {
  if (!session) return false;
  try {
    if (debugging_enabled) {
      session->add_fact("debuggingEnabled");
    }
    if (!ignore_rtti) {
      session->add_fact("rTTIEnabled");
    }
    if (no_guessing) {
      session->add_fact("guessingDisabled");
    }
    add_method_facts();
    add_vftable_facts(ooa);
    add_usage_facts(ooa);
    add_call_facts();
    add_thisptr_facts();
    add_function_facts();
    add_import_facts();
  }
  catch (const Error& error) {
    GFATAL << error.what() << LEND;
    return false;
  }
  return true;
}

// The main analysis call.  It adds facts, invokes the anlaysis, and reports the results.
bool
OOSolver::analyze(OOAnalyzer& ooa) {
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
  }

  return true;
}

// Dump facts primarily associated with a this call method.  This currently includes object
// offsets passed to otehr methods, member accesses, and possible vftable writes.
void
OOSolver::add_method_facts()
{
  FunctionDescriptorMap& fdmap = global_descriptor_set->get_func_map();
  for (FunctionDescriptor& fd : boost::adaptors::values(fdmap)) {
    ThisCallMethod* tcm = fd.get_oo_properties();
    if (tcm == NULL) continue;

    std::string thisptr_term = "invalid";
    const SymbolicValuePtr& this_ptr = tcm->get_this_ptr();
    if (this_ptr) {
      thisptr_term = "sv_" + std::to_string(this_ptr->get_hash());
    }

    std::string status = "certain";
    const CallingConventionPtrVector& conventions = tcm->fd->get_calling_conventions();
    if (conventions.size() > 1) status = "uncertain";
    if (conventions.size() == 0) status = "notthiscall";

    session->add_fact("thisCallMethod", tcm->get_address(), thisptr_term, status);

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

    for (const FuncOffset& fo : boost::adaptors::values(tcm->passed_func_offsets)) {
      session->add_fact("funcOffset", fo.insn->get_address(),
                        tcm->get_address(), fo.tcm->get_address(), fo.offset);
    }

    for (const Member& member : boost::adaptors::values(tcm->data_members)) {
      for (const SgAsmx86Instruction* insn : member.using_instructions) {
        session->add_fact("methodMemberAccess", insn->get_address(),
                          tcm->get_address(), member.offset, member.size);
      }
    }
  }
}

// Dump facts primarily associated with virtual function tables (the entries and the RTTI
// information).
void
OOSolver::add_vftable_facts(OOAnalyzer& ooa)
{
  VirtualTableInstallationMap& installs = ooa.virtual_table_installations;
  for (const VirtualTableInstallationPtr vti : boost::adaptors::values(installs)) {
    GDEBUG << "Considering VFTable Install " << addr_str(vti->insn->get_address()) << LEND;
    // Historically, we've only exported VTable facts for this call methods, but hopefully
    // that's going to change soon.
    if (vti->fd->get_oo_properties() == NULL) continue;

    std::string fact_name = "possibleVFTableWrite";
    if (vti->base_table) fact_name = "possibleVBTableWrite";

    // This fact should include the object pointer, but does not currently.
    session->add_fact(fact_name, vti->insn->get_address(), vti->fd->get_address(),
                      vti->offset, vti->table_address);
  }

  std::set<rose_addr_t> exported;

  size_t arch_bytes = global_descriptor_set->get_arch_bytes();
  VFTableAddrMap& vftables = global_descriptor_set->get_vftables();
  for (const VirtualFunctionTable* vft : boost::adaptors::values(vftables)) {
    size_t e = 0;
    while (true) {
      rose_addr_t value = vft->read_entry(e);
      if (!(global_descriptor_set->memory_in_image(value))) {
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

    if (vft->rtti != NULL) {
      add_rtti_facts(vft);
    }
  }

  VBTableAddrMap& vbtables = global_descriptor_set->get_vbtables();
  for (const VirtualBaseTable* vbt : boost::adaptors::values(vbtables)) {
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
OOSolver::add_usage_facts(OOAnalyzer& ooa)
{
  for (const ObjectUse& obj_use : boost::adaptors::values(ooa.object_uses)) {
    rose_addr_t func_addr = obj_use.fd->get_address();

    for (const ThisPtrUsage& tpu : boost::adaptors::values(obj_use.references)) {
      // Report where this object was allocated.
      if (tpu.alloc_insn != NULL) {
        // Report relationships for the this-pointer later.
        thisptrs.insert(tpu.this_ptr->get_expression());
        // Report the allocation fact now though.
        std::string thisptr_term = "sv_" + std::to_string(tpu.this_ptr->get_hash());
        session->add_fact("thisPtrAllocation", tpu.alloc_insn->get_address(), func_addr,
                          thisptr_term, "type_" + Enum2Str(tpu.alloc_type), tpu.alloc_size);
      }

      for (const MethodEvidenceMap::value_type& mepair : tpu.get_method_evidence()) {
        SgAsmInstruction* meinsn = mepair.first;
        rose_addr_t meaddr = meinsn->get_address();

        // Report relationships for the this-pointer later.
        thisptrs.insert(tpu.this_ptr->get_expression());
        // Each instruction references multiple methods, since the call have multiple targets.
        for (const ThisCallMethod* called : mepair.second) {
          std::string thisptr_term = "sv_" + std::to_string(tpu.this_ptr->get_hash());
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

    FunctionDescriptor* callfunc = cd.get_containing_function();
    if (!callfunc) continue;
    // For each target of the call, consider whether it calls operator delete().
    for (rose_addr_t target : cd.get_targets()) {

      // This code should really be implemented as cd.get_real_targets(), but that's going to
      // require an iterator or something like that.  Instead I've implemented an example of
      // how to do it here.
      // bool endless;
      // rose_addr_t real_target = target;
      // FunctionDescriptor* tfd = global_descriptor_set->get_func(target);
      // if (tfd) real_target = tfd->follow_thunks(&endless);

      session->add_fact("callTarget", cd.get_address(), callfunc->get_address(), target);

      bool isdelete = false;
      FunctionDescriptor* tfd = global_descriptor_set->get_func(target);
      if (tfd && tfd->is_delete_method()) isdelete = true;
      ImportDescriptor* id = global_descriptor_set->get_import(target);
      if (id && id->is_delete_method()) isdelete = true;
      std::string thisptr_term = "invalid";
      if (isdelete) {
        const ParamVector& params = cd.get_parameters().get_params();
        if (params.size() > 0) {
          const ParameterDefinition& param = params.at(0);
          const SymbolicValuePtr& value = param.get_value();
          if (value) thisptr_term = "sv_" + std::to_string(value->get_hash());
          GDEBUG << "Parameter to delete at " << cd.address_string() << " was: "
                 << thisptr_term << " tn=" << *(value->get_expression()) << LEND;
        }
        session->add_fact("insnCallsDelete", cd.get_address(),
                          callfunc->get_address(), thisptr_term);
      }
    }

    // Report all parameters for every call (in the future we'll try using an OO subset)
    const ParameterList& call_params = cd.get_parameters();
    const ParamVector& cparams = call_params.get_params();
    for (const ParameterDefinition& cpd : cparams) {
      if (!cpd.value) continue;
      TreeNodePtr expr = cpd.value->get_expression();
      if (!expr) continue;
      // If the expression is a constant and not a global variable we do not want to export it.
      if (expr->isNumber()) {
        if (expr->nBits() > 64) continue;
        if (global_descriptor_set->get_global(expr->toInt()) == NULL) continue;
      }
      std::string term = "sv_" + std::to_string(expr->hash());
      if (debug_sv_facts) {
        session->add_fact("termDebug", term, to_string(*expr));
      }
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
    const ParamVector& creturns = call_params.get_returns();
    for (const ParameterDefinition& cpd : creturns) {
      if (!cpd.value) continue;
      TreeNodePtr expr = cpd.value->get_expression();
      if (!expr) continue;
      // If the expression is a constant and not a global variable we do not want to export it.
      if (expr->isNumber()) {
        if (expr->nBits() > 64) continue;
        if (global_descriptor_set->get_global(expr->toInt()) == NULL) continue;
      }
      std::string term = "sv_" + std::to_string(expr->hash());
      if (debug_sv_facts) {
        session->add_fact("termDebug", term, to_string(*expr));
      }
      if (cpd.is_reg()) {
        std::string regname = unparseX86Register(cpd.get_register(), NULL);
        session->add_fact("callReturn", cd.get_address(), callfunc->get_address(), regname, term);
      }
    }

    // From here on, we're only interested in virtual calls.
    if (cd.get_call_type() != CallVirtualFunction) continue;

    CallInformationPtr ci = cd.get_call_info();
    VirtualFunctionCallInformationPtr vci =
      boost::dynamic_pointer_cast<VirtualFunctionCallInformation>(ci);
    // If there's no virtual funtion call information, don't dereference NULL.
    if (!vci || !(vci->obj_ptr)) continue;

    thisptrs.insert(vci->obj_ptr->get_expression());
    // Report the virtual call fact now.
    std::string thisptr_term = "sv_" + std::to_string(vci->obj_ptr->get_hash());
    session->add_fact("possibleVirtualFunctionCall", cd.get_address(),
                      callfunc->get_address(), thisptr_term,
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
      std::string thisptr_term = "sv_" + std::to_string(thisptr->hash());
      const TreeNodePtr& varptr = ace.variable_portion();
      std::string variable_term = "sv_" + std::to_string(varptr->hash());
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

    // Turns out that we need to export thunk data to Prolog, because the presence or absence
    // of thunks can affect our logic.  For example, thunk1 and thunk2 can be assigned to
    // different classes, even if they jump to the same function.
    if (fd.is_thunk()) {
      session->add_fact("thunk", fd.get_address(), fd.get_jmp_addr());
    }
    else {
      // Report all calling conventions for all functions (except thunks).
      const CallingConventionPtrVector& conventions = fd.get_calling_conventions();
      for (const CallingConvention* cc: conventions) {
        session->add_fact("callingConvention", fd.get_address(), cc->get_name());
      }
    }

    // Report all parameters for every function (in the future we'll try using an OO subset)
    const ParameterList& func_params = fd.get_parameters();
    const ParamVector& fparams = func_params.get_params();
    for (const ParameterDefinition& fpd : fparams) {
      if (!fpd.value) continue;
      TreeNodePtr expr = fpd.value->get_expression();
      if (!expr) continue;
      // If the expression is a constant and not a global variable we do not want to export it.
      // Is it possible to have _function_ parameters that are constants, or only on calls?
      if (expr->isNumber()) {
        if (expr->nBits() > 64) continue;
        if (global_descriptor_set->get_global(expr->toInt()) == NULL) continue;
      }
      std::string term = "sv_" + std::to_string(expr->hash());
      if (fpd.is_reg()) {
        std::string regname = unparseX86Register(fpd.get_register(), NULL);
        session->add_fact("funcParameter", fd.get_address(), regname, term);
      }
      else {
        session->add_fact("funcParameter", fd.get_address(), fpd.get_num(), term);
      }
    }

    // Report all parameters for every function (in the future we'll try using an OO subset)
    const ParamVector& freturns = func_params.get_returns();
    for (const ParameterDefinition& fpd : freturns) {
      if (!fpd.value) continue;
      TreeNodePtr expr = fpd.value->get_expression();
      if (!expr) continue;
      // If the expression is a constant and not a global variable we do not want to export it.
      if (expr->isNumber()) {
        if (expr->nBits() > 64) continue;
        if (global_descriptor_set->get_global(expr->toInt()) == NULL) continue;
      }
      std::string term = "sv_" + std::to_string(expr->hash());
      if (fpd.is_reg()) {
        std::string regname = unparseX86Register(fpd.get_register(), NULL);
        session->add_fact("funcReturn", fd.get_address(), regname, term);
      }
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
      auto dtype = demangle::visual_studio_demangle(id.get_name());
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

        session->add_fact("symbolClass", id.get_address(), clsname, method_name);


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

  exported += session->print_predicate(facts_file, "returnsSelf", 1);
  exported += session->print_predicate(facts_file, "noCallsBefore", 1);
  exported += session->print_predicate(facts_file, "noCallsAfter", 1);
  exported += session->print_predicate(facts_file, "uninitializedReads", 1);
  exported += session->print_predicate(facts_file, "insnCallsDelete", 3);
  exported += session->print_predicate(facts_file, "purecall", 1);
  exported += session->print_predicate(facts_file, "thisCallMethod", 3);
  exported += session->print_predicate(facts_file, "funcOffset", 4);
  exported += session->print_predicate(facts_file, "methodMemberAccess", 4);
  exported += session->print_predicate(facts_file, "possibleVFTableWrite", 4);
  exported += session->print_predicate(facts_file, "possibleVBTableWrite", 4);
  exported += session->print_predicate(facts_file, "initialMemory", 2);
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
  exported += session->print_predicate(facts_file, "thunk", 2);
  exported += session->print_predicate(facts_file, "callingConvention", 2);
  exported += session->print_predicate(facts_file, "funcParameter", 3);
  exported += session->print_predicate(facts_file, "funcReturn", 3);
  exported += session->print_predicate(facts_file, "callParameter", 4);
  exported += session->print_predicate(facts_file, "callReturn", 4);
  exported += session->print_predicate(facts_file, "callTarget", 3);
  exported += session->print_predicate(facts_file, "termDebug", 2);

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
  exported += session->print_predicate(results_file, "finalVFTable", 5);
  exported += session->print_predicate(results_file, "finalVBTable", 4);
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
    OOClassDescriptorPtr new_cls = std::make_shared<OOClassDescriptor>(cid, vft, csize, dtor, method_list);
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
      derived->add_parent(obj_offset, std::make_shared<OOClassDescriptor>(*base));

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

    for (OOClassDescriptorPtr cls : classes) {
      for (OOVirtualFunctionTablePtr v : cls->get_vftables()) {
        if (v->get_address() == vft_addr) {

          v->set_size(vft_size);
          v->set_rtti_address(rtti_addr);

          // set the class name based on RTTI
          if (rtti_name.size() > 0) {
            cls->set_name(rtti_name);
            GDEBUG << "Found RTTI name for "
                   <<  addr_str(cls->get_id()) << " = " << cls->get_name() << LEND;

            // Seems legit, but now all parent names must also be updated

          }
          break;
        }
      }
    }
    vft_query->next(); // there should only be 1, but you never know
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

      OOElementPtr existing_elm = cls->member_at(mbr_off);
      if (existing_elm) {

        // ingest the new member evidence as a set of instructions, not addresses
        InsnSet insn_evidence;
        std::stringstream ss;

        // convert evidence from instructions to addresses
        for (rose_addr_t a : mbr_evidence) {
          SgAsmInstruction* i = global_descriptor_set->get_insn(a);
          if (i) {
            insn_evidence.insert(i);
            ss << addr_str(i->get_address()) << " ";
          }
        }

        // this is a traditional member because that is what prolog reports for this query
        // OOMemberPtr existing_mbr = std::dynamic_pointer_cast<OOMember>(existing_elm);

        existing_elm->add_evidence(insn_evidence);

        if (existing_elm->get_size() != mbr_size) {
          GDEBUG << "Class member: "<< cls->get_name() << " @ " << addr_str(mbr_off)
                 << " has a conflicting size with access, previous size=" << existing_elm->get_size()
                 << " access size=" << mbr_size;

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
      OOElementPtr elm = std::make_shared<OOMember>(selected_size, mbr_off);

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

            size_t arch_bytes = global_descriptor_set->get_arch_bytes();
            for (size_t offset=0; offset<vftbl->get_size(); offset++) {

              rose_addr_t faddr = global_descriptor_set->read_addr(vftbl->get_address()+(offset*arch_bytes));

              // Handle thunks ... sigh
              const FunctionDescriptor *f = global_descriptor_set->get_func(faddr);
              if (f) {
                if (f->is_thunk()) faddr = f->get_jmp_addr();

                GDEBUG << "faddr=" << addr_str(faddr)
                       << ", meth->get_address()="
                       << addr_str(meth->get_address()) << LEND;

                if (faddr == meth->get_address() ) {
                  vftbl->add_virtual_function(OOVirtualFunctionTableEntry(offset, meth));

                  GDEBUG << "Added virtual function " << addr_str(meth->get_address())
                         << " to vftable " << addr_str(vftbl->get_address()) << " @ " << offset << LEND;
                  break;
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

  for (OOClassDescriptorPtr cls : classes) {
    for (OOVirtualFunctionTablePtr vftcall : cls->get_vftables()) {
      if (vftcall->get_address() == vfcall_id) {

        for (OOMethodPtr mtd : cls->get_methods()) {
          if (mtd->get_address() == to_addr) {

            CallDescriptor *vcall_cd = global_descriptor_set->get_call(from_addr);

            if (vcall_cd) {
              // As part of the analysis, update the call descriptor
              vcall_cd->add_target(to_addr);
              vftcall->add_virtual_call(vcall_cd);

              GDEBUG << "Added virtual function call for "<< cls->get_name()
                     << " in vftable " << addr_str(vftcall->get_address())
                     << " from=" << addr_str(vcall_cd->get_address()) << ", to=" << addr_str(mtd->get_address()) << LEND;
            }
            else {
              GWARN << "Could not add virtual function call from="
                    << addr_str(from_addr) << ", to=" << addr_str(mtd->get_address())
                    << " due to invalid call descriptor" << LEND;
            }
            break;
          }
        }
      }
    }
  }
  return true;
}

// The public interface to importing results back into C++ classes.  It's wrapped in a
// try/catch for more graceful handling of unexpected conditions.
bool
OOSolver::import_results() {
  if (!session) return false;
  try {
    GINFO << "Analyzing object oriented data structures..." << LEND;
    auto query = session->query("solve");
    if (query->done()) {
      GERROR << "The solution found is not internally consistent and may have significant errors!" << LEND;
    }

    // Populate the C++ data structures with the prolog results
    OOSolverAnalysisPassRunner runner(this);

    std::shared_ptr<OOSolverAnalysisPass> final_class
      = std::make_shared<SolveClassesFromProlog>(session);
    runner.add_pass(final_class);

    // Placing the vftable query before the inheritance query ensures that the proper class name
    // is used in the presence of RTTI information
    std::shared_ptr<OOSolverAnalysisPass> final_vftable
      = std::make_shared<SolveVFTableFromProlog>(session);
    runner.add_pass(final_vftable);

    // Not importing virtual base tables (yet)...

    std::shared_ptr<OOSolverAnalysisPass> final_inheritance
      = std::make_shared<SolveInheritanceFromProlog>(session);
    runner.add_pass(final_inheritance);

    std::shared_ptr<OOSolverAnalysisPass> final_mem
      = std::make_shared<SolveMemberFromProlog>(session);
    runner.add_pass(final_mem);

    std::shared_ptr<OOSolverAnalysisPass> final_emb_obj
      = std::make_shared<SolveEmbeddedObjFromProlog>(session);
    runner.add_pass(final_emb_obj);

    std::shared_ptr<OOSolverAnalysisPass> final_mem_access
      = std::make_shared<SolveMemberAccessFromProlog>(session);
    runner.add_pass(final_mem_access);

    std::shared_ptr<OOSolverAnalysisPass> final_method
      = std::make_shared<SolveMethodPropertyFromProlog>(session);
    runner.add_pass(final_method);

    std::shared_ptr<OOSolverAnalysisPass> final_vcall
      = std::make_shared<SolveResolvedVirtualCallFromProlog>(session);
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
