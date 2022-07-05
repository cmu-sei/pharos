// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

// This code represents the new Prolog based approach!

#include <boost/range/adaptor/map.hpp>

#include "pdg.hpp"
#include "descriptors.hpp"
#include "method.hpp"
#include "usage.hpp"
#include "defuse.hpp"
#include "ooanalyzer.hpp"
#include "vcall.hpp"
#include "oosolver.hpp"
#include "masm.hpp"

namespace pharos {

// Some of these should probably be methods on OOAnalyzer, and others might be best just local
// to this file.  Since the original objdigger.cpp design didn't have a master class, we'll
// just prototype all of the functions here for now.
// OOSolver
void analyze_vtable_overlap();

OOAnalyzer::OOAnalyzer(DescriptorSet& ds_, const ProgOptVarMap& vm_) :
  BottomUpAnalyzer(ds_, vm_) {
  user_new_addrs = option_addr_list(vm, "new-method");
  user_delete_addrs = option_addr_list(vm, "delete-method");
  user_purecall_addrs = option_addr_list(vm, "purecall");

  set_mode(MULTI_THREADED);
}

bool OOAnalyzer::identify_method(
  FunctionDescriptor const & fd,
  AddrSet const * user_addrs,
  check_method_t check,
  set_method_t set,
  std::string const & tag)
{
  assert(check);
  assert(set);

  rose_addr_t faddr = fd.get_address();

  // If we're already marked as an identified method we're done.
  if ((this->*check)(faddr)) return true;

  // If the user has marked this as an identified method, mark it.
  if (user_addrs && user_addrs->find(faddr) != user_addrs->end()) {
    GINFO << "Function at " << fd.address_string() << " is a " << tag << "() method"
          << " because the user explicitly marked it as such." << LEND;
    (this->*set)(faddr);
    return true;
  }

  // If the signature for the function matches, it is identified.
  std::string sig = fd.get_pic_hash();
  if (ds.tags().check_hash(sig, tag)) {
    GINFO << "Function at " << fd.address_string() << " is a " << tag << "() method"
          << " because it matches hash " << sig << "." << LEND;
    (this->*set)(faddr);
    return true;
  }

  // If this is a thunk to a import descriptor with a name that has the given tag,
  // this method is identified.
  if (fd.is_thunk()) {
    bool endless;
    rose_addr_t thunk_target = fd.follow_thunks(&endless);
    if ((this->*check)(thunk_target)) {
      GINFO << "Function at " << fd.address_string() << " is a " << tag << "() method"
            << " because it thunks to " << addr_str(thunk_target) << "." << LEND;
      (this->*set)(faddr);
      return true;
    }
    auto imp = ds.get_import(thunk_target);
    if (imp && imp->is_name_valid()) {
      if (ds.tags().check_name(imp->get_name(), tag)) {
        GINFO << "Function at " << fd.address_string() << " is a " << tag << "() method"
              << " because it thunks to import \"" << imp->get_name() << "\"." << LEND;
        (this->*set)(faddr);
        return true;
      }
    }
  }

  // The logic for the tail calls differs slightly for each tag.

  // For purecalls, there's no real reason to apply this logic.
  if (tag == "purecall") return false;
  // For free(), the delete case will handle the updates.
  if (tag == "free") return false;
  // Delete is more complicated.  In this case, the function is marked as a candidate delete
  // instead of a known delete, and the criteria is that the function tail calls to either
  // free, a known delete, or a candidate delete.
  std::string tailtag = tag;
  if (tag == "delete") {
    tailtag = "candidate delete";
    // Free, delete, or candidate delete.
    check = &OOAnalyzer::is_free_like_method;
    set = &OOAnalyzer::set_candidate_delete_method;
  }
  // For new() there's no change in the set/check methods -- tail calls to new() are new().

  // If this function is a tail call to identified method, this method is also identified.
  for (const CallDescriptor* cd : fd.get_outgoing_calls()) {
    // This requires that the calling relationship be an actual tail call and not a
    // conventional call.  That distinction is fairly important because it imposes a certain
    // amount of implied data flow analysis.
    if (cd->is_tail_call()) {
      for (rose_addr_t target : cd->get_targets()) {
        if ((this->*check)(target)) {
          GINFO << "Function at " << fd.address_string() << " is a " << tailtag << "() method"
                << " because it tail calls to " << addr_str(target) << "." << LEND;
          (this->*set)(faddr);
          return true;
        }
      }
    }
  }

  // Not all source code tail calls receive the assembly level tail call optimization that
  // results in a jmp instruction instead of call & ret instructions.  If the function matches
  // the hash of a call stub and calls an identitified method, then this method is also
  // identified.
  if (ds.tags().check_hash(sig, "callstub")) {
    GDEBUG << "Function at " << fd.address_string() << " matches hash "
           << sig << " of a callstub." << LEND;
    for (const CallDescriptor* cd : fd.get_outgoing_calls()) {
      for (rose_addr_t target : cd->get_targets()) {
        GDEBUG << "Function at " << fd.address_string() << " calls "
               << addr_str(target) << "." << LEND;
        if ((this->*check)(target)) {
          GINFO << "Function at " << fd.address_string() << " is a " << tailtag
                << "() method because it stub calls to " << addr_str(target) << "." << LEND;
          (this->*set)(faddr);
          return true;
        }
      }
    }
  }

  return false;
}

bool OOAnalyzer::identify_new_method(FunctionDescriptor const & fd) {
  return identify_method(
    fd, &user_new_addrs, &OOAnalyzer::is_new_method,
    &OOAnalyzer::set_new_method, "new");
}

bool OOAnalyzer::identify_free_method(FunctionDescriptor const & fd) {
  return identify_method(
    fd, &user_new_addrs, &OOAnalyzer::is_free_method,
    &OOAnalyzer::set_free_method, "free");
}

bool OOAnalyzer::identify_delete_method(FunctionDescriptor const & fd) {
  return identify_method(
    fd, &user_delete_addrs, &OOAnalyzer::is_delete_method,
    &OOAnalyzer::set_delete_method, "delete");
}

bool OOAnalyzer::identify_purecall_method(FunctionDescriptor const & fd) {
  return identify_method(
    fd, &user_purecall_addrs, &OOAnalyzer::is_purecall_method,
    &OOAnalyzer::set_purecall_method, "purecall");
}

bool OOAnalyzer::identify_nonreturn_method(FunctionDescriptor & fd) {
  std::string sig = fd.get_pic_hash();
  //OINFO << "Function at " << fd.address_string() << " hashes to " << sig << LEND;
  if (ds.tags().check_hash(sig, "nonreturn")) {
    //OINFO << "Function at " << fd.address_string() << " matches hash "
    //      << sig << " of function known not to return." << LEND;
    fd.set_never_returns(true);
    return true;
  }

  // If this is a thunk to a import descriptor which a name that has been tagged as nonreturn,
  // this is a nonreturn method.
  if (fd.is_thunk()) {
    auto tfd = fd.get_jmp_fd();
    if (tfd && tfd->get_never_returns()) {
      fd.set_never_returns(true);
      return true;
    }
    auto imp = ds.get_import(fd.get_jmp_addr());
    if (imp && imp->is_name_valid()) {
      if (ds.tags().check_name(imp->get_name(), "nonreturn")) {
        GINFO << "Function at " << fd.address_string() << " is a thunk to an import named \""
              << imp->get_name() << "\" which is known not to return." << LEND;
        fd.set_never_returns(true);
        return true;
      }
    }
  }

  return false;
}

// Sadly, the whole objdigger output seems to mildly susceptible to changes in this loop.
// Fortunately, it mostly seems to affect test case seven (by far the largest), and the
// changes are usually pretty small (a single difference or two and possibly some cascading
// effects).  Cory suspects that the mild non-determinism is a function of having sets of
// object pointers in some situation where our logic is dependent on the order of the members
// in the set.  Since this pass significantly alters the memory layout for later passes, it
// appears to trigger the non-determinism. :-( :-( :-( Needless to say, we should be on the
// lookout for cases where we're inapproriately sensitive to ordering.
void OOAnalyzer::visit(FunctionDescriptor* fd) {
  GINFO << "Processing function " << fd->address_string() << LEND;
  identify_new_method(*fd);
  identify_free_method(*fd);
  identify_delete_method(*fd);
  identify_purecall_method(*fd);
  identify_nonreturn_method(*fd);

  // Without this we deadlock?!
  fd->get_pdg();

  // For future me, the problem that this code corrects is that delete methods are sometimes
  // tail-call optimized into thunklets (a few instructions plus an unconditional jump to
  // another delete implementation).  Because we don't propagate parameters correctly through
  // thunklets, we don't know that the thunklet takes any parameters, so we don't create
  // parameters, and then we can't inspect them later when we want to know the symbolic value
  // that was passed to delete().  The hack is to force the normal delete() API onto the
  // thunklets, which is __cdecl with a single stack parameter.  An example can be found in
  // Lite/ooeex7 at 401d07, 401d10, and 401d19 (in std::numpunct<char>::_Tidy(void)), all of
  // which call to 406b10 (delete[](void*)) which jumps to 406276 (delete(void*)).  A better
  // solution to this problems would be to propagate parameters through all tail-call optimized
  // thunklets, but this requires a more complicated analysis of the instructions before the
  // tail-call optimized JMP instruction.
  if (is_candidate_delete_method(fd->get_address())) {
    // This fetches the API database entry for delete().  This code isn't perfect because it
    // presumes Windows 32-bit MS Visual Studio, but since most delete() implementations have
    // the same prototype, it probably doesn't matter too much.  If we do the right thing wil
    // tail-call optimized thunklets in the future, we won't need this code at all.
    APIDefinitionList apis = ds.apidb->get_api_definition("MSVCRT", "??3@YAXPAX@Z");
    if (apis.size() > 0) {
      fd->set_api(*(apis.front()));
    }
  }

  // Decide which calls might be virtual function calls.
  for (CallDescriptor const * cd : fd->get_outgoing_calls()) {
    // Filter to only indeterminate calls (CallRegister and CallUnknown)
    if (true) {
      SgAsmX86Instruction* insn = isSgAsmX86Instruction(cd->get_insn());
      VirtualFunctionCallAnalyzer vcall(insn, fd);
      if (vcall.analyze()) {
        write_guard<decltype(mutex)> guard{mutex};
        // The creation of entries in the vcalls map is intentional.
        // Move the vector of possible resolutions (information) into our map.
        vcalls[insn->get_address()] = std::move(vcall.vcall_infos);
      }
    }
  }

  // Find methods that roughly follow the "this-call" calling convention and create an entry in
  // the "methods" map.

  // Speculatively construct a ThisCallMethods from the function.  The ThisCallMethod class
  // will tell us whether the function was really object oriented or not.
  auto utcm = make_unique<ThisCallMethod>(fd);
  auto tcm = utcm.get();
  if (utcm->is_this_call()) {
    GINFO << "Function " << utcm->address_string() << " uses __thiscall convention." << LEND;
    // This is the only write to the methods map anywhere.  OOAnalyzer now owns the pointer.
    write_guard<decltype(mutex)> guard{mutex};
    methods[fd->get_address()] = std::move(utcm);
  }
  else {
    utcm.reset();
    tcm = nullptr;
  }

  // Analyze every function in the program looking for object uses, where the definition of an
  // object use is passing the symbolic value to a known OO method.  References to each object
  // are grouped first by the function that they occured in, and then by the symbolic value of
  // the this-pointer.  Analysis in this pass is entirely local to the function, and the only
  // interprocedural analysis is from knowing which methods are __thiscall.  As a consequence,
  // we probably will not have the complete lifetime of the object from construction to
  // destruction, although in some cases we might.  After finding the object uses, we then
  // analyze them to see if we can determine whether there's an allocation site in this usage.

  // Find all uses of objects in the function and record them as a list of this-pointers and
  // the methods that were invoked using those pointers.  Store it in the global map for
  // later reference (while avoiding the use of the default constructor).
  ObjectUse u = ObjectUse(*this, fd);
  u.update_ctor_dtor(*this);
  {
    write_guard<decltype(mutex)> guard{mutex};
    object_uses.insert(ObjectUseMap::value_type(fd->get_address(), u));
  }

  // Analyze all function descriptors for possible vftable writes (not just this call methods).
  find_vtable_installations(*fd);
  if (tcm) tcm->stage2();

  // Experimental new memory reduction undiscussed major design revision. ;-) ;-)
  fd->free_pdg();

  // Record the symbolic value of the possible this-pointer at each call.
  record_this_ptrs_for_calls(fd);
}

void OOAnalyzer::start() {
  start_ts = clock::now();
}

void OOAnalyzer::finish() {
  size_t new_size = 0;
  size_t delete_size = 0;
  size_t purecall_size = 0;
  for (auto & v : call_addrs) {
    switch (v.second) {
     case NEW:      new_size++;      break;
     case CANDIDATE_DELETE: // fall through
     case DELETE:   delete_size++;   break;
     case PURECALL: purecall_size++; break;
     default: break;
    }
  }
  if (new_size == 0) {
    GERROR << "No new() methods were found.  Heap objects may not be detected." << LEND;
  }
  if (delete_size == 0) {
    GERROR << "No delete() methods were found.  Object analysis may be impaired." << LEND;
  }
  GINFO << "Found " << new_size << " new() methods, "
        << delete_size << " delete() methods, and "
        << purecall_size << " purecall() methods." << LEND;
  time_point end_ts = clock::now();
  duration secs = end_ts - start_ts;
  GINFO << "Function analysis complete, analyzed " << processed_funcs
        << " functions in " << secs.count() << " seconds." << LEND;

  // Alternate version of the find_heap_objects() routine, in transition...
  find_heap_allocs();

  // Analyze virtual function calls.  Dependent on the interprocedual PDGs for instruction
  // reads and writes for each function with a virtual call in it.
  // ds.update_vf_call_descriptors();

  // Look for methods that pass their this-pointers to other methods.
  for (auto & tcm : boost::adaptors::values(methods)) {
    tcm->find_passed_func_offsets(*this);
  }

  // Test virtual base tables and virtual function tables for overlaps.  This is the new Prolog
  // compatible approach, and it may not actually modify function tables yet.
  // For every virtual base table...
  for (auto & vbt : boost::adaptors::values(vbtables)) {
    // Ask the virtual base table to compare itself with all other tables, and update its size.
    vbt->analyze_overlaps(vftables, vbtables);
  }
  // In the new way of doing things we should probably be doing this too...
  //for (const VirtualFunctionTable* vft : boost::adaptors::values(vftables)) {
  //  vft->analyze_overlaps(vftables, vbtables);
  //}

  //analyze_vftables_in_all_fds();

  OOSolver oosolver = OOSolver(ds, vm);
  oosolver.analyze(*this);
  // The OO Classes are the classes from prolog. Should these be the pure output classes?
  ooclasses = oosolver.get_classes();
}

std::vector<OOClassDescriptorPtr>
OOAnalyzer::get_result_classes() {
  return ooclasses;
}

void OOAnalyzer::handle_heap_allocs(const rose_addr_t saddr) {
  GDEBUG << "handle_heap_allocs inspecting addr " << addr_str(saddr) << LEND;
  const CallDescriptor* cd = ds.get_call(saddr);
  if (cd == NULL) {
    GINFO << "No call descriptor for call at " << addr_str(saddr) << LEND;
    return;
  }

  SgAsmInstruction* insn = cd->get_insn();
  const FunctionDescriptor* cfd = ds.get_func_containing_address(cd->get_address());
  if (cfd == NULL) {
    GINFO << "No function for call at " << addr_str(saddr) << LEND;
    return;
  }

  rose_addr_t faddr = cfd->get_address();
  ObjectUseMap::iterator oufinder = object_uses.find(faddr);
  if (oufinder == object_uses.end()) {
    GINFO << "No object use for " << cfd->address_string() << LEND;
    return;
  }

  // Find the object use for the function the call is in.
  ObjectUse& obj_use = object_uses.find(faddr)->second;

  // For backwards compatibility.  This is very duplicative of effort right now, but Cory
  // intends for this call to go away soon.
  //find_heap_objects(obj_use);

  // Get the return value from the call to new(), which should be our this-pointer.
  SymbolicValuePtr rc = cd->get_return_value();
  if (!rc) {
    GERROR << "Missing return value from new() call at " << cd->address_string() << LEND;
    return;
  }
  // Lookup the this-pointer in the references map.
  ThisPtrUsageMap::iterator finder = obj_use.references.find(rc->get_hash());
  if (finder == obj_use.references.end()) {
    // In the cases Cory looked at this was caused by objects that were not used to call
    // any methods in that class.  Typically the object would be passed as a parameter to
    // another function or some method was inlined following the new() call.  This
    // appears to happen primarily when the constructor is inlined or non-existent.
    GWARN << "Missing this-pointer usage for new() call at "
          << debug_instruction(insn) << LEND;
    return;
  }

  // Record that we know which type of allocation the object has.
  ThisPtrUsage& tpu = finder->second;
  tpu.alloc_type = AllocHeap;
  tpu.alloc_insn = insn;

  // Get the parameters to the new() call.  Cory's had a few problems with the version of
  // this logic that accepts only a single parameter to new().  For now we'll switch to a
  // slightly less correct, but more defensive version that involves looking for the
  // first STACK parameter.  The problem is that in some Lite builds, we're not handling
  // the leave instruction correctly with respect to saved and restored register
  // analysis, which adds extra bogus register parameters. :-(
  const ParameterDefinition* pd = cd->get_parameters().get_stack_parameter(0);
  if (pd != NULL) {
    // And the parameter should usually be a constant value.
    if (pd->get_value() != NULL && pd->get_value()->isConcrete()
        && pd->get_value()->get_width() <= 64)
    {
      unsigned int size = *pd->get_value()->toUnsigned();
      if (size > 0 and size < 0xFFFFFFF) {
        tpu.alloc_size = size;
        GDEBUG << "The size parameter to new() at " << cd->address_string()
               << " was: " << tpu.alloc_size << LEND;
      }
      else {
        GWARN << "Bad size parameter " << size
              << " for new() call at " << cd->address_string() << LEND;
      }
    }
  }
  else {
    GWARN << "Unable to find parameter for new() call at " << cd->address_string() << LEND;
  }
}

void OOAnalyzer::find_heap_allocs() {
  // Second pass - Having completed the object use analysis for all functions, make another
  // pass over the functions looking for the ones we've identified as new() methods.  For each
  // new() method, analyze all of it's callers and record that they are heap allocated objects.
  const FunctionDescriptorMap& fdmap = ds.get_func_map();
  for (const FunctionDescriptor& fd : boost::adaptors::values(fdmap)) {
    if (is_new_method(fd.get_address())) {
      // This is a pretty horrible way to get the callers.  Wes used the function call graph,
      // and that had different problems, including skipping some calls to new, and adding some
      // jumps to new.  At least this way we're using our CallDescriptor infrastructure, and
      // if get_callers() was cleaned up some, then we'd be in pretty good shape.
      for (const rose_addr_t saddr : fd.get_callers()) {
        handle_heap_allocs(saddr);
      }
    }
  }
  // now have to iterate over import descriptors, because the func desc contained within them
  // are not in the global descriptor set func map...
  const ImportDescriptorMap& idmap = ds.get_import_map();
  for (const ImportDescriptor& id : boost::adaptors::values(idmap)) {
    if (is_new_method(id.get_address())) {
      // This is a pretty horrible way to get the callers.  Wes used the function call graph,
      // and that had different problems, including skipping some calls to new, and adding some
      // jumps to new.  At least this way we're using our CallDescriptor infrastructure, and
      // if get_callers() was cleaned up some, then we'd be in pretty good shape.
      for (const rose_addr_t saddr : id.get_callers()) {
        handle_heap_allocs(saddr);
      }
    }
  }
}

// Analyze an address that might be a virtual table.  If it meets the criteria for being a
// table, add it to the appropriate list, and return true.  If it does not meet the criteria,
// return false.  Entries may be added to the appropriate list to prevent reprocessing
// regardless of the final outcome.
bool OOAnalyzer::analyze_possible_vtable(rose_addr_t address, bool allow_base) {
  // Begin by checking whether we've already processed this address.
  if (virtual_tables.find(address) != virtual_tables.end()) {
    return virtual_tables.at(address);
  }

  // Assume that we're going to fail.  If we actually create a table, we'll set this to true.
  virtual_tables[address] = false;

  // If the caller allows it, try creating a virtual base table first.
  if (allow_base) {
    // Starting by doing virtual base table analysis.  This analysis should not falsely
    // claim any virtual function tables, and tables that are very invalid will get handled
    // as malformed virtual function tables..
    auto vbtable = make_unique<VirtualBaseTable>(ds, address);
    // If the vbtable is valid add it to the list.
    if (vbtable->analyze()) {
      GDEBUG << "Found possible virtual base table at: " << addr_str(address) << LEND;
      vbtables[address] = std::move(vbtable);
      virtual_tables[address] = true;
      return true;
    }
  }

  // If we did not find a valid vitual base table, try creating a virtual function table.
  auto vftable = make_unique<VirtualFunctionTable>(ds, address);
  // If the vbtable is valid add it to the list.
  if (vftable->analyze(vftables)) {
    vftables[address] = std::move(vftable);
    virtual_tables[address] = true;
    return true;
  }

  // If we made it to here, the address was not really a virtual table (as far as we know).
  return false;
}

// Find the value of ECX at the time of the call, by inspecting the state that was saved when
// the call was evaluated.  Uses the state from the call descriptor!  The FunctionDescriptor is
// non-const, because we're going to free the states in each CallDescriptor that we visit.
void OOAnalyzer::record_this_ptrs_for_calls(FunctionDescriptor* fd) {
  for (const CallDescriptor* cd : fd->get_outgoing_calls()) {
    SymbolicStatePtr state = cd->get_state();
    if (state == NULL) {
      // Customize this message a little to account for known failure modes.,
      if (cd->is_tail_call()) {
        GINFO << "Tail call at " << cd->address_string() << " was not analyzed correctly for OO usages." << LEND;
      }
      else {
        GINFO << "Call at " << cd->address_string() << " was not analyzed correctly for OO usages." << LEND;
      }
      continue;
    }
    write_guard<decltype(mutex)> guard{mutex};
    // We should be able to find this globally somehow...
    RegisterDescriptor this_reg = cd->ds.get_arch_reg(THIS_PTR_STR);
    assert(this_reg.is_valid());
    // Read ECX from the state immediately before the call.
    callptrs[cd->get_address()] = state->read_register(this_reg);
    // Now that we've saved a copy of the this-pointer value, we don't need the the rest of the
    // state anymore, and we can free a lot of memory simply by removing the reference to the
    // state from the call descriptor.
    CallDescriptor* nccd = ds.get_rw_call(cd->get_address());
    nccd->discard_state();
  }
}

void OOAnalyzer::find_vtable_installations(FunctionDescriptor const & fd) {
  const PDG* p = fd.get_pdg();
  if (p == NULL) return;

  GDEBUG << "Analyzing vtables for " << fd.address_string() << LEND;

  // For every write in the function...
  for (const AccessMap::value_type& access : p->get_usedef().get_accesses()) {
    // The second entry of the pair is the vector of abstract accesses.
    for (const AbstractAccess& aa : access.second) {
      // We only want writes
      if (aa.isRead) continue;

      // We're only interested in writes that write a constant value to the target.
      // This is a reasonably safe presumption for compiler generated code.
      if (!aa.value->isConcrete() || aa.value->get_width() > 64) continue;

      // I was doubtful about the requirement that the write must be to memory, but after
      // further consideration, I'm fairly certain that even if we moved the constant value
      // into a register, and the register into the object's memory (which is literally
      // required), then we'd detect the memory write on the second instruction.
      if (!aa.is_mem()) continue;

      // We're only interested in constant addresses that are in the memory image.  In some
      // unusual corner cases this might fail, but it should work for compiler generated code.
      rose_addr_t taddr = *aa.value->toUnsigned();
      if (!ds.memory.is_mapped(taddr)) continue;

      // We're not interested in writes to fixed memory addresses.  This used to exclude stack
      // addresses, but now it's purpose is a little unclear.  It might prevent vtable updates
      // to global objects while providing no benefit, or it might correctly eliminate many
      // write to fixed memory addresses correctly.  Cory doesn't really know.
      if (aa.memory_address->isConcrete()) continue;

      // This is the instruction we're talking about.
      SgAsmInstruction* insn = fd.ds.get_insn(access.first);
      if (!insn) {
        GERROR << "Unable to find instruction at address " << addr_str(access.first) << LEND;
      }
      // This algorithm only works for X86 instructions.
      SgAsmX86Instruction* x86insn = isSgAsmX86Instruction(insn);
      if (!x86insn) continue;

      // We're not interested in call instructions, which write constant return addresses to
      // the stack.  This is largely duplicative of the test above, but will be needed when the
      // stack memory representation gets fixed to include esp properly.
      if (insn_is_call(x86insn)) continue;

      // Expand the representation of the pointer so we can dump the expression to thisPtrDefinition.
      TreeNodePtr tn_expanded = ThisPtrUsage::expand_thisptr (&fd, insn, aa.memory_address);

      // Let's try to extract the object pointer variable, and any offset that's present.
      TreeNodePtr tn = aa.memory_address->get_expression();
      AddConstantExtractor ace(tn);
      TreeNodePtr vp = ace.variable_portion();
      int64_t offset = ace.constant_portion();
      // There must be a variable portion.
      if (vp == NULL) {
        GDEBUG << "Malformed virtual function table initialization: expr=" << *tn
               << " at instruction: " << debug_instruction(insn) << LEND;
        continue;
      }

      write_guard<decltype(mutex)> guard{mutex};
      // The criteria for validating virtual tables differs a little bit right now based on
      // whether the method is an OO method.
      ThisCallMethod* tcm = get_method_rw(fd.get_address());
      bool allow_base = tcm;

      // Create and attempt to validate the virtual table.
      bool valid = analyze_possible_vtable(taddr, allow_base);
      if (valid) {

        // Is this address a virtual base table (or a virtual function table)?
        bool base_table = (vbtables.find(taddr) != vbtables.end());

        // It look like we're going to have a valid virtual table.
        VirtualTableInstallationPtr install = std::make_shared<VirtualTableInstallation>(
          insn, &fd, taddr, vp, offset, tn_expanded, base_table);
        //VirtualTableInstallation* install = NULL;
        //install = new VirtualTableInstallation(insn, taddr, vp, offset);

        // But if the method was an OO method, we can do some additional validation.  After
        // this call, valid is really whether the installation was deemed valid or not.
        if (tcm) {
          valid = tcm->validate_vtable(install);
        }

        // If the table installation was also valid, record in the OOAnalyzer.
        if (valid) {
          virtual_table_installations[insn->get_address()] = std::move(install);
        }
      }

      // In all cases, this loop should continue to the next instruction, since there can be
      // multiple virtual tables per function, and any failures we encountered won't prevent
      // later tables from validating correctly.

    } // For each access
  } // For all accesses
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
