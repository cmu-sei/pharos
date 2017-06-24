// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/range/adaptor/map.hpp>

#include "pdg.hpp"
#include "descriptors.hpp"
#include "oo.hpp"
#include "member.hpp"
#include "method.hpp"
#include "usage.hpp"
#include "class.hpp"
#include "defuse.hpp"
#include "ooanalyzer.hpp"
#include "vcall.hpp"
#include "oosolver.hpp"

namespace pharos {

// Some of these should probably be methods on OOAnalyzer, and others might be best just local
// to this file.  Since the original objdigger.cpp design didn't have a master class, we'll
// just prototype all of the functions here for now.
void report_this_call_methods();
void report_object_uses();
void report_classes();
void find_this_call_methods();
void analyze_functions_for_object_uses();
void make_classes_from_allocations();
void analyze_passed_func_offsets();
void force_class_entries();
void update_class_with_ptr_groups();
void recursively_find_methods();
void set_members_from_methods();
void remove_ancestor_methods();
void update_calling_classes();
void merge_classes_sharing_methods();
void report_this_call_methods();
void report_object_uses();
void report_classes();
void analyze_vtable_overlap();
void analyze_vtable_overlap_new();
void analyze_virtual_calls();
void merge_classes_sharing_vftables();
void remove_empty_classes();
void reanalyze_members_from_methods();
void analyze_embedded_objects();
void analyze_final_class_sizes();
void evaluate_possible_destructors();
void deleting_destructors_must_be_virtual();
void disallow_virtual_constructors();
void analyze_class_names();
void mangle_dominance();
void analyze_vftables_in_all_fds();

OOAnalyzer::OOAnalyzer(DescriptorSet* ds_, ProgOptVarMap& vm_, AddrSet& new_addrs_) :
  BottomUpAnalyzer(ds_, vm_) {
  new_methods_found = 0;
  delete_methods_found = 0;
  purecall_methods_found = 0;
  new_addrs = new_addrs_;
  start_ts = clock::now();

  prolog_mode = false;
  if (vm_.count("prolog-facts")) {
    prolog_mode = true;
  }

  // Initialize the new_hashes string set with the hashes of known methods.
  initialize_known_method_hashes();
  find_imported_new_methods();
  find_imported_delete_methods();
  find_imported_purecall_methods();
}

bool OOAnalyzer::identify_new_method(FunctionDescriptor* fd) {
  std::string sig = fd->get_pic_hash();
  if (new_addrs.find(fd->get_address()) != new_addrs.end()) {
    fd->set_new_method(true);
    new_methods_found++;
    return true;
  }
  else if (new_hashes.find(sig) != new_hashes.end()) {
    GINFO << "Function at " << fd->address_string() << " matches hash "
          << sig << " of known new() method." << LEND;
    fd->set_new_method(true);
    new_methods_found++;
    return true;
  }
  return false;
}

bool OOAnalyzer::identify_delete_method(FunctionDescriptor* fd) {
  std::string sig = fd->get_pic_hash();
  if (delete_addrs.find(fd->get_address()) != delete_addrs.end()) {
    fd->set_delete_method(true);
    delete_methods_found++;
    return true;
  }
  else if (delete_hashes.find(sig) != delete_hashes.end()) {
    // Because the hash for a delete method is basically just a stub that jumps to _free,
    // we need to do some additional analysis to avoid a bunch of false positives. :-(
    //GINFO << "Function at " << fd->address_string() << " matches hash "
    //      << sig << " of known delete() method (but has not been confirmed)." << LEND;

    // Some of the delete hashes are actually short stubs that jump to other implementations of
    // delete.  An example of this was the statically linked implementation of ??3@YAXPAXI@Z in
    // our prtscrpp example at 0x406F9B.  It appears that we should except hashes that call to
    // known delete methods as well.
    for (const CallDescriptor* cd : fd->get_outgoing_calls()) {
      for (rose_addr_t target : cd->get_targets()) {
        FunctionDescriptor* call_fd = global_descriptor_set->get_func(target);
        if (call_fd && call_fd->is_delete_method()) {
          GINFO << "Function at " << fd->address_string() << " matches hash "
                << sig << " of known delete() method." << LEND;
          fd->set_delete_method(true);
          delete_methods_found++;
          return true;
        }
      }
    }

    // This was the original logic for delete hashes that call other stactically linked
    // implementations of free().
    for (SgAsmBlock *block : fd->get_return_blocks()) {
      rose_addr_t target = block_get_jmp_target(block);
      FunctionDescriptor* free_fd = global_descriptor_set->get_func(target);
      if (!free_fd) continue;
      std::string free_sig = free_fd->get_pic_hash();
      if (free_hashes.find(free_sig) != free_hashes.end()) {
        GINFO << "Function at " << fd->address_string() << " matches hash "
              << sig << " of known delete() method." << LEND;
        fd->set_delete_method(true);
        delete_methods_found++;
        return true;
      }
    }
  }
  return false;
}

bool OOAnalyzer::identify_purecall_method(FunctionDescriptor* fd) {
  std::string sig = fd->get_pic_hash();
  if (purecall_addrs.find(fd->get_address()) != purecall_addrs.end()) {
    fd->set_purecall_method(true);
    purecall_methods_found++;
    return true;
  }
  else if (purecall_hashes.find(sig) != purecall_hashes.end()) {
    GINFO << "Function at " << fd->address_string() << " matches hash "
          << sig << " of known _purecall() method." << LEND;
    fd->set_purecall_method(true);
    purecall_methods_found++;
    return true;
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
  fd->get_pdg();

  identify_new_method(fd);
  identify_delete_method(fd);
  identify_purecall_method(fd);
}

void OOAnalyzer::finish() {
  if (new_methods_found == 0) {
    GERROR << "No new() methods were found.  Heap objects may not be detected." << LEND;
  }
  if (delete_methods_found == 0) {
    GERROR << "No delete() methods were found.  Object analysis may be impaired." << LEND;
  }
  time_point end_ts = clock::now();
  duration secs = end_ts - start_ts;
  OINFO << "Function analysis complete, analyzed " << processed_funcs
        << " functions in " << secs.count() << " seconds." << LEND;

  // Now complete the OO analysis by running all of the class detection algorithms.

  // Analyze virtual function calls.  Dependent on the interprocedual PDGs for instruction
  // reads and writes for each function with a virtual call in it.
  global_descriptor_set->update_vf_call_descriptors();

  // Find methods that roughly follow the "this-call" calling convention.  Populate the global
  // map this_call_methods with each method found.  After this analysis pass, the membership of
  // this_call_methods does not change, but subsequent passes will fill in more information for
  // each thiscall method.  This analysis includes finding instructions that use ECX, deciding
  // which methods look like constructors, and making a list of member accesses for each method.
  find_this_call_methods();

  // Find object usages throughout the program by looking for symbolic values passed to known
  // OO methods.  Analyze those usages to identify allocation sites.
  analyze_functions_for_object_uses();

  // Certain methods that look like destructors can be identified at this stage.
  evaluate_possible_destructors();

  // Test virtual base tables and virtual function tables for overlaps.  This is the new Prolog
  // compatible approach, and it may not actually modify function tables yet.
  analyze_vtable_overlap_new();

  // Export our current knowledge in the form of Prolog facts (if requested).
  if (prolog_mode) {
    analyze_vftables_in_all_fds();
    OOSolver oosolver = OOSolver(vm);
    oosolver.analyze();
  }

  mangle_dominance();

  // Make classes from the object uses that include allocation sites.  These are the cases
  // where we'll be able to identify (or make a good guess at) the constructor.
  make_classes_from_allocations();

  // This routine is still rather muddled.  It primarily updates classes with
  // observations from this_call_methods, specifically by looking at passed_func_offsets,
  // although it also looks for parent constructors and embedded objects.
  analyze_passed_func_offsets();

  // Force entries in classes for each __thiscall method with a vftable.  This pass
  // is depdendent on nothing but this_call_methods.  It used to be very late in the analysis,
  // but the only risk Cory sees for placing it earlier is false-positive identification of
  // virtual function tables which seems fairly unlikely.  To place it an earlier in the
  // analysis significantly affected the output.  It's unclear whether those changes were
  // improvements or not.
  force_class_entries();

  // Merge classes based on shared methods, adding information from this-pointer usages.
  update_class_with_ptr_groups();

  // In bottom up order, determine which methods are on the same class (or ancestor classes)
  // based on methods that call other methods with the same object pointer.
  RecursiveMethodAnalyzer rma(global_descriptor_set, vm);
  rma.analyze();

  // Add methods to classes (clearly a class description at this point) using the
  // following logic: if my this-pointer is passed to func1() which in turn calls func2() with
  // it's this-pointer (at offset zero), then I could also have called func2().
  recursively_find_methods();

  // Propagate members to classes based on the methods they call.
  // remove if doesn't work - remove comment if comment was intended. :-)
  set_members_from_methods();

  // Remove all methods from a class that are known to be valid methods on one of their
  // ancestors.  This analytical pass is probably reasonably correct, but currently very
  // incomplete because of missing knowledge about parent classes.
  remove_ancestor_methods();

  // Update the list of classes that call each __thiscall method.
  update_calling_classes();

  // Merge classes that share methods, under the presumption that once we removed our
  // ancestors methods, what's left must have been multiple detections of the same class.
  merge_classes_sharing_methods();

  // All reporting, no analysis.
  report_this_call_methods();
  report_object_uses();
  report_classes();

  // This is currently very late in the analysis because it uses classes.  It should
  // use global_vftables, and then it could be much earlier (and probably more correct, unless
  // we've somehow magically excluded invalid vtables, which isn't likely).
  analyze_vtable_overlap();

  // Resolve the targets of virtual function calls.  This should be a very late pass, except
  // that it validates that our suspected virtual function tables are in fact 100% certain to
  // be virtual function tables.  If we're having flase positives on virtual function tables
  // that we can't resolve in other ways, then it should be moved earlier (if possible).
  analyze_virtual_calls();

  // Merge classes that share the same virtual function table at offset zero.
  merge_classes_sharing_vftables();

  // Remove classes that no longer have any members or methods.  This is typically cause by
  // merging those classes into other classes.
  remove_empty_classes();

  // Rediscover members after methods have been removed from multiple classes.
  reanalyze_members_from_methods();

  // Resolve object relationships
  analyze_embedded_objects();

  // Constructors may not be virtual.
  disallow_virtual_constructors();

  // Deleting destructors must be virtual.
  deleting_destructors_must_be_virtual();

  analyze_final_class_sizes();

  // After all the analysis is complete, assign names to the final set of classes.
  analyze_class_names();
}

RecursiveMethodAnalyzer::RecursiveMethodAnalyzer(DescriptorSet* ds_, ProgOptVarMap& vm_) :
  BottomUpAnalyzer(ds_, vm_) {
  GDEBUG << "Beginning recursively analyzing methods." << LEND;
}

// Visiting each function in bottom up order ensures that we visit each method call in bottom
// up order as well.
void RecursiveMethodAnalyzer::visit(FunctionDescriptor* fd) {
  // Get the address of the function.
  rose_addr_t faddr = fd->get_address();
  // If that function is not an OO method, we're not interested.
  if (this_call_methods.find(faddr) == this_call_methods.end()) return;
  // Get the this-call method reference for that function.
  ThisCallMethod& tcm = this_call_methods.at(faddr);
  // Update the recursive methods fields.
  tcm.update_recursive_methods();
}

void RecursiveMethodAnalyzer::finish() {
  GDEBUG << "Finished recursively analyzing methods." << LEND;
}

// Initialize the list of known methods with some well-known hashes.  It's unclear how big this
// set will eventually be, but it'll probably be managable regardless.  We should investigate
// the variation some more and expand the list for real use.
void OOAnalyzer::initialize_known_method_hashes() {
#if 0 // old hash function
  // OO cases 0-6
  new_hashes.insert("A0DE1FEA2A6C8806CEEF453E2480677C"); // uhh, no?
  // OO cases 7-9
  new_hashes.insert("7B8365EB6F754CB9714F8A99E1334171");
  // Unidentified msvc2010 debug test cases
  new_hashes.insert("443BABE6802D856C2EF32B80CD14B474");
#else // new hash function:
  //new_hashes.insert(""); // where was that one?
  new_hashes.insert("9F377A6D9EDE41E4F1B43C475069EE28");
  new_hashes.insert("443BABE6802D856C2EF32B80CD14B474");

  // Notepad++5.6.8 ordinary new(), at 0x49FD6E
  new_hashes.insert("356087289F58C87C27410EFEDA931E4D");
  // Notepad++5.6.8 new_nothrow(), at 0x4A2C94
  // void *__cdecl operator new(size_t Size, const struct std::nothrow_t *)
  new_hashes.insert("CC883629B7DB64E925D711EC971B8FCA");

#endif // 0

  // PIC hashes for delete...
  // This hash was taken from ooex2 and ooex8 test cases.
  delete_hashes.insert("3D3F9E46688A1687E2AB372921A31394");
  // This is an implementation of ??3@YAXPAXI@Z from prtscrpp at 406F9B.
  delete_hashes.insert("3D01B1E1279476F6FFA9296C4E387579");

  // PIC hashes for free (the more identifiable method that delete calls)
  // This hash was taken from ooex2 and ooex8 test cases.
  free_hashes.insert("3F4896D9B44BD7A745E0E5A23753934D");

  // PIC hashes for _purecall
  // This hash was taken from 2010/Lite/oo test case.
  purecall_hashes.insert("0CF963B9B193252F2CDEC4159322921B");

  // _purecall from notepad++5.6.8, at 0x4A0FAA
  purecall_hashes.insert("3F464C9D7A17BBBB054583A48EE66661");

}

// Find new methods by examining imports.
void OOAnalyzer::find_imported_new_methods() {
  GINFO << "Finding imported new methods..." << LEND;

  // Make a list of names that represent new in it's various forms.
  StringSet new_method_names;
  new_method_names.insert("??2@YAPAXI@Z");
  new_method_names.insert("??2@YAPAXIHPBDH@Z");
  // From notepad++5.6.8:
  // void *__cdecl operator new(size_t Size, const struct std::nothrow_t *)
  new_method_names.insert("??2@YAPAXIABUnothrow_t@std@@@Z");

  // Get the import map out of the provided descriptor set.
  ImportDescriptorMap& im = global_descriptor_set->get_import_map();

  // For each new() name...
  for (const std::string & name : new_method_names) {
    // Find all the import descriptors that match.

    for (ImportDescriptor* id : im.find_name(name)) {
      GINFO << "Imported new '" << name << "' found at address "
            << id->address_string() << "."<< LEND;
      id->set_new_method(true);
      id->get_rw_function_descriptor()->set_new_method(true);
      new_methods_found++;
      // This part is kind-of icky.  Maybe we should make a nice set of backward links to all
      // the imports from all the thunks that jump to them...  For now Cory's going to brute
      // force it and move on.
      FunctionDescriptorMap& fdmap = global_descriptor_set->get_func_map();
      for (FunctionDescriptor& fd : boost::adaptors::values(fdmap)) {
        // If it's not a thunk to the import, move on to the next function.
        if (fd.get_jmp_addr() != id->get_address()) continue;
        // If this function is a thunk to the import, it's a new method.
        GINFO << "Function at " << fd.address_string()
              << " is a thunk to a new() method." << LEND;
        fd.set_new_method(true);
        // Also any functions that are thunks to this function are new methods.  This is
        // another example of why thunks are tricky.  In this case we want to access them
        // backwards.  We don't currently have an inverted version of follow_thunks().
        for (FunctionDescriptor* tfd : fd.get_thunks()) {
          GINFO << "Function at " << tfd->address_string()
                << " is a thunk to a thunk to a new() method." << LEND;
          tfd->set_new_method(true);
        }
      }
    }
  }
}

// Find delete methods by examining imports.  Rather than walking all of the functions twice
// (or more), we could probably detect new() methods and delete() methods at the same time! ;-)
void OOAnalyzer::find_imported_delete_methods() {
  GINFO << "Finding imported delete methods..." << LEND;

  StringSet del_method_names;
  del_method_names.insert("??3@YAXPAX@Z");
  del_method_names.insert("??3@YAXPAXI@Z");

  ImportDescriptorMap& im = global_descriptor_set->get_import_map();

  // For each delete() name...
  for (const std::string & name : del_method_names) {
    // Find all the import descriptors that match.
    for (ImportDescriptor* id : im.find_name(name)) {
      GINFO << "Imported delete '" << name << "' found at address "
            << id->address_string() << "."<< LEND;
      id->set_delete_method(true);
      delete_methods_found++;
      // This part is kind-of icky.  Maybe we should make a nice set of backward links to all
      // the imports from all the thunks that jump to them...  For now Cory's going to brute
      // force it and move on.
      FunctionDescriptorMap& fdmap = global_descriptor_set->get_func_map();
      for (FunctionDescriptor& fd : boost::adaptors::values(fdmap)) {
        // If it's not a thunk to the import, move on to the next function.
        if (fd.get_jmp_addr() != id->get_address()) continue;
        // If this function is a thunk to the import, it's a delete method.
        GINFO << "Function at " << fd.address_string()
              << " is a thunk to a delete() method." << LEND;
        fd.set_delete_method(true);
        // Also any functions that are thunks to this function are new methods.  This is
        // another example of why thunks are tricky.  In this case we want to access them
        // backwards.  We don't currently have an inverted version of follow_thunks().
        for (FunctionDescriptor* tfd : fd.get_thunks()) {
          GINFO << "Function at " << tfd->address_string()
                << " is a thunk to a thunk to a delete() method." << LEND;
          tfd->set_delete_method(true);
        }
      }
    }
  }
}

// Find purecall methods by examining imports.
void OOAnalyzer::find_imported_purecall_methods() {
  GINFO << "Finding imported purecall methods..." << LEND;

  StringSet purecall_method_names;
  purecall_method_names.insert("_purecall");

  ImportDescriptorMap& im = global_descriptor_set->get_import_map();

  // For each purecall() name...
  for (const std::string & name : purecall_method_names) {
    // Find all the import descriptors that match.
    for (ImportDescriptor* id : im.find_name(name)) {
      GINFO << "Imported purecall '" << name << "' found at address "
            << id->address_string() << "."<< LEND;
      id->set_purecall_method(true);
      purecall_methods_found++;
      // This part is kind-of icky.  Maybe we should make a nice set of backward links to all
      // the imports from all the thunks that jump to them...  For now Cory's going to brute
      // force it and move on.
      FunctionDescriptorMap& fdmap = global_descriptor_set->get_func_map();
      for (FunctionDescriptor& fd : boost::adaptors::values(fdmap)) {
        // If it's not a thunk to the import, move on to the next function.
        if (fd.get_jmp_addr() != id->get_address()) continue;
        // If this function is a thunk to the import, it's a delete method.
        GINFO << "Function at " << fd.address_string()
              << " is a thunk to a purecall() method." << LEND;
        fd.set_purecall_method(true);
        // Also any functions that are thunks to this function are new methods.  This is
        // another example of why thunks are tricky.  In this case we want to access them
        // backwards.  We don't currently have an inverted version of follow_thunks().
        for (FunctionDescriptor* tfd : fd.get_thunks()) {
          GINFO << "Function at " << tfd->address_string()
                << " is a thunk to a thunk to a purecall() method." << LEND;
          tfd->set_purecall_method(true);
        }
      }
    }
  }
}

// Find functions that have instructions that uses THIS_PTR without initialization
void find_this_call_methods() {
  FunctionDescriptorMap& fdmap = global_descriptor_set->get_func_map();
  for (FunctionDescriptor& fd : boost::adaptors::values(fdmap)) {
    // Speculatively construct a ThisCallMethods from the function.  The ThisCallMethod class
    // will tell us whether the function was really object oriented or not.
    ThisCallMethod tcm(&fd);

    // Add the function to the set if it has any instructions that used ECX.  This is currently
    // our "standard" for being object oriented, but it could use some improvement.
    if (tcm.is_this_call()) {
      GINFO << "Function " << tcm.address_string() << " uses __thiscall convention." << LEND;
      this_call_methods.insert(ThisCallMethodMap::value_type(fd.get_address(), tcm));
    }
  }

  // Look for methods that pass their this-pointers to other methods.  This analysis pass must
  // follow the loop above that builds this_call_methods, because it uses membership in that
  // map to decide which functions are __thiscall, and thus are receiving the current value of
  // ECX.
  for (ThisCallMethod& tcm : boost::adaptors::values(this_call_methods)) {
    tcm.find_passed_func_offsets();
  }
}

// Force entries in the classes map for all this call methods that have virtual
// function tables.  This used to be part of set_members_from_methods(), but it had nothing to
// do with that conceptually, and it seems like this should occur much earlier in the analysis.
// Cory moved it to a separate function for clarity, and experimentation.
void force_class_entries() {
  // For every object oriented method in the program...
  for (ThisCallMethod& tcm : boost::adaptors::values(this_call_methods)) {
    rose_addr_t taddr = tcm.get_address();

    // The logic here used to be quite different.  Cory's made it two separate passes.  First
    // ensure that every constructor that's obviously a constructor because it initializes
    // virtual fuction table pointers has an entry of it's own in classes.  This
    // probably should have been long before this point in the code, but for whatever reason it
    // was only eventually done here.
    for (const Member& member : boost::adaptors::values(tcm.data_members)) {
      if (member.is_virtual()) {
        if (classes.find(taddr) == classes.end()) {
          GDEBUG << "Last second addition of virtual constructor! " << addr_str(taddr) << LEND;
          classes[taddr] = ClassDescriptor(tcm.get_address(), &tcm);
        }
      }
    }
  }
}

// This pass propagates member information from the thiscall method to classes.  The rule is
// that all member accesses in all methods called by an object are valid members for that
// object.  Add all the members to both the class for the thiscall method if it's a
// constructor, and for any class that calls this method.  We used to do only one or the other,
// which Cory thought was wrong.  This does uncover some interesting cases for conflicting
// write to vftables for example, but that's largely handled in Member::merge() now.  There's
// still some wrongness here in that the ordering of the loops is probably sub-optimal.
void set_members_from_methods() {
  // For every object oriented method in the program...
  for (const ThisCallMethod& tcm : boost::adaptors::values(this_call_methods)) {
    rose_addr_t taddr = tcm.get_address();

    GDEBUG << "Setting data members in " << tcm.address_string() << LEND;
    // For each member this method accesses..
    for (const Member& member : boost::adaptors::values(tcm.data_members)) {
      // Make sure the member is on the class for this method.
      if (classes.find(taddr) != classes.end()) {
        classes[taddr].add_data_member(member);
      }
      // For each class...
      for (ClassDescriptor& cls : boost::adaptors::values(classes)) {
        // For each method called by the class...
        for (const ThisCallMethod* mtcm : cls.methods) {
          // If it's the current method under consideration, add it to classes.
          if (mtcm->get_address() == taddr) {
            cls.add_data_member(member);
          }
        }
      }
    }
  }
}

// Set members from the methods associated with each class.  This routine only works once the
// methods have been associated with the classes, so it might not be a suitable replacement for
// the set_members_from_methods() routine above.  On the other hand, this logic is clear, and
// makes sense,
void set_members_from_methods_in_classes() {
  GINFO << "Setting members from methods in classes..." << LEND;

  // For each class...
  for (ClassDescriptor& cls : boost::adaptors::values(classes)) {
    // For each method called by the class...
    for (const ThisCallMethod* tcm : cls.methods) {
      // For each member updated by the method.
      for (const Member& member :  boost::adaptors::values(tcm->data_members)) {
        // Add the member to the class.
        cls.add_data_member(member);
      }
    }
  }
}

// Remove all members from the classes, and then repopulate them from just the methods
// associated with the class, but do not include the methods that have since been associated
// with the parent classes.
void reanalyze_members_from_methods() {
  GINFO << "Reanalyzing members from methods..." << LEND;

  for (ClassDescriptor& cls : boost::adaptors::values(classes)) {
    cls.data_members.clear();
    cls.update_size();
  }
  // rebuild the methods
  set_members_from_methods_in_classes();
}

// This function started life as a loop buried inside ananlyze_passed_func_offsets.  It used to
// use the basic block number out of a passed func offset, but that was buggy and eliminated,
// so now we only need a thiscall method.  It's possible that the only reason that this code
// detects the second parent is because it's not sufficiently rigorous, and is accepting the
// first function table overwrite as evidence of the second parent relationship.  If that's the
// case we should get rid of it entirely.  The sole purpose of this code appears to be to
// detect the second parent in ooex8, so maybe it ought be called something like
// look_for_multiple_inheritance_parent().  It is also the code that causes entries to appear
// in inherited methods.
bool look_for_parent_constructor(ThisCallMethod& tcm) {
  FunctionDescriptor* srcfd = tcm.fd;
  PDG* p = srcfd->get_pdg();
  if (p == NULL) return false;

  auto & ud = p->get_usedef();

  SymbolicValuePtr tptr = tcm.get_this_ptr();

  // Wes used to start at a specific block, and Cory was confused about why that could be
  // correct.  Turns out that apparently it wasn't since starting at block zero only resulted
  // in the correct detection of parent relationships in ooex8.
  for (SgAsmStatement* bs : srcfd->get_func()->get_statementList()) {
    SgAsmBlock *bb = isSgAsmBlock(bs);
    if (!bb) continue;
    for (SgAsmStatement* is : bb->get_statementList()) {
      SgAsmX86Instruction *insn = isSgAsmX86Instruction(is);
      if (!insn) continue;

      // Look for a mov [REG], dword_offsetXXXX
      // If this instruction isn't a move, just go to the next one.
      if (insn->get_kind() != x86_mov) continue;

      SgAsmExpressionPtrList &ops = insn->get_operandList()->get_operands();
      if (ops.size() >= 2 && isSgAsmMemoryReferenceExpression(ops[0])) {
        for (const AbstractAccess& aa : ud.get_mem_writes(insn)) {
          // Does the value in REG match the last defined value of ECX before
          if (tptr->can_be_equal(aa.memory_address)) {
            GDEBUG << "Parent constructor found " << debug_instruction(insn) << LEND;
            return true;
          }
        }
      }
    }
  }

  return false;
}

void analyze_passed_func_offsets() {
  for (ThisCallMethod& tcm : boost::adaptors::values(this_call_methods)) {
    rose_addr_t taddr = tcm.get_address();

    for (FuncOffset& fo : boost::adaptors::values(tcm.passed_func_offsets)) {
      ThisCallMethod* fotcm = fo.tcm;
      rose_addr_t caddr = fotcm->get_address();

      // The setting of the boolean used to be outside the loop, at the very beginning of the
      // function.  Cory's not sure why it was there and not here.  Were we concerned about
      // modifications to classes during the loop?  Moving it here doesn't appear
      // to have broken anything, but it's still unclear what was really meant.
      bool srcIsConstructor = classes.find(taddr) != classes.end();
      if (!srcIsConstructor) continue;

      // Check to see if the call target is not in classes.  This appears to be a
      // test for whether it's a constructor or not.
      if (classes.find(caddr) != classes.end()) {
        // Cory says: Oops this call now has nothing to do with the func offset!  We used to
        // need it because it held the bbnum that we've since eliminated since it was buggy,
        // and so now I guess we should move this call somewhere else, like on the
        // ThisCallMethod.
        if (look_for_parent_constructor(tcm)) {
          GINFO << "Possible inherited constructor: " << addr_str(taddr)
                << " inherits from " << addr_str(caddr) << LEND;
          GINFO << "Parent constructor is located at offset 0x"
                << std::hex << fo.offset << std::dec << LEND;

          // Ensure that the entry really exists.
          if (classes.find(taddr) == classes.end())
            classes[taddr] = ClassDescriptor(tcm.get_address(), &tcm);

          // Actually, I guess we need it here, although we're not really using the inherited
          // methods field. In fact, this appears to be the only place that we're setting it,
          // so maybe we should revisit it's purpose entirely.
          classes[taddr].inherited_methods[fotcm] = fo.offset;
        }
        else {
          // It's unclear how this code now relates to the nearly identical test in
          // ThisCallMethod::find_passed_func_offsets()...  Maybe this code isn't needed?
          GINFO << "Embedded object at offset " << fo.offset << " in method at "
                << fotcm->address_string() << " is passed to " << addr_str(caddr) << LEND;
          Member mem(fo.offset, 0, caddr, fo.insn, NULL);
          classes[taddr].add_data_member(mem);
        }
      }
      // We're in classes... so why wouldn't we be a constructor?
      else {
        // Is the called method a constructor?
        if (fotcm->is_constructor()) {
          GINFO << "Possible parent constructor found at " << addr_str(caddr) << LEND;
          classes[caddr] = ClassDescriptor(fotcm->get_address(), fotcm);
        }
        else if (fo.offset == (int64_t)0) {
          GINFO << "Possible member function found in constructor "
                << addr_str(taddr) << " " << addr_str(caddr) << LEND;
          classes[taddr].methods.insert(fotcm);
        }
      }
    }
  }
}

// Find the instruction that calls from the src function to the dst function.  Perhaps this
// should become a method on a function descriptor.  For example: fd->get_insn_calling(dst)
SgAsmX86Instruction* get_caller(const FunctionDescriptor *src, const FunctionDescriptor *dst) {
  // Wes appeared to have some debugging paranoia about finding callers.  In every case that he
  // called findCallingInstruction, he then asserted to make sure that it worked, but he also
  // logged, so I'm still unsure whether he thinks this can happen or not.  Putting the code
  // here cleans up elsewhere some and reminds Cory to investigate.

  for (const CallDescriptor* scd : src->get_outgoing_calls()) {
    for (const rose_addr_t saddr : scd->get_targets()) {

      FunctionDescriptor* sfd = global_descriptor_set->get_func(saddr);
      if (sfd == NULL) continue;

      if ((dst == sfd) || (dst == sfd->get_jmp_fd())) {
        SgAsmInstruction* insn = scd->get_insn();
        GDEBUG << "Caller " << debug_instruction(insn) << LEND;
        return isSgAsmX86Instruction(insn);
      }
    }
  }

  GERROR << "Caller not found. src = 0x" << src->address_string()
         << " called method 0x" << dst->address_string() << LEND;
  return NULL;
}

void make_class(const ObjectUse& obj_use, ThisCallMethod* ctor, const ThisPtrUsage& tpu) {
  FunctionDescriptor* fd = obj_use.fd;
  // If the passed constructor is NULL, we must be trying to create a class without a
  // constructor.  This is a new capability, and for now this only happens with global objects.
  // In this case get the caddr from the this-pointer.  In the future we'll probably want to
  // pass this address somehow.
  rose_addr_t caddr;
  rose_addr_t caller_addr;
  if (ctor == NULL) {
    if (tpu.this_ptr != NULL && tpu.this_ptr->is_number()) {
      caddr = tpu.this_ptr->get_number();
      caller_addr = 0;
      GDEBUG << "Class has no constructor for this-pointer " << addr_str(caddr)
             << " in function " << fd->address_string() << LEND;
    }
    else {
      GERROR << "Attempted to create class without valid address!" << LEND;
      return;
    }
  }
  else {
    caddr = ctor->get_address();
    // There's probably a more efficient way to get the caller now.  In fact, caller == NULL is
    // probably no longer possible.  But we're still using this in the obj_use loop below.
    SgAsmX86Instruction *caller = get_caller(fd, ctor->fd);
    if (caller == NULL) return;
    caller_addr = caller->get_address();
    GDEBUG << "Object constructed by " << ctor->address_string() << " at call "
           << addr_str(caller_addr) << " in function " << fd->address_string() << LEND;
  }

  if (classes.find(caddr) == classes.end())
    classes[caddr] = ClassDescriptor(caddr, ctor);

  // If the this-pointer usage came with an allocation size because it was dynamically
  // allocated, propogate that into the class definition.
  if (tpu.alloc_size != 0) {
    classes[caddr].set_alloc_size(tpu.alloc_size);
    GDEBUG << "Setting size of class id=" << addr_str(caddr) << " to " << tpu.alloc_size
           << " in function " << tpu.get_fd()->address_string() << LEND;
  }

  // Add all methods from the this-pointer usage to the object instance.
  classes[caddr].merge_all_methods(tpu);

  GDEBUG << "In " << fd->address_string() << " processing nested make_class loop." << LEND;
  // Can we find any groups that have a this-pointer that depends on the return code of the
  // constructor?  Why we should need to do this is unclear to Cory, but it does still have an
  // effect.
  for (const ThisPtrUsage& otpu : boost::adaptors::values(obj_use.references)) {
    InsnSet defs = otpu.this_ptr->get_defining_instructions();
    GDEBUG << "  Looping OTPU: ";
    otpu.debug();
    GDEBUG << LEND;
    for (SgAsmInstruction* dinsn : defs) {
      GDEBUG << "    Defining instruction: " << debug_instruction(dinsn) << LEND;
      if (dinsn->get_address() != caller_addr) continue;
      GDEBUG << "    Filtered instruction: " << debug_instruction(dinsn) << LEND;
      for (ThisCallMethod* tcm : otpu.get_methods()) {
        GDEBUG << "Checking TCM" << LEND;
        if (GDEBUG) tcm->debug();
        if (classes[caddr].methods.find(tcm) == classes[caddr].methods.end()) {
          GDEBUG << "Member function dependent on constructor return code "
                 << tcm->address_string() << LEND;
          classes[caddr].methods.insert(tcm);
        }
      }
      // When we've found the one that matches, we're done.
      break;
    }
  }
}

void handle_heap_allocs(const rose_addr_t saddr) {
  GDEBUG << "handle_heap_allocs inspecting addr " << addr_str(saddr) << LEND;
  CallDescriptor* cd = global_descriptor_set->get_call(saddr);
  if (cd == NULL) {
    GINFO << "No call descriptor for call at " << addr_str(saddr) << LEND;
    return;
  }

  SgAsmInstruction* insn = cd->get_insn();
  FunctionDescriptor* cfd = global_descriptor_set->get_fd_from_insn(insn);
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
    if (pd->value != NULL && pd->value->is_number()) {
      unsigned int size = pd->value->get_number();
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

void find_heap_allocs() {
  // Second pass - Having completed the object use analysis for all functions, make another
  // pass over the functions looking for the ones we've identified as new() methods.  For each
  // new() method, analyze all of it's callers and record that they are heap allocated objects.
  FunctionDescriptorMap& fdmap = global_descriptor_set->get_func_map();
  for (FunctionDescriptor& fd : boost::adaptors::values(fdmap)) {
    if (fd.is_new_method()) {
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
  ImportDescriptorMap& idmap = global_descriptor_set->get_import_map();
  for (ImportDescriptor& id : boost::adaptors::values(idmap)) {
    if (id.get_function_descriptor()->is_new_method()) {
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

// Analyze every function in the program looking for object uses, where the definition of an
// object use is passing the symbolic value to a known OO method.  References to each object
// are grouped first by the function that they occured in, and then by the symbolic value of
// the this-pointer.  Analysis in this pass is entirely local to the function, and the only
// interprocedural analysis is from knowing which methods are __thiscall.  As a consequence, we
// probably will not have the complete lifetime of the object from construction to destruction,
// although in some cases we might.  After finding the object uses, we then analyze them to see
// if we can determine whether there's an allocation site in this usage.
void analyze_functions_for_object_uses() {
  // First pass - Find all object uses in all functions in program.
  FunctionDescriptorMap& fdmap = global_descriptor_set->get_func_map();
  for (FunctionDescriptor& fd : boost::adaptors::values(fdmap)) {
    rose_addr_t faddr = fd.get_address();

    // Find all uses of objects in the function and record them as a list of this-pointers and
    // the methods that were invoked using those pointers.  Store it in the global map for
    // later reference (while avoiding the use of the default constructor).
    object_uses.insert(ObjectUseMap::value_type(faddr, ObjectUse(&fd)));
  }

  // Alternate version of the find_heap_objects() routine, in transition...
  find_heap_allocs();
}

// This method is called mangle dominance because it applies _incorrect_ dominance logic to
// determining which methods might be constructors.  It needs to be performed _after_ the
// Prolog fact exporting in order for both to work correctly at the same time.
void mangle_dominance() {
  for (ObjectUse& obj_use : boost::adaptors::values(object_uses)) {
    obj_use.apply_constructor_dominance_rule();
  }
}

// Make classes from the object uses that have allocation sites.  Essentially, in cases where
// the object is a local stack variable or allocated by new() we know that a constructor has to
// be in the method list, so pick the best available method as the constructor, and begin
// accumulating information about that class.
void make_classes_from_allocations() {
  for (ObjectUse& obj_use : boost::adaptors::values(object_uses)) {
    // This is a little hackish, and should perhaps be someplace else.
    for (ThisPtrUsage& tpu : boost::adaptors::values(obj_use.references)) {
      tpu.pick_ctor();
      // If the allocation type was a recognized one...
      if (tpu.alloc_type == AllocLocalStack || tpu.alloc_type == AllocHeap) {
        ThisCallMethod* tcm = tpu.get_ctor();
        // If we couldn't decide which methods was the constructor, continue.
        if (tcm == NULL) continue;

        // Create entries in classes...
        make_class(obj_use, tcm, tpu);

      }
      else if (tpu.alloc_type == AllocGlobal) {
        make_class(obj_use, NULL, tpu);
      }
    }
  }
}

// this analytical pass should associate object instances with ThisCallMethods. Somewhere
// we should report whether there are any ThisCallMethods that are not associated with an
// object instance
void analyze_assign_objinstances_to_tcm() {


}

bool DemangleCppName(std::string &mangled_name, std::string &demangled_name) {

  GDEBUG << "Demangling name: " << mangled_name << LEND;

  std::string start_mark = "V";
  std::string end_mark = "@";

  std::size_t start = mangled_name.find(start_mark);
  if (start != std::string::npos) {
    std::string class_name_start = mangled_name.substr (start+1);
    std::size_t end = class_name_start.find(end_mark);

    if (end != std::string::npos) {
      demangled_name = class_name_start.substr(0,end);
      return true;
    }
  }
  return false;
}

void analyze_class_names()  {

  //for (ClassDescriptor& cls : boost::adaptors::values(classes)) {
  for (ClassDescriptorMap::value_type& cpair : classes) {

    ClassDescriptor &obj = cpair.second;
    rose_addr_t obj_key = cpair.first;

    bool use_default = true;

    for (const Member& member : boost::adaptors::values(obj.data_members)) {
      if (!(member.is_virtual())) continue;

      VirtualFunctionTable *vtab = member.get_vftable();
      // this is a vtable - get the RTTI

      // Various preconditions for the situation that interests us.
      if (vtab == NULL) continue;
      if (vtab->rtti == NULL)  continue;
      if (vtab->rtti_confidence == ConfidenceNone) continue;
      if (vtab->rtti->signature.value != 0) continue;
      if (vtab->rtti->class_desc.signature.value != 0) continue;

      std::string rtti_classname = vtab->rtti->type_desc.name.value;
      std::string demangled_rtti_classname = "";
      if (DemangleCppName(vtab->rtti->type_desc.name.value,demangled_rtti_classname)) {
        if (!demangled_rtti_classname.empty()) {
          obj.set_name(demangled_rtti_classname);
          use_default = false;
          break;
        }
      }
    }

    if (use_default) {
      GDEBUG << "Using default name" << LEND;
      std::ostringstream clsNameStream;
      clsNameStream << "Cls_" << std::hex << obj_key << std::dec;
      obj.set_name(clsNameStream.str());
    }
  }
}

// There are so many passes to adjust the size of classes that one final pass to calculate final
// sizes
void analyze_final_class_sizes() {
  GINFO << "Analyzing final class sizes..." << LEND;

  for (ClassDescriptor& cls : boost::adaptors::values(classes)) {
    cls.update_size();
  }
}

// A method belongs to exactly one class (right?). This function returns a pointer to the
// ClassDescriptor that contains a method (virtual or otherwise)
ClassDescriptor *find_class_by_method(const rose_addr_t method_addr) {

  for (ClassDescriptor& cls : boost::adaptors::values(classes)) {

    for (ThisCallMethodSet::value_type method : cls.methods) {
      if (method_addr == method->get_address()){
        return &cls;
      }
    }

    // Now we must search virtual functions for the class ...  Cory thinks that we should
    // probably just have a pass that adds the methods in the virtual function table to the
    // class descriptor, then the code above would be sufficient.  Although it's _NOT_ true
    // that functions are only in one classes' virtual function table, so this code violates
    // the rule about a method only belonging to one class.  This should still be true _after_
    // we've done proper movement of methods to their parents.  Why exactly did you need this
    // behavior again?
    for (const Member& member : boost::adaptors::values(cls.data_members)) {
      if (member.is_virtual() == false) continue;

      // this is a vfptr
      VirtualFunctionTable *vtable = member.get_vftable();
      if (vtable != NULL) {
        // Perhaps we should print the whole vtable here via vftable->print(o)...
        for (unsigned int e = 0; e < vtable->max_size; e++) {
          rose_addr_t vf_addr = vtable->read_entry(e);
          if (method_addr == vf_addr) {
            return &cls;
          }
        }
      }
    }
  }

  return NULL;
}

// Evaluate methods to determine whether the meet basic criteria for being a deleting
// destructor.  If so, mark the ThisCallMethod as a deleting destructor, and the real
// destructor to reduce confusion with constructors.  Both properties are stored on the
// ThisCallMethod.  The criteria for being tested for is:
//
//  * The function has two outgoing calls
//  * One outgoing call is to delete
//  * The other outgoing call is to a constructor
//
// Gennari says: This is admitedly weak.
void evaluate_possible_destructors() {

  GDEBUG << "Evaluating possible destructors..." << LEND;

  for (ThisCallMethod& possible_dtor_tcm : boost::adaptors::values(this_call_methods)) {
    rose_addr_t real_dtor_addr;

    // can't find function descriptor for possible deleting destructor - skip it.
    if (!possible_dtor_tcm.fd) {
      GDEBUG << "Cannot find FunctionDescriptor for address Thiscall method" << LEND;
      continue;
    }

    GDEBUG << "Evaluating possible deleting destructor " << addr_str(possible_dtor_tcm.get_address()) << LEND;

    const CallDescriptorSet& calls = possible_dtor_tcm.fd->get_outgoing_calls();
    if (calls.size() != 2) {
      // deleting destructors have exactly 2 calls - destructor and delete
      // this is boilerplate code so it's probably reliable
      continue;
    }

    bool found_delete=false, found_real_dtor=false; // deleting destructors have exactly 2 requirements

    for (const CallDescriptor *cd : calls) {
      const CallTargetSet &call_targets = cd->get_targets();

      // assuming one target for now
      rose_addr_t target = *(call_targets.begin());

      GDEBUG << " Checking call:  " << addr_str(cd->get_address()) << " to "
             << addr_str(target) << LEND;

      FunctionDescriptor *target_func = global_descriptor_set->get_func(target);

      if (target_func == NULL) {
        continue; // can't determine what this is so just skip it
      }

      // is the target function a thiscall method?
      if (this_call_methods.find(target_func->get_address()) != this_call_methods.end()) {

        ThisCallMethod& tcm = this_call_methods.at(target_func->get_address());

        // does it look like a constructor?
        if (tcm.is_constructor() && !found_real_dtor) {

          // this call is the destructor
          GDEBUG << " Possible programmer-defined destructor: " << tcm.address_string() << LEND;

          found_real_dtor = true; // found this requirement

          // it is the real destructor
          real_dtor_addr = tcm.get_address();

        }
        else {
          break; // two calls to constructor-like things disqualify this candidate
        }
      }
      // is it the delete operator?
      else if (target_func->is_delete_method()) {
        GDEBUG << " Found delete call: " << target_func->address_string() << LEND;
        found_delete = true;
      }

      // did we find both requirements - break
      if (found_real_dtor && found_delete) break;

    } // end for each outgoing call

    if (found_real_dtor && found_delete) {

      // we've satisfied both requirements for the deleting destructor
      possible_dtor_tcm.set_deleting_destructor(true,ConfidenceGuess);

      // we also know something about the real destructor
      if (this_call_methods.find(real_dtor_addr) != this_call_methods.end()) {
        ThisCallMethod &dtor_tcm = this_call_methods.at(real_dtor_addr);
        dtor_tcm.set_destructor(true,ConfidenceGuess);
      }
    }
  }
}

// This pass was disabled, because most of this code is now in evaluate_possible_destructors().
void deleting_destructors_must_be_virtual() {
  GINFO << "Evaluating virtual destructors..." << LEND;

  rose_addr_t real_dtor_addr=0, deleting_dtor_addr=0;
  bool real_dtor_found=false, deleting_dtor_found=false;

  for (const VirtualFunctionTable* vtab : boost::adaptors::values(global_vftables)) {
    for (unsigned int i=0; i<vtab->max_size; i++) {

      rose_addr_t possible_deldtor_addr = vtab->read_entry(i);
      FunctionDescriptor *fd = global_descriptor_set->get_func(possible_deldtor_addr);

      // can't find function descriptor for possible deleting destructor - skip it.
      if (!fd) {
        GDEBUG << "Cannot find FunctionDescriptor for address "
               << addr_str(possible_deldtor_addr) << LEND;
        continue;
      }

      const CallDescriptorSet& calls = fd->get_outgoing_calls();
      if (calls.size() != 2) {
        // deleting destructors have exactly 2 calls - destructor and delete
        // this is boilerplate code so it's probably reliable
        continue;
      }

      for (const CallDescriptor *cd : calls) {
        const CallTargetSet &call_targets = cd->get_targets();

        // assuming one target for now
        rose_addr_t target = *(call_targets.begin());

        GDEBUG << "Checking possible delete target call:  " << addr_str(cd->get_address()) << " to "
               << addr_str(target) << LEND;

        FunctionDescriptor *target_func = global_descriptor_set->get_func(target);

        if (target_func == NULL) {
          continue; // can't determine what this is so just skip it
        }

        // is the target function a thiscall method?
        rose_addr_t target_addr = target_func->get_address();

        if (this_call_methods.find(target_addr) != this_call_methods.end()) {
          ThisCallMethod& tcm = this_call_methods.at(target_addr);
          if (tcm.is_constructor()) {

            // this call is the destructor
            GDEBUG << "Found programmer-defined destructor: " << tcm.address_string() << LEND;

            tcm.set_constructor(false, ConfidenceGuess);
            tcm.set_destructor(true, ConfidenceGuess);

            real_dtor_addr = tcm.get_address();
            real_dtor_found = true;
          }
        }
        else if (target_func->is_delete_method()) {
          if (this_call_methods.find(possible_deldtor_addr) != this_call_methods.end()) {
            ThisCallMethod &del_tcm = this_call_methods.at(possible_deldtor_addr);
            del_tcm.set_destructor(true, ConfidenceGuess);

            deleting_dtor_addr = possible_deldtor_addr;
            deleting_dtor_found = true;

            GDEBUG << "Found deleting destructor " << addr_str(deleting_dtor_addr) << LEND;
            // ideally here would be where analysis of whether the this pointer is deleted
            // would come in to play for this analysis
          }
        }
      }
    }

    // set the two identified destructors in the ClassDescriptorSet

    if (real_dtor_found) {
      ClassDescriptor *real_dtor_cls = find_class_by_method(real_dtor_addr);
      if (real_dtor_cls != NULL) {
        ThisCallMethod *real_dtor = real_dtor_cls->get_method(real_dtor_addr);
        if (real_dtor) {
          real_dtor_cls->set_real_dtor(real_dtor);
        }
      }
    }

    if (deleting_dtor_found) {
      ClassDescriptor *del_dtor_cls = find_class_by_method(deleting_dtor_addr);
      if (del_dtor_cls != NULL) {

        ThisCallMethod *del_dtor = del_dtor_cls->get_method(deleting_dtor_addr);
        if (del_dtor != NULL) {
          del_dtor_cls->set_deleting_dtor(del_dtor);
        }
      }
    }
  }
}


// Mark functions that appear in virtual function tables as not being constructors.  This
// algorithm will help eliminate false positives from our weak constructor filtering heuristic,
// since real constructors can't be virtual.  This pass should happen as early as possible
// after we've established where the virtual function tables are to prevent the incorrect
// identification of destructors as constructors and so forth.  Right now the primary goal is
// to quit incorrectly labeling destructors as constructors in the final output.
void disallow_virtual_constructors() {
  GINFO << "Disallowing virtual constructors..." << LEND;

  // For each virtual function table...
  for (const VirtualFunctionTable* vtab : boost::adaptors::values(global_vftables)) {
    // For each entry in the virtual function table...
    for (unsigned int i=0; i < vtab->max_size; i++) {
      rose_addr_t vfunc_addr = vtab->read_entry(i);

      // Find the method (if there is one), with that address.  If there's not one, that's not
      // surprising, and there's no work for us to do anyway.
      ThisCallMethodMap::iterator tcmfinder = this_call_methods.find(vfunc_addr);
      if (tcmfinder != this_call_methods.end()) {
        ThisCallMethod& tcm = tcmfinder->second;

        // If it's already marked as a constructor, the most likely case is that it's really a
        // destructor (the two look similar to us for a while).  This logic doesn't really
        // belong here.  If we did a better job of guessing about destructors earlier, we
        // probably wouldn't need this part of the algorithm.  For example, Jeff's destructor
        // detection above could be done during method analysis, long before we got here.
        if (tcm.is_constructor()) {
          GDEBUG << "Method " << tcm.address_string() << " cannot be a constructor because it's virtual." << LEND;
          tcm.set_destructor(true, ConfidenceGuess);
        }

        // If our virtual function table analysis is correct, then this method can NOT be a
        // constructor, so we're pretty confident in this heuristic.  We'd have to misidentify
        // a virtual function table or get the boundaries wrong and then for there to be a
        // pointer to constructor nearby.  Since constructors can't appear in nearby virtual
        // function tables either, this failure mode is probably pretty rare.
        tcm.set_constructor(false, ConfidenceConfident);

      }
    }
  }
}

void analyze_destructors() {
}


// For each object instance, cycle through each member and determine if it is an embedded object
// by looking up its constructor. If it is an embedded object, the match it with the other
// embedded objects based on methods. This will allow calculation of total object size

// Jeff Gennari thinks this logic is flawed because it relies on the embedded_ctors list being
// an up-to-date list of unique object identifiers - it is not that.  Cory agreed with this
// change, but doesn't understand Jeff's comment.
void analyze_embedded_objects() {
  GINFO << "Analyzing embedded objects..." << LEND;

  // phase 1: cycle through the members for each object and determine if they are embedded
  // objects. If they are, then identify them as members.
  for (ClassDescriptor& obj : boost::adaptors::values(classes)) {
    for (Member& member : boost::adaptors::values(obj.data_members)) {
      // if this member is an embedded object, correct it's size and type
      if (member.is_embedded_object() == true) {

        for (rose_addr_t ector : member.embedded_ctors) {

          GDEBUG << "Looking for embedded constructor: " << addr_str(ector) << LEND;

          ClassDescriptor *embedded_cls = find_class_by_method(ector);
          if (embedded_cls!=NULL) {
            // members cannot be their own parents
            if (embedded_cls->get_address() == obj.get_address()) continue;

            member.object = embedded_cls;
            member.size = member.object->get_size();

            GDEBUG << "Correcting embedded object " << addr_str(ector)
                   << " size to " << member.object->get_size() << LEND;
          }
          else {
            GDEBUG << "Could not find embedded ctor in master list" << LEND;
          }
        }
      }
    }
  }
  // Phase 2: identify and removing overlapping members. This is not working

#if 0

  for (ClassDescriptor& obj : boost::adaptors::values(classes)) {
    for (const MemberMap& obj_mbr : boost::adaptors::values(obj.data_members)) {
      if (obj_mbr.object != NULL) {

        // this member is an object
        ClassDescriptor *embedded_obj = obj_mbr.object;

        // start searching for overlap
        for (const MemberMap& other_mbr : boost::adaptors::values(obj.data_members)) {
          if (obj_mbr != other_mbr ) {
            if ((obj_mbr.offset+obj_mbr.size ) >= other_mbr.offset) {

              // overlap has occurred. if the
              for (const MemberMap& m : boost::adaptors::values(embedded_obj->data_members)) {
                if (m == other_mbr) {
                  // the other_mbr is not in the embedded object, add it and remove it from the
                  // containing object
                  embedded_obj->add_data_member(other_mbr);
                  break;
                }
              }
              // the overlapping member has been added to the embedded object -> delete it
              obj.delete_data_member(other_mbr);
            }
          }
        }
      }
    }
  }
#endif
}

// For virtual function table overlap analysis.
typedef std::map<rose_addr_t, rose_addr_t> Addr2AddrMap;

void analyze_vtable_overlap_new() {
  // For every virtual base table...
  for (VirtualBaseTable* vbt : boost::adaptors::values(global_vbtables)) {
    // Ask the virtual base table to compare itself with all other tables, and update its size.
    vbt->analyze_overlaps();
  }
  // In the new way of doing things we should probably be doing this too...
  //for (const VirtualFunctionTable* vft : boost::adaptors::values(global_vftables)) {
  //  vft->analyze_overlaps();
  //}
}

// this function checks for overlaps in the detected vtables by analyzing each table's starting
// address and size
void analyze_vtable_overlap() {
  GINFO << "Analyzing vtable overlap..." << LEND;

  // key is start address, value is the end address
  Addr2AddrMap vt_map;

  // for each class, if that constructor has a vtable then use the
  // best size to determine how -- Cory thinks GlobalVTableMap would be better here.
  for (const VirtualFunctionTable* vtab : boost::adaptors::values(global_vftables)) {
    if (vtab->addr > 0 && vtab->best_size > 0) {
      vt_map[vtab->addr] = vtab->addr + (vtab->best_size*4);
    }
  }

  // all the vftables have been accumulated in the vt_map. Now figure out if they overlap by
  // checking if the start of the vtable plus the number of functions is greater than the
  std::map<rose_addr_t,unsigned int> adjust_list;
  Addr2AddrMap::iterator next = vt_map.begin();
  for (Addr2AddrMap::value_type& vpair : vt_map) {
    rose_addr_t vt_start = vpair.first;
    rose_addr_t vt_end = vpair.second;
    next++;

    if (next != vt_map.end()) {
      rose_addr_t next_vt_start = next->first;
      if (vt_end >= next_vt_start) {

        // set new size to be bounded by the start of the next vtable.
        // Dividing by four gives the number of entries in the table
        size_t new_size = (next_vt_start-vt_start)/4;
        adjust_list[vt_start] = new_size ;

        GINFO << "Virtual function table at " << addr_str(vt_start)
              << " has a size of " << ((vt_end-vt_start)/4)
              << " and overlaps with virtual function table at "
              << addr_str(next_vt_start) << ". Adjusting size to " << new_size << LEND;
      }
    }
  }
  // the adjusted size of the vtable is now known, update the global vtable list
  for (VirtualFunctionTable* vtab : boost::adaptors::values(global_vftables)) {
    if (adjust_list.find(vtab->addr) != adjust_list.end()) {
      // update max and recompute the size guess
      vtab->update_maximum_size(adjust_list[vtab->addr]);
      vtab->update_size_guess();
    }
  }

  // At this point, virtual function tables will not overlap. However, there are some cases
  // where there

  // adjust size based on rtti data
  for (const VirtualFunctionTable* target_vtab : boost::adaptors::values(global_vftables)) {
    // this vtable has rtti information
    if (target_vtab->rtti != NULL) {

      // check to see if other vtables count this vtable's rtti as a virtual function method
      for (VirtualFunctionTable* other_vtab : boost::adaptors::values(global_vftables)) {

        if (target_vtab->addr != other_vtab->addr) {
          // the address of the last entry
          rose_addr_t other_vtab_last_entry = other_vtab->addr + (other_vtab->best_size*4);

          // check for a collision, rather we need  to check if the last entry is beyond the
          // first entry of the target
          if (other_vtab->rtti_addr < target_vtab->rtti_addr &&
              target_vtab->rtti_addr <= other_vtab_last_entry) {

            // the best size must be less than the target vtable
            other_vtab->best_size = ((other_vtab_last_entry-4)-other_vtab->addr)/4;

            GINFO << "Virtual function table at " << addr_str(other_vtab->addr)
                  << " includes the RTTI pointer from the virtual function table at "
                  << addr_str(target_vtab->addr) << ". Adjusting best size to "
                  << other_vtab->best_size << " ("
                  << (other_vtab->addr+other_vtab->best_size*4) << ")" << LEND;

            break;
          }
        }
      }
    }
  }
}

// This function is responsible for updating the targets in the virtual function call
// descriptor once the constructor for the object pointer associated with the virtual function
// call has been identified.  The parameters are the virtual function call descriptor to
// update, and the this call method for the constructor.
void resolve_virtual_function_call(CallDescriptor& vfcd, ThisCallMethod* tcm) {
  // Get the virtual function call information.
  CallInformationPtr ci = vfcd.get_call_info();
  VirtualFunctionCallInformationPtr vci =
    boost::dynamic_pointer_cast<VirtualFunctionCallInformation>(ci);

  if (tcm == NULL)
  {
    GERROR << "resolve_virtual_function_call, tcm is NULL? (vfcd addr == "
           << addr_str(vfcd.get_address()) << ")" << LEND;
    return;
  }

  if (!(tcm->is_constructor())) {
    GERROR << "Method at " << tcm->address_string() << " is not a constructor." << LEND;
    // It look like there may be some functions with virtual function tables that aren't yet
    // marked as constructors, so rather than giving up, let's just complain about the
    // inconsistency, and keep going.  We'll not do anything unless we find an actual virual
    // function table, which will be duplicative of this test anyway.

    //return;
  }

  // Get the member from the method that should be the virtual function table.
  MemberMap::iterator mfinder = tcm->data_members.find(vci->vtable_offset);
  if (mfinder == tcm->data_members.end()) {
    GERROR << "No member at offset " << vci->vtable_offset << " in constructor at "
           << tcm->address_string() << "." << LEND;
    return;
  }

  Member& mem = mfinder->second;
  if (!(mem.is_virtual())) {
    // There are a few of these in Notepad++.  Left at error importance, should investigate.
    GERROR << "Member at offset " << vci->vtable_offset << " in constructor at "
           << tcm->address_string() << " is not a vftable pointer." << LEND;
    return;
  }

  VirtualFunctionTable* vftable = mem.get_vftable();

  // Several more things should happen here.  We should increase our confidence in the virtual
  // function table, we should increase the minimum size, we should check for exceeding our
  // current maxium size, etc.
  unsigned int func_entry = vci->vfunc_offset / 4;
  if (func_entry > vftable->max_size && vftable->max_size != 0) {
    GWARN << "VFTable at offset " << vci->vtable_offset << " in constructor at "
          << tcm->address_string() << " is too small. "
          << func_entry << ">" << vftable->max_size << LEND;
    // In at least one case, failing here was the wrong thing to do.  Warn for now, and we'll
    // see if we find cases where continuing is the wrong thing as well.
    // return;
  }

  rose_addr_t target = vftable->read_entry(func_entry);
  ThisCallMethod* ttcm = follow_oo_thunks(target);

  if (ttcm == NULL) {
    GWARN << "Call at " << vfcd.address_string() << " was resolved to non-OO method "
          << addr_str(target) << "." << LEND;
  }
  else {
    GINFO << "Call at " << vfcd.address_string() << " was resolved to OO method "
          << addr_str(target) << "." << LEND;
  }
  vfcd.add_target(target);
}

void analyze_virtual_calls() {
  GINFO << "Analyzing virtual function calls..." << LEND;

  // For every call...
  for (CallDescriptor& vfcd : boost::adaptors::values(global_descriptor_set->get_call_map())) {
    // We're only interested in virtual calls.
    if (vfcd.get_call_type() != CallVirtualFunction) continue;

    CallInformationPtr ci = vfcd.get_call_info();
    VirtualFunctionCallInformationPtr vci =
      boost::dynamic_pointer_cast<VirtualFunctionCallInformation>(ci);

    // This next two are just to get the function that the call is in.  We should probably have
    // a convenience function on the call descriptor that returns the function descriptor.
    // Start by getting the call instruction.
    SgAsmInstruction* insn = vfcd.get_insn();
    // The function that contains the instruction.
    FunctionDescriptor* fd = global_descriptor_set->get_fd_from_insn(insn);
    // Did we find it ok?
    if (fd == NULL) {
      GERROR << "Unable to find function for virtual function call: "
             << debug_instruction(insn) << LEND;
      // Give up and go to the next virtual function call.
      continue;
    }
    // Here's what we really wanted.
    rose_addr_t faddr = fd->get_address();

    // Find the this-pointer usage that matches the one used in the call.
    SymbolicValuePtr sv_this_ptr = vci->obj_ptr;

    // Get the important part of the this-pointer.  This was a change as well, but I made it
    // back in vcall.cpp, closer to where it belongs.  It's unclear whether the obj_ptr field
    // has much value or not.  There could be some cases where it's useful, I'm just not sure
    // that this is one of them.
    LeafNodePtr thisptr = vci->lobj_ptr;

    GDEBUG << vfcd << LEND;
    GDEBUG << "THISPTR SV=" << *sv_this_ptr << LEND;

    // Starting here we have all of the information about the call that we need.
    GDEBUG << "Call at " << vfcd.address_string() << " is: func=" << fd->address_string()
           << " vtoff=" << vci->vtable_offset << " vfoff=" << vci->vfunc_offset
           << " thisptr=" << *thisptr << " insn=" << debug_instruction(insn) << LEND;

    // =====================================================================================
    // The virtual function reaolution call algorithm is undergoing changes to correct earlier
    // defects.
    // =====================================================================================

    // Find the object use for the function.
    ObjectUseMap::iterator oufinder = object_uses.find(faddr);
    if (oufinder == object_uses.end()) {
      GERROR << "No object uses found for function " << addr_str(faddr)
             << " for call: " << debug_instruction(insn) << LEND;
      continue;
    }
    ObjectUse& obj_use = oufinder->second;
    if (GDEBUG) {
      GDEBUG << "Found object use in " << fd->address_string() << ", size="
             << obj_use.references.size() << LEND;
      obj_use.debug();
    }

    // There's a couple of different scenarios that can resolve the virtual function call, and
    // many of them can actually resolve multiple times.  We'll set this to true when we've
    // found at least one strategy that worked, so we can skip later approaches.
    bool resolved = false;

    // =====================================================================================
    // This is now the primary virtual function call resolution mechanism.
    // =====================================================================================

    for (const ThisPtrUsage& tpu : boost::adaptors::values(obj_use.references)) {
      // Post NEWWAY, it might be sufficient to replace this with pick_this_ptr().
      for (const TreeNodePtr& leaf : tpu.this_ptr->get_possible_values()) {
        GDEBUG << "Considering leaf this-ptr=" << *leaf << LEND;
        // If they don't match, examine the next reference.
        if (!(leaf->mustEqual(thisptr, NULL))) continue;
        // But if they do, then the first method is our constructor!
        ThisCallMethod* ctor = tpu.get_ctor();
        // If we couldn't decide which method was the constructor, examine the next reference.
        if (ctor == NULL) {
          GINFO << "Call at " << vfcd.address_string()
                << " has a this-pointer usage group, but no constructor." << LEND;
          continue;
        }

        GINFO << "Call at " << vfcd.address_string()
              << " uses the this-constructor at " << ctor->address_string() << "." << LEND;
        resolve_virtual_function_call(vfcd, ctor);
        resolved = true;
      }
    }

    // We have to use a resolved boolean because we can't break and then continue.
    if (resolved) continue;

    // If our symbolic value is the return code of a function get the address of the call and
    // that function that it calls.  Cory feels a little dirty about the way we get this, but
    // we may not actually need to do this long term.  The test for fairly obviously
    // non-virtual calls may be worth keeping.  In the meantime it's really handy to have this
    // value a suspected value for the ctor, so I can experiment.
    //rose_addr_t ctor_addr = 0;
    std::string cmt = thisptr->comment();
    if (cmt.find(std::string("RC_of_0x")) == 0) {
      rose_addr_t rc_call_addr = strtol(cmt.substr(6, 10).c_str(), NULL, 0);
      GDEBUG << "The this-pointer came from the call at " << addr_str(rc_call_addr) << LEND;
      CallDescriptor* rc_cd = global_descriptor_set->get_call(rc_call_addr);
      assert (rc_cd != NULL);
      rose_addr_t last_target = 0;
      bool oo_target_found = false;
      for (const rose_addr_t target : rc_cd->get_targets()) {
        // Just keep the last target in the list (there's usually only one) to improve our
        // debugging message.
        last_target = target;
        // See if this target ends up at an OO method.
        ThisCallMethod* ctcm = follow_oo_thunks(target);
        // If it did, then that's our constructor.
        if (ctcm != NULL) {
          //ctor_addr = target;
          oo_target_found = true;
          break;
        }
      }
      if (!oo_target_found) {
        ImportDescriptor* vcid = rc_cd->get_import_descriptor();
        if (vcid != NULL) {
          // This change was made just to provide a more useful error message while Cory still
          // understood what was causing it.  First we need the function descriptor for the
          // target.
          GWARN << "Call at " << vfcd.address_string()
                << " is maybe not virtual because the call at " << addr_str(rc_call_addr)
                << " calls import " << vcid->get_long_name() << LEND;
        }
        else {
          GWARN << "Call at " << vfcd.address_string()
                << " is not really virtual because the call at " << addr_str(rc_call_addr)
                << " calls " << addr_str(last_target) << " which is not an OO method." << LEND;
        }
        // Corys says we should probably do something here to mark the call descriptor as not
        // virtual, so that we can skip it entirely in later reporting.
        continue;
      }
    }

    // Now match that information up with what we know about virtual function tables.

    // The first scenario is when the this-pointer being passed to the virtual function call is
    // the primary this-pointer of an object oriented method.  In other words, the this-pointer
    // was passed to the current method in the ECX register.  We need to identify the current
    // method (containing the call), check that the this-pointers match, and then locate the
    // appropriate constructors for the method.  It's appropriate here to use find() and end()
    // rather than follow_oo_thunks() because the call can't be in the thunk.
    ThisCallMethodMap::iterator tcmfinder = this_call_methods.find(faddr);
    if (tcmfinder == this_call_methods.end()) {
      GDEBUG << "No this call method found for " << addr_str(faddr) << LEND;
    }
    else {
      GDEBUG << "FOUND THISCALLMETHOD 0x" << addr_str(faddr) << LEND;
      ThisCallMethod& tcm = tcmfinder->second;
      LeafNodePtr tcm_leaf = tcm.get_leaf_ptr();
      GDEBUG << "And the leaf thisptr for the TCM is " << *tcm_leaf << LEND;
      if (tcm_leaf->mustEqual(thisptr, NULL)) {
        GINFO << "Call at " << vfcd.address_string()
              << " uses the this-pointer from the current method at "
              << fd->address_string() << "." << LEND;

        // There's no reverse map, so we're going to have to walk over all the
        // classes looking for ones that call this method.  And worse, none of the
        // existing cases of this actually work because we're missing the required data in
        // classes :-(
        for (const ClassDescriptor& obj : boost::adaptors::values(classes)) {
          GDEBUG << "Considering ClassDescriptor at " << obj.address_string() << LEND;
          // Does this object instance call this method?
          if (obj.methods.find(&tcm) != obj.methods.end()) {
            // If so then the constructor for this instance could have defined our virtual
            // function table pointer.  Go resolve the call using it.
            resolve_virtual_function_call(vfcd, obj.get_ctor());
            resolved = true;
          }
        }

        if (!resolved) {
          GWARN << "Call at " << vfcd.address_string()
                << " uses the this-ptr from the unassociated method "
                << tcm.address_string() << " so call resolution failed." << LEND;
          // For debugging, we may want to continue trying other things, but for all of the
          // current cases, we've failed, and can go to the next call.
          continue;
        }
      }
    }

    // Icky, but it's how we continue.
    if (resolved) continue;

    // If there are no known object uses in the function, report that as our error.
    if (obj_use.references.size() == 0) {
      GWARN << "Call at " << vfcd.address_string() << " is in function "
            << addr_str(faddr) << " which has no known object uses." << LEND;
      continue;
    }

    GWARN << "Call at " << vfcd.address_string() << " was not properly resolved. " << LEND;
    GINFO << "Call at " << vfcd.address_string() << " func=" << fd->address_string()
          << " vtoff=" << vci->vtable_offset << " vfoff=" << vci->vfunc_offset
          << " thisptr=" << *thisptr << " insn=" << debug_instruction(insn) << LEND;
  }
}

// This pass updates the classes map repeatedly until it converges on an answer.  The general
// idea is to group objects with shared methods, copying information from this-pointer usages
// into classes.  This pass is clearly a "class" consolidation pass, and might be simpler with
// a new class map.  It's impact on the test suite is limited, and the need for this function
// might go away accidentally, so we should check it periodically.  Currently, it appears to be
// propagating private methods, which might not even actually be correct.  Cory reversed the
// logic for which method list was the copy, and which we walked over.  This allowed us to call
// merge_all_methods() and is probably more efficient as well.
void update_class_with_ptr_groups() {
  GDEBUG << "Updating classes with this-pointer groups..." << LEND;
  bool changed;
  do {
    changed = false;
    // For each existing class...
    for (ClassDescriptor& obj : boost::adaptors::values(classes)) {
      // Make a copy of our method set so that we can walk the old version while updating it.
      ThisCallMethodSet methods_copy = obj.methods;
      // The constructor for this class.
      ThisCallMethod* ctcm = obj.get_ctor();
      // If we have no constructor, we're done.
      if (ctcm == NULL) continue;

      // Now for each this-pointer usage, look to see if we can improve our list of methods.
      for (ObjectUse& obj_use : boost::adaptors::values(object_uses)) {
        // This is a little hackish, and should perhaps be someplace else.
        for (ThisPtrUsage& tpu : boost::adaptors::values(obj_use.references)) {
          // If our constructor is a member of the tpu methods, then all of the tpu methods are
          // part of our class.
          obj.merge_shared_methods(tpu, ctcm);
          // If any of our methods are the in the tpu methods group, then all of the tpu methods
          // methods are part of our class.
          for (ThisCallMethod *mtcm : methods_copy) {
            obj.merge_shared_methods(tpu, mtcm);
          }
        }

        // If our temporary methods set has changed, update the class with improved set, and set
        // changed to true so that we go over the entire classes set at least once
        // more.
        if (methods_copy.size() != obj.methods.size()) {
          changed = true;
        }
      }
    }
    // When we've finally converged, we've merged all possible shared method information.
  } while (changed);
}

// Propagate knowledge about which classes are currently calling which methods.  This allows us
// to assess how we're doing on assigning each method to one and only one class.
void update_calling_classes() {
  // If we end up calling this routine repeatedly, we'll need to add code to clear the existing
  // answers before generating new ones, but for now we just know that it's empty.
  for (ClassDescriptor& cls : boost::adaptors::values(classes)) {
    for (ThisCallMethod *tcm : cls.methods) {
      tcm->add_class(&cls);
    }
  }
}


// Populate the recursive methods set by examining each known object instance, and updating the
// list.  This algorithm references other ThisCallMethods, and so needs to be called repeatedly
// until we converge on an answer.  Returns true if the internal list of recursive methods was
// updated.  See recursively_find_methods() for the code that invokes this method repeatedly to
// converge on a complete answer.  The efficiency of this method could probably be improved
// with a work list.
bool ThisCallMethod::update_recursive_methods() {
  // For each function invoked from the this method...
  for (FuncOffset& fo : boost::adaptors::values(passed_func_offsets)) {
    // We're only interested in methods that are invoked on offset zero.  This is presumed
    // (slightly incorrectly) to mean it's eitehr the same class or a parent class.
    if (fo.offset == 0) {
      // Get a handle to the method that was called on the same this-pointer.
      ThisCallMethod* ptcm = fo.tcm;
      assert(ptcm != NULL);

      // We directly call that method, so it needs to be in our recursive methods list.
      recursive_methods.insert(ptcm);
      // But we also call all methods that it calls (recursively).  In order for thisalgorithm
      // to work correctly, this method must be called using a BottomUpAnalzyer().
      recursive_methods.insert(ptcm->recursive_methods.begin(), ptcm->recursive_methods.end());
    }
  }

  if (GDEBUG) {
    GDEBUG << "Recursive methods for " << address_string() << " are: " << LEND;
    for (ThisCallMethod *rtcm : recursive_methods) {
      GDEBUG << "  " << rtcm->address_string() << LEND;
    }
  }
  return true;
}

// Add methods to classes (clearly a class description at this point) using the
// following logic: if my this-pointer is passed to meth1() which in turn calls meth2() with
// it's this-pointer (at offset zero), then I could also have called meth2().  There are a few
// complications with this routine.  First, this process must be repeated until the list of
// methods stops growing because meth2() might call meth3(), which calls meth4() and so on.
//
// Second, this routine is not strictly correct.  One possible scenario is that there's an
// object at offset zero in our class that is not a parent of our class, and that we're not
// really passing our this-pointer, but rather the this-pointer of the embedded object.
// Unfortunately, this is a very difficult case to detect, and to not make this assumption at
// this point would result in missing many methods that are legitimately part of our class.
// We'll need to revisit this code to determine if there's anything we can do about this.
//
// Finally, there's some ambiguity about what is desired with respect to parent classes.  This
// logic is part of an "accumlate everything" approach, where all of the parent's methods are
// assigned to both the derived classes and the parent classes.  The idea is that once you have
// complete information, you can come back and remove the inherited methods more easily.
// Previously the logic was a bit confused in this regard, because it sort-of attempted to
// exclude parent constructors, but didn't exclude parent methods.
void recursively_find_methods() {
  GINFO << "Recursively finding methods..." << LEND;
  // This phase now only takes a single pass, because we pull all the methods into the class at
  // once, using the ThisCallMethod's recursive methods set.

  // For each existing class...
  for (ClassDescriptor& cls : boost::adaptors::values(classes)) {
    // Make a copy of our method set so that we're not updating while walking over it.
    ThisCallMethodSet methods = cls.methods;

    // For each of our existing methods...
    for (const ThisCallMethod *tcm : cls.methods) {
      // All of the methods in the recursive methods set are either our methods or one of
      // our ancestors.   Add them to our class' method set, and we'll remove the ones that
      // really belong to our parents in a later analysis phase.
      methods.insert(tcm->recursive_methods.begin(), tcm->recursive_methods.end());
    }

    // Some debugging to see if we did it correctly...
    if (GDEBUG) {
      GDEBUG << "Class " << cls.address_string() << " has methods (including ancestors): " << LEND;
      for (const ThisCallMethod *ctcm : methods) {
        GDEBUG << "  " << ctcm->address_string() << LEND;
      }
    }

    // Replace the methods set with the updated value.   We should probably use swap here.
    cls.methods = methods;
  }
}

void remove_ancestor_methods() {
  GINFO << "Removing ancestor methods..." << LEND;

  // For each existing constructor...
  for (ClassDescriptor& obj : boost::adaptors::values(classes)) {
    GDEBUG << "Removing ancestors for " << obj.address_string() << LEND;
    // Find all of our ancestors
    obj.find_ancestors();
    GDEBUG << "Ancestors found for " << obj.address_string() << LEND;

    // For each of our ancestors...
    for (rose_addr_t addr : obj.ancestor_ctors) {
      // Get the class for that ancestor if it exists.
      ClassDescriptorMap::iterator finder = classes.find(addr);
      // If it wasn't found, just skip it.  This shouldn't really happen.  Generate a warning?
      if (finder == classes.end()) continue;
      // The ancestor object instance.
      ClassDescriptor& ancestor = finder->second;

      // For each of the methods in the ancestor...
      for (ThisCallMethod* ameth : ancestor.methods) {
        GDEBUG << "Removing ancestor method " << ameth->address_string() << " from class "
               << obj.address_string() << LEND;
        obj.methods.erase(ameth);
      }
    }
  }
}

// Merge classes that share methods, under the presumption that once we've removed our
// ancestor's methods, what's left must have been multiple detections of the same class.  This
// probably isn't really sound, but it's important for minimizing confusion for the user in
// IDA, where each method can only get one name.  It's better for there to be a chance of
// having merged two classes incorrectly than commmonly splitting classes in half, with some
// methods labeled one way, and the other labeled some other way.  In the future we can do a
// better job of this by only allowing mergers that meet additional requirements.
void merge_classes_sharing_methods() {
  // For every method in the program...
  for (ThisCallMethod& tcm : boost::adaptors::values(this_call_methods)) {
    // Get the classes that think they "own" that method...
    const ClassDescriptorSet& tcm_classes = tcm.get_classes();
    // And if there's more than one, we need to "fix" that.
    if (tcm_classes.size() > 1) {
      // This will point to the class that the others get merged into.
      ClassDescriptor* master = NULL;
      // For each class that "owns" the method...
      for (ClassDescriptor* cls : tcm_classes) {
        // Classes with no methods have already been merged somewhere else, skip them.
        if (cls->methods.size() == 0) {
          continue;
        }
        // Make the first class with real methods the "master".  This isn't 100% correct
        // because we might move things away from one class, and when another class wants to
        // merge with the methods that have been moved, but can't.  If that happens we're
        // probably not doing the correct thing at all here, so it's not clear it matters.
        else if (master == NULL) {
          master = cls;
        }
        // On subsequent classes, merge them into the master class.  This code is probably
        // wrong, and almost certainly destroys the integrity of the field in the Class
        // Descriptor, but we're still experimenting this part of the code.  If this idea turns
        // out to be worth keeping, we can be more careful...
        else {
          GDEBUG << "Merging classes that share method: " << tcm.address_string() << LEND;
          GDEBUG << "  Class: " << master->address_string() << LEND;
          GDEBUG << "  Class: " << cls->address_string() << LEND;
          master->merge_all_methods(cls->methods);
          // This marks that we've already done something, and prevents us from repeating work.
          cls->methods.clear();
        }
      }
    }
    // Perhaps we should update the classes list to remove the classes that we didn't keep, but
    // the accessor is currently const, and I think it should stay that way.  If we really need
    // this, we can recompute the whole list or make it non-const.
  }
}

// Remove classes that don't have any methods (inherited or otherwise) or members. These
// classes serve no purpose.
void remove_empty_classes() {
  GINFO << "Removing empty classes..." << LEND;

  // Cory recommends against using the auto keyword until we've comitted to C++11.
  auto it = classes.begin();

  // Cory asks: Is all the confusing iterator stuff because we're deleting from the list as we
  // iterate over it?  Does that actually work?   Is there a clearer way to do this?
  while (it!=classes.end()) {
    ClassDescriptor& obj = it->second;

    // Currently, being empty means no methods or members. It is an open question whether or
    // not this should include inherited methods?
    if (obj.data_members.empty() && obj.methods.empty() && obj.inherited_methods.empty()) {

      GDEBUG << "Removing empty class: " << addr_str(it->first) << LEND;
      classes.erase(it++);
    }
    else {
      ++it;
    }
  }
}

// If separate ClassDescriptors share the same virtual function table (at offset zero in the
// object), then they are the same class. This analysis pass must be followed by a call to
// reanalyze_members_from_methods() because methods are redistributed among classes.
void merge_classes_sharing_vftables() {
  GINFO << "Merging classes that share methods..." << LEND;
  // This map will replace classes once we're done iterating over classes.
  ClassDescriptorMap new_classes;

  // For each class in the program...
  for (ClassDescriptorMap::value_type& ucpair : classes) {
    ClassDescriptor& cls = ucpair.second;

    // The new key for this class in the map.
    rose_addr_t new_class_key = 0;
    // Find the virtual function table at offset zero for this class if there is one.
    for (const Member& member : boost::adaptors::values(cls.data_members)) {
      // We're only interested in virtual function tables in the member at offset zero.  To
      // look at more members is incorrect in the case of embedded classes within inlined
      // constructors.  In the case of classes with multiple inheritance, there might be
      // multiple virtual function tables, but merging them based on their first virtual
      // function table should always be sufficient to get the correct answer.
      if (member.offset != 0) continue;

      if (member.is_virtual()) {
        VirtualFunctionTable *vtab = member.get_vftable();
        // This class should now be keyed by the address of it's virtual function table.
        new_class_key = vtab->addr;
        GDEBUG << "Rekeying class " << addr_str(ucpair.first) << " as " << addr_str(new_class_key) << LEND;
        break;
      }
    }

    // If we didn't find a table, continue using the existing key.
    if (new_class_key == 0) new_class_key = ucpair.first;

    // If there's already a class at that key, it's the same class, so merge them.
    ClassDescriptorMap::iterator existing = new_classes.find(new_class_key);
    if (existing != new_classes.end()) {
      existing->second.merge_class(cls);
    }
    // Otherwise just add the class to to the map.
    else {
      new_classes.insert(ClassDescriptorMap::value_type(new_class_key, cls));
    }
  }

  // Replace the classes global map with our updated map.
  classes.swap(new_classes);
}

void report_this_call_methods() {
  for (const ThisCallMethod& tcm : boost::adaptors::values(this_call_methods)) {
    tcm.debug();
  }
}

void report_object_uses() {
  for (const ObjectUse& obj_use : boost::adaptors::values(object_uses)) {
    obj_use.debug();
  }
}

void report_classes() {
  for (const ClassDescriptor& cls : boost::adaptors::values(classes)) {
    cls.debug();
  }
}

// This function is basically a clone of ThisCallMethod::analyze_vftables().  As we expand into
// better support for inlined methods, we'll need to merge these two routines into a single one
// that takes external knowledge about the value of the this-pointer (without the thiscall
// presumptions).  Ultimately, we'll probably still want to keep this routine as a backup
// catch-all for cases where the better algorithms failed.  Unfortunately, because we don't
// know the value of this-pointer here, we won't be able to say which object the table was
// written into.  I also had to eliminate Virtual Base Tables from this logic because the
// heuristics were too weak and introduced many false positives.
void analyze_vftables_in_all_fds() {

  FunctionDescriptorMap& fdmap = global_descriptor_set->get_func_map();
  for (FunctionDescriptor& fd : boost::adaptors::values(fdmap)) {

    // Analyze the function if we haven't already.
    PDG* p = fd.get_pdg();
    if (p == NULL) return;

    GDEBUG << "Analyzing vftables for " << fd.address_string() << LEND;

    // For every write in the function...
    for (const AccessMap::value_type& access : p->get_usedef().get_accesses()) {
      // The second entry of the pair is the vector of abstract accesses.
      for (const AbstractAccess& aa : access.second) {
        // We only want writes
        if (aa.isRead) continue;

        // We're only interested in writes that write a constant value to the target.
        // This is a reasonably safe presumption for compiler generated code.
        if (!aa.value->is_number()) continue;

        // I was doubtful about the requirement that the write must be to memory, but after
        // further consideration, I'm fairly certain that even if we moved the constant value
        // into a register, and the register into the object's memory (which is literally
        // required), then we'd detect the memory write on the second instruction.
        if (!aa.is_mem()) continue;

        // In the immortal words of JSG "this is a hack to prevent a core dump in ROSE"
        if (aa.value->get_expression()->nBits() > 64) continue;

        // We're only interested in constant addresses that are in the memory image.  In some
        // unusual corner cases this might fail, but it should work for compiler generated code.
        rose_addr_t constaddr = aa.value->get_number();
        if (!global_descriptor_set->memory_in_image(constaddr)) continue;

        // We're not interested in writes to fixed memory addresses.  This used to exclude stack
        // addresses, but now it's purpose is a little unclear.  It might prevent vtable updates
        // to global objects while providing no benefit, or it might correctly eliminate many
        // write to fixed memory addresses correctly.  Cory doesn't really know.
        if (aa.memory_address->is_number()) continue;

        // This is the instruction we're talking about.
        SgAsmInstruction* insn = access.first;
        SgAsmX86Instruction* x86insn = isSgAsmX86Instruction(insn);

        // We're not interested in call instructions, which write constant return addresses to
        // the stack.  This is largely duplicative of the test above, but will be needed when
        // the stack memory representation gets fixed to include esp properly.
        if (insn_is_call(x86insn)) continue;

        GDEBUG << "Analyzing vtable access instruction: " << debug_instruction(insn) << LEND;

        // This is where should have checked whether the write was to an object-pointer or not.

        // What's left is starting to look a lot like the initialization of a virtual function
        // table pointer.  Let's check to see if we've already analyzed this address.  If so,
        // there's no need to analyze it again, just use the previous results.
        VirtualFunctionTable* vftable = NULL;
        if (global_vftables.find(constaddr) != global_vftables.end()) {
          // We've already found the VFtable, so we're done!
        }
        else {
          // It's important that the table go into one of the two global lists here so that we
          // don't have to keep processing it over and over again.

          // This memory is not currently freed anywhere. :-( Sorry 'bout that. -- Cory

          //GDEBUG << "Found possible virtual function table at: " << addr_str(constaddr) << LEND;
          // Now try creating a virtual function table at the same address.
          vftable = new VirtualFunctionTable(constaddr);
          vftable->analyze();
          global_vftables[constaddr] = vftable;

          // The address can only truly be a virtual function table if it passes some basic tests,
          // such as having at least one function pointer.
          if (vftable->max_size < 1) {
            // If there were no pointer at all, just reject the table outright.
            if (vftable->non_function == 0) {
              GDEBUG << "Possible extra virtual function table at " << addr_str(constaddr)
                     << " rejected because no valid pointers were found." << LEND;
              // Don't add the table to the list of tables for the object.
              continue;
            }
            // But if there were valid non-function pointers, let's continue to assume that we've
            // had a disassembly failure, and add the table to the list of tables even though it's
            // obviously broken.
            else {
              GDEBUG << "Possible extra virtual function table at " << addr_str(constaddr)
                     << " is highly suspicious because no function pointers were found." << LEND;
            }
          }
          else {
            GINFO << "Possible extra virtual function table found at"
                  << addr_str(constaddr) << " installed by " << addr_str(insn->get_address()) << LEND;
          }
        }

        // In all cases, this loop should continue to the next instruction, since there can be
        // multiple virtual function tables per constructor, and any failures we encountered
        // won't prevent later tables from validating correctly.

      } // For each access
    } // For all accesses
  } // For all functions
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
