// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/format.hpp>
#include <boost/foreach.hpp>

#include <rose.h>

#include "class.hpp"
#include "misc.hpp"

// Data accumulated about objects with one specific constructor
ClassDescriptorMap classes;

// Order classes by their "address", which is really just a unique identifier.
bool ClassDescriptorCompare::operator()(const ClassDescriptor* x, const ClassDescriptor* y) const {
  return (x->get_address() < y->get_address()) ? true : false;
}

// Required for std::map sillyness :-(.  This should absolutely not be used at all. :-(
ClassDescriptor::ClassDescriptor() {
  // assert(false);  Sadly it is stil called, at some point Cory would like to fix that.
  address = 0;
  real_dtor = NULL;
  deleting_dtor = NULL;
  size = 0;
  alloc_size = 0;
  name = "";
}

// We're using a poiner for tc instead of a reference in anticipation of using the API in a
// way that doesn't know where the constructor is at.  But presently (Wes' code), we're
// always supplied with a non-NULL constructor.
ClassDescriptor::ClassDescriptor(rose_addr_t a, ThisCallMethod* tc) {
  address = a;
  real_dtor = NULL;
  deleting_dtor = NULL;
  if (tc != NULL) {
    // If a constructor was provided, use it.
    ctors.insert(tc);
    // In cases in which we're not being created from a TPU, we might not ever initialize the
    // methods set.  Ensure that the ctor is being added at the very least.  This is
    // consistent with our decision to include constructors in the method list in general.
    methods.insert(tc);
  }
  size = 0;
  alloc_size = 0;

  // create a default name for this class
  name = "";

  // This is a bit messy, but Cory wants it to just work first.
  parents_computed = false;
  ancestors_computed = false;
}

void ClassDescriptor::debug() const {
  GDEBUG << "CL: addr=" << addr_str(address) << " { ";
  BOOST_FOREACH(ThisCallMethod* tcm, methods) {
    GDEBUG << tcm->address_string() << " ";
  }
  GDEBUG << "}" << LEND;
}

ThisCallMethod* ClassDescriptor::get_method(const rose_addr_t addr) {
  BOOST_FOREACH(ThisCallMethod *m, methods) {
    if (m->get_address() == addr) {
      return m;
    }
  }

  // Now we have to check virtual functions ... sigh ... these should probably be in the
  // method set
  BOOST_FOREACH(MemberMap::value_type &mpair, data_members) {
    Member &mbr = mpair.second;

    if (mbr.is_virtual() == false) continue;

    // this is a vfptr
    VirtualFunctionTable *vtable = mbr.get_vftable();
    if (vtable != NULL) {

      // Perhaps we should print the whole vtable here via vftable->print(o)...
      for (unsigned int e = 0; e < vtable->max_size; e++) {
        rose_addr_t vf_addr = vtable->read_entry(e);
        if (addr == vf_addr) {
          return follow_oo_thunks(vf_addr);
        }
      }
    }
  }
  return NULL;
}

// Merge all methods from a this-pointer usage into this object instance, but only if the
// provided method is already one of the methods in the this-pointer usage.
void ClassDescriptor::merge_shared_methods(const ThisPtrUsage& tpu, ThisCallMethod* tcm) {
  if (tpu.get_methods().find(tcm) != tpu.get_methods().end()) {
    if (GDEBUG) {
      GDEBUG << "ThisPtrUsage " << tpu.identifier() << " calls method " << tcm->address_string()
             << " so merging it into class " << addr_str(address) << ":" << LEND;
      tpu.debug();
      GDEBUG << LEND;
    }
    methods.insert(tpu.get_methods().begin(), tpu.get_methods().end());
  }
}

// For propogating class sizes from this pointer usages that were dynamically allocated, and
// therefore we know the correct size.  Even so, let's be defensive and only propogate this
// size if it doesn't shrink the object.
void ClassDescriptor::set_alloc_size(size_t s) {
  // If we already have an allocation size, check for mismatches.  This shouldn't happen, so
  // when it does, something is wrong.
  if (alloc_size != 0 && s != alloc_size) {
    GWARN << "Allocation size of " << s << " didn't match previous size of " << alloc_size << LEND;
  }
  // Latest write wins.
  alloc_size = s;
  // Also check to see if the alloc size is bigger than the current size.
  if (size != 0 && alloc_size < size) {
    GWARN << "Allocation size of " << s
          << " incorrectly shrinks object from previous size of " << size << "." << LEND;
  }
  else {
    size = alloc_size;
  }
}

// Update the size
void ClassDescriptor::update_size() {
  // If we've got a dynamic allocation size, use that.  It's generally the most reliable.
  // Perhaps we should check for conflicting data with members and so forth here...
  if (alloc_size != 0) {
    size = alloc_size;
    return;
  }

  // special case where there are no members, thus the class has a size of 0
  if (data_members.empty()) {
    size = 0;
    return;
  }

  // Get the largest member offset. In an std::map this is the last key.
  size_t last_member_size = data_members.rbegin()->second.size;
  unsigned int last_member_offset = data_members.rbegin()->first;
  // The total size of the object is roughly: offset + size of the last member
  if (size < (last_member_size + last_member_offset)) {
    size = last_member_size + last_member_offset;
  }
}

void ClassDescriptor::add_data_member(Member m) {
  // Warning here allows us to be more relaxed elsewhere...
  MemberMap::iterator finder = data_members.find(m.offset);
  // If there's no existing member, just add it and update the size.
  if (finder == data_members.end()) {
    // This avoids the need for a default constructor on Member...
    data_members.insert(MemberMap::value_type(m.offset, m));
    // adding a new member to this object instance may augment its size
    update_size();
    // We're done with this case...
    return;
  }

  // If we found an existing member, things are more complicated.
  Member& fm = finder->second;

  // For now just take the first constructor because multiple constructors are not supported
  // This is flawed, but will work.
  ThisCallMethod *ctor = *(ctors.begin());

  fm.merge(m, address);

  // This is probably the wrong place for this test, but I want to work-around the multiple
  // inheritance bug and move on...  The problem is that the logic which merges members
  // based on shared methods merges parent constructors, which creates confusion about
  // which vftable object is the correct one.  At this point we know the right answer --
  // it's the one in our ctor.  We should really use this condition to record parent class
  // constructor observations in an organized way, and then test for parent relationships
  // to handle this situation correctly.  But I don't know where to do that right now.

  if (ctor != NULL && m.get_vftable() != NULL) {
    // Because we've merged already, this part of the condition now longer applies.
    //&& fm.get_vftable() != m.get_vftable()) {
    MemberMap::iterator cfinder = ctor->data_members.find(m.offset);
    if (cfinder != ctor->data_members.end()) {
      Member& fcm = cfinder->second;
      // This condition should be ridiculously rare.  Notepad++ triggers this message a
      // non-trivial number of times, so there must be a bug of sorts in our code.  Moving
      // this warning importance as well for now.
      if (!(fcm.is_virtual())) {
        GWARN << "Existing ctor member unexpectedly not virtual!" << LEND;
      }
      else if (fcm.get_vftable()->addr != fm.get_vftable()->addr) {
        // And as a result of changing the condition, this message is much more common.
        GDEBUG << "Fixing data member vftable pointer, correct is "
               << addr_str(fcm.get_vftable()->addr)
               << " existing " << addr_str(fm.get_vftable()->addr)
               << " vs. passed " << addr_str(m.get_vftable()->addr) << " at offset "
               << m.offset << " in function " << ctor->address_string() << LEND;
        fm.set_best_vftable(fcm.get_vftable());
      }
    }
    else {
      // Also not possible?  Nope, also occurs in Notepad++.  Given offsets of 1500+, I
      // suspect that the messages were caused by analysis failures, but let's move it to
      // warning until we investigate more.
      GWARN << "No member found at offset in ctor!" << LEND;
    }
  }
}

// Delete a data member from the class.  Used for removing data members that are really in
// embedded objects.
void ClassDescriptor::delete_data_member(Member m) {
  MemberMap::iterator finder = data_members.find(m.offset);
  if (finder != data_members.end()) {
    Member& fm = finder->second;
    if (fm == m) {
      data_members.erase(finder);
      // removing an element may also update size
      update_size();
    }
  }
}

void ClassDescriptor::find_parents() {
  // If we've already done the work, just return.
  if (parents_computed) return;

  // Clear any existing answer.
  parent_ctors.clear();

  // Accumulate parents from the list of members.
  BOOST_FOREACH(const MemberMap::value_type &mpair, data_members) {
    const Member& member = mpair.second;
    // For this purpose, we've also declared any embedded object at offset zero as
    // effectively a parent class.  By that I mean that we've included methods that are
    // associated with that embedded object.  Perhaps we should change is_parent() to match
    // as well, but Cory would like to discuss it with Jeff first.
    if (member.is_parent() || member.offset == 0) {
      BOOST_FOREACH(rose_addr_t addr, member.embedded_ctors) {
        GTRACE << "Evaluating embedded method addr: " << addr_str(addr) << LEND;
        // Skip methods that are not constructors.
        if (this_call_methods.find(addr) == this_call_methods.end()) continue;
        // Get the this-call method reference, didn't really need to follow thunks here.
        ThisCallMethod* tcm = follow_oo_thunks(addr);
        // Cory added the address != address clause to address a situation where a class was
        // it's own parent.  I'm not 100% sure why this happened, but if it ever happened
        // again, we'd want to not cause a cascding failure byt incorrectly identifying parents
        // here anyway.  This does "break" std::basic_char_string in example ooex7, but that's
        // really a problem with parent detection in general.
        if (tcm != NULL && tcm->get_address() != get_address()) {
          // Insert the method into the parent ctor list, but only if it's a constructor.
          if (tcm->is_constructor()) parent_ctors.insert(addr);
        }
      }
    }
  }

  if (parent_ctors.size() > 0) {
    GDEBUG << "Parents of " << address_string() << LEND;
    BOOST_FOREACH(rose_addr_t parent, parent_ctors) {
      GDEBUG << "  Parent: " << addr_str(parent) << LEND;
    }
  }

  // Don't do this work again until explicitly requested.
  parents_computed = true;
}

void ClassDescriptor::find_ancestors() {
  // If we've already done the work, just return.
  if (ancestors_computed) return;

  // Don't do this work again until explicitly requested.
  ancestors_computed = true;

  // Clear any existing answer.
  ancestor_ctors.clear();
  // Find our immediate parents.
  find_parents();
  // Our immediate parents are ancestors.
  ancestor_ctors.insert(parent_ctors.begin(), parent_ctors.end());

  ThisCallMethod* my_ctor = get_ctor();
  // Why would we not have a constructor?
  if (my_ctor != NULL) {
    // For each parent recursively find ancestors.
    BOOST_FOREACH(rose_addr_t parent, parent_ctors) {
      // Get the class for the parent.
      ClassDescriptorMap::iterator finder = classes.find(parent);
      // If it wasn't found, just skip it.  This shouldn't really happen.  Genearte a warning?
      if (finder == classes.end()) continue;
      // The parent object.
      ClassDescriptor& pobj = finder->second;
      // The parent's constructor (unique identifier).
      ThisCallMethod* parent_ctor = pobj.get_ctor();
      // If we can't uniquely identify our parent, we can't continue.
      if (parent_ctor == NULL) continue;
      // Don't recurse infinitely if we're looking for ourself.
      if (my_ctor->get_address() == parent_ctor->get_address()) continue;
      GDEBUG << "Finding ancestor-parents for " << pobj.address_string() << LEND;
      // The parents ancestors.
      pobj.find_ancestors();
      // Add of of them to our ancestors.
      ancestor_ctors.insert(pobj.ancestor_ctors.begin(), pobj.ancestor_ctors.end());
    }
  }

  if (ancestor_ctors.size() > 0) {
    GDEBUG << "Ancestors of " << address_string() << LEND;
    BOOST_FOREACH(rose_addr_t ancestor, ancestor_ctors) {
      GDEBUG << "  Ancestor: " << boost::str(boost::format("0x%08X") % ancestor) << LEND;
    }
  }
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
