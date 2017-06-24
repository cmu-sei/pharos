// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Class_H
#define Pharos_Class_H

#include "member.hpp"
#include "method.hpp"
#include "usage.hpp"

namespace pharos {

// An object representing all methods and members associated with a particular constructor.
class ClassDescriptor {

  // The function that has been identified as the constructor for this object instance, or NULL
  // if no constructor was identified.

  // Jeff Gennari thinks this is flawed and that the "ctor"-ness of a method is a property of
  // the method itself rather than the class. If anything, this should be a set. At the least,
  // it is possible for a class to have multiple constructors
  ThisCallMethodSet ctors;

  // The function that has been identified as the destructor for this object instance, or NULL
  // if no destructor was identified.  This field currently always NULL, but it has been added
  // to clarify the intended evolution of this class.
  ThisCallMethod* real_dtor, *deleting_dtor;

  // The best available size of the object.  Sometimes based on the allocation size, and
  // sometimes on the largest known member.
  size_t size;
  // The size of the object solely based on allocation size.  Will be zero if no allocations
  // are found.
  size_t alloc_size;

  // The address uniquely identifying this class (usually the address of the constructor
  // still), but increasingly we're trying to use a more generic address.  In the case of
  // global variables, it's the actual this-pointer.
  rose_addr_t address;

  // The class name. In the future this will be based on program information, such as RTTI.
  std::string name;

public:

  // A list of constructors representing the parentsof this class.  Not well thought out, but
  // needed to move forward on eliminating methods from derived classes.  Populated by
  // find_parents().
  AddrSet parent_ctors;
  bool parents_computed;
  AddrSet ancestor_ctors;
  bool ancestors_computed;

  size_t get_size() const { return size; }

  // List of identified member functions
  ThisCallMethodSet methods;

  // List of identified variables. In an object instance, this would be the aggregation of
  // multiple data member maps from the methods listed above.
  MemberMap data_members;

  // Method -> offset
  InheritedMethodMap inherited_methods;

  // Required for std::map sillyness :-(.  This should absolutely not be used at all. :-(
  ClassDescriptor();

  // We're using a poiner for tc instead of a reference in anticipation of using the API in a
  // way that doesn't know where the constructor is at.  But presently (Wes' code), we're
  // always supplied with a non-NULL constructor.
  ClassDescriptor(rose_addr_t a, ThisCallMethod* tc);

  // Build a ClassDescriptor with a name.
  ClassDescriptor(rose_addr_t a, ThisCallMethod* tc, std::string n): ClassDescriptor(a,tc) {
    name = n;
  }

  ThisCallMethod* get_method(const rose_addr_t addr) const;

  void set_name(std::string n) { name.assign(n); }
  std::string get_name() const { return name; }
  ThisCallMethodSet get_ctors() const { return ctors; }
  ThisCallMethod* get_ctor() const {
    if (ctors.empty()) return NULL;
    return *(ctors.begin());
  }

  void add_ctor(ThisCallMethod *new_ctor) {
    ctors.insert(new_ctor);
  }

  ThisCallMethod* get_real_dtor() const { return real_dtor; }
  void set_real_dtor(ThisCallMethod *d) { real_dtor = d; }

  ThisCallMethod* get_deleting_dtor() const { return deleting_dtor; }
   void set_deleting_dtor(ThisCallMethod *d) { deleting_dtor = d; }

  rose_addr_t get_address() const { return address; }
  std::string address_string() const { return addr_str(address); }

  void debug() const;

  // Merge this class with another class.  This method is a superset of merge_all_methods, and
  // can transfer other information like RTTI, allocation size, etc.  For right now, just merge
  // all the methods from the other class.
  void merge_class(const ClassDescriptor& cls) {
    // Merge methods
    methods.insert(cls.methods.begin(), cls.methods.end());
    // Merge allocation size?
    // Merge other fields?
  }

  // Merge all methods from a this-pointer usage into this object instance.
  void merge_all_methods(const ThisPtrUsage& tpu) {
    methods.insert(tpu.get_methods().begin(), tpu.get_methods().end());
  }

  // Merge all methods from another method set (presumably from a class).
  void merge_all_methods(const ThisCallMethodSet& m) {
    methods.insert(m.begin(), m.end());
  }

  // Merge all methods from a this-pointer usage into this object instance, but only if the
  // provided method is already one of the methods in the this-pointer usage.
  void merge_shared_methods(const ThisPtrUsage& tpu, ThisCallMethod* tcm);

  // For propogating class sizes from this pointer usages that were dynamically allocated, and
  // therefore we know the correct size.  Even so, let's be defensive and only propogate this
  // size if it doesn't shrink the object.
  void set_alloc_size(size_t s);

  // Update the size
  void update_size();

  // Find our parents.
  void find_parents();

  // Find all of our ancestors.
  void find_ancestors();

  // Add a data member to the class.
  void add_data_member(Member m);

  // Delete a data member from the class.
  void delete_data_member(Member m);
};

typedef std::map<rose_addr_t, ClassDescriptor> ClassDescriptorMap;

// Data accumulated about objects with one specific constructor
extern ClassDescriptorMap classes;

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
