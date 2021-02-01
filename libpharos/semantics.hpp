// Copyright 2015-2020 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Semantics_H
#define Pharos_Semantics_H

// This header is for files that need to operate on symbolic values, value sets, and abstract
// accesses (aka most of the project).  Please try not to add higher level dependencies to this
// file if possible, since it is widely included, and would seriously aggravate include loops.

#include <cstdio>
#include <vector>
#include <map>
#include <sstream>

#include <rose.h>
#include <SymbolicSemantics2.h>
#include <DispatcherX86.h>

#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/type_erased.hpp>

#include "misc.hpp"

namespace pharos {

class DescriptorSet;

using SmtSolverPtr = Rose::BinaryAnalysis::SmtSolverPtr;
// Import specific names from the external ROSE namepaces
using RoseFormatter = Semantics2::BaseSemantics::Formatter;
using RoseDispatcherX86 = Semantics2::DispatcherX86;
using DispatcherPtr = Semantics2::DispatcherX86Ptr;
using BaseSValuePtr = Semantics2::BaseSemantics::SValuePtr;
using ParentSValue = Semantics2::SymbolicSemantics::SValue;
using ParentSValuePtr = Semantics2::SymbolicSemantics::SValuePtr;
// A class for providing context while merging.
using BaseMergerPtr = Semantics2::BaseSemantics::MergerPtr;

// A naughty global variables for controlling spew.  Used in SymbolicValue::scopy().
extern unsigned int discarded_expressions;

enum MemoryType {
  // Local variables on the stack (addr < 0)
  StackMemLocalVariable,
  // The saved EIP register on the stack (addr == 0)
  StackMemReturnAddress,
  // Parameters on the stack (addr > 0, but not in program image)
  StackMemParameter,
  // The address is numeric and valid in the program image.
  ImageMem,
  // The address is known to be dynamically allocated on the heap (currently unused).
  HeapMem,
  // The memory type is unknown.
  UnknownMem
};

// For reporting unexpected conditions in get_stack_const().
constexpr uint32_t CONFUSED = UINT32_C(0x7FFFFFE);

// Our hash is now the 64-bit integer provided by ROSE on the TreeNode.
using SVHash = uint64_t;

using SymbolicValuePtr = Sawyer::SharedPointer<class SymbolicValue>;

using ValueSet = std::set<SymbolicValuePtr>;

// The incomplete bit is a TreeNode flags bit that means that the expression has not been
// reasoned about in a completely rigorous manner.  For example, the values of expressions
// after a loop will usually be some variation of the first iteration (and marked incomplete),
// reads of incomplete addresses will return incomplete values, and if-then-else expressions
// for which we've lost the expression condition, will have conditions that are simply an
// unknown variable (marked incomplete).  See also TreeNode::UNSPECIFIED and
// TreeNode::INDETERMINATE.
constexpr uint32_t INCOMPLETE          = UINT32_C(0x00010000);
constexpr uint32_t UNKNOWN_STACK_DELTA = UINT32_C(0x00020000);
constexpr uint32_t LOADER_DEFINED      = UINT32_C(0x00040000);

class SymbolicValue: public ParentSValue {

 private:
  // These two used to be in OUR SValue (non-templated) class.  Cory notes that these should
  // all be private to ensure that we're not using them inappropriately.  Fortunately, at the
  // time of this comment, all constructor calls are wrapped in SymbolicValuePtr().
  SymbolicValue(): ParentSValue(0) { }

  SymbolicValue(size_t nbits, std::string com=""): ParentSValue(nbits) {
    this->set_comment(com);
  }

  SymbolicValue(size_t nbits, uint64_t n, std::string com=""): ParentSValue(nbits, n) {
    this->set_comment(com);
  }

  // Copy constructor.  Not needed now that OUR_MODIFIERS is gone?
  SymbolicValue(const SymbolicValue &other): ParentSValue(other) {
    this->set_comment(other.get_comment());
  }

 public:

  // Conversion to TreeNodePtr
  operator TreeNodePtr() const {
    return get_expression();
  }

  bool is_valid() const { return (get_width() != 0); }
  bool is_invalid() const { return (get_width() == 0); }

  // Cory's a bit unclear whether these need to be on the TreeNode or the SymbolicValue.
  bool is_unspecified() const;
  bool is_incomplete() const;
  bool is_loader_defined() const;

#ifdef CUSTOM_ROSE
  // Once we've decided exactly what the API should be we can revisit whether there's a better
  // way to do this.  Perhaps we don't really need this capability at all.  It turns out that
  // the one place where we need this is in RiscOps::readMemory(), where we can't create our
  // own value, because the default value was passed to us.  Discussing with Matzke now.
  void set_incomplete(bool i);
#endif

  // This is a helper function designed to mark where we're doing stack delta extraction.  See
  // the longer comment in the cpp file for more details.
  boost::optional<int64_t> get_stack_const() const;
  // Here's another attempt at a helper method to cleanup our long held ESP problem.  This one
  // looks at the current symbolic value and attempts to return a memory "type".  The types
  // include several subdivisions of stack memory, plus heap, image, and unknown.
  MemoryType get_memory_type() const;

  // This portion of the interface must be implemented, or we'll end up returning the
  // the wrong types when the machinery calls protoval->number_()
  virtual BaseSValuePtr bottom_(size_t nbits) const override;
  // virtual method isBottom() does not need to be overridden.
  virtual BaseSValuePtr undefined_(size_t nbits) const override;
  virtual BaseSValuePtr unspecified_(size_t nbits) const override;

  // A new constructor added by the SEI for creating incomplete values.
  static SymbolicValuePtr incomplete(size_t nbits);
  // Another SEI defined constructor for creating variables defined by the loader.
  static SymbolicValuePtr loader_defined();

  virtual BaseSValuePtr number_(size_t nbits, uint64_t value) const override {
    //STRACE << "SymbolicValue::number_() nbits="
    // << nbits << " value=" << value << LEND;
    return SymbolicValuePtr(new SymbolicValue(nbits, value));
  }
  virtual BaseSValuePtr boolean_(bool value) const override {
    return SymbolicValuePtr(new SymbolicValue(1, value?1:0));
    // Cory says: we should probably be using instance_xxx to match ROSE, which did it this way:
    //return instance_integer(1, value?1:0);
  }

  virtual BaseSValuePtr copy(size_t new_width = 0) const override {
    return scopy(new_width);
  }

  virtual Sawyer::Optional<BaseSValuePtr>
  createOptionalMerge(const BaseSValuePtr &other,
                      const BaseMergerPtr& merger,
                      const SmtSolverPtr &solver) const override;


  // Non virtualized version returns a SymbolicValuePtr
  SymbolicValuePtr scopy(size_t new_width = 0) const;

  // If the expression is "too large" discard it, and replace it with a single incomplete
  // variable.  Currently this method is only called from scopy, but should probably be moved
  // to merge() instead, which is why it's now a function of it's own.  Eventually, we'd like
  // to eliminate it completely, since it's hiding a bug somewhere else in the architecture.
  void discard_oversized_expression();

  // Cory says: This used to be needed and then was removed?
  //virtual BaseSValuePtr create(const TreeNodePtr &expr_, const InsnSet &defs_=InsnSet()) {
  //  return SymbolicValuePtr(new SymbolicValue(expr_, defs_));
  //}

  // Construct a prototypical value. Prototypical values are only used for their virtual constructors.
  static SymbolicValuePtr instance() {
    return SymbolicValuePtr(new SymbolicValue(1));
  }


  // Some additional APIs created by Cory because the undefined_() and number_() methods
  // required a protoval, and I wanted to be able to create new variables and constants without
  // having to have a protoval or go through a specific RiscOps context.
  static SymbolicValuePtr variable_instance(size_t nbits) {
    return SymbolicValuePtr(new SymbolicValue(nbits));
  }
  static SymbolicValuePtr constant_instance(size_t nbits, uint64_t value) {
    return SymbolicValuePtr(new SymbolicValue(nbits, value));
  }
  static SymbolicValuePtr treenode_instance(const TreeNodePtr& tn) {
    // Confusingly create a constant symbolic value no avoid needless creating a new variable
    // and incrementing the variable counter?
    SymbolicValuePtr sv = SymbolicValuePtr(new SymbolicValue(tn->nBits(), 0));
    sv->set_expression(tn);
    return sv;
  }

  // Promote from the standard ROSE "base" SValue to ours.
  static SymbolicValuePtr promote(const BaseSValuePtr &v) {
    //STRACE << "SymbolicValue::promote(" << *v << ")" << LEND;
    SymbolicValuePtr retval = Semantics2::BaseSemantics::dynamic_pointer_cast<SymbolicValue>(v);
    assert(retval!=NULL);
    return retval;
  }

  TreeNodePtrSet get_possible_values() const;

  // Maybe only useful for debugging, but it's handy for right now.
  bool contains_ite() const;

  // Convenience functions to improve readability.
  bool has_definers() const { return (get_defining_instructions().size() > 0); }

  // Used to be  in a couple of places, no longer needed?
  void set_expression(const TreeNodePtr& new_expr) override {
    expr = new_expr;
  }

  // Retrieve the hash from the TreeNode.
  inline SVHash get_hash() const { return get_expression()->hash(); }

  // Return the expression as a string.
  std::string str() const {
    std::stringstream stupid_stream_formatting;
    stupid_stream_formatting << *(this->expr);
    return stupid_stream_formatting.str();
  }

  // Print the symbolic value to a stream.
  // We should revisit why these overrides are needed now that OUR_MODIFIERS is gone.
  void print(std::ostream &stream) const { RoseFormatter fmt; print(stream, fmt); }
  virtual void print(std::ostream &o, RoseFormatter& fmt) const override;

  friend std::ostream& operator<<(std::ostream &o, const SymbolicValue &sv) {
    sv.print(o);
    return o;
  }

  friend bool operator<(const SymbolicValue& a, const SymbolicValue& b);
  friend bool operator==(const SymbolicValue& a, const SymbolicValue& b);

  // This routine tests whether any of the possible values are equal to any of the possible
  // values in other.
  bool can_be_equal(SymbolicValuePtr other);

  // This is our custom extension, and the old way to handling merges.  We should be moving
  // away from this approach, but it's called in multiple places, including memory cell merges.
  void merge(const SymbolicValuePtr& elt, const SymbolicValuePtr& condition, bool inverted);
};

inline SymbolicValuePtr & operator+=(SymbolicValuePtr & a, int64_t i) {
  a->set_expression(a->get_expression() + i);
  return a;
}
inline SymbolicValuePtr operator+(const SymbolicValuePtr & a, int64_t i) {
  auto copy = a->scopy();
  return copy += i;
}
inline SymbolicValuePtr operator+(int64_t i, const SymbolicValuePtr & a) {
  return a + i;
}


// Forward declaration for AbstractAccess constructor.
class SymbolicState;
using SymbolicStatePtr = boost::shared_ptr<class SymbolicState>;

// Class representing either a register location or a memory location This is currently a
// horrible bastardization of an abstract location and a couple of Wes' [Mem|Reg]Access pairs.
// I have no idea if it will work yet, but I'm trying...
class AbstractAccess {

  // Is this abstract location a memory address?  Perhaps this should be a multistate enum
  // including the incompletely initialized scenario where nither field is populated.
  bool isMemReference;

  // Computing the list of modifying instructions is kind of complicated.  Delegate
  // responsibility in the constructor to this private method.
  void set_latest_writers(DescriptorSet const & ds, SymbolicStatePtr& state);

 public:

  // The memory address when the abstract location references memory.
  SymbolicValuePtr memory_address;

  // The register when the abstract location references registers.
  RegisterDescriptor register_descriptor;

  // The size of the access (in bits)
  size_t size = 0;

  // The values that was accessed.
  SymbolicValuePtr value;

  // A hybrid of definers and writers, tracking the latest definition of this symbolic value
  // including memory read instructions that initialized values.
  InsnSet latest_writers;

  // Was this access a read or a write?
  bool isRead;

  AbstractAccess() = default;

  // Construct a memory abstract access.
  AbstractAccess(DescriptorSet const & ds, bool b, SymbolicValuePtr ma,
                 size_t s, SymbolicValuePtr v, SymbolicStatePtr state);
  // Construct a register abstract access.
  AbstractAccess(DescriptorSet const & ds, bool b, RegisterDescriptor r,
                 SymbolicValuePtr v, SymbolicStatePtr state);

  // Some of these are unsafe now that there are three states. :-(
  // Add another boolean or something to really fix it.
  bool is_gpr() const { return (!isMemReference && register_descriptor.get_major() == x86_regclass_gpr); }
  bool is_reg() const { return (!isMemReference); }
  bool is_reg(const RegisterDescriptor r) const {
    return (!isMemReference && register_descriptor.get_major() == r.get_major() &&
            register_descriptor.get_minor() == r.get_minor()); }
  bool is_mem() const { return (isMemReference); }
  bool is_invalid() const { return (size == 0); }
  bool is_valid() const { return (size != 0); }

  size_t get_byte_size() const { return (size / 8); }

  std::string reg_name() const {
    assert(!isMemReference); return unparseX86Register(register_descriptor, NULL);
  }

  std::string str() const;

  bool same_location(const AbstractAccess& other) const {
    if (is_reg(other.register_descriptor)) return true;
    else if (is_mem() && *memory_address == *(other.memory_address)) return true;
    else return false;
  }

  // Comparsion and equality operators for orderings permitting sets of AbstractAccesses.
  bool operator<(const AbstractAccess& other) const;
  bool operator==(const AbstractAccess& other) const;
  bool exact_match(const AbstractAccess& other) const;

  void debug(std::ostream &o) const;
  void print(std::ostream &o) const;

  friend std::ostream& operator<<(std::ostream &o, const AbstractAccess &a) {
    a.print(o);
    return o;
  }
};

using AbstractAccessVector = std::vector<AbstractAccess>;
using AccessMap = std::map<rose_addr_t, AbstractAccessVector>;

namespace access_filters {

using boost::adaptors::filtered;

inline bool read_pred(const AbstractAccess &aa) {
  return aa.isRead;
}

inline bool write_pred(const AbstractAccess &aa) {
  return !aa.isRead;
}

inline bool reg_pred(const AbstractAccess &aa) {
  return aa.is_reg();
}

inline bool mem_pred(const AbstractAccess &aa) {
  return aa.is_mem();
}

template <typename T>
struct reg_pred_match {
  T match;
  reg_pred_match(const T arg) : match(arg) {}
  bool operator()(const AbstractAccess &aa) const { return aa.is_reg(match); }
};

inline auto read(const AbstractAccessVector & c) {
  return c | filtered(read_pred);
}

inline auto write(const AbstractAccessVector & c) {
  return c | filtered(write_pred);
}

inline auto reg(const AbstractAccessVector & c) {
  return c | filtered(reg_pred);
}

inline auto mem(const AbstractAccessVector & c) {
  return c | filtered(mem_pred);
}

inline auto read_reg(const AbstractAccessVector & c) {
  return c | filtered(read_pred) | filtered(reg_pred);
}

inline auto write_reg(const AbstractAccessVector & c) {
  return c | filtered(write_pred) | filtered(reg_pred);
}

inline auto read_mem(const AbstractAccessVector & c) {
  return c | filtered(read_pred) | filtered(mem_pred);
}

inline auto write_mem(const AbstractAccessVector & c) {
  return c | filtered(write_pred) | filtered(mem_pred);
}

using aa_range = boost::any_range<const AbstractAccess, boost::forward_traversal_tag,
                                  const AbstractAccess &, std::ptrdiff_t>;

namespace {
template <typename F>
aa_range mapped(const F & filt, const AccessMap & map, rose_addr_t addr) {
  using erased = boost::adaptors::type_erased<
    const AbstractAccess, boost::forward_traversal_tag,
    const AbstractAccess &, std::ptrdiff_t>;
  auto i = map.find(addr);
  if (i == map.end()) {
    return boost::iterator_range<AbstractAccess *>(nullptr, nullptr) | erased();
  }
  return filt(i->second) | erased();
}
} // unnamed namespace

inline aa_range read(const AccessMap & map, rose_addr_t addr) {
  return mapped([](const AbstractAccessVector &a) {return read(a);}, map, addr);
}

inline aa_range write(const AccessMap & map, rose_addr_t addr) {
  return mapped([](const AbstractAccessVector &a) {return write(a);}, map, addr);
}

inline aa_range reg(const AccessMap & map, rose_addr_t addr) {
  return mapped([](const AbstractAccessVector &a) {return reg(a);}, map, addr);
}

inline aa_range mem(const AccessMap & map, rose_addr_t addr) {
  return mapped([](const AbstractAccessVector &a) {return mem(a);}, map, addr);
}

inline aa_range read_reg(const AccessMap & map, rose_addr_t addr) {
  return mapped([](const AbstractAccessVector &a) {return read_reg(a);}, map, addr);
}

inline aa_range read_mem(const AccessMap & map, rose_addr_t addr) {
  return mapped([](const AbstractAccessVector &a) {return read_mem(a);}, map, addr);
}

inline aa_range write_reg(const AccessMap & map, rose_addr_t addr) {
  return mapped([](const AbstractAccessVector &a) {return write_reg(a);}, map, addr);
}

inline aa_range write_mem(const AccessMap & map, rose_addr_t addr) {
  return mapped([](const AbstractAccessVector &a) {return write_mem(a);}, map, addr);
}


} // namespace access_filters

void extract_possible_values(const TreeNodePtr& tn, TreeNodePtrSet& s);

void set_may_equal_callback();

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
