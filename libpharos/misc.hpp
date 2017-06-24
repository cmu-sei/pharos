// Copyright 2015, 2016, 2017 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Misc_H
#define Pharos_Misc_H

// This file contains utility functions for ROSE and the like.

#include <rose.h>
// For TreeNodePtr, LeafNodePtr, etc.
#include <BinarySymbolicExpr.h>
// For Semantics2 namespace.
#include <SymbolicSemantics2.h>
#include <MemoryMap.h>

#include <numeric>

namespace pharos {

using Rose::BinaryAnalysis::MemoryMap;


// Make sure overload resolution for operator<< can see into the global namespace
// (Needed in funcs.cpp so
//
//     std::ostream& ::operator<<(std::ostream&, const AddressIntervalSet&);
//
//  from rose/Cxx_Grammar.h can be used.)
using ::operator<<;

// Duplicative with funcs.hpp. :-(
typedef std::set<rose_addr_t> AddrSet;

typedef Rose::BinaryAnalysis::SymbolicExpr::Leaf LeafNode;
typedef Rose::BinaryAnalysis::SymbolicExpr::LeafPtr LeafNodePtr;
typedef Rose::BinaryAnalysis::SymbolicExpr::Interior InternalNode;
typedef Rose::BinaryAnalysis::SymbolicExpr::InteriorPtr InternalNodePtr;
typedef Rose::BinaryAnalysis::SymbolicExpr::Node TreeNode;
typedef Rose::BinaryAnalysis::SymbolicExpr::Ptr TreeNodePtr;

typedef Rose::BinaryAnalysis::Disassembler RoseDisassembler;

typedef std::set<LeafNodePtr> LeafNodePtrSet;
typedef std::set<TreeNodePtr> TreeNodePtrSet;

// Some Nodes are actually stored in a vector
typedef std::vector<TreeNodePtr> TreeNodePtrVector;

// Comparator for TreeNodePtrs
struct TreeNodePtrCompare {
  bool operator()(const TreeNodePtr & a, const TreeNodePtr & b) const {
    if (!b) {
      return false;
    }
    if (!a) {
      return true;
    }
    return a->compareStructure(b) < 0;
  }
};

// Addition for TreeNodePtr
TreeNodePtr operator+(const TreeNodePtr & a, int64_t b);
inline TreeNodePtr operator+(uint64_t a, const TreeNodePtr & b) {
  return b + a;
}
inline TreeNodePtr & operator+=(TreeNodePtr & a, int64_t b) {
  return a = a + b;
}


// A helper function for the mess that is stack delta constants (More at the implementation).
bool filter_stack(rose_addr_t addr);

// Convert an SgUnsignedCharList into a hex C++ string.
std::string MyHex(const SgUnsignedCharList& data);

// Create s string from an address
std::string addr_str(rose_addr_t addr);

// Make the ROSE Semantics2 namespace a little shorter to type...
namespace Semantics2 = Rose::BinaryAnalysis::InstructionSemantics2;

// Import InsnSet from ROSE.
typedef Semantics2::SymbolicSemantics::InsnSet InsnSet;

// A set of X86 instructions.
class X86InsnCompare {
  public:
  bool operator()(const SgAsmx86Instruction* x, const SgAsmx86Instruction* y)
    const { return (x->get_address() < y->get_address()); }
};

typedef std::set<SgAsmx86Instruction*, X86InsnCompare> X86InsnSet;

// An ordered list of register descriptors.
typedef std::vector<const RegisterDescriptor*> RegisterVector;

// Limit the maximum number of parameters.  This is arbitrary and incorrect, but if we don't
// limit it to some reasonable number, then we generate tons of error spew.  Some experience
// with actual code and an error level message, should keep this arbitrary limit from becoming
// a real problem.  Alternatively, we can remove the limit once we're confident that the
// parameter detection code always works.
#define ARBITRARY_PARAM_LIMIT 60

// An unordered set of register descriptors.  There's been a lot of flailing with respect to
// register descriptors, sets, const, etc. In the end this is the approach that appears to work
// best.
class RegisterCompare {
  public:
  bool operator()(const RegisterDescriptor* x, const RegisterDescriptor* y)
    const { return (*x < *y); }
};

typedef std::set<const RegisterDescriptor*, RegisterCompare> RegisterSet;

} // namespace pharos

// The main program need to provide a global logging facility.
extern Sawyer::Message::Facility glog;
#define GCRAZY (glog[Sawyer::Message::DEBUG]) && glog[Sawyer::Message::DEBUG]
#define GTRACE (glog[Sawyer::Message::TRACE]) && glog[Sawyer::Message::TRACE]
#define GDEBUG (glog[Sawyer::Message::WHERE]) && glog[Sawyer::Message::WHERE]
#define GMARCH (glog[Sawyer::Message::MARCH]) && glog[Sawyer::Message::MARCH]
#define GINFO  (glog[Sawyer::Message::INFO])  && glog[Sawyer::Message::INFO]
#define GWARN  (glog[Sawyer::Message::WARN])  && glog[Sawyer::Message::WARN]
#define GERROR glog[Sawyer::Message::ERROR]
#define GFATAL glog[Sawyer::Message::FATAL]

// The semantics module provides a logging facility as well.
namespace pharos { extern Sawyer::Message::Facility slog; }
#define SCRAZY (pharos::slog[Sawyer::Message::DEBUG]) && pharos::slog[Sawyer::Message::DEBUG]
#define STRACE (pharos::slog[Sawyer::Message::TRACE]) && pharos::slog[Sawyer::Message::TRACE]
#define SDEBUG (pharos::slog[Sawyer::Message::WHERE]) && pharos::slog[Sawyer::Message::WHERE]
#define SMARCH (pharos::slog[Sawyer::Message::MARCH]) && pharos::slog[Sawyer::Message::MARCH]
#define SINFO  (pharos::slog[Sawyer::Message::INFO])  && pharos::slog[Sawyer::Message::INFO]
#define SWARN  (pharos::slog[Sawyer::Message::WARN])  && pharos::slog[Sawyer::Message::WARN]
#define SERROR pharos::slog[Sawyer::Message::ERROR]
#define SFATAL pharos::slog[Sawyer::Message::FATAL]

// For local context logging
#define MCRAZY (mlog[Sawyer::Message::DEBUG]) && mlog[Sawyer::Message::DEBUG]
#define MTRACE (mlog[Sawyer::Message::TRACE]) && mlog[Sawyer::Message::TRACE]
#define MDEBUG (mlog[Sawyer::Message::WHERE]) && mlog[Sawyer::Message::WHERE]
#define MMARCH (mlog[Sawyer::Message::MARCH]) && mlog[Sawyer::Message::MARCH]
#define MINFO  (mlog[Sawyer::Message::INFO])  && mlog[Sawyer::Message::INFO]
#define MWARN  (mlog[Sawyer::Message::WARN])  && mlog[Sawyer::Message::WARN]
#define MERROR mlog[Sawyer::Message::ERROR]
#define MFATAL mlog[Sawyer::Message::FATAL]

namespace pharos {

void backtrace(
  Sawyer::Message::Facility & log = glog,
  Sawyer::Message::Importance level = Sawyer::Message::FATAL,
  int maxlen = 20);

} // namespace pharos

#include "options.hpp"
#include "util.hpp"

namespace pharos {

// The distinction between this files and Cory's utils is poorly defined.  The restrictions on
// preconditions for things in this file is also poorly defined.  In general, this header
// should not include anything but rose headers (e.g. it should be lightweight with respect to
// our code).

// This file should only be included once from the main program, since it's not really a
// header.

// Compare two RegisterDescriptors, ought to be on RegisterDescriptor
bool RegisterDescriptorLtCmp(const RegisterDescriptor a, const RegisterDescriptor b);

// Now shared between here (for Partitioner 1) and partitioner.cpp (for Partitioner 2).
void customize_message_facility(const ProgOptVarMap& vm,
                                Sawyer::Message::Facility facility, std::string name);
// Get the Win32 interpretation out of a PE file project.
SgAsmInterpretation* GetWin32Interpretation(SgProject* project);

// This should be a method on SgAsmX86Instruction and possibly on SgAsmInstruction as well.
bool insn_is_call(const SgAsmx86Instruction* insn);

// I think we meant insn_is_call() in all of these cases...
bool insn_is_callNF(const SgAsmx86Instruction* insn);

// Conditional jumps, but not uncoditional jumps.
bool insn_is_jcc(const SgAsmx86Instruction* insn);

// Calls and conditional jumps, but not unconditional jumps.  Should be renamed?
bool insn_is_branch(const SgAsmx86Instruction* insn);

// All control flow instructions (calls, jumps, and conditional jumps).
bool insn_is_control_flow(const SgAsmx86Instruction* insn);

// Get the fallthru address of this instruction.
rose_addr_t insn_get_fallthru(SgAsmInstruction* insn);
// Get the non-fallthru (branch) address of this instruction.
rose_addr_t insn_get_branch_target(SgAsmInstruction* insn);
// Get the fixed portion of an instruction in the form: "jmp [X]"
rose_addr_t insn_get_jump_deref(SgAsmInstruction* insn);
// Get the fixed portion of a block ending "jmp X".
rose_addr_t block_get_jmp_target(SgAsmBlock* bb);

const SgAsmInstruction* last_insn_in_block(const SgAsmBlock* bb);
const SgAsmX86Instruction* last_x86insn_in_block(const SgAsmBlock* bb);

// Returns a descriptive string for a generic category of instructions, sort of along the lines
// of the breakdowns in the Intel manuals Vol 1 Ch 5 (mostly matching):
//   TRANSFER (mov, push. xchg), ARITHMETIC (add, sub, lea), LOGIC (and, or, xor, shl, ror),
//   COMPARE (test,cmp), BRANCH (jmp, call), FLOAT, SIMD (MMX/SSE related), CRYPTO (aes*,
//   sha*), VIRTUALIZATION, SYSTEM (int, sysenter), PRIVILEGED (maybe just use SYSTEM?),
//   STRING, I/O, UNCATEGORIZED
// Actually, since I'm using these things as strings in a hash caclulation, here's shorter
// values to help keep the sizes down:
//    XFER, MATH, LOGIC, CMP, BR, FLT, SIMD, CRYPTO, VMM (as in Virtual Machine Monitor), SYS,
//    STR, I/O, UNCAT
std::string insn_get_generic_category(SgAsmInstruction *insn);
// and here's a func to get the full list of generic categories (it's sorted):
const std::vector< std::string > get_all_insn_generic_categories();

// Get the block containing the instruction.
SgAsmBlock* insn_get_block(const SgAsmInstruction* insn);
// Get the function containing the instruction.
SgAsmFunction* insn_get_func(const SgAsmInstruction* insn);

// Determine whether an expression contains an additive offset
class AddConstantExtractor {
public:
  // Well formed means that we had both a variable and a constant portion, although the
  // variable portion might be more complex than the caller desired.  If desired the caller can
  // confirm that the variable portion is a simple leaf node (and not an ADD operation).
  bool well_formed() const;

  // The variable portion of the expression (everything not a constant addition).
  const TreeNodePtr & variable_portion() const;

  // The constant portion of the expression.
  int64_t constant_portion() const;

  // The end results are:
  //
  // Input expression   Well formed   Constant  Variable portion
  // ----------------   -----------   --------  ----------------
  // 3                  false         3         NULL!
  // 3+4                false         7         NULL!
  // x                  false         0         x
  // x+y                false         0         x+y
  // x+3                true          3         x
  // x+3+4              true          7         x
  // x+y+3              true          3         x+y
  // x+y+3+4            true          7         x+y

  AddConstantExtractor(const TreeNodePtr& tn);

  using constset_t = std::set<int64_t>;

 private:
  using datamap_t = std::map<TreeNodePtr, constset_t, TreeNodePtrCompare>;

 public:

  // A variable_set_t is an object that wraps iterators over TreeNodePtr, constset_t pairs.
  class variable_set_t {
   public:
    using value_type = std::pair<const TreeNodePtr &, const constset_t &>;
    using reference  = value_type;
    using const_reference = const reference;
    using size_type = constset_t::size_type;

    class iterator : public boost::iterator_facade<
      iterator, value_type, boost::forward_traversal_tag, value_type>
    {
     private:
      friend class boost::iterator_core_access;

      value_type dereference() const {
        return value_type(sub_iter->first, sub_iter->second);
      }
      void increment() {
        ++sub_iter;
      }
      bool equal(iterator other) const {
        return sub_iter == other.sub_iter;
      }

      friend class variable_set_t;
      iterator(datamap_t::const_iterator other) : sub_iter(other) {}

      datamap_t::const_iterator sub_iter;
    };
    using const_iterator = iterator;

    iterator cbegin() const {
      return iterator(std::begin(data));
    }
    iterator cend() const {
      return iterator(std::end(data));
    }
    iterator begin() const {
      return cbegin();
    }
    iterator end() const {
      return cend();
    }

    size_type size() const {
      return data.size();
    }

   private:
    friend class AddConstantExtractor;
    variable_set_t(const datamap_t & d) : data(d) {}
    const datamap_t & data;
  };

  // A variable_set_t is an object that wraps iterators over TreeNodePtr, int pairs.
  class power_set_t {
   public:
    using value_type = std::pair<const TreeNodePtr &, int64_t>;
    using reference  = value_type;
    using const_reference = const reference;
    using size_type = constset_t::size_type;

    class iterator : public boost::iterator_facade<
      iterator, value_type, boost::forward_traversal_tag, value_type>
    {
     private:
      iterator(const datamap_t & map) : i1(std::begin(map)), i1_end(std::end(map))
      {
        if (i1 != i1_end) {
          i2 = std::begin(i1->second);
        }
      }
      static iterator end(const datamap_t & map) {
        auto i = iterator(map);
        i.i1 = i.i1_end;
        return i;
      }

      friend class boost::iterator_core_access;

      void increment() {
        ++i2;
        if (i2 == std::end(i1->second)) {
          ++i1;
          if (i1 != i1_end) {
            i2 = std::begin(i1->second);
          }
        }
      }

      bool equal(const iterator & other) const {
        return (i1 == other.i1) && ((i1 == i1_end) || (i2 == other.i2));
      }

      value_type dereference() const {
        return value_type(i1->first, *i2);
      }

      friend class AddConstantExtractor;
      datamap_t::const_iterator i1;
      datamap_t::const_iterator i1_end;
      constset_t::const_iterator i2;
    };
    using const_iterator = iterator;

    iterator cbegin() const {
      return iterator(data);
    }
    iterator cend() const {
      return iterator::end(data);
    }
    iterator begin() const {
      return cbegin();
    }
    iterator end() const {
      return cend();
    }

    size_type size() const {
      return std::accumulate(std::begin(data), std::end(data), size_type(),
                             [](size_type a, const datamap_t::value_type & b) {
                               return a + b.second.size(); });
    }

   private:
    friend class AddConstantExtractor;
    power_set_t(const datamap_t & d) : data(d) {}
    const datamap_t &data;
  };


  // Returns an object that can be iterated over generating <const TreeNodePtr &, const
  // std::set<int64_t> &> pairs, representing the possible variable portions of the expression,
  // and the set of constant values that can be associated with them.
  variable_set_t get_data() const {
    return variable_set_t(data);
  }

  // Returns an object that can be iterated over generating <const TreeNodePtr &, int64_t>
  // pairs, representing the variable and constant portions of the expression in all producable
  // combinations.
  power_set_t get_power_set() const {
    return power_set_t(data);
  }

 private:
  datamap_t data;

  void merge(AddConstantExtractor && other);
  void add(AddConstantExtractor && other);
};

} // namespace pharos

#endif // Pharos_Misc_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
