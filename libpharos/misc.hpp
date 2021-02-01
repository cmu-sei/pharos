// Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Misc_H
#define Pharos_Misc_H

// This file contains utility functions for ROSE and the like.

#include <rose.h>
// For TreeNodePtr, LeafNodePtr, etc.
#include <BinarySymbolicExpr.h>
// For Semantics2 namespace.
#include <SymbolicSemantics2.h>
// For P2 namespace.
#include <Partitioner2/Partitioner.h>
#include <MemoryMap.h>

#include <numeric>

namespace pharos {

using Rose::BinaryAnalysis::MemoryMap;
namespace P2 = Rose::BinaryAnalysis::Partitioner2;
namespace Semantics2 = Rose::BinaryAnalysis::InstructionSemantics2;
namespace SymbolicSemantics = Semantics2::SymbolicSemantics;

// Make sure overload resolution for operator<< can see into the global namespace
// (Needed in funcs.cpp so
//
//     std::ostream& ::operator<<(std::ostream&, const AddressIntervalSet&);
//
//  from rose/Cxx_Grammar.h can be used.)
using ::operator<<;

// Duplicative with funcs.hpp. :-(
using AddrSet = std::set<rose_addr_t>;

namespace SymbolicExpr = Rose::BinaryAnalysis::SymbolicExpr;
using LeafNode = SymbolicExpr::Leaf;
using LeafNodePtr = SymbolicExpr::LeafPtr;
using InternalNode = SymbolicExpr::Interior;
using InternalNodePtr = SymbolicExpr::InteriorPtr;
using TreeNode = SymbolicExpr::Node;
using TreeNodePtr = SymbolicExpr::Ptr;

using LeafNodePtrSet = std::set<LeafNodePtr>;
using TreeNodePtrSet = std::set<TreeNodePtr>;


// These should all eventually be replaced by non-x86 specific calls.  When that time comes,
// remove these, and the compiler will tell us what places we need to touch.
constexpr auto x86_add              = Rose::BinaryAnalysis::x86_add;
constexpr auto x86_call             = Rose::BinaryAnalysis::x86_call;
constexpr auto x86_farcall          = Rose::BinaryAnalysis::x86_farcall;
constexpr auto x86_farjmp           = Rose::BinaryAnalysis::x86_farjmp;
constexpr auto x86_int3             = Rose::BinaryAnalysis::x86_int3;
constexpr auto x86_ja               = Rose::BinaryAnalysis::x86_ja;
constexpr auto x86_jmp              = Rose::BinaryAnalysis::x86_jmp;
constexpr auto x86_js               = Rose::BinaryAnalysis::x86_js;
constexpr auto x86_lea              = Rose::BinaryAnalysis::x86_lea;
constexpr auto x86_leave            = Rose::BinaryAnalysis::x86_leave;
constexpr auto x86_regclass_gpr     = Rose::BinaryAnalysis::x86_regclass_gpr;
constexpr auto x86_regclass_ip      = Rose::BinaryAnalysis::x86_regclass_ip;
constexpr auto x86_regclass_segment = Rose::BinaryAnalysis::x86_regclass_segment;
constexpr auto x86_mov              = Rose::BinaryAnalysis::x86_mov;
constexpr auto x86_pop              = Rose::BinaryAnalysis::x86_pop;
constexpr auto x86_push             = Rose::BinaryAnalysis::x86_push;
constexpr auto x86_ret              = Rose::BinaryAnalysis::x86_ret;
constexpr auto x86_sub              = Rose::BinaryAnalysis::x86_sub;
constexpr auto x86_xor              = Rose::BinaryAnalysis::x86_xor;
constexpr auto x86_rep_insb         = Rose::BinaryAnalysis::x86_rep_insb;
constexpr auto x86_repne_scasw      = Rose::BinaryAnalysis::x86_repne_scasw;

// Some Nodes are actually stored in a vector
using TreeNodePtrVector = std::vector<TreeNodePtr>;

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

rose_addr_t address_from_node(LeafNodePtr tnp);

// Make the ROSE Semantics2 namespace a little shorter to type...
namespace Semantics2 = Rose::BinaryAnalysis::InstructionSemantics2;

// Expression printers (very useful from a debugger)
void print_expression(std::ostream & stream, TreeNode & e);
void print_expression(TreeNode & e);
void print_expression(std::ostream & stream, TreeNodePtr & e);
void print_expression(TreeNodePtr & e);
void print_expression(std::ostream & stream, SymbolicSemantics::SValue const & e);
void print_expression(SymbolicSemantics::SValue const & e);
void print_expression(std::ostream & stream, SymbolicSemantics::SValuePtr const & e);
void print_expression(SymbolicSemantics::SValuePtr const & e);

template <typename Arg>
void debug_print_expression(std::ostream & stream, Arg && arg)
{
  print_expression(stream, std::forward<Arg>(arg));
  stream << std::endl;
}

template <typename Arg>
void debug_print_expression(Arg && arg)
{
  debug_print_expression(std::cout, std::forward<Arg>(arg));
}

// Same as print_expression, but with a terminated newline
extern template void debug_print_expression(std::ostream & stream, TreeNode & e);
extern template void debug_print_expression(TreeNode & e);
extern template void debug_print_expression(std::ostream & stream, TreeNodePtr & e);
extern template void debug_print_expression(TreeNodePtr & e);
extern template void debug_print_expression(
  std::ostream & stream, SymbolicSemantics::SValue const & e);
extern template void debug_print_expression(SymbolicSemantics::SValue const & e);
extern template void debug_print_expression(
  std::ostream & stream, SymbolicSemantics::SValuePtr const & e);
extern template void debug_print_expression(SymbolicSemantics::SValuePtr const & e);


// ROSE's InsnSet isn't sorted, so we're using our own...
class InsnCompare {
 public:
  bool operator()(const SgAsmInstruction* x, const SgAsmInstruction* y)
    const { return (x->get_address() < y->get_address()); }
};

// A set of architecture independent instructions.
using InsnSet = std::set<SgAsmInstruction*, InsnCompare>;
using RoseInsnSet = Semantics2::SymbolicSemantics::InsnSet;

// A set of X86 instructions.
using X86InsnSet = std::set<SgAsmX86Instruction*, InsnCompare>;

// Introduce RegiserDescriptor into the pharos namespace
using Rose::BinaryAnalysis::RegisterDescriptor;

// An ordered list of register descriptors.
using RegisterVector = std::vector<RegisterDescriptor>;

// Limit the maximum number of parameters.  This is arbitrary and incorrect, but if we don't
// limit it to some reasonable number, then we generate tons of error spew.  Some experience
// with actual code and an error level message, should keep this arbitrary limit from becoming
// a real problem.  Alternatively, we can remove the limit once we're confident that the
// parameter detection code always works.
#define ARBITRARY_PARAM_LIMIT 60

using RegisterSet = std::set<RegisterDescriptor>;
using Rose::BinaryAnalysis::RegisterDictionary;

void set_glog_name(std::string const & name);

} // namespace pharos

// The main program need to provide a global logging facility.
namespace pharos { extern Sawyer::Message::Facility glog; }
#define GCRAZY (pharos::glog[Sawyer::Message::DEBUG]) && pharos::glog[Sawyer::Message::DEBUG]
#define GTRACE (pharos::glog[Sawyer::Message::TRACE]) && pharos::glog[Sawyer::Message::TRACE]
#define GDEBUG (pharos::glog[Sawyer::Message::WHERE]) && pharos::glog[Sawyer::Message::WHERE]
#define GMARCH (pharos::glog[Sawyer::Message::MARCH]) && pharos::glog[Sawyer::Message::MARCH]
#define GINFO  (pharos::glog[Sawyer::Message::INFO])  && pharos::glog[Sawyer::Message::INFO]
#define GWARN  (pharos::glog[Sawyer::Message::WARN])  && pharos::glog[Sawyer::Message::WARN]
#define GERROR pharos::glog[Sawyer::Message::ERROR]
#define GFATAL pharos::glog[Sawyer::Message::FATAL]

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

// For logging from prolog (pharos:log, pharos:logln)
namespace pharos { namespace prolog { extern Sawyer::Message::Facility plog; } }

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

// Now shared between here (for Partitioner 1) and partitioner.cpp (for Partitioner 2).
void customize_message_facility(Sawyer::Message::Facility facility, std::string name);

// This should be a method on SgAsmX86Instruction and possibly on SgAsmInstruction as well.
bool insn_is_call(const SgAsmX86Instruction* insn);

// Unconditional jumps (near and far).
bool insn_is_jmp(const SgAsmX86Instruction* insn);

// For detecting call and call-like unconditional jumps.
bool insn_is_call_or_jmp(const SgAsmX86Instruction* insn);

// I think we meant insn_is_call() in all of these cases...
bool insn_is_callNF(const SgAsmX86Instruction* insn);

// Conditional jumps, but not uncoditional jumps.
bool insn_is_jcc(const SgAsmX86Instruction* insn);

// Calls and conditional jumps, but not unconditional jumps.  Should be renamed?
bool insn_is_branch(const SgAsmX86Instruction* insn);

// All control flow instructions (calls, jumps, and conditional jumps).
bool insn_is_control_flow(const SgAsmInstruction* insn);

// Does this instruction have a valid repeat (REP/REPE/REPNE) prefix?
bool insn_is_repeat(const SgAsmX86Instruction* insn);

// Is the instruction an X86 nop?
bool insn_is_nop(const SgAsmX86Instruction* insn);

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

// A hackish approch to 64-bit support...
// If you have a descriptor set, it's easier to call the similar method on it.
RegisterDescriptor get_arch_reg(RegisterDictionary const & regdict,
                                const std::string & name, size_t arch_bytes);

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
