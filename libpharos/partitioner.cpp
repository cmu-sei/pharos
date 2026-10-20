// Copyright 2015-2025 Carnegie Mellon University.  See LICENSE file for terms.

#include <stdarg.h>
#include <stdexcept>
#include <fstream>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>

#include <Rose/BinaryAnalysis/BinaryLoader.h>

#include "partitioner.hpp"
#include "descriptors.hpp"
#include "masm.hpp"
#include "util.hpp"
#include "limit.hpp"
#include "misc.hpp"
#include "options.hpp"

namespace pharos {

namespace bfs = boost::filesystem;
namespace bar = boost::archive;
namespace bio = boost::iostreams;

// This method now uses the new partitioner approach instead of the old AST approach.  This
// allows it to be called from more contexts.  This code is a bare function, so that it can
// be easily called on the stock partitioner as well.
void
report_partitioner_statistics(P2::PartitionerConstPtr const & partitioner)
{
  size_t num_funcs = partitioner->nFunctions();
  size_t num_bbs = partitioner->nBasicBlocks();
  size_t num_dbs = partitioner->nDataBlocks();
  size_t num_insns = 0;
  size_t num_bytes = 0;

  for (const P2::BasicBlock::Ptr & bb : partitioner->basicBlocks()) {
    for (const SgAsmInstruction *insn : bb->instructions()) {
      num_insns++;
      num_bytes += insn->get_size();
    }
  }

  for (const P2::DataBlock::Ptr & db : partitioner->dataBlocksOverlapping(partitioner->aum().hull())) {
    num_bytes += db->size();
  }

  OINFO << "Partitioned " << num_bytes << " bytes, " << num_insns << " instructions, "
        << num_bbs << " basic blocks, " << num_dbs << " data blocks and "
        << num_funcs << " functions." << LEND;
}

// Return true if the function at the given address in the partitioner is a PIC thunk, i.e.
// its entry block contains exactly "mov GPR32, [esp]; ret".  Delegates to the shared
// match_pic_thunk_pattern() helper in misc.hpp.
static bool
is_pic_thunk_at(P2::PartitionerConstPtr const & partitioner, rose_addr_t addr) {
  if (!partitioner->functionExists(addr)) return false;
  P2::BasicBlock::Ptr bb = partitioner->basicBlockExists(addr);
  if (!bb || bb->instructions().size() != 2) return false;
  return match_pic_thunk_pattern(bb->instructions()[0], bb->instructions()[1]).is_initialized();
}

// If the given function is a GOT preamble (call <pic_thunk>; add REG, IMM) that falls
// through to a body function, return the body's start address.  Otherwise return nothing.
//
// Note: in ROSE's Partitioner2 a call instruction terminates a basic block, so the entry BB
// of a preamble function contains only the call, and the add lives in the fallthrough BB.
static boost::optional<rose_addr_t>
get_got_preamble_body(P2::PartitionerConstPtr const & partitioner, const P2::Function::Ptr & func) {
  // Entry BB must be a single call instruction.
  P2::BasicBlock::Ptr call_bb = partitioner->basicBlockExists(func->address());
  if (!call_bb || call_bb->instructions().size() != 1) return boost::none;

  SgAsmX86Instruction* call = isSgAsmX86Instruction(call_bb->instructions()[0]);
  if (!call || call->get_kind() != x86_call) return boost::none;

  // The call target must be a concrete address hosting a PIC thunk.
  bool complete;
  auto succs = partitioner->basicBlockConcreteSuccessors(call_bb, &complete);
  rose_addr_t fallthrough = call->get_address() + call->get_size();
  bool found_thunk = false;
  for (rose_addr_t s : succs) {
    if (s != fallthrough && is_pic_thunk_at(partitioner, s)) { found_thunk = true; break; }
  }
  if (!found_thunk) return boost::none;

  // The fallthrough BB must be a single add instruction.
  P2::BasicBlock::Ptr add_bb = partitioner->basicBlockExists(fallthrough);
  if (!add_bb || add_bb->instructions().size() != 1) return boost::none;

  SgAsmX86Instruction* add = isSgAsmX86Instruction(add_bb->instructions()[0]);
  if (!add || add->get_kind() != x86_add) return boost::none;

  // The ADD's first operand must be a GPR and the second an immediate.
  const SgAsmExpressionPtrList& addArgs = add->get_operandList()->get_operands();
  if (addArgs.size() != 2) return boost::none;
  SgAsmDirectRegisterExpression* addDst = isSgAsmDirectRegisterExpression(addArgs[0]);
  if (!addDst || addDst->get_descriptor().majorNumber() != x86_regclass_gpr) return boost::none;
  if (!isSgAsmIntegerValueExpression(addArgs[1])) return boost::none;

  // The body starts at the instruction after the ADD.
  rose_addr_t body = add->get_address() + add->get_size();
  return body;
}

// Just sort of copying and pasting from the ROSE examples here...  We're adding a pattern for
// a common tail-call optimization case where an object pointer in loaded into ECX, then
// adjusted by some offset into the object, and then finally a function is called with a JMP
// instruction.  The JMP is really conceptually a CALL, which is why this code is needed.
P2::ThunkDetection
isX86MovAddJmpThunk(P2::PartitionerConstPtr const & partitioner, const std::vector<SgAsmInstruction*> &insns) {
  if (!partitioner || insns.size() < 3)
    return {};
  SgAsmX86Instruction *mov = isSgAsmX86Instruction(insns[0]);
  if (!mov || mov->get_kind() != x86_mov)
    return {};
  const SgAsmExpressionPtrList &movArgs = mov->get_operandList()->get_operands();
  if (movArgs.size() != 2)
    return {};
  SgAsmDirectRegisterExpression *movArg0 = isSgAsmDirectRegisterExpression(movArgs[0]);
  if (!movArg0 || movArg0->get_descriptor().majorNumber() != x86_regclass_gpr ||
      movArg0->get_descriptor().minorNumber() != Rose::BinaryAnalysis::x86_gpr_cx)
    return {};

  // We didn't bother to restrict the type of the second operand.  It was a memory
  // dereference operation in the case that was encountered, but it's not clear what the
  // general constraint is.  It's probably sufficient that we're loading a value into ECX
  // (which is presumed to be an object pointer).
  //SgAsmIntegerValueExpression *movArg1 = isSgAsmIntegerValueExpression(movArgs[1]);
  //if (!movArg1)
  //    return 0;

  SgAsmX86Instruction *add = isSgAsmX86Instruction(insns[1]);
  if (!add || add->get_kind() != x86_add)
    return {};
  const SgAsmExpressionPtrList &addArgs = add->get_operandList()->get_operands();
  if (addArgs.size() != 2)
    return {};
  SgAsmDirectRegisterExpression *addArg0 = isSgAsmDirectRegisterExpression(addArgs[0]);
  if (!addArg0 || addArg0->get_descriptor().majorNumber() != x86_regclass_gpr ||
      addArg0->get_descriptor().minorNumber() != Rose::BinaryAnalysis::x86_gpr_cx)
    return {};
  SgAsmIntegerValueExpression *addArg1 = isSgAsmIntegerValueExpression(addArgs[1]);
  if (!addArg1)
    return {};

  // Validate the tail jump through the ROSE predicate, which additionally requires the target
  // to be executable and not to land in the middle of an instruction.
  std::vector<SgAsmInstruction*> jump_insns{insns[2]};
  if (!P2::isX86JmpImmThunk(partitioner, jump_insns))
    return {};

  using namespace std::string_literals;
  return {3, "pharos::isX86MovAddJmpThunk"s};
}

// Decompose the simple memory addressing forms used by Itanium ABI virtual-adjustment thunks.
// ROSE represents a negative x86 displacement as an addition of a signed integer, so both
// [reg+constant] and [reg-constant] arrive here as SgAsmBinaryAdd nodes.
static bool
match_register_displacement(const SgAsmMemoryReferenceExpression* mem,
                            RegisterDescriptor& base, int64_t& displacement) {
  if (!mem) return false;

  SgAsmExpression* address = mem->get_address();
  if (SgAsmDirectRegisterExpression* reg = isSgAsmDirectRegisterExpression(address)) {
    base = reg->get_descriptor();
    displacement = 0;
    return true;
  }

  SgAsmBinaryAdd* add = isSgAsmBinaryAdd(address);
  if (!add) return false;

  SgAsmDirectRegisterExpression* reg = isSgAsmDirectRegisterExpression(add->get_lhs());
  SgAsmIntegerValueExpression* offset = isSgAsmIntegerValueExpression(add->get_rhs());
  if (!reg) {
    reg = isSgAsmDirectRegisterExpression(add->get_rhs());
    offset = isSgAsmIntegerValueExpression(add->get_lhs());
  }
  if (!reg || !offset) return false;

  base = reg->get_descriptor();
  displacement = offset->get_signedValue();
  return true;
}

static bool
is_amd64_this_pointer_register(RegisterDescriptor reg) {
  return reg.majorNumber() == x86_regclass_gpr &&
    (reg.minorNumber() == Rose::BinaryAnalysis::x86_gpr_di ||
     reg.minorNumber() == Rose::BinaryAnalysis::x86_gpr_si) &&
    reg.offset() == 0 && reg.nBits() == 64;
}

static bool
is_endbr64(const SgAsmInstruction* insn) {
  if (!insn) return false;
  const SgUnsignedCharList& bytes = insn->get_rawBytes();
  return bytes.size() == 4 &&
    bytes[0] == 0xf3 && bytes[1] == 0x0f && bytes[2] == 0x1e && bytes[3] == 0xfa;
}

// The MSVC "this" pointer register: ECX under __thiscall, RCX under the 64 bit convention.
// Requiring a zero offset and the full register width keeps CL, CH and CX out, which a bare
// minor number comparison would wrongly admit.
static bool
is_msvc_this_pointer_register(RegisterDescriptor reg) {
  return reg.majorNumber() == x86_regclass_gpr &&
    reg.minorNumber() == Rose::BinaryAnalysis::x86_gpr_cx &&
    reg.offset() == 0 && (reg.nBits() == 32 || reg.nBits() == 64);
}

// Match a fixed "this" adjustment applied in place to whichever register the ABI passes the
// object pointer in, as identified by is_this_reg.  ADD and SUB are the usual encodings, but
// LEA is equivalent and is also accepted when it preserves the data flow.  The signed amount
// added to the this pointer is reported in delta.
//
// Adjusting the register in place is what makes this a thunk rather than an ordinary method:
// the pointer the callee receives is the one we were called with, offset by a constant.  A
// sequence that first loads the register from somewhere is not an adjustment at all.
static bool
is_fixed_this_adjustment(SgAsmInstruction* insn, bool (*is_this_reg)(RegisterDescriptor),
                         RegisterDescriptor& this_reg, int64_t& delta) {
  SgAsmX86Instruction* xinsn = isSgAsmX86Instruction(insn);
  if (!xinsn) return false;

  const SgAsmExpressionPtrList& args = xinsn->get_operandList()->get_operands();
  if (args.size() != 2) return false;

  SgAsmDirectRegisterExpression* dst = isSgAsmDirectRegisterExpression(args[0]);
  if (!dst || !is_this_reg(dst->get_descriptor())) return false;
  RegisterDescriptor candidate = dst->get_descriptor();

  if (xinsn->get_kind() == x86_add || xinsn->get_kind() == x86_sub) {
    SgAsmIntegerValueExpression* amount = isSgAsmIntegerValueExpression(args[1]);
    if (!amount || amount->get_signedValue() == 0) return false;
    this_reg = candidate;
    delta = xinsn->get_kind() == x86_sub ? -amount->get_signedValue()
                                         : amount->get_signedValue();
    return true;
  }

  if (xinsn->get_kind() == x86_lea) {
    RegisterDescriptor base;
    int64_t displacement = 0;
    SgAsmMemoryReferenceExpression* src = isSgAsmMemoryReferenceExpression(args[1]);
    if (!match_register_displacement(src, base, displacement) ||
        base != candidate || displacement == 0) {
      return false;
    }
    this_reg = candidate;
    delta = displacement;
    return true;
  }

  return false;
}

// Match a fixed Itanium ABI "this" adjustment.  The this pointer is normally in RDI, or RSI
// when RDI holds the hidden address for an indirectly returned object.
static bool
is_itanium_fixed_adjustment(SgAsmInstruction* insn, RegisterDescriptor& this_reg,
                            int64_t& delta) {
  return is_fixed_this_adjustment(insn, is_amd64_this_pointer_register, this_reg, delta);
}

// Match the memory-derived adjustment used for a virtual base:
//
//   mov scratch, [this]
//   add this, [scratch + displacement]
//
// Match the register data flow instead of requiring GCC's usual R10 scratch register.  The
// displacement of the vcall-offset slot is reported in slot; the delta it contributes to the
// this pointer is only known at run time.
static bool
is_itanium_virtual_adjustment(const std::vector<SgAsmInstruction*>& insns, size_t index,
                              RegisterDescriptor& this_reg, int64_t& slot) {
  if (index + 1 >= insns.size()) return false;

  SgAsmX86Instruction* mov = isSgAsmX86Instruction(insns[index]);
  if (!mov || mov->get_kind() != x86_mov) return false;
  const SgAsmExpressionPtrList& mov_args = mov->get_operandList()->get_operands();
  if (mov_args.size() != 2) return false;

  SgAsmDirectRegisterExpression* scratch = isSgAsmDirectRegisterExpression(mov_args[0]);
  if (!scratch) return false;
  RegisterDescriptor scratch_reg = scratch->get_descriptor();
  if (scratch_reg.majorNumber() != x86_regclass_gpr ||
      scratch_reg.offset() != 0 || scratch_reg.nBits() != 64) {
    return false;
  }

  RegisterDescriptor vtable_base;
  int64_t ignored_displacement = 0;
  SgAsmMemoryReferenceExpression* vtable = isSgAsmMemoryReferenceExpression(mov_args[1]);
  if (!match_register_displacement(vtable, vtable_base, ignored_displacement) ||
      !is_amd64_this_pointer_register(vtable_base) || ignored_displacement != 0 ||
      scratch_reg == vtable_base) {
    return false;
  }

  SgAsmX86Instruction* add = isSgAsmX86Instruction(insns[index + 1]);
  if (!add || add->get_kind() != x86_add) return false;
  const SgAsmExpressionPtrList& add_args = add->get_operandList()->get_operands();
  if (add_args.size() != 2) return false;

  SgAsmDirectRegisterExpression* add_dst = isSgAsmDirectRegisterExpression(add_args[0]);
  if (!add_dst || add_dst->get_descriptor() != vtable_base) return false;

  RegisterDescriptor adjustment_base;
  int64_t adjustment_displacement = 0;
  SgAsmMemoryReferenceExpression* adjustment = isSgAsmMemoryReferenceExpression(add_args[1]);
  if (!match_register_displacement(adjustment, adjustment_base, adjustment_displacement) ||
      adjustment_base != scratch_reg) {
    return false;
  }

  this_reg = vtable_base;
  slot = adjustment_displacement;
  return true;
}

// Detect SysV AMD64 thunks emitted under the Itanium C++ ABI, and report how they modify the
// this pointer.  As a ROSE predicate this is deliberately installed only as a function
// splitter: scanning arbitrary executable bytes for these short patterns would create too many
// speculative functions.
static boost::optional<AdjustingThunk>
analyze_x86_itanium_adjusting_thunk(P2::PartitionerConstPtr const & partitioner,
                                    const std::vector<SgAsmInstruction*>& insns) {
  if (!partitioner || insns.size() < 2) return boost::none;

  size_t index = 0;
  if (is_endbr64(insns[index])) ++index;

  bool fixed = false;
  bool virtual_adjustment = false;
  RegisterDescriptor fixed_this_reg;
  RegisterDescriptor virtual_this_reg;
  int64_t fixed_delta = 0;
  int64_t virtual_slot = 0;

  if (index < insns.size() &&
      is_itanium_fixed_adjustment(insns[index], fixed_this_reg, fixed_delta)) {
    fixed = true;
    ++index;
  }

  if (is_itanium_virtual_adjustment(insns, index, virtual_this_reg, virtual_slot)) {
    if (fixed && fixed_this_reg != virtual_this_reg) return boost::none;
    virtual_adjustment = true;
    index += 2;
  }

  if (!fixed && !virtual_adjustment) return boost::none;
  if (index >= insns.size()) return boost::none;

  std::vector<SgAsmInstruction*> jump_insns{insns[index]};
  if (!P2::isX86JmpImmThunk(partitioner, jump_insns)) return boost::none;

  AdjustingThunk thunk;
  thunk.ninsns = index + 1;
  if (fixed) thunk.adjustment.fixed_delta = fixed_delta;
  if (virtual_adjustment) {
    thunk.adjustment.virtual_adjustment =
      ThunkAdjustment::VirtualAdjustment{ThunkAdjustment::VirtualKind::vcall_offset,
                                         virtual_slot};
  }
  return thunk;
}

// Match the MSVC vtordisp adjustment, which reads a displacement written into the object during
// construction and subtracts it.  Two encodings, both leaving the this pointer in place:
//
//   sub ecx, [ecx - 4]                            32 bit
//
//   movsxd scratch, [rcx - 4]                     64 bit, the field is a 32 bit signed int
//   sub    rcx, scratch
//
// The displacement of the vtordisp field is reported in slot.  Unlike an Itanium vcall offset
// this is read from the object rather than from the vftable, and it is subtracted rather than
// added, so it cannot share a representation with one.
static bool
is_msvc_vtordisp_adjustment(const std::vector<SgAsmInstruction*>& insns, size_t index,
                            RegisterDescriptor& this_reg, int64_t& slot, size_t& ninsns) {
  if (index >= insns.size()) return false;

  SgAsmX86Instruction* first = isSgAsmX86Instruction(insns[index]);
  if (!first) return false;

  // The 32 bit form subtracts straight from memory.
  if (first->get_kind() == x86_sub) {
    const SgAsmExpressionPtrList& args = first->get_operandList()->get_operands();
    if (args.size() != 2) return false;

    SgAsmDirectRegisterExpression* dst = isSgAsmDirectRegisterExpression(args[0]);
    if (!dst || !is_msvc_this_pointer_register(dst->get_descriptor())) return false;

    RegisterDescriptor base;
    int64_t displacement = 0;
    if (!match_register_displacement(isSgAsmMemoryReferenceExpression(args[1]),
                                     base, displacement) ||
        base != dst->get_descriptor()) {
      return false;
    }

    this_reg = dst->get_descriptor();
    slot = displacement;
    ninsns = 1;
    return true;
  }

  // The 64 bit form widens the field into a scratch register first.  Match the register data
  // flow rather than requiring the compiler's usual choice of RAX.
  if (first->get_kind() != Rose::BinaryAnalysis::x86_movsx &&
      first->get_kind() != Rose::BinaryAnalysis::x86_movsxd) {
    return false;
  }
  if (index + 1 >= insns.size()) return false;

  const SgAsmExpressionPtrList& load_args = first->get_operandList()->get_operands();
  if (load_args.size() != 2) return false;

  SgAsmDirectRegisterExpression* scratch = isSgAsmDirectRegisterExpression(load_args[0]);
  if (!scratch) return false;
  RegisterDescriptor scratch_reg = scratch->get_descriptor();
  if (scratch_reg.majorNumber() != x86_regclass_gpr ||
      scratch_reg.offset() != 0 || scratch_reg.nBits() != 64) {
    return false;
  }

  RegisterDescriptor base;
  int64_t displacement = 0;
  if (!match_register_displacement(isSgAsmMemoryReferenceExpression(load_args[1]),
                                   base, displacement) ||
      !is_msvc_this_pointer_register(base) || scratch_reg == base) {
    return false;
  }

  SgAsmX86Instruction* sub = isSgAsmX86Instruction(insns[index + 1]);
  if (!sub || sub->get_kind() != x86_sub) return false;
  const SgAsmExpressionPtrList& sub_args = sub->get_operandList()->get_operands();
  if (sub_args.size() != 2) return false;

  SgAsmDirectRegisterExpression* sub_dst = isSgAsmDirectRegisterExpression(sub_args[0]);
  SgAsmDirectRegisterExpression* sub_src = isSgAsmDirectRegisterExpression(sub_args[1]);
  if (!sub_dst || !sub_src || sub_dst->get_descriptor() != base ||
      sub_src->get_descriptor() != scratch_reg) {
    return false;
  }

  this_reg = base;
  slot = displacement;
  ninsns = 2;
  return true;
}

// Is this a 32 bit general purpose register?
static bool
is_gpr32(RegisterDescriptor reg) {
  return reg.majorNumber() == x86_regclass_gpr && reg.offset() == 0 && reg.nBits() == 32;
}

// The SysV i386 ABI passes the object pointer on the stack rather than in a register, so its
// adjustor thunks rewrite the argument slot instead of a register.  On entry the return address
// occupies [esp], which puts the this pointer at [esp+4], or at [esp+8] when [esp+4] holds the
// hidden address for an indirectly returned object.  This mirrors the AMD64 convention of
// passing this in RDI, or in RSI when RDI is taken by the hidden pointer.  The displacement is
// reported in slot so that a caller can require the same one throughout.
static bool
is_sysv32_this_slot(SgAsmExpression* expr, int64_t& slot) {
  RegisterDescriptor base;
  int64_t displacement = 0;
  if (!match_register_displacement(isSgAsmMemoryReferenceExpression(expr), base, displacement)) {
    return false;
  }
  if (base.majorNumber() != x86_regclass_gpr ||
      base.minorNumber() != Rose::BinaryAnalysis::x86_gpr_sp ||
      base.offset() != 0 || base.nBits() != 32 ||
      (displacement != 4 && displacement != 8)) {
    return false;
  }
  slot = displacement;
  return true;
}

// Match a fixed SysV i386 adjustment, applied directly to the argument slot:
//
//   sub DWORD PTR [esp+4], 8
static bool
is_sysv32_fixed_adjustment(SgAsmInstruction* insn, int64_t& delta) {
  SgAsmX86Instruction* xinsn = isSgAsmX86Instruction(insn);
  if (!xinsn || (xinsn->get_kind() != x86_add && xinsn->get_kind() != x86_sub)) return false;

  const SgAsmExpressionPtrList& args = xinsn->get_operandList()->get_operands();
  int64_t this_slot = 0;
  if (args.size() != 2 || !is_sysv32_this_slot(args[0], this_slot)) return false;

  SgAsmIntegerValueExpression* amount = isSgAsmIntegerValueExpression(args[1]);
  if (!amount || amount->get_signedValue() == 0) return false;

  delta = xinsn->get_kind() == x86_sub ? -amount->get_signedValue() : amount->get_signedValue();
  return true;
}

// Match a SysV i386 virtual adjustment, which loads the argument slot into a register, folds in
// the vcall offset, and writes it back:
//
//   mov this, [esp+4]
//   add this, fixed          (optional, for a combined thunk)
//   mov scratch, [this]
//   add this, [scratch + slot]
//   mov [esp+4], this
//
// As on AMD64 the slot is a displacement from the object's vftable pointer, so the value found
// there is added, and this shares the vcall_offset representation.
static bool
is_sysv32_virtual_adjustment(const std::vector<SgAsmInstruction*>& insns, size_t index,
                             int64_t& fixed_delta, int64_t& slot, size_t& ninsns) {
  size_t start = index;
  auto next = [&insns, &index]() -> SgAsmX86Instruction* {
    return index < insns.size() ? isSgAsmX86Instruction(insns[index]) : nullptr;
  };

  SgAsmX86Instruction* load = next();
  if (!load || load->get_kind() != x86_mov) return false;
  const SgAsmExpressionPtrList& load_args = load->get_operandList()->get_operands();
  int64_t this_slot = 0;
  if (load_args.size() != 2 || !is_sysv32_this_slot(load_args[1], this_slot)) return false;
  SgAsmDirectRegisterExpression* this_expr = isSgAsmDirectRegisterExpression(load_args[0]);
  if (!this_expr || !is_gpr32(this_expr->get_descriptor())) return false;
  RegisterDescriptor this_reg = this_expr->get_descriptor();
  ++index;

  // An optional constant adjustment, present only in a combined thunk.
  fixed_delta = 0;
  RegisterDescriptor fixed_reg;
  int64_t candidate_delta = 0;
  if (is_fixed_this_adjustment(index < insns.size() ? insns[index] : nullptr, is_gpr32,
                               fixed_reg, candidate_delta) && fixed_reg == this_reg) {
    fixed_delta = candidate_delta;
    ++index;
  }

  SgAsmX86Instruction* vptr = next();
  if (!vptr || vptr->get_kind() != x86_mov) return false;
  const SgAsmExpressionPtrList& vptr_args = vptr->get_operandList()->get_operands();
  if (vptr_args.size() != 2) return false;
  SgAsmDirectRegisterExpression* scratch_expr = isSgAsmDirectRegisterExpression(vptr_args[0]);
  if (!scratch_expr || !is_gpr32(scratch_expr->get_descriptor())) return false;
  RegisterDescriptor scratch_reg = scratch_expr->get_descriptor();
  RegisterDescriptor vptr_base;
  int64_t vptr_displacement = 0;
  if (scratch_reg == this_reg ||
      !match_register_displacement(isSgAsmMemoryReferenceExpression(vptr_args[1]),
                                   vptr_base, vptr_displacement) ||
      vptr_base != this_reg || vptr_displacement != 0) {
    return false;
  }
  ++index;

  SgAsmX86Instruction* add = next();
  if (!add || add->get_kind() != x86_add) return false;
  const SgAsmExpressionPtrList& add_args = add->get_operandList()->get_operands();
  if (add_args.size() != 2) return false;
  SgAsmDirectRegisterExpression* add_dst = isSgAsmDirectRegisterExpression(add_args[0]);
  RegisterDescriptor adjustment_base;
  int64_t adjustment_displacement = 0;
  if (!add_dst || add_dst->get_descriptor() != this_reg ||
      !match_register_displacement(isSgAsmMemoryReferenceExpression(add_args[1]),
                                   adjustment_base, adjustment_displacement) ||
      adjustment_base != scratch_reg) {
    return false;
  }
  ++index;

  SgAsmX86Instruction* store = next();
  if (!store || store->get_kind() != x86_mov) return false;
  const SgAsmExpressionPtrList& store_args = store->get_operandList()->get_operands();
  int64_t store_slot = 0;
  if (store_args.size() != 2 || !is_sysv32_this_slot(store_args[0], store_slot) ||
      store_slot != this_slot) {
    return false;
  }
  SgAsmDirectRegisterExpression* store_src = isSgAsmDirectRegisterExpression(store_args[1]);
  if (!store_src || store_src->get_descriptor() != this_reg) return false;
  ++index;

  slot = adjustment_displacement;
  ninsns = index - start;
  return true;
}

// Detect SysV i386 adjustor thunks.
static boost::optional<AdjustingThunk>
analyze_x86_sysv32_adjusting_thunk(P2::PartitionerConstPtr const & partitioner,
                                   const std::vector<SgAsmInstruction*>& insns) {
  if (!partitioner || insns.size() < 2) return boost::none;

  size_t index = 0;
  int64_t fixed_delta = 0;
  int64_t slot = 0;
  size_t virtual_insns = 0;
  bool virtual_adjustment =
    is_sysv32_virtual_adjustment(insns, index, fixed_delta, slot, virtual_insns);
  if (virtual_adjustment) {
    index += virtual_insns;
  }
  else if (is_sysv32_fixed_adjustment(insns[index], fixed_delta)) {
    ++index;
  }
  else {
    return boost::none;
  }

  if (index >= insns.size()) return boost::none;
  std::vector<SgAsmInstruction*> jump_insns{insns[index]};
  if (!P2::isX86JmpImmThunk(partitioner, jump_insns)) return boost::none;

  AdjustingThunk thunk;
  thunk.ninsns = index + 1;
  thunk.adjustment.fixed_delta = fixed_delta;
  if (virtual_adjustment) {
    thunk.adjustment.virtual_adjustment =
      ThunkAdjustment::VirtualAdjustment{ThunkAdjustment::VirtualKind::vcall_offset, slot};
  }
  return thunk;
}

// Detect MSVC adjustor thunks, which adjust ECX or RCX in place before tail jumping.  A vtordisp
// adjustment for a virtual base may be followed by a fixed adjustment, in that order.
static boost::optional<AdjustingThunk>
analyze_x86_msvc_adjusting_thunk(P2::PartitionerConstPtr const & partitioner,
                                 const std::vector<SgAsmInstruction*>& insns) {
  if (!partitioner || insns.size() < 2) return boost::none;

  size_t index = 0;
  RegisterDescriptor vtordisp_this_reg;
  RegisterDescriptor fixed_this_reg;
  int64_t vtordisp_slot = 0;
  int64_t fixed_delta = 0;
  size_t vtordisp_insns = 0;
  bool vtordisp = is_msvc_vtordisp_adjustment(insns, index, vtordisp_this_reg, vtordisp_slot,
                                              vtordisp_insns);
  if (vtordisp) index += vtordisp_insns;

  bool fixed = index < insns.size() &&
    is_fixed_this_adjustment(insns[index], is_msvc_this_pointer_register, fixed_this_reg,
                             fixed_delta);
  if (fixed) {
    if (vtordisp && fixed_this_reg != vtordisp_this_reg) return boost::none;
    ++index;
  }

  if (!vtordisp && !fixed) return boost::none;
  if (index >= insns.size()) return boost::none;

  std::vector<SgAsmInstruction*> jump_insns{insns[index]};
  if (!P2::isX86JmpImmThunk(partitioner, jump_insns)) return boost::none;

  AdjustingThunk thunk;
  thunk.ninsns = index + 1;
  if (fixed) thunk.adjustment.fixed_delta = fixed_delta;
  if (vtordisp) {
    thunk.adjustment.virtual_adjustment =
      ThunkAdjustment::VirtualAdjustment{ThunkAdjustment::VirtualKind::vtordisp, vtordisp_slot};
  }
  return thunk;
}

P2::ThunkDetection
isX86ItaniumAdjustingThunk(P2::PartitionerConstPtr const & partitioner,
                           const std::vector<SgAsmInstruction*>& insns) {
  auto thunk = analyze_x86_itanium_adjusting_thunk(partitioner, insns);
  if (!thunk) return {};
  using namespace std::string_literals;
  return {thunk->ninsns, "pharos::isX86ItaniumAdjustingThunk"s};
}

P2::ThunkDetection
isX86Sysv32AdjustingThunk(P2::PartitionerConstPtr const & partitioner,
                          const std::vector<SgAsmInstruction*>& insns) {
  auto thunk = analyze_x86_sysv32_adjusting_thunk(partitioner, insns);
  if (!thunk) return {};
  using namespace std::string_literals;
  return {thunk->ninsns, "pharos::isX86Sysv32AdjustingThunk"s};
}

P2::ThunkDetection
isX86MsvcAdjustingThunk(P2::PartitionerConstPtr const & partitioner,
                        const std::vector<SgAsmInstruction*>& insns) {
  auto thunk = analyze_x86_msvc_adjusting_thunk(partitioner, insns);
  if (!thunk) return {};
  using namespace std::string_literals;
  return {thunk->ninsns, "pharos::isX86MsvcAdjustingThunk"s};
}

// Only shapes that adjust the incoming this pointer in place belong here.  The MOV/ADD/JMP
// pattern deliberately does not: its MOV overwrites the this register before the ADD, so the
// value it adjusts is some other object rather than the one handed to us.  "mov ecx, [ecx]; add
// ecx, 0x18; jmp" is std::locale::c_str() forwarding to a member, not an adjustor, and treating
// it as a thunk discards that method's own this pointer and members.  See isX86MovAddJmpThunk,
// which still uses that pattern for the only thing it can support, function splitting.
boost::optional<AdjustingThunk>
detect_adjusting_thunk(P2::PartitionerConstPtr const & partitioner,
                       const std::vector<SgAsmInstruction*> & insns) {
  auto thunk = analyze_x86_itanium_adjusting_thunk(partitioner, insns);
  if (thunk) return thunk;
  thunk = analyze_x86_sysv32_adjusting_thunk(partitioner, insns);
  if (thunk) return thunk;
  return analyze_x86_msvc_adjusting_thunk(partitioner, insns);
}

// ===============================================================================================
// Partitioner2
// ===============================================================================================

P2::PartitionerPtr create_partitioner(const ProgOptVarMap& vm, P2::Engine* engine,
                                      std::vector<std::string> const & specimen_names)
{
  using clock = std::chrono::steady_clock;
  using time_point = std::chrono::time_point<clock>;
  using duration = std::chrono::duration<double>;

  auto & settings = engine->settings();

  // Mark all segments in the program as executable.  This is important in environments such as
  // Windows, where the segments can easily have their permissions altered after loading.
  // Enabling this feature alone in the stock partitioner can cause bad things to happen --
  // such as the creation of very large basic blocks full of zero instructions.
  if (vm.count("mark-executable")) {
    GINFO << "Marking all sections as executable during function partitioning." << LEND;
    settings.loader.memoryIsExecutable = true;
  }

  // The standard rose approach of marking blocks of zeros as non-excutable doesn't work well,
  // because among other issues, it consumes zeros in valid instructions that are adjacent to
  // other blocks of zeros.  It might be useful to enable temporarily while troublshooting
  // other problems.
  // engine->deExecuteZeros(256);
  // MWD: The following line might have same effect for newer ROSE, but is untested
  // settings.loader.deExecuteZerosThreshold = 256;

  // It's VERY unclear right now whether enabling semantics helps or hinders.  There are some
  // known bugs in enabling it, probably because it hasn't been well tested (Robb has it off by
  // default because of the performance impact).  On the Objdigger test suite, it doesn't
  // impact the object detections regardless of the setting, but it does add and remove a wide
  // variety of other messages about unexpected conditions.  It definately affects performance
  // in a negative way, and should optional in some future code.
  bool disable_semantics = vm.count("no-semantics");
  if (!disable_semantics) {
    auto v = vm.config().path_get("pharos.partitioner_semantics");
    disable_semantics = v && (v.as<bool>() == false);
  }
  if (!disable_semantics) {
    GINFO << "Enabling semantic control flow analysis during function partitioning." << LEND;
    settings.partitioner.base.usingSemantics = true;
  }
  else {
    GINFO << "Semantic control flow analysis disabled, analysis may be less correct." << LEND;
  }

  // We're leaving post analysis in general on right now, even though we've disabled all of the
  // passes.  We disabled these passes because they take additional CPU and don't provide any
  // benefit since we're not actually using them.
  settings.partitioner.doingPostAnalysis = false;
  // Honor configured may-return answers and assume that functions return when the analysis
  // cannot decide.
  settings.partitioner.doingPostFunctionMayReturn = false;
  settings.partitioner.functionReturnAnalysis =
    Rose::BinaryAnalysis::Partitioner2::MAYRETURN_DEFAULT_YES;
  // We're not using ROSE's stack delta analysis or calling convention analysis because we have
  // our own.  We should consolidate these as soon as possible.
  settings.partitioner.doingPostFunctionStackDelta = false;
  settings.partitioner.doingPostCallingConvention = false;
  settings.partitioner.doingPostFunctionNoop = false;

  // TODO mwd: This is needed to keep things from being exceptionally slow since Rose commit
  // 4f0db690696dcd4c6dfaf898504a75fcd76770a6
  settings.partitioner.findingInterFunctionCalls = false;

  // We'll handle errors.  We don't want to unilaterally exit.
  settings.engine.exitOnError = false;

  // Enable Robb's standard thunk splitting logic.  Needed for our debug test cases?
  settings.partitioner.splittingThunks = true;

  // Disable Robb's demangler because it was exiting abruptly on some important files.
  settings.partitioner.demangleNames = false;

  // Check the specimens
  if (specimen_names.empty()) {
    GFATAL << "no specimen specified; see --help" << LEND;
    std::exit(EXIT_FAILURE);
  }

  // Parse the binary container (ELF/PE) and obtain a loader configured for relocations.
  auto *binary_engine = dynamic_cast<P2Engine*>(engine);
  MemoryMap::Ptr map;
  try {
    // Parse containers so that the interpretation and headers exist.
    engine->parseContainers(specimen_names);

    // Enable ROSE's built-in relocation fixups so that PIE vtable entries and other
    // relocated data are patched in the memory map.  Obtain and configure the loader
    // now so that subsequent load calls performed by engine->loadSpecimens() will
    // perform relocations.
    if (binary_engine) {
      auto loader = binary_engine->obtainLoader();
      loader->performingRelocations(true);
    }

    // If the user requested a specific base address, set it on the file headers before
    // mapping so that ROSE's remap and relocation fixup phases use the desired base.
    if (vm.count("base-address") > 0) {
      std::string base_str = vm["base-address"].as<std::string>();
      rose_addr_t desired_base = 0;
      try {
        desired_base = (rose_addr_t)parse_number(base_str);
      } catch (std::exception const &) {
        GFATAL << "Invalid --base-address value: " << base_str << LEND;
        std::exit(EXIT_FAILURE);
      }
      if (SgAsmInterpretation* interp = engine->interpretation()) {
        for (SgAsmGenericHeader *hdr : interp->get_headers()->get_headers()) {
          GINFO << "Rebasing specimen from " << addr_str(hdr->get_baseVa())
                << " to " << addr_str(desired_base) << LEND;
          hdr->set_baseVa(desired_base);
        }
      }
    }

    map = engine->loadSpecimens(specimen_names);
  } catch (SgAsmExecutableFileFormat::FormatError &e) {
    GFATAL << "Error while loading specimen: " << e.what () << LEND;
    std::exit(EXIT_FAILURE);
  } catch (std::exception const & e) {
    GFATAL << "Error while loading specimen: " << e.what () << LEND;
    std::exit(EXIT_FAILURE);
  }

  // Get the interpretation.
  SgAsmInterpretation* interp = engine->interpretation();

  // Mark the entry point segment as executable (unless the user asked us not to).
  if (vm.count("no-executable-entry") < 1 && interp) {
    for (const SgAsmGenericHeader *fileHeader : interp->get_headers()->get_headers()) {
      for (const rose_rva_t &rva : fileHeader->get_entryRvas()) {
        // Get the address of the entry point.
#if PHAROS_ROSE_RVA_HACK
        rose_addr_t va = rva.rva() + fileHeader->get_baseVa();
#else
        rose_addr_t va = rva.get_rva() + fileHeader->get_baseVa();
#endif
        // A constraint containing just the entry point address.
        auto segments = map->at(va).segments();
        if (segments.empty()) {
          continue;
        }
        // The name of the segment that address is in.
        const std::string & name = segments.front().name();
        // A predicate for all addresses in a segment with the same name.
        NamePredicate name_constraint(name);
        // The map constraint matching the predicate (all addresses in the segment).
        // auto rather than:
        // class Sawyer::Container::AddressMapConstraints<Sawyer::Container::AddressMap<long unsigned int, unsigned char> >
        auto data_segment = map->segmentPredicate(&name_constraint);
        // Set ther permission to executable.
        data_segment.changeAccess(MemoryMap::EXECUTABLE, 0);
        GINFO << "Marked entry point address " << addr_str(va) << " in segment " << name
              << " as executable." << LEND;
      }
    }
  }

  // Does the tool only support Windows PE files (aka OOAnalzyer)?
  boost::optional<bool> allow = vm.get<bool>("pharos.allow_non_pe");
  if (allow) {
    if (*allow) {
      // We support non-PE files
      boost::optional<std::string> disassembler = vm.get<std::string>("pharos.disassembler");
      if (disassembler) {
        // Use the value of pharos.disassembler if it is set
        settings.disassembler.isaName = *disassembler;
      }
      if (settings.disassembler.isaName.empty()) {
        auto dis = engine->architecture()->newInstructionDecoder();
        if (!dis) {
          OWARN << "Unable to determine disassembler from specimen; using i386 by default"
                << LEND;
          settings.disassembler.isaName = "intel-i386";
        } else {
          settings.disassembler.isaName = dis->name();
        }
      }
    } else {
      // If so ensure that the input executable is of the correct file type.
      SgAsmPEFileHeader *pehdr = nullptr;
      if (interp) {
        auto h = interp->get_headers();
        if (h) {
          auto & hdrs = h->get_headers();
          if (hdrs.size()) {
            pehdr = isSgAsmPEFileHeader(hdrs[0]);
          }
        }
      }
      if (!pehdr) {
        GWARN << "Support for ELF executables is *very* experimental!" << LEND;
      }
    }
  }


  // Create a partitioner that's tuned for a certain architecture, and then tune it even more
  // depending on our command-line.
  P2::PartitionerPtr partitioner = engine->createPartitioner();

  // Tell the partitioner not to give a call to a non-returning function a call-return edge.
  // The "nonreturn" tags are the single source of truth, and users extend them through
  // pharos.function_tags.  ROSE names PLT stubs "NAME@plt" while everything else uses the bare
  // symbol, so configure both spellings.
  //
  // This only reaches functions that ROSE has already attached and named when it decides the
  // edge, which in practice excludes imports: a PLT stub is still an unnamed placeholder at
  // that point, and its indirect jump reads as "returns by virtue of having only an
  // indeterminate successor".  FunctionDescriptor::get_pharos_cfg() is what actually removes
  // those edges, using our own never-returns answer.
  for (auto const & name : DescriptorSet::create_tag_manager(vm)->names_with_tag("nonreturn")) {
    partitioner->configuration().insertMaybeFunction(name).mayReturn(false);
    partitioner->configuration().insertMaybeFunction(name + "@plt").mayReturn(false);
  }

  // Enable our Monitor (previously for CFG debugging, now for timeout limit checking).
  partitioner->cfgAdjustmentCallbacks().append(Monitor::instance());

  size_t arch_bits = partitioner->instructionProvider().instructionPointerRegister().get_nbits();
  if (arch_bits != 32) {
    // What does the config file say about whether 64-bit analysis is supported for this tool?
    auto config_allow64 = vm.config().path_get("pharos.allow-64bit");
    // If it's not enabled in the config file, warn regardless of the command line option.
    if ((not config_allow64) or (not config_allow64.as<bool>())) {
      OWARN << "Non 32-bit Windows PE support is still highly experimental for this tool!" << LEND;
      if (not vm.count("allow-64bit")) {
        GFATAL << "Please specify --allow-64bit to allow the analysis of 64-bit executables." << LEND;
        std::exit(EXIT_FAILURE);
      }
    }
  }

  customize_message_facility(P2::mlog, "PRT2");
  P2::mlog[Sawyer::Message::FATAL].enable();
  P2::mlog[Sawyer::Message::ERROR].enable();
  P2::mlog[Sawyer::Message::MARCH].enable();
  if (vm.count("pdebug")) {
    ODEBUG << "Partitioner debugging enabled." << LEND;
    // Set the time limit to zero seconds to report everything.
    P2::mlog[Sawyer::Message::WARN].enable();
    P2::mlog[Sawyer::Message::INFO].enable();
    P2::mlog[Sawyer::Message::DEBUG].enable();
  }

  // We used to load partitioner configs, with the --pconfig option, but that feature never got
  // ported to ROSE Partitioner2. :-(   It would be nice to have it back some day.

  // We also used to configure logging in the disassembler and the loader more or less the same
  // way that we're now configuring the logging in P2::mlog.  Is that perhaps why we've begun
  // receiving warnings about malformed PE files?   Does that matter?

  // Show what we'll be working on (stdout for the record, and diagnostics also)
  //partitioner->memoryMap().dump(mlog[INFO]);

  // Run the partitioner
  if (vm.count("serialize")) {
    // Partitioner data is or will be serialized

    // Try reading the serialized file, if it exists
    bfs::path path = vm["serialize"].as<bfs::path>();
    if (exists(path)) {
      OINFO << "Reading serialized data from " << path << "." << LEND;
      try {
        std::ifstream file(path.native(), std::ios_base::in | std::ios_base::binary);
        if (!file) {
          GFATAL << "Could not open " << path << " for reading." << LEND;
          std::exit(EXIT_FAILURE);
        }
        bio::filtering_streambuf<bio::input> in;
        in.push(bio::gzip_decompressor());
        in.push(file);
        bar::binary_iarchive ia(in);
        std::string version;
        bool semantics_were_disabled;
        ia >> version >> semantics_were_disabled;
        if (version != ROSE_PACKAGE_VERSION) {
          if (vm.count("ignore-serialize-version")) {
            GWARN << "Serialized data was from a different version of Rose."
                  << "  Loading anyway as requested." << LEND;
            version = ROSE_PACKAGE_VERSION;
          } else {
            GFATAL << "Serialized data was from a different version of Rose.  Exiting.\n"
                   << "If you want to overwrite the file, remove the file " << path << '\n'
                   << "If you want to ignore this, use the --ignore-serialize-version switch."
                   << LEND;
            std::exit(EXIT_FAILURE);
          }
        }
        if (disable_semantics != semantics_were_disabled) {
          char const * onoff = semantics_were_disabled ? "disabled" : "enabled";
          GWARN << "Serialized data was generated with semantics " << onoff
                << ", which is which is contrary to how this program was run." << LEND;
        }
        time_point start_ts = clock::now();
        ia >> *partitioner;
        duration secs = clock::now() - start_ts;
        OINFO << "Reading serialized data took " << secs.count() << " seconds." << LEND;
      } catch (boost::iostreams::gzip_error &e) {
        OFATAL << "Unable to read serialized data: " << e.what () << LEND;
        std::exit(EXIT_FAILURE);
      }
    } else {
      std::ofstream file(path.native(), std::ios_base::out | std::ios_base::binary);
      if (!file) {
          GFATAL << "Could not open " << path << " for writing." << LEND;
          std::exit(EXIT_FAILURE);
      }
      // This is kind of yucky, but the inner try ensures that we remove the .serialize file.
      // The outer try then allows us to "really" handle the exceptions.
      try {
        try {
          // No serialized data.  Write it instead.
          time_point start_ts = clock::now();
          engine->runPartitioner(partitioner);
          time_point now = clock::now();
          duration secs = now - start_ts;
          start_ts = now;
          OINFO << "Function partitioning took " << secs.count() << " seconds." << LEND;
          OINFO << "Writing serialized data to " << path << "." << LEND;
          bio::filtering_streambuf<bio::output> out;
          out.push(bio::gzip_compressor());
          out.push(file);
          bar::binary_oarchive oa(out);
          oa << std::string{ROSE_PACKAGE_VERSION} << disable_semantics;
          oa << *partitioner;
          secs = clock::now() - start_ts;
          OINFO << "Writing serialized data took " << secs.count() << " seconds." << LEND;
        } catch (...) {
          file.close();
          boost::system::error_code ec;
          if (!bfs::remove(path, ec)) {
            OWARN << "Could not remove incomplete serialization file " << path << LEND;
          }
          throw;
        }
      } catch (const Monitor::ResourceException &e) {
        OFATAL << "During partitioning: " << e.what () << LEND;
        std::exit(EXIT_FAILURE);
      }
    }
  } else {
    time_point start_ts = clock::now();
    try {
      engine->runPartitioner(partitioner);
    } catch (const Monitor::ResourceException &e) {
      OFATAL << LEND << "During partitioning: " << e.what () << LEND;
      std::exit(EXIT_FAILURE);
    }
    duration secs = clock::now() - start_ts;
    OINFO << "Pharos function partitioning took " << secs.count() << " seconds." << LEND;
  }

  // Report statistics for what we found in the partitioner.  This function needs to be called
  // from here and not from our custom partitioner so that we get statistics for the stock ROSE
  // partitioner as well.
  report_partitioner_statistics(partitioner);

  // Enable progress bars only if the output is to a terminal...
  if (interactive_logging()) {
    partitioner->progress(Rose::Progress::Ptr());
  }

  // This test may have been added because buildAst failed when the function list was empty.
  // Since we're no longer returning the interpretation, but the engine instead, we can
  // probably return the engine anyway (no AST?) and not crash... Hopefully.
  if (partitioner->functions().empty() && settings.partitioner.functionStartingVas.empty()) {
    GERROR << "No starting points for recursive disassembly." << LEND;
    return partitioner;
  }

  return partitioner;
}

uint8_t CERTEngine::read_byte(rose_addr_t addr) {
  uint8_t byte;
  if (1 != memoryMap()->at(addr).limit(1).require(MemoryMap::EXECUTABLE).read(&byte).size()) {
    // This is a debug message and not an error because the user can't conclude anything useful from it.
    GDEBUG << "Failed to read byte at " << addr_str(addr) << LEND;
    throw std::out_of_range(std::string("Failed to read byte at ") + addr_str(addr));
  }
  return byte;
}

// Is this instruction the sort of thing compilers emit between functions to align the next one?
//
// This is deliberately not the same set as insn_is_nop().  INT3 is padding but is emphatically
// not a no-op, and conversely the no-ops that mark a function entry -- the ENDBR landing pad and
// the MSVC hot-patch slot -- are not padding, because consuming them would push the following
// function's entry past its real beginning, the very problem this code exists to prevent.
static bool
insn_is_padding(const SgAsmX86Instruction* insn) {
  if (!insn) return false;
  if (insn_is_entry_marker(insn)) return false;
  return insn_is_nop(insn) || insn->get_kind() == x86_int3;
}

// Consume padding instructions starting at addr, returning the address just past the last one,
// or addr unchanged when the first instruction is not padding.
static rose_addr_t
consume_padding_insns(P2::PartitionerPtr const & partitioner, rose_addr_t addr) {
  rose_addr_t current = addr;
  while (true) {
    // Never consume bytes that already belong to something else.
    if (partitioner->instructionExists(current)) break;
    SgAsmX86Instruction* insn = isSgAsmX86Instruction(partitioner->discoverInstruction(current));
    if (!insn || insn->get_size() == 0) break;
    if (!insn_is_padding(insn)) break;
    current += insn->get_size();
  }
  return current;
}

P2::DataBlock::Ptr
CERTEngine::try_making_padding_block(P2::PartitionerPtr const & partitioner, rose_addr_t addr, bool backwards) {
  // The padding data block that we're going to create (or return as a nulllptr).
  P2::DataBlock::Ptr dblock;

  // OINFO << "Started at address " << addr_str(addr) << " going backwards=" << backwards << LEND;

  rose_addr_t current = addr;
  uint8_t byte;
  uint8_t expected;

  // Going forwards we can decode instructions, which is the only way to recognize the padding
  // that compilers actually emit.  Alignment padding is not a run of identical bytes: GCC uses
  // multi-byte no-ops such as "lea esi, [esi+0]" (with and without a CS prefix) and the 0F 1F
  // family, none of which the byte oriented logic below can express.  Failing to consume them
  // makes the following function appear to start at its padding instead of at its first real
  // instruction.
  if (!backwards) {
    rose_addr_t end = consume_padding_insns(partitioner, addr);
    if (end == addr) {
      not_pad_gaps.insert(addr);
      return dblock;
    }
    dblock = P2::DataBlock::instanceBytes(addr, end - addr);
    partitioner->attachDataBlock(dblock);
    return dblock;
  }

  // Read the first byte.
  try {
    expected = read_byte(current);
  }
  catch (std::exception& e) {
    // Trigger unexpected byte logic in next code block.  This probably never happens.
    expected = 0;
  }

  // If the first byte wasn't recognized as a "pad character" return immediately.
  if (expected != 0xCC && expected != 0x90) {
    // If the first byte does not have the correct value, we'll never be a padding block.  If
    // it does we'll either add the padding block, and be done, or it's actually correct for us
    // to revisit the issue later (hopefully in a forward direction).
    not_pad_gaps.insert(addr);
    return dblock;
  }

  // We only reach here scanning backwards, one byte at a time.
  int8_t direction = -1;

  // While there are more bytes of the same type, consume those as well.
  byte = expected;
  while (byte == expected) {
    // Advance (forwards or backwards) to the next byte.
    current += direction;
    // OINFO << "Advanced to address " << addr_str(current) << "." << LEND;
    try {
      byte = read_byte(current);
    }
    // Continue to try making a block if we read pas the end of the segment.
    catch (std::exception& e) {
      break;
    }
  }

  // We've read one byte past the last matching byte, so back up one byte.
  current -= direction;

  // Since we might be scanning backwards, determine which address is the start, and what the
  // number of bytes in the data block is.
  rose_addr_t start = std::min(addr, current);
  rose_addr_t end = std::max(addr, current);
  size_t num_bytes = end - start + 1;

  // When we're scanning in the forward direction, we presumably know that the previous block
  // did not flow into this block, because if it did we wouldn't be in a gap.  But if we're
  // scanning backwards we don't really know this, and so we must have at least two bytes,
  // because the the correct interpretation might be that a single byte was an actually
  // instruction.  Technically if there were multiple 0x90 NOPs, this could still be
  // incorrect. :-(
  if (backwards && num_bytes < 2) return dblock;

  // Create the data block, and attach it to the CFG.  We'll determine the correct function to
  // attach the block to in a final pass.
  dblock = P2::DataBlock::instanceBytes(start, num_bytes);
  partitioner->attachDataBlock(dblock);

  // NOTE: should really be marking this block as padding! The original Partitioner
  // would put a block reason on there of SgAsmBlock::BLK_PADDING but it looks like
  // Partitioner2 code doesn't do anything like this currently?  It has a generic
  // "Attributes" capability (key/val pairs) that looks like it'll be used for this
  // and other things, but it isn't used for anything currently?  And the P2
  // DataBlock structure does have a string "printableName()" method, but that just
  // is a manually generated answer every time you ask for it, can't set the name so
  // no hacky workaround potential there either.

  return dblock;
}

// Top and bottom allow the caller to enable and disable matching padding at the top and bottom
// of the gap respectively.  This probably isn't the most efficient approach, but it makes it
// easy to experiment with different approaches.
bool
CERTEngine::consume_padding(P2::PartitionerPtr const & partitioner, bool top, bool bottom) {
  // Have we changed anything?
  bool changed = false;

  // Find unused executable address intervals.  This may not be the most efficient way of doing
  // it, but we needed to generate unused once for each segment so that we didn't get gaps that
  // crossed segment boundaries.
  for (const MemoryMap::Node &node : partitioner->memoryMap()->nodes()) {
    auto seg = node.value();
    // Only consider executable segments.
    if ((seg.accessibility() & MemoryMap::EXECUTABLE) == 0) continue;
    // Get unused gaps _within_ this segment.
    AddressIntervalSet unused = partitioner->aum().unusedExtent(node.key());

    // For each unused interval.
    for (const AddressInterval &interval : unused.intervals()) {
      rose_addr_t least = interval.least();
      rose_addr_t greatest = interval.greatest();
      //OINFO << "Evaluating gap for padding blocks: " << addr_str(least) << " - " << addr_str(greatest) << LEND;

      // Look for padding at the start of the block going forward...
      if (top && !not_pad_gaps.exists(least)) {
        // Mark the end of this gap as having been analyzed, so we don't try again.
        P2::DataBlock::Ptr dblock = try_making_padding_block(partitioner, least);
        if (dblock) {
          changed = true;
          // If we consumed the entire gap, we should not check in the backwards direction.
          if (dblock->address() + dblock->size() >= greatest) {
            continue;
          }
        }
      }

      // Look for padding at the end of the block going backwards.  Strictly speaking the
      // not_pad_gaps test is a little bit incorrect because we're using the same address to
      // reflect both forward and backward searching.  That should be fine as long as we're only
      // doing one byte padding but if we started consuming NOP padding, we'd need two lists or a
      // more sophisticated approach.
      if (bottom && !not_pad_gaps.exists(greatest)) {
        // Mark the end of this gap as having been analyzed, so we don't try again.
        P2::DataBlock::Ptr dblock = try_making_padding_block(partitioner, greatest, true);
        if (dblock) changed = true;
      }
    }
  }

  return changed;
}

bool
CERTEngine::try_making_thunk(P2::PartitionerPtr const & partitioner, rose_addr_t address) {
  // If we've looked for thunks at this exact address once before, either we've already made
  // code or we've decided not to.  Nothing from subsequent analysis is going to change that
  // conclusion, so we're done.
  if (not_thunk_gaps.exists(address)) {
    return false;
  }

  // Mark this gap as having been analyzed already so that we don't try to analyze it again.
  not_thunk_gaps.insert(address);

  // Disassemble the instruction?
  SgAsmX86Instruction *insn = isSgAsmX86Instruction(partitioner->discoverInstruction(address));

  // If it's not a jump instruction, we're not interested.
  if (!insn || insn->get_kind() != x86_jmp) return false;

  P2::BasicBlock::Ptr bb = P2::BasicBlock::instance(address, partitioner);
  bb->append(partitioner, insn);

  bool complete;
  std::vector<rose_addr_t> successors = partitioner->basicBlockConcreteSuccessors(bb, &complete);
  if (successors.size() == 0) // to prevent a coredump...
    return false;
  rose_addr_t target = successors.front();

  // OINFO << "Thunk: " << addr_str(least) << LEND;
  unsigned reasons = SgAsmFunction::FUNC_THUNK | SgAsmFunction::FUNC_PATTERN;
  P2::Function::Ptr thunk_function = P2::Function::instance(address, reasons);
  partitioner->attachOrMergeFunction(thunk_function);

  // OINFO << "Remaking target function " << addr_str(target) << LEND;
  P2::Function::Ptr target_function = P2::Function::instance(target, SgAsmFunction::FUNC_GRAPH);
  partitioner->attachOrMergeFunction(target_function);

  return true;
}

// Top and bottom allow the caller to enable and disable matching thunks at the top and bottom
// of the gap respectively.  This probably isn't the most efficient approach, but it makes it
// easy to experiment with different approaches.
bool
CERTEngine::consume_thunks(P2::PartitionerPtr const & partitioner, bool top, bool bottom) {
  // Have we changed anything?
  bool changed = false;

  // Find unused executable address intervals.
  for (const MemoryMap::Node &node : partitioner->memoryMap()->nodes()) {
    auto seg = node.value();
    // Only consider executable segments.
    if ((seg.accessibility() & MemoryMap::EXECUTABLE) == 0) continue;
    // Get unused gaps _within_ this segment.
    AddressIntervalSet unused = partitioner->aum().unusedExtent(node.key());

    // For each unused interval.
    for (const AddressInterval &interval : unused.intervals()) {
      rose_addr_t least = interval.least();
      rose_addr_t greatest = interval.greatest();
      //OINFO << "Thunk Gap: " << addr_str(least) << " - " << addr_str(greatest) << LEND;

      if (top && try_making_thunk(partitioner, least)) changed = true;

      // Now check for a thunk at the end of the gap as well.  Here we've hard-coded an
      // instruction legth of 5, and that's horrible.
      if (greatest < 5) continue; // TODO: (mwd) Fix for 64-bit code
      rose_addr_t target = greatest - 4;
      if (target <= least) continue;

      if (bottom && try_making_thunk(partitioner, target)) changed = true;
    }
  }

  //if (changed) P2Engine::runPartitionerRecursive(partitioner);

  return changed;
}

SgAsmX86Instruction* non_overlapping_instruction(P2::PartitionerConstPtr const & partitioner, rose_addr_t addr) {
  // First check to see if there's an existing instruction.  If so return it.  This circumvents
  // the overlap check later which should include the starting address during checks for
  // overlapping data blocks, but exclude existing instructions.
  P2::AddressUser oau = partitioner->instructionExists(addr);
  if (oau.insn()) {
    SgAsmInstruction* insn = oau.insn();
    //OINFO << "NOI already exists at " << addr_str(addr) << " : " << debug_instruction(insn, 9) << LEND;
    return isSgAsmX86Instruction(insn);
  }

  // Find an existing instruction, or try creating one if it does not exist.
  SgAsmInstruction* insn = partitioner->discoverInstruction(addr);
  // If we couldn't create an instruction, then there's just no instruction here.
  if (!insn || insn->architecture()->isUnknown(insn)) {
    //OINFO << "Failed to create non-overlapping instruction at " << addr_str(addr) << LEND;
    return nullptr;
  }
  // It must also be an X86 instruction, because this whole module is X86 specific.
  SgAsmX86Instruction* xinsn = isSgAsmX86Instruction(insn);
  if (!xinsn) {
    //OINFO << "Failed to create X86 non-overlapping instruction at " << addr_str(addr) << LEND;
    return nullptr;
  }
  // Now check to see if this instruction overlaps with another.
  rose_addr_t end_addr = addr + insn->get_size() - 1;
  AddressInterval ii(AddressInterval::hull(addr, end_addr));
  bool overlap = partitioner->aum().anyExists(ii);
  if (overlap) {
    //OINFO << "  Rejecting instruction at " << addr_str(addr)
    //      << " because it overlaps with something else." << LEND;
    return nullptr;
  }
  // And if it does not, return it.
  return xinsn;
}

bool
CERTEngine::bad_code(P2::PartitionerConstPtr const & partitioner, const P2::BasicBlock::Ptr bb) const {
  if (!bb || bb->nInstructions() == 0) {
    // This condition doesn't represent "bad" code, just non-existent code.  For reasons that
    // are unclear, we're sometimes producing blocks with no instructions, and in this case, we
    // do _not_ want to make a data block, which is what happens in practice if we return true.
    return false;
  }

  SgAsmInstruction* lastinsn = bb->instructions()[bb->nInstructions() - 1];

  // True if we know all of the successors for the instruction.
  bool complete;
  // Get the list of successor addresses.
  auto successors = lastinsn->architecture()->getSuccessors(lastinsn, complete);

  for (rose_addr_t successor : successors.values()) {
    SgAsmX86Instruction* xinsn = non_overlapping_instruction(partitioner, successor);
    if (!xinsn) {
      //OINFO << "Bad code at " << addr_str(bb->address())
      //      << " because no instruction at successor " << addr_str(successor) << LEND;
      return true;
    }
  }

  //OINFO << "The code at " << addr_str(bb->address()) << " was valid." << LEND;
  return false;
}

class SpeculativeBasicBlock {
 private:
  P2::PartitionerPtr partitioner;
  rose_addr_t addr;
  rose_addr_t end;
 public:
  P2::BasicBlock::Ptr bb;
  rose_addr_t successor = 0;
  rose_addr_t fallthru = 0;
  bool already_existed = false;
  bool was_call = false;

  SpeculativeBasicBlock(P2::PartitionerPtr const & p, rose_addr_t a, rose_addr_t e) :
    partitioner(p), addr(a), end(e) {}

  // Analyze the block.  Return true if the block was valid, and code should be made.
  // Also fill in various member fields to control "higher level logic".
  bool analyze() {
    // If a block already exists return it.
    bb = partitioner->basicBlockExists(addr);
    if (bb) {
      //OINFO << "Basic block at " << addr_str(addr) << " already existed." << LEND;
      already_existed = true;
      return true;
    }

    // Otherwise create one, and we're going to add isntructions to it.
    bb = P2::BasicBlock::instance(addr, partitioner);

    rose_addr_t current = addr;
    while (current < end) {
      // This might be duplicative, but don't create blocks of zeros.
      RefuseZeroCode::Ptr zero_code_detector = RefuseZeroCode::instance();
      if (zero_code_detector->check_zeros(partitioner, current, bb)) {
        //OINFO << "Refused to make arbitrary code because of zeros at " << addr_str(current) << LEND;
        return false;
      }

      // If we've flowed into an existing instruction, that's valid.
      if (partitioner->instructionExists(current)) {
        //OINFO << "Found existing instruction at: " << addr_str(current) << LEND;
        successor = 0;
        return true;
      }

      // Disassemble the instruction?
      SgAsmX86Instruction *insn = non_overlapping_instruction(partitioner, current);
      //OINFO << "Made instruction at " << addr_str(current) << LEND;

      // If we couldn't create a valid, non overlapping instruction, that's fairly good
      // evidence that this entire gap is not really code.
      if (!insn) {
        //OINFO << "Unable to make a non overlapping instruction at " << addr_str(current) << LEND;
        return false;
      }

      // Stop making code at INT3 instructions.  This heuristic is because data occasionally
      // occurs after the function and before the padding, and if the "code" flows into the
      // padding, this will correctly signal that this block is data not code.
      if (insn->get_mnemonic() == "int3") {
        //OINFO << "Found int3 instruction found at " << addr_str(insn->get_address()) << LEND;
        SgAsmX86Instruction* ninsn = non_overlapping_instruction(partitioner, current+1);
        if (ninsn && ninsn->get_mnemonic() == "int3") {
          //OINFO << "Followed by another int3 instruction at " << addr_str(ninsn->get_address()) << LEND;
          return false;
        }
      }

      // It looks like this instruction is a valid one, so keep it.
      bb->append(partitioner, insn);

      // Compute the fallthru address for this function.
      // This is exposed to our caller so we know how many instructions we consumed.
      fallthru = insn->get_address() + insn->get_size();

      bool end_of_block = false;
      bool complete;
      SgAsmX86Instruction* xinsn = isSgAsmX86Instruction(insn);
      for (rose_addr_t s : partitioner->basicBlockConcreteSuccessors(bb, &complete)) {

        //OINFO << "Successor of " << addr_str(current) << " is " << addr_str(s) << LEND;
        // We're interested in any non-fallthru successors.
        if (s != fallthru) {
          // Any successor that's not the fallthru marks the end of the basic block.
          end_of_block = true;
          // Check if the successor is valid.

          // If the instruction is a call, the successor of interest is the fallthru (we're
          // assuming that the call returns).  The code that check the legitimacy of the
          // successor should really be invoked on call targets as well, but there's currently
          // a bug in ROSE where --use-semanics causes "call [import]" to incorrectly return a
          // bogus successor.  That in turn incorrectly suppresses the creation of this basic
          // block, so until that's fixed we're just going to assume that all call targets are
          // valid.
          if (insn_is_call(insn)) {
            //OINFO << "Successor of interest (call) is: " << addr_str(fallthru) << LEND;
            was_call = true;
            successor = fallthru;
          }
          // It turns out that the same problem occurs for jmp [import]...
          else if (xinsn && xinsn->get_kind() == x86_jmp) {
            successor = 0;
            fallthru = 0;
          }
          // If the instruction is not a call, then the successor is the successor of interest,
          // but the block is only valid if the the target is valid.
          else {
            SgAsmX86Instruction *sinsn = non_overlapping_instruction(partitioner, s);
            if (!sinsn) {
              //OINFO << "Unable to make a non overlapping successor at " << addr_str(current) << LEND;
              return false;
            }
            else {
              //OINFO << "Successor of interest is: " << addr_str(s) << LEND;
              successor = s;
            }
          }
        }
      }

      // If we're at the end of the block we're done.
      if (end_of_block) {
        //OINFO << "End of block at " << addr_str(current) << LEND;
        return true;
      }

      // An indeterminate successor also marks the end of the basic block, and is valid, but has
      // no successor of interest.
      if (!complete) {
        //OINFO << "Instruction at " << addr_str(current) << " has incomplete successors." << LEND;
        return true;
      }

      // If we're about flow into a known data block, we're not really an instruction.
      if (partitioner->aum().overlapping(fallthru).dataBlockUsers().size()) {
        //OINFO << "Instruction at " << addr_str(current) << " flows into a known data block "
        //      << "(and is therefore not really an instruction)." << LEND;
        return false;
      }

      // Go to the next instruction, we'll check whether it overlaps with anything at the start
      // of the loop.
      current = fallthru;
    }

    // If we reached the end exactly, then we're a valid basic block, and our successor of
    // interest is the current address (the one we fell through to from the last isntruction).
    //OINFO << "Reached the end of the gap while speculatively making code at: " << addr_str(current) << LEND;
    successor = current;
    return true;
  }

};

bool
CERTEngine::create_arbitrary_code(P2::PartitionerPtr const & partitioner) {
  // Have we changed anything?
  bool changed = false;
  bool ever_changed = false;

  // Find unused executable address intervals.
  AddressIntervalSet executableSpace;
  for (const MemoryMap::Node &node : partitioner->memoryMap()->nodes()) {
    if ((node.value().accessibility() & MemoryMap::EXECUTABLE) != 0)
      executableSpace.insert(node.key());
  }

  while (true) {
    AddressIntervalSet unused = partitioner->aum().unusedExtent(executableSpace);

    // For each unused interval.
    for (const AddressInterval &interval : unused.intervals()) {
      rose_addr_t least = interval.least();
      rose_addr_t greatest = interval.greatest();

      // If we've considered making code at this exact address once before, either we've already
      // made code or we've decided not to.  Nothing from subsequent analysis is going to change
      // that conclusion, so we're done.
      if (not_code_gaps.exists(least)) {
        GDEBUG << "Arbitrary code gap: " << addr_str(least) << " - " << addr_str(greatest)
               << " -- previously analyzed." << LEND;
        continue;
      }

      //OINFO << "Arbitrary code gap: " << addr_str(least) << " - " << addr_str(greatest) << LEND;

      // Mark this gap as having been analyzed already so that we don't try to analyze it again.
      not_code_gaps.insert(least);

      // We're going to look at each address.
      rose_addr_t current = least;

      // Check to see if there's a padding block next (there should be, but still can be?)
      P2::DataBlock::Ptr ipblock = try_making_padding_block(partitioner, least);
      if (ipblock) {
        //OINFO << "Made padding block in code gap at " << addr_str(least) << LEND;
        // Make our next block after the padding.
        current = ipblock->address() + ipblock->size();
        //OINFO << "Advancing to next address at " << addr_str(current) << LEND;
      }

      // For each address in the block (or until we don't have a fallthru edge)...
      while (current < greatest) {
        SpeculativeBasicBlock sbb(partitioner, current, greatest + 1);
        bool valid = sbb.analyze();

        // Check to make sure that the basic block meets other criteria for being valid code.
        if (valid) {
          valid = !bad_code(partitioner, sbb.bb);
        }

        // If it wasn't a valid block we're done with this gap.
        if (!valid) {
          //OINFO << "Block at " << addr_str(current) << " was not valid code." << LEND;

          P2::DataBlock::Ptr dblock = try_making_padding_block(partitioner, current);
          if (dblock) break;

          rose_addr_t end = current;
          while (true) {
            try {
              if (read_byte(end) == 0xCC) break;
              if (end == greatest) break;
              ++end;
            }
            catch (const Monitor::ResourceException &e) {
              // Make sure we keep propagating ResourceExceptions back up to the caller so we
              // can terminate.
              throw;
            }
            // ejs: Why is this here? What exceptions is it supposed to be catching?
            catch (std::exception& e) {
              break;
            }
          }
          size_t len = end - current + 1;

          P2::DataBlock::Ptr resized_dblock = P2::DataBlock::instanceBytes(current, len);
          partitioner->attachDataBlock(resized_dblock);
          //OINFO << "Data block at " << addr_str(dblock->address()) << " was "
          //      << dblock->size() << " bytes long." << LEND;
          break;
        }
        // If there was already a block at this address, we're done with this gap.
        if (sbb.already_existed) {
          //OINFO << "Block at " << addr_str(current) << " already existed." << LEND;
          break;
        }

        //OINFO << "Valid block starts at " << addr_str(current) << LEND;

        bool block_only = false;

        // Now try to decide which function to attach this block to.
        P2::Function::Ptr function;
        // If there's a function _entry_ point at the address in question, make this block into a
        // separate function because it follows the tail call optimization pattern.  But if the
        // successor merely belongs to a function, then assign this new block to that existing
        // function (a common pattern in execption handlers that jump to return blocks).
        //OINFO << "Checking for function at successor of interest: " << addr_str(sbb.successor) << LEND;
        if (sbb.successor) {
          P2::Function::Ptr entryfunc = partitioner->functionExists(sbb.successor);
          if (entryfunc) {
            //OINFO << "Address " << addr_str(sbb.successor)
            //      << " flows directly into  " << addr_str(entryfunc->address()) << LEND;
          }
          else {
            //OINFO << "Evaluating owners of successor of interest: " << addr_str(sbb.successor) << LEND;
            // Is there a basic block at our successor, if so attach that function.
            P2::BasicBlock::Ptr existing_bblock = partitioner->basicBlockExists(sbb.successor);
            if (existing_bblock) {
              //OINFO << "Basic block exists, checking for functions..." << LEND;
              for (P2::Function::Ptr f : partitioner->functionsOwningBasicBlock(existing_bblock)) {
                function = f;
                //OINFO << "Address " << addr_str(sbb.successor)
                //      << " is owned by " << addr_str(function->address()) << LEND;
              }
              // If we found a block but not a function, try something experimental!
              if (!function) block_only = true;
            }
            else {
              //OINFO << "Basic block at " << addr_str(sbb.successor) << " does not exist!" << LEND;
            }
          }
        }

        // Before making a code block, check to see if there's a data block.
        if (partitioner->aum().overlapping(current).dataBlockUsers().size()) {
          //OINFO << "There's already a data block at " << addr_str(current)
          //      << " so we're not going to make a code block." << LEND;
          break;
        }

        if (block_only) {
          // OINFO << "Attaching a bare basic block at " << addr_str(current) << LEND;
          P2::BasicBlock::Ptr new_block = partitioner->discoverBasicBlock(current);
          partitioner->attachBasicBlock(new_block);
        }
        else {
          // If we're not found a function to attach the block to already.
          if (!function) {
            //OINFO << "Checking for existing function at " << addr_str(current) << LEND;
            function = partitioner->functionExists(current);
            if (!function) {
              unsigned reasons = SgAsmFunction::FUNC_USERDEF;
              function = P2::Function::instance(current, reasons);
              partitioner->attachFunction(function);
              //size_t new_placeholders = partitioner->attachFunction(function);
              //OINFO << "Creating new function at " << addr_str(current) << " had "
              //      << new_placeholders << " new placeholders." << LEND;
            }
          }

          partitioner->detachFunction(function);
          partitioner->insertPlaceholder(current);
          function->insertBasicBlock(current);
          while (makeNextBasicBlock(partitioner)) /*void*/;
          partitioner->discoverFunctionBasicBlocks(function);
          partitioner->attachFunction(function);
        }

        // We need to rerun the the full partitioner, because we've changed things.
        changed = true;
        ever_changed = true;

        // If the last instruction of our block was a call, defer further work on this block
        // until the full partitioner has had a chance to follow more complex control flow.
        if (sbb.was_call) break;

        // Another way to signal that we're done with the gap is to not have a fallthru.
        if (sbb.fallthru == 0) break;

        // Make our next speculative block at the fallthru address.
        current = sbb.fallthru;
        //OINFO << "Making next block at " << addr_str(current) << LEND;

        // Check to see if there's a padding block next.
        P2::DataBlock::Ptr dblock = try_making_padding_block(partitioner, current);
        if (dblock) {
          //OINFO << "Code detected padding block at " << addr_str(current) << LEND;
          // Make our next block after the padding.
          current = dblock->address() + dblock->size();
          //OINFO << "Instead, making next block at " << addr_str(current) << LEND;
        }
      }

      //OINFO << "Reached end of gap: " << addr_str(least) << " - " << addr_str(greatest) << LEND;
    }

    if (!changed) break;
    changed = false;
  }

  // Having pointed the partitioner at a bunch of gaps, less invoke it again, and have it make
  // code at all of the locations simultaneously.  This is suboptimal since they might
  // contradict each other, but invoking the paritioner after each gap was far too slow when
  // there were lots of gaps.  Additionally, we (still) have the problem that the gap code
  // might flow into the middle of existing basic blocks causing large changes than we intend.
  if (ever_changed) {
    GDEBUG << "Starting arbitrary code run of partitioner..." << LEND;
    P2Engine::runPartitionerRecursive(partitioner);
    GDEBUG << "Finished arbitrary code run of partitioner..." << LEND;
  }

  return ever_changed;
}

void
CERTEngine::runPartitioner(P2::PartitionerPtr const &partitioner) {
  // Permit overlapping code during ROSE's initial, non-speculative discovery pass.
  overlapping_code_detector->set_refusing(false);
  P2Engine::runPartitioner(partitioner);

  // For each padding block, assign the data block to the function that preceeds it.  The
  // functions will exist now, because this is literally the last code we run during
  // partitioning.

  // The stock ROSE partitioner normally attaches padding to the function after the block, but
  // this is annoying because that results in the wrong answer for jump tables and other
  // unidentified data which usually follows the function that it is associated with in most
  // compilers.
  const P2::AddressUsageMap& aum = partitioner->aum();

  // The address users
  auto users = aum.overlapping(aum.hull()).addressUsers();
  for (const P2::AddressUser& au : users) {
    if (!au.isDataBlock()) continue;
    const P2::DataBlock::Ptr db = au.dataBlock();
    if (!db) continue;

    rose_addr_t addr = db->address();
    //OINFO << "Found a data block address user at " << addr_str(addr) << LEND;

    // The address of the byte before the padding.
    rose_addr_t pre_addr = addr - 1;

    const AddressInterval ai(pre_addr);
    for (const P2::Function::Ptr & func : partitioner->functionsOverlapping(ai)) {
      // Attach the data block to the function.
      partitioner->attachDataBlockToFunction(
        P2::DataBlock::instanceBytes(addr, db->size()), func);
      //OINFO << "Attaching data block at " << addr_str(addr) << " to function "
      //      << addr_str(func->address()) << LEND;
    }
  }

  //OINFO << "Custom partitioner 2 final pass complete." << LEND;
}

void
CERTEngine::runPartitionerFinal(P2::PartitionerPtr const & partitioner) {
  // These discovery passes used to live in our runPartitionerRecursive override. Recent
  // ROSE versions run initial discovery through a private, non-virtual overload instead,
  // silently bypassing that override. Use the still-virtual finalization hook so our passes
  // run after initial discovery and before ROSE's final cleanup on both old and new ROSE.
  // This hook does not automatically restart recursive discovery: create_arbitrary_code()
  // explicitly reruns it when it adds code, and we run it once more below before merging
  // GOT preambles and calling the base runPartitionerFinal(). This preserves the previous
  // ordering of discovery, preamble merging, and cleanup.

  GDEBUG << "Making functions for Prologue phase!" << LEND;

  // Create functions at the places suggested by our jump to prologue matcher.
  jump_to_prologue_matcher->make_functions(partitioner);

  // From this point on, our behavior is too speculative to permit overlapping code.
  overlapping_code_detector->set_refusing(true);

  report_partitioner_statistics(partitioner);

  // Disable these...
  partitioner->functionPrologueMatchers().clear();

  GDEBUG << "Starting FIRST iteration!" << LEND;

  // Pass two. Once all of that is complete, we want to do our own custom passes.  This logic
  // should really be worklist driven because the current implementation of looking at every
  // gap for every type of action is pretty inefficient.
  bool changed = true;
  while (changed) {
    changed = false;
    changed |= consume_thunks(partitioner, true, false);
    changed |= consume_padding(partitioner, true, true);

    // We only want to "make arbitary code" when the safer options are exhausted.
    if (!changed) {
      changed |= create_arbitrary_code(partitioner);
    }

    // Our prologue matcher is still installed, so we might have found more prologues.
    jump_to_prologue_matcher->make_functions(partitioner);

    GDEBUG << "" << LEND;
  }

  // Now add the prologue matchers back, and analyze one more time.
  // It unclear whether this helped much, but it's difficult for me to believe that it hurts.
  partitioner->functionPrologueMatchers().push_back(P2::ModulesX86::MatchHotPatchPrologue::instance());
  partitioner->functionPrologueMatchers().push_back(P2::ModulesX86::MatchStandardPrologue::instance());
  partitioner->functionPrologueMatchers().push_back(P2::ModulesX86::MatchAbbreviatedPrologue::instance());
  partitioner->functionPrologueMatchers().push_back(P2::ModulesX86::MatchEnterPrologue::instance());

  // Disabled for the same reason as in createTunedPartitioner().
  //partitioner->functionPrologueMatchers().push_back(
  //  P2::Modules::MatchThunk::instance(functionMatcherThunks()));

  P2Engine::runPartitionerRecursive(partitioner);

  // Merge entry-marker and GOT preambles when we are finally done.  Do not run the prologue
  // matchers again after these passes or they will recreate the body functions we remove.
  merge_endbr_preambles(partitioner);
  merge_got_preambles(partitioner);

  GDEBUG << "Custom partitioner 2 recursive pass complete." << LEND;

  P2Engine::runPartitionerFinal(partitioner);
}

// ROSE decodes ENDBR32/ENDBR64 as a NOP.  In stripped binaries its standard prologue matcher
// can consequently create a speculative function at the following PUSH/MOV while references
// to the function still point at the ENDBR four bytes earlier.  Coalesce that prologue-only
// body back into the real CET entry point.  A body with any independent discovery reason is a
// legitimate alternate entry and must remain separate.
void
CERTEngine::merge_endbr_preambles(P2::PartitionerPtr const & partitioner) {
  struct Merge {
    rose_addr_t entry;
    P2::Function::Ptr body;
    P2::Function::Ptr canonical;
  };

  std::vector<Merge> merges;
  for (const P2::Function::Ptr & body : partitioner->functions()) {
    rose_addr_t body_addr = body->address();
    if (body_addr < 4 || !body->name().empty()) continue;

    // Only a function created by speculative instruction-pattern/graph discovery is safe to
    // fold.  FUNC_GRAPH can be added when the overlapping entries converge on the same body.
    // In particular, preserve symbols, exports, exception metadata, imports, thunk targets,
    // and user-defined entries.  Direct calls and jumps are checked explicitly below.
    unsigned reasons = body->reasons();
    const unsigned speculative_reasons =
      SgAsmFunction::FUNC_PATTERN | SgAsmFunction::FUNC_GRAPH;
    if ((reasons & SgAsmFunction::FUNC_PATTERN) == 0 ||
        (reasons & ~speculative_reasons) != 0) {
      continue;
    }

    rose_addr_t entry_addr = body_addr - 4;
    SgAsmX86Instruction* marker =
      isSgAsmX86Instruction(partitioner->discoverInstruction(entry_addr));
    if (!insn_is_endbr(marker) || marker->get_address() + marker->get_size() != body_addr) {
      continue;
    }

    // Function reasons alone are insufficient here: ROSE can retain FUNC_PATTERN as the only
    // reason even when a direct edge also targets the matched prologue.  The only incoming CFG
    // edge that is compatible with a split ENDBR preamble is the marker's own fall-through.
    // A call, jump, or any other predecessor makes B an independently addressable entry.
    P2::ControlFlowGraph::ConstVertexIterator vertex = partitioner->findPlaceholder(body_addr);
    if (vertex == partitioner->cfg().vertices().end()) continue;

    bool independently_referenced = false;
    for (const P2::ControlFlowGraph::Edge & edge : vertex->inEdges()) {
      const P2::ControlFlowGraph::Vertex & source = *edge.source();
      if (source.value().type() != P2::V_BASIC_BLOCK) {
        independently_referenced = true;
        break;
      }
      P2::BasicBlock::Ptr source_block = source.value().bblock();
      if (!source_block || source_block->instructions().empty()) {
        independently_referenced = true;
        break;
      }

      // ROSE can label this fall-through as E_FUNCTION_XFER solely because its current
      // function ownership is split.  Identify the permissible edge by its instruction,
      // not by that derived edge label.
      SgAsmX86Instruction* predecessor =
        isSgAsmX86Instruction(source_block->instructions().back());
      if (!predecessor || predecessor->get_address() != entry_addr ||
          !insn_is_endbr(predecessor) || insn_get_fallthru(predecessor) != body_addr) {
        independently_referenced = true;
        break;
      }
    }
    if (independently_referenced) continue;

    P2::Function::Ptr canonical = partitioner->functionExists(entry_addr);
    merges.push_back({entry_addr, body, canonical});
  }

  for (const Merge & merge : merges) {
    // An earlier merge can change function ownership.  Confirm that this body is still the
    // attached function selected above before mutating the partitioner.
    if (partitioner->functionExists(merge.body->address()) != merge.body) continue;

    GINFO << "Merging ENDBR entry at " << addr_str(merge.entry)
          << " with speculative body at " << addr_str(merge.body->address()) << LEND;

    partitioner->detachFunction(merge.body);

    P2::Function::Ptr canonical = merge.canonical;
    if (canonical) {
      if (partitioner->functionExists(canonical->address()) == canonical) {
        partitioner->detachFunction(canonical);
      }
      canonical->insertReasons(merge.body->reasons());
    }
    else {
      canonical = P2::Function::instance(merge.entry, merge.body->reasons());
    }

    // A vtable-only function can have no incoming CFG edge.  Detaching its two overlapping
    // function objects may therefore remove the entry placeholder along with the last owner.
    // discoverFunctionBasicBlocks() requires that placeholder to exist.
    partitioner->insertPlaceholder(merge.entry);
    partitioner->discoverFunctionBasicBlocks(canonical);
    partitioner->attachFunction(canonical);
  }
}

// In 32-bit PIC ELF code GCC emits a GOT preamble (call <pic_thunk>; add REG, IMM) at the
// start of every function.  ROSE's prologue matcher sees the push/mov after the ADD and
// creates a spurious function boundary there, splitting the preamble from the body.  Detect
// these splits and merge the body back into the preamble's function.
void
CERTEngine::merge_got_preambles(P2::PartitionerPtr const & partitioner) {
  // Collect merges first to avoid mutating while iterating.
  std::vector<std::pair<P2::Function::Ptr, P2::Function::Ptr>> merges; // (preamble, body)
  for (const P2::Function::Ptr & func : partitioner->functions()) {
    auto body_addr = get_got_preamble_body(partitioner, func);
    if (!body_addr) continue;
    P2::Function::Ptr body_func = partitioner->functionExists(*body_addr);
    if (!body_func) continue;
    merges.emplace_back(func, body_func);
  }

  for (auto & pair : merges) {
    GINFO << "Merging GOT preamble at " << addr_str(pair.first->address())
          << " with body at " << addr_str(pair.second->address()) << LEND;

    // Detach both so we can re-discover blocks for the combined function.
    partitioner->detachFunction(pair.second);
    partitioner->detachFunction(pair.first);
    partitioner->discoverFunctionBasicBlocks(pair.first);
    partitioner->attachFunction(pair.first);
  }
}

#if 0
bool
MatchInterFunctionGap::match(P2::PartitionerConstPtr const &partitioner, rose_addr_t anchor) {
  // If there's an instruction at this address, there's not need to create another.
  if (partitioner->instructionExists(anchor)) {
    OINFO << "MatchInterFunctionGap(" << addr_str(anchor) << ") -- insn exists" << LEND;
    return false;
  }

  // If anyone is already using this address for anything, we don't want to use it.
  if (!(partitioner->aum().overlapping(anchor).isEmpty())) {
    OINFO << "MatchInterFunctionGap(" << addr_str(anchor) << ") -- already in use" << LEND;
    return false;
  }

  // If nobody is using the previous byte for anything, then we're not "adjacent" to existing
  // code, and we don't want to
  if (partitioner->aum().overlapping(anchor - 1).isEmpty()) {
    //OINFO << "MatchInterFunctionGap(" << addr_str(anchor) << ") -- not adjacent" << LEND;
    return false;
  }

  // Disassemble the instruction?
  SgAsmX86Instruction *insn = isSgAsmX86Instruction(partitioner->discoverInstruction(anchor));

  if (!insn) {
    OINFO << "MatchInterFunctionGap(" << addr_str(anchor) << ") -- no valid instruction" << LEND;
    return false;
  }

  if (insn->get_kind() == x86_add) {
    OINFO << "MatchInterFunctionGap(" << addr_str(anchor) << ") -- rejected (add/zeros): "
          << debug_instruction(insn) << LEND;
    return false;
  }
  if (insn->get_kind() == x86_int3) {
    OINFO << "MatchInterFunctionGap(" << addr_str(anchor) << ") -- rejected (int3): "
          << debug_instruction(insn) << LEND;
    return false;
  }

  if (insn->get_kind() != x86_jmp)
    function_ = P2::Function::instance(anchor, SgAsmFunction::FUNC_THUNK | SgAsmFunction::FUNC_PATTERN);
  else
    function_ = P2::Function::instance(anchor, SgAsmFunction::FUNC_PATTERN);

  OINFO << "MatchInterFunctionGap(" << addr_str(anchor) << ") -- made code from: "
        << debug_instruction(insn) << LEND;

  return true;
}
#endif

// This section of code provided multiple experimental approaces to ensure that thunks (jumps
// to the entry point of a function) are NOT coalesced into the function's first basic block,
// since this alters the entry point of the function, which is likely to be inconvenient when
// later more advanced analysis find references to the true entry point of the function.


// This approach attempts to use the standard prologue matching facility to make code from any
// jump instruction found in the program image.
bool
MatchThunkPrologue::match(const P2::PartitionerConstPtr &partitioner, rose_addr_t anchor) {
  // If the instruction already exists, there's no need to create another?
  if (partitioner->instructionExists(anchor))
    return false;

  // Disassemble the instruction?
  SgAsmX86Instruction *insn = isSgAsmX86Instruction(partitioner->discoverInstruction(anchor));

  // If it's not a jump instruction, we're not interested.
  if (!insn || insn->get_kind() != x86_jmp)
    return false;

  // We should add some additional criteria to further reduce false positives.

  // We found a jmp instruction! Make a function out of it!
  GDEBUG << "Making thunk function from: " << debug_instruction(insn) << LEND;
  function_ = P2::Function::instance(
    anchor, SgAsmFunction::FUNC_THUNK | SgAsmFunction::FUNC_PATTERN);
  return true;
}

bool
RefuseZeroCode::check_zeros(P2::PartitionerConstPtr const & partitioner,
                            rose_addr_t address, const P2::BasicBlock::Ptr& bblock) {
  SgAsmInstruction *insn = partitioner->discoverInstruction(address);
  // Quick fail if we're a normal instruction.
  if (!check_zero_insn(insn)) return false;

  // A more general approach to finding an arbitrary number of zero instructions.
  rose_addr_t current = address + 2;
  size_t found = 1;
  while (check_zero_insn(insn) && found < threshold) {
    current += 2;
    insn = partitioner->discoverInstruction(current);
    found++;
  }

  // If we've failed on address alone, we're done.
  if (found >= threshold) return true;

  // If not, we need to look at the accumulated instructions in the basic block.
  for (auto binsn : bblock->instructions()) {
    if (check_zero_insn(binsn)) found++;
  }

  // If we've failed on address alone, we're done.
  if (found >= threshold) return true;

  // Otherwise, we're not at the threshold yet.
  return false;
}

bool
check_zero_insn(SgAsmInstruction *insn) {
  // If we're given a bad instruction, return false.
  if (!insn) return false;
  // If the size isn't two bytes, return false.
  if (insn->get_size() != 2) return false;
  // If the bytes aren't all zero, return false.
  for (auto byte : insn->get_rawBytes()) {
    if (byte != 0) return false;
  }
  // We're a zero instruction!
  return true;
}

bool
RefuseZeroCode::operator()(bool chain, const Args &args) {
  if (chain) {
    size_t last = args.bblock->instructions().size();
    if (last < 1)
      return chain;
    SgAsmX86Instruction* insn = isSgAsmX86Instruction(args.bblock->instructions()[last-1]);
    if (insn == NULL)
      return chain;
    if (check_zeros(args.partitioner, insn->get_address(), args.bblock)) {
      GDEBUG << "Refused to make code from zeros at: " << addr_str(insn->get_address()) << LEND;
      args.results.terminate = TERMINATE_PRIOR;
    }
  }
  return chain;
}

bool
RefuseOverlappingCode::operator()(bool chain, const Args &args) {
  if (chain) {
    // If we're not really enabled, we're done.
    if (!refusing)
      return chain;
    size_t last = args.bblock->instructions().size();
    if (last < 1)
      return chain;
    SgAsmX86Instruction* insn = isSgAsmX86Instruction(args.bblock->instructions()[last-1]);
    if (insn == NULL)
      return chain;

    // Would this approach be better here?
    // if (!(partitioner->aum().overlapping(anchor).isEmpty())) {
    for (size_t o = 1; o < insn->get_size(); o++) {
      rose_addr_t addr = insn->get_address() + o;
      if (args.partitioner->instructionExists(addr)) {
        GDEBUG << "Instruction at " << addr_str(addr) << " already exists, no overlapping code!" << LEND;
        args.results.terminate = TERMINATE_PRIOR;
      }
      break;
    }
  }
  return chain;
}

bool
MatchJmpToPrologue::operator()(bool chain, const Args &args) {
  if (chain) {
    // We're only interested in unconditional jump instructions.
    size_t last = args.bblock->instructions().size();
    if (last < 1)
      return chain;
    SgAsmX86Instruction* insn = isSgAsmX86Instruction(args.bblock->instructions()[last-1]);
    if (insn == NULL)
      return chain;
    if (insn->get_kind() != x86_jmp)
      return chain;

    //OINFO << "MatchJmpToPrologue found jump instruction: " << debug_instruction(insn) << LEND;

    bool found_prologues = false;

    // If we've found one, lets look at the successor(s?).
    bool complete;
    std::vector<rose_addr_t> successors = args.partitioner->basicBlockConcreteSuccessors(args.bblock, &complete);
    for (rose_addr_t s : successors) {
      // The case that we're really interested in is the one where the function doesn't exist.
      // We want to look to see if it matches a prologue and if it does, then mark it as such.
      // We couldn't use the standard prologue matchers because they insisted on looking only
      // at _new_ bytes, and we're interested in whether the potentially existing bytes match a
      // prologue.
      rose_addr_t current = s;
      //OINFO << "MatchJmpToPrologue successor: " << addr_str(current) << LEND;

      // If there's a "mov edi, edi", that's ok, but not required.
      SgAsmX86Instruction *pinsn = isSgAsmX86Instruction(args.partitioner->discoverInstruction(current));
      if (P2::ModulesX86::matchMovDiDi(args.partitioner, pinsn)) {
        //OINFO << "MatchJmpToPrologue found 'mov edi, edi' at: " << addr_str(pinsn->get_address()) << LEND;
        current = pinsn->get_address() + pinsn->get_size();
        pinsn = isSgAsmX86Instruction(args.partitioner->discoverInstruction(current));
      }

      // We must have a "push ebp" instruction.
      if (!P2::ModulesX86::matchPushBp(args.partitioner, pinsn)) {
        continue;
      }

      //OINFO << "MatchJmpToPrologue found 'push ebp' at: " << addr_str(pinsn->get_address()) << LEND;
      current = pinsn->get_address() + pinsn->get_size();
      pinsn = isSgAsmX86Instruction(args.partitioner->discoverInstruction(current));
      // We must have a "mov esp, ebp" instruction.
      if (!P2::ModulesX86::matchMovBpSp(args.partitioner, pinsn))
        continue;

      //OINFO << "MatchJmpToPrologue match at: " << addr_str(s) << LEND;
      found_prologues = true;
      prologues.insert(s);
    }

    // Curiously, we can't actually return TERMINATE_NOW without breaking our code.  Cory has
    // no idea why really...
    if (found_prologues) {
      // Turns out that we _can't_ do this for some reason?
      // args.results.terminate = TERMINATE_NOW;
      // Are we supposed to return false to ensure that our result is used?
      // return false;
    }
  }
  return chain;
}

void
MatchJmpToPrologue::make_functions(P2::PartitionerPtr const &partitioner) {
  for (rose_addr_t addr : prologues) {
    //OINFO << "MatchJmpToPrologue function created at: " << addr_str(addr) << LEND;
    P2::Function::Ptr function = P2::Function::instance(addr, SgAsmFunction::FUNC_PATTERN);
    partitioner->attachOrMergeFunction(function);
  }
  prologues.clear();
}

#if 0
// This custom BasicBlockCallback is derived from PreventDiscontiguousBlocks (?), except that
// it has been modified to experiment with BasicBlockCall backs.
bool
ThunkDetacher::operator()(bool chain, const Args &args) {
  if (chain) {

    // This callback is invoked for each instruction added to the basic block, so our first
    // objective is to ignore all cases where we're not the first instruction in a new basic
    // block.
    size_t ninsns = args.bblock->nInstructions();
    // Thunks are always one instruction!
    if (ninsns != 1)
      return chain;

    // Also, we're only interested in jump instructions.
    SgAsmX86Instruction* insn = isSgAsmX86Instruction(args.bblock->instructions()[0]);
    if (insn == NULL)
      return chain;
    if (insn->get_kind() != x86_jmp)
      return chain;

    OINFO << "ThunkDetacher found jump instruction: " << debug_instruction(insn) << LEND;

    // I'm not sure what we were doing here.   Perhaps just copying code from Robb?
    bool complete;
    std::vector<rose_addr_t> successors = args.partitioner.basicBlockConcreteSuccessors(args.bblock, &complete);

    OINFO << "ThunkDetacher at " << args.bblock->printableName()
          << " has " << Rose::StringUtility::plural(args.bblock->instructions().size(),
                                                    "instructions")
          << " and " << Rose::StringUtility::plural(successors.size(), "successors") << LEND;

    if (complete && 1==successors.size()) {
      P2::ControlFlowGraph::ConstVertexIterator vertex =
        args.partitioner.findPlaceholder(args.bblock->address());

      for (const P2::ControlFlowGraph::Edge& edge : vertex->inEdges()) {
        const P2::ControlFlowGraph::Vertex &source = *edge.source();
        P2::BasicBlock::Ptr sblock = source.value().bblock();
        //OINFO << "Predecessor block is " << sblock->printableName() << LEND;

        // Get the number of instructions in the predecessor basic block.
        size_t pninsns = sblock->nInstructions();

        if (pninsns > 0) {
          SgAsmX86Instruction* pred_insn = isSgAsmX86Instruction(sblock->instructions()[pninsns-1]);
          //OINFO << "Previous instruction is: " << debug_instruction(pred_insn) << LEND;
          rose_addr_t fall_thru = insn_get_fallthru(pred_insn);
          if (fall_thru == args.bblock->address()) {
            //OINFO << "Block " << args.bblock->printableName() << " is not really a thunk!" << LEND;
            return chain;
          }
        }
      }

      // This is a thunk.  Terminate the existing basic block now (at the jmp).  This might
      // also detach some unconditional jumps that are not thunks (e.g. the target of the jump
      // is not really the start of a function).  For right now I don't really care, but if
      // this turns out to be a problem we can use some other heuristics.  But we can't rely on
      // there being other in edges, or the default Partitioner2 will already do the right
      // thing.
      //OINFO <<" thunk detected\n";
      args.results.terminate = TERMINATE_NOW;

      // We also want to make sure that the target address will become a function. We can't
      // modify the partitioner while we're inside the callback, so save them up for later.  We
      // save the addresses, but we could have also created the Function objects (just not
      // attach them to the partitioner).
      jmpVas.insert(insn->get_address());
      targetVas.insert(successors[0]);
    }
  }

  return chain;
}

void
ThunkDetacher::makeFunctions(P2::PartitionerPtr const &partitioner) {
  // Make each JMP a function.  This could be a little dangerous: if we split off a JMP even
  // though it wasn't a thunk, we would end up making it a function of its own even though it
  // isn't really.  Perhaps this is where we should add the additional heuristics.
  for (rose_addr_t va : jmpVas) {
    P2::Function::Ptr function = P2::Function::instance(va, SgAsmFunction::FUNC_THUNK);
    partitioner->attachOrMergeFunction(function);
  }

  // Make each JMP target a function.
  for (rose_addr_t va : targetVas) {
    P2::Function::Ptr function = P2::Function::instance(va);
    partitioner->attachOrMergeFunction(function);
  }
}
#endif

P2::PartitionerPtr
CERTEngine::createTunedPartitioner() {

  //OINFO << "Creating custom partitioner!" << LEND;
  auto partitioner = P2Engine::createTunedPartitioner();

  // Non-returning functions (including the unwinder, which transfers control to an exception
  // handler rather than returning) are configured from the "nonreturn" tags in
  // create_partitioner(), so that every engine gets them.

  // We're building out own list of Prolog matchers because MatchRetPadPush does things that we
  // did not find helpful (like skipping "mov edi,edi" instructions as padding).
  partitioner->functionPrologueMatchers().clear();
  partitioner->functionPrologueMatchers().push_back(P2::ModulesX86::MatchHotPatchPrologue::instance());
  partitioner->functionPrologueMatchers().push_back(P2::ModulesX86::MatchStandardPrologue::instance());
  partitioner->functionPrologueMatchers().push_back(P2::ModulesX86::MatchAbbreviatedPrologue::instance());
  partitioner->functionPrologueMatchers().push_back(P2::ModulesX86::MatchEnterPrologue::instance());

  // We're explicitly disabling the function Prologue thunk matchers here.  In our opinion
  // "matching" on thunks by scanning the program image space is counter productive, and that
  // logic should only be used to "split" thunks from otehr functions.
  //partitioner->functionPrologueMatchers().push_back(
  //  P2::Modules::MatchThunk::instance(functionMatcherThunks()));

  // See comment above about MatchRetPadPush...
  //partitioner->functionPrologueMatchers().push_back(ModulesX86::MatchRetPadPush::instance());

  // Add another thunk splitting predicate.
  const P2::ThunkPredicates::Ptr thunk_splitters = functionSplittingThunks();
  P2::ThunkPredicates::Ptr new_thunk_splitters = P2::ThunkPredicates::instance();
  for (auto pred : thunk_splitters->predicates()) {
    new_thunk_splitters->predicates().push_back(pred);
  }
  new_thunk_splitters->predicates().push_back(isX86MovAddJmpThunk);
  new_thunk_splitters->predicates().push_back(isX86ItaniumAdjustingThunk);
  new_thunk_splitters->predicates().push_back(isX86Sysv32AdjustingThunk);
  new_thunk_splitters->predicates().push_back(isX86MsvcAdjustingThunk);
  functionSplittingThunks(new_thunk_splitters);

  // Register a basic block callback that will track jumps to prologues.
  jump_to_prologue_matcher = MatchJmpToPrologue::instance();
  partitioner->basicBlockCallbacks().append(jump_to_prologue_matcher);
  partitioner->basicBlockCallbacks().append(RefuseZeroCode::instance());
  overlapping_code_detector = RefuseOverlappingCode::instance();
  partitioner->basicBlockCallbacks().append(overlapping_code_detector);

  return partitioner;
}

// ==========================================================================================

// For the Superset engine, the partioning algorithm is very simple.
void
SupersetEngine::runPartitioner(P2::PartitionerPtr const &partitioner) {
  OINFO << "Running the superset partitioning algorithm." << LEND;

  Rose::BinaryAnalysis::InstructionProvider& ip = partitioner->instructionProvider();

  auto mmap = partitioner->memoryMap();

  // The minimum and maximum addresses that we visited.
  rose_addr_t least = 0;  //
  rose_addr_t greatest = 0;

  // The memory map is IntervalMap, which maps Intervals to Buffers.  Each Interval and Buffer
  // represents a contiguous, identically protected region of program memory.  The Interval
  // itself is also iterable, and contains the addresses of the region.
  for (Sawyer::Container::Interval<rose_addr_t> interval : mmap->intervals()) {

    rose_addr_t l = interval.least();
    rose_addr_t g = interval.greatest();
    GINFO << "Disassembling segment " << addr_str(l) << " - " << addr_str(g) << LEND;
    if (l < least || least == 0) least = l;
    if (g > greatest) greatest = g;

    for (rose_addr_t addr : interval) {
      // Too verbose to be of much use.
      //GDEBUG << "Disassembling " << addr_str(addr) << LEND;

      // Disassemble the instruction, and store it in the instruction provider cache.
      SgAsmInstruction* insn = ip[addr];

      // If there's no instruction at that address, move on to the next one.
      if (!insn || insn->architecture()->isUnknown(insn)) continue;

      OINFO << boost::str(boost::format("%-60s") % debug_instruction(insn, 12)); // No LEND!

      // Get the successor from the instruction.  This code can't be here permanently, because
      // we need to create each instruction vertex in the graph before creating the edges, but
      // it's a start.
      bool complete;
      auto successors = insn->architecture()->getSuccessors(insn, complete);
      if (successors.size() > 0) {
        for (rose_addr_t saddr : successors.values()) {
          OINFO << addr_str(saddr) << " ";
        }
        OINFO << LEND;
      }
      else {
        OINFO << "None" << LEND;
      }
    }
  }

  GINFO << "Disassembled addresses " << addr_str(least) << " - " << addr_str(greatest) << LEND;
}

// ==========================================================================================

Monitor::Monitor()
{
  // Set the partitioner limits.
  get_global_limits().set_limits(partitioner_limit, PharosLimits::limit_type::PARTITIONER);
}

bool
Monitor::operator()(bool chain, const AttachedBasicBlock& /* args */) {
  // Calling this on every basic block attachement is probably wasteful.
  // The overhead appears to negligible based on testing hoever.
  partitioner_limit.increment_counter();
  LimitCode rstatus = partitioner_limit.check();
  if (rstatus != LimitSuccess) {
    std::stringstream ss;
    ss << "Partitioner " << partitioner_limit.get_message() << " exceeded: "
       << partitioner_limit.get_absolute_usage()
       << ", adjust with --maximum-memory";

    // This is an old comment:
    // Rather ungraceful exit here. :-(  I'm not sure how else to stop the partitioner.

    // ejs: I'm not sure what the above comment means.  Why not throw an exception?  We need to
    // throw an exception here so we can catch it and remove the .serialize file we may have
    // opened.
    throw ResourceException(ss.str());
  }
  //if (args.bblock)
  //  OINFO << "Attached basic block " << addr_str(args.bblock->address()) << LEND;
  return chain;
}

bool
Monitor::operator()(bool chain, const DetachedBasicBlock& /* args */) {
  //if (args.bblock)
  //  OINFO << "Detached basic block " << addr_str(args.bblock->address()) << LEND;
  return chain;
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
