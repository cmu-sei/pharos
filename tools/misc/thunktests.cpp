// Copyright 2026 Carnegie Mellon University.  See LICENSE file for terms.
//
// Semantic tests for adjusting thunk recognition, run against tests/itanium_thunks.exe and
// tests/x86_thunks.exe.  The partitioner golden output for those specimens only proves which
// function owns which basic block; these tests assert the property that actually drives the
// object oriented analysis, namely that FunctionDescriptor::is_thunk() is true and reports the
// right target and this-pointer adjustment.
//
// Two specimens are needed because the calling conventions differ by word size: AMD64 passes
// the object pointer in a register, i386 on the stack.  The case tables are chosen from the
// specimen's architecture rather than its filename.

#include <libpharos/descriptors.hpp>
#include <libpharos/funcs.hpp>
#include <libpharos/misc.hpp>
#include <libpharos/options.hpp>

#include <gtest/gtest.h>

using namespace pharos;

const DescriptorSet* global_ds = nullptr;

namespace {

using VirtualKind = ThunkAdjustment::VirtualKind;

struct ThunkCase {
  const char* name;
  rose_addr_t entry;
  rose_addr_t target;
  int64_t fixed_delta;
  // Whether the thunk folds in a run-time displacement, where it reads it from, and the
  // displacement of the slot.
  bool is_virtual;
  VirtualKind kind;
  int64_t virtual_slot;
};

// The AMD64 specimen, tests/itanium_thunks.exe.
const ThunkCase amd64_thunk_cases[] = {
  {"thunk_fixed_add",      0x401109, 0x401185,   8, false, VirtualKind::vcall_offset,   0},
  {"thunk_fixed_sub",      0x40110f, 0x40118b,  -8, false, VirtualKind::vcall_offset,   0},
  {"thunk_fixed_lea",      0x401115, 0x401191,  16, false, VirtualKind::vcall_offset,   0},
  {"thunk_virtual",        0x40111b, 0x401197,   0, true,  VirtualKind::vcall_offset, -24},
  {"thunk_combined",       0x401124, 0x40119d, -16, true,  VirtualKind::vcall_offset, -32},
  {"thunk_cet",            0x401131, 0x4011a3,   0, true,  VirtualKind::vcall_offset, -40},
  {"thunk_sret_fixed",     0x40113e, 0x4011a9,   8, false, VirtualKind::vcall_offset,   0},
  {"thunk_sret_virtual",   0x401144, 0x4011af,   0, true,  VirtualKind::vcall_offset, -24},
  {"thunk_sret_combined",  0x40114d, 0x4011b5, -16, true,  VirtualKind::vcall_offset, -32},
};

// Near misses that must remain ordinary functions, plus main() for good measure.
const ThunkCase amd64_non_thunk_cases[] = {
  {"not_thunk_wrong_this",       0x40115a, 0, 0, false, VirtualKind::vcall_offset, 0},
  {"not_thunk_mixed_this",       0x401163, 0, 0, false, VirtualKind::vcall_offset, 0},
  {"not_thunk_wrong_scratch",    0x401170, 0, 0, false, VirtualKind::vcall_offset, 0},
  {"not_thunk_zero_adjustment",  0x401179, 0, 0, false, VirtualKind::vcall_offset, 0},
  {"not_thunk_indirect_jump",    0x40117f, 0, 0, false, VirtualKind::vcall_offset, 0},
  // The MOV overwrites the this pointer, so the ADD does not adjust the one we were called
  // with.  This is std::locale::c_str()'s shape; treating it as a thunk cost us that method's
  // member at offset zero and its class.  See detect_adjusting_thunk().
  {"not_thunk_mov_add_jmp",      0x4011d3, 0, 0, false, VirtualKind::vcall_offset, 0},
  {"main",                       0x401106, 0, 0, false, VirtualKind::vcall_offset, 0},
};

// The 32-bit specimen, tests/x86_thunks.exe.  It covers the MSVC __thiscall forms, which
// adjust ECX in place, and the SysV i386 forms, which rewrite the incoming stack slot.
// The specimen is position independent, so these are the symbol offsets plus the
// --base-address the test is invoked with.
const ThunkCase x86_thunk_cases[] = {
  {"msvc_fixed_sub",       0x401003, 0x401082,  -8, false, VirtualKind::vcall_offset,   0},
  {"msvc_fixed_add",       0x401008, 0x401088,  16, false, VirtualKind::vcall_offset,   0},
  {"msvc_fixed_lea",       0x40100d, 0x40108e,  24, false, VirtualKind::vcall_offset,   0},
  {"msvc_vtordisp",        0x401012, 0x401094,   0, true,  VirtualKind::vtordisp,      -4},
  {"msvc_vtordisp_fixed",  0x401017, 0x40109a, -12, true,  VirtualKind::vtordisp,      -4},
  {"sysv_fixed",           0x40101f, 0x4010a0,  -8, false, VirtualKind::vcall_offset,   0},
  {"sysv_fixed_sret",      0x401026, 0x4010a6, -28, false, VirtualKind::vcall_offset,   0},
  {"sysv_virtual",         0x40102d, 0x4010ac,   0, true,  VirtualKind::vcall_offset, -16},
  {"sysv_virtual_sret",    0x40103c, 0x4010b2,   0, true,  VirtualKind::vcall_offset, -28},
  {"sysv_combined",        0x40104b, 0x4010b8, -16, true,  VirtualKind::vcall_offset, -32},
};

const ThunkCase x86_non_thunk_cases[] = {
  {"not_thunk_mov_add_jmp",         0x40105d, 0, 0, false, VirtualKind::vcall_offset, 0},
  {"not_thunk_byte_register",       0x401064, 0, 0, false, VirtualKind::vcall_offset, 0},
  {"not_thunk_slot_mismatch",       0x401069, 0, 0, false, VirtualKind::vcall_offset, 0},
  {"not_thunk_vtordisp_wrong_base", 0x401078, 0, 0, false, VirtualKind::vcall_offset, 0},
  {"not_thunk_zero_adjustment",     0x40107d, 0, 0, false, VirtualKind::vcall_offset, 0},
  {"main",                          0x401000, 0, 0, false, VirtualKind::vcall_offset, 0},
};

// Which tables apply is decided by the specimen's architecture rather than its filename, since
// the two specimens exist precisely to cover the 64-bit and 32-bit calling conventions.
std::vector<ThunkCase> thunk_cases;
std::vector<ThunkCase> non_thunk_cases;

template<size_t N>
void select(std::vector<ThunkCase>& dst, const ThunkCase (&src)[N]) {
  dst.assign(std::begin(src), std::end(src));
}

} // namespace

TEST(ItaniumThunks, AdjustingThunksAreThunks) {
  for (const ThunkCase& tc : thunk_cases) {
    SCOPED_TRACE(tc.name);
    const FunctionDescriptor* fd = global_ds->get_func(tc.entry);
    ASSERT_NE(fd, nullptr);

    EXPECT_TRUE(fd->is_thunk());
    EXPECT_EQ(fd->get_jmp_addr(), tc.target);

    auto adjustment = fd->get_thunk_adjustment();
    ASSERT_TRUE(bool(adjustment));
    EXPECT_EQ(adjustment->fixed_delta, tc.fixed_delta);
    EXPECT_EQ(bool(adjustment->virtual_adjustment), tc.is_virtual);
    if (adjustment->virtual_adjustment && tc.is_virtual) {
      EXPECT_EQ(adjustment->virtual_adjustment->slot, tc.virtual_slot);
      EXPECT_EQ(adjustment->virtual_adjustment->kind == VirtualKind::vtordisp,
                tc.kind == VirtualKind::vtordisp);
    }
  }
}

// The thunk target must be a function in its own right, and must know that it is thunked to.
// This is what update_connections() establishes, and what dethunk() ultimately depends on.
TEST(ItaniumThunks, TargetsAreConnected) {
  for (const ThunkCase& tc : thunk_cases) {
    SCOPED_TRACE(tc.name);
    const FunctionDescriptor* target = global_ds->get_func(tc.target);
    ASSERT_NE(target, nullptr);
    EXPECT_FALSE(target->is_thunk());
    EXPECT_TRUE(target->is_thunk_target());

    const FunctionDescriptor* fd = global_ds->get_func(tc.entry);
    ASSERT_NE(fd, nullptr);
    EXPECT_EQ(fd->follow_thunks(), tc.target);
  }
}

TEST(ItaniumThunks, NearMissesAreNotThunks) {
  for (const ThunkCase& tc : non_thunk_cases) {
    SCOPED_TRACE(tc.name);
    const FunctionDescriptor* fd = global_ds->get_func(tc.entry);
    ASSERT_NE(fd, nullptr);

    EXPECT_FALSE(fd->is_thunk());
    EXPECT_EQ(fd->get_jmp_addr(), rose_addr_t(0));
    EXPECT_FALSE(fd->is_adjusting_thunk());
  }
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);

  set_glog_name("THNK");
  ProgOptVarMap vm = parse_cert_options(argc, argv, cert_standard_options());

  // Thunk detection is complete once the descriptor set has been built; no further analysis is
  // required to answer is_thunk().
  DescriptorSet ds(vm);
  global_ds = &ds;

  if (ds.get_arch_bits() == 64) {
    select(thunk_cases, amd64_thunk_cases);
    select(non_thunk_cases, amd64_non_thunk_cases);
  }
  else {
    select(thunk_cases, x86_thunk_cases);
    select(non_thunk_cases, x86_non_thunk_cases);
  }

  int rc = RUN_ALL_TESTS();
  global_rops.reset();
  return rc;
}
