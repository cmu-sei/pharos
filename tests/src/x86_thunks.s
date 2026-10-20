// Copyright 2015-2026 Carnegie Mellon University.  See LICENSE file for terms.
//
// Small hand-written 32-bit ELF specimen for the adjustor thunk regression tests.  It covers
// the two 32-bit ABIs together, because the detector keys off instruction shape rather than
// file format: the MSVC forms adjust ECX in place, and the SysV i386 forms rewrite the stack
// slot holding the incoming object pointer.
//
// Regenerate it from the repository root with:
//   as --32 tests/src/x86_thunks.s -o /tmp/pharos-x86-thunks.o
//   cc -m32 -shared -nostdlib -Wl,--build-id=none \
//      -o tests/x86_thunks.exe /tmp/pharos-x86-thunks.o
//
// It links without the C runtime, because a 32-bit libc is often absent on a 64-bit build host
// and nothing here is ever executed.  It links as a shared object rather than an executable
// because ROSE's ELF loader requires a dynamic symbol table, which a -nostdlib executable does
// not have.  That makes it position independent, so the test passes --base-address and the
// addresses asserted in thunktests.cpp are the symbol offsets plus that base.

.intel_syntax noprefix
.file "x86_thunks.s"
.section .text

.global main
.type main, @function
main:
  xor eax, eax
  ret
.size main, .-main

// ---------------------------------------------------------------------------------------
// MSVC __thiscall adjustors.  ECX carries the object pointer and is adjusted in place.
// ---------------------------------------------------------------------------------------

.global msvc_fixed_sub
.type msvc_fixed_sub, @function
msvc_fixed_sub:
  sub ecx, 8
  jmp target_msvc_fixed_sub
.size msvc_fixed_sub, .-msvc_fixed_sub

.global msvc_fixed_add
.type msvc_fixed_add, @function
msvc_fixed_add:
  add ecx, 16
  jmp target_msvc_fixed_add
.size msvc_fixed_add, .-msvc_fixed_add

.global msvc_fixed_lea
.type msvc_fixed_lea, @function
msvc_fixed_lea:
  lea ecx, [ecx + 24]
  jmp target_msvc_fixed_lea
.size msvc_fixed_lea, .-msvc_fixed_lea

// The vtordisp field sits just below the subobject, and the displacement it holds is
// subtracted rather than added.
.global msvc_vtordisp
.type msvc_vtordisp, @function
msvc_vtordisp:
  sub ecx, DWORD PTR [ecx - 4]
  jmp target_msvc_vtordisp
.size msvc_vtordisp, .-msvc_vtordisp

.global msvc_vtordisp_fixed
.type msvc_vtordisp_fixed, @function
msvc_vtordisp_fixed:
  sub ecx, DWORD PTR [ecx - 4]
  sub ecx, 12
  jmp target_msvc_vtordisp_fixed
.size msvc_vtordisp_fixed, .-msvc_vtordisp_fixed

// ---------------------------------------------------------------------------------------
// SysV i386 adjustors.  The object pointer is a stack argument, at [esp+4] normally and at
// [esp+8] when [esp+4] holds the hidden address for an indirectly returned object.
// ---------------------------------------------------------------------------------------

.global sysv_fixed
.type sysv_fixed, @function
sysv_fixed:
  sub DWORD PTR [esp + 4], 8
  jmp target_sysv_fixed
.size sysv_fixed, .-sysv_fixed

.global sysv_fixed_sret
.type sysv_fixed_sret, @function
sysv_fixed_sret:
  sub DWORD PTR [esp + 8], 28
  jmp target_sysv_fixed_sret
.size sysv_fixed_sret, .-sysv_fixed_sret

.global sysv_virtual
.type sysv_virtual, @function
sysv_virtual:
  mov eax, DWORD PTR [esp + 4]
  mov ecx, DWORD PTR [eax]
  add eax, DWORD PTR [ecx - 16]
  mov DWORD PTR [esp + 4], eax
  jmp target_sysv_virtual
.size sysv_virtual, .-sysv_virtual

.global sysv_virtual_sret
.type sysv_virtual_sret, @function
sysv_virtual_sret:
  mov eax, DWORD PTR [esp + 8]
  mov ecx, DWORD PTR [eax]
  add eax, DWORD PTR [ecx - 28]
  mov DWORD PTR [esp + 8], eax
  jmp target_sysv_virtual_sret
.size sysv_virtual_sret, .-sysv_virtual_sret

.global sysv_combined
.type sysv_combined, @function
sysv_combined:
  mov eax, DWORD PTR [esp + 4]
  add eax, -16
  mov ecx, DWORD PTR [eax]
  add eax, DWORD PTR [ecx - 32]
  mov DWORD PTR [esp + 4], eax
  jmp target_sysv_combined
.size sysv_combined, .-sysv_combined

// ---------------------------------------------------------------------------------------
// Near misses that must remain ordinary functions.
// ---------------------------------------------------------------------------------------

// The shape of std::locale::c_str(): the MOV overwrites the object pointer, so the ADD does
// not adjust the one we were called with.  This is the real 32-bit encoding of the sequence
// at 0x401720 in ooex_vs2010/Lite/ooex7.
.global not_thunk_mov_add_jmp
.type not_thunk_mov_add_jmp, @function
not_thunk_mov_add_jmp:
  mov ecx, DWORD PTR [ecx]
  add ecx, 24
  jmp target_not_thunk_mov_add_jmp
.size not_thunk_mov_add_jmp, .-not_thunk_mov_add_jmp

// A byte-sized subregister of ECX is not the object pointer.  Matching on the register's
// minor number alone would wrongly admit this.
.global not_thunk_byte_register
.type not_thunk_byte_register, @function
not_thunk_byte_register:
  sub cl, 8
  jmp target_not_thunk_byte_register
.size not_thunk_byte_register, .-not_thunk_byte_register

// Reading one stack slot and writing back to a different one does not adjust anything.
.global not_thunk_slot_mismatch
.type not_thunk_slot_mismatch, @function
not_thunk_slot_mismatch:
  mov eax, DWORD PTR [esp + 4]
  mov ecx, DWORD PTR [eax]
  add eax, DWORD PTR [ecx - 16]
  mov DWORD PTR [esp + 8], eax
  jmp target_not_thunk_slot_mismatch
.size not_thunk_slot_mismatch, .-not_thunk_slot_mismatch

// The vtordisp displacement must be read relative to the object pointer being adjusted.
.global not_thunk_vtordisp_wrong_base
.type not_thunk_vtordisp_wrong_base, @function
not_thunk_vtordisp_wrong_base:
  sub ecx, DWORD PTR [edx - 4]
  jmp target_not_thunk_vtordisp_wrong_base
.size not_thunk_vtordisp_wrong_base, .-not_thunk_vtordisp_wrong_base

// A zero constant adjusts nothing, so this is an ordinary thunk rather than an adjustor.
.global not_thunk_zero_adjustment
.type not_thunk_zero_adjustment, @function
not_thunk_zero_adjustment:
  sub ecx, 0
  jmp target_not_thunk_zero_adjustment
.size not_thunk_zero_adjustment, .-not_thunk_zero_adjustment

// ---------------------------------------------------------------------------------------
// Jump targets.
// ---------------------------------------------------------------------------------------

target_msvc_fixed_sub:
  mov eax, 1
  ret

target_msvc_fixed_add:
  mov eax, 2
  ret

target_msvc_fixed_lea:
  mov eax, 3
  ret

target_msvc_vtordisp:
  mov eax, 4
  ret

target_msvc_vtordisp_fixed:
  mov eax, 5
  ret

target_sysv_fixed:
  mov eax, 6
  ret

target_sysv_fixed_sret:
  mov eax, 7
  ret

target_sysv_virtual:
  mov eax, 8
  ret

target_sysv_virtual_sret:
  mov eax, 9
  ret

target_sysv_combined:
  mov eax, 10
  ret

target_not_thunk_mov_add_jmp:
  mov eax, 11
  ret

target_not_thunk_byte_register:
  mov eax, 12
  ret

target_not_thunk_slot_mismatch:
  mov eax, 13
  ret

target_not_thunk_vtordisp_wrong_base:
  mov eax, 14
  ret

target_not_thunk_zero_adjustment:
  mov eax, 15
  ret
