// Copyright 2015-2026 Carnegie Mellon University.  See LICENSE file for terms.
//
// Small hand-written ELF specimen for the Itanium ABI thunk-splitting regression test.
// Regenerate it from the repository root with:
//   as --64 tests/src/itanium_thunks.s -o /tmp/pharos-itanium-thunks.o
//   cc -no-pie -Wl,--build-id=none -o tests/itanium_thunks.exe /tmp/pharos-itanium-thunks.o

.intel_syntax noprefix
.file "itanium_thunks.s"
.section .text

.global main
.type main, @function
main:
  xor eax, eax
  ret
.size main, .-main

.global thunk_fixed_add
.type thunk_fixed_add, @function
thunk_fixed_add:
  add rdi, 8
  jmp target_fixed_add
.size thunk_fixed_add, .-thunk_fixed_add

.global thunk_fixed_sub
.type thunk_fixed_sub, @function
thunk_fixed_sub:
  sub rdi, 8
  jmp target_fixed_sub
.size thunk_fixed_sub, .-thunk_fixed_sub

.global thunk_fixed_lea
.type thunk_fixed_lea, @function
thunk_fixed_lea:
  lea rdi, [rdi + 16]
  jmp target_fixed_lea
.size thunk_fixed_lea, .-thunk_fixed_lea

.global thunk_virtual
.type thunk_virtual, @function
thunk_virtual:
  mov r10, [rdi]
  add rdi, [r10 - 24]
  jmp target_virtual
.size thunk_virtual, .-thunk_virtual

.global thunk_combined
.type thunk_combined, @function
thunk_combined:
  sub rdi, 16
  mov r11, [rdi]
  add rdi, [r11 - 32]
  jmp target_combined
.size thunk_combined, .-thunk_combined

.global thunk_cet
.type thunk_cet, @function
thunk_cet:
  .byte 0xf3, 0x0f, 0x1e, 0xfa
  mov rax, [rdi]
  add rdi, [rax - 40]
  jmp target_cet
.size thunk_cet, .-thunk_cet

.global thunk_sret_fixed
.type thunk_sret_fixed, @function
thunk_sret_fixed:
  add rsi, 8
  jmp target_sret_fixed
.size thunk_sret_fixed, .-thunk_sret_fixed

.global thunk_sret_virtual
.type thunk_sret_virtual, @function
thunk_sret_virtual:
  mov r10, [rsi]
  add rsi, [r10 - 24]
  jmp target_sret_virtual
.size thunk_sret_virtual, .-thunk_sret_virtual

.global thunk_sret_combined
.type thunk_sret_combined, @function
thunk_sret_combined:
  sub rsi, 16
  mov r11, [rsi]
  add rsi, [r11 - 32]
  jmp target_sret_combined
.size thunk_sret_combined, .-thunk_sret_combined

// Near misses.  These remain ordinary functions and retain ownership of their targets.

.global not_thunk_wrong_this
.type not_thunk_wrong_this, @function
not_thunk_wrong_this:
  mov r10, [rdx]
  add rdx, [r10 - 24]
  jmp target_wrong_this
.size not_thunk_wrong_this, .-not_thunk_wrong_this

.global not_thunk_mixed_this
.type not_thunk_mixed_this, @function
not_thunk_mixed_this:
  sub rdi, 16
  mov r10, [rsi]
  add rsi, [r10 - 24]
  jmp target_mixed_this
.size not_thunk_mixed_this, .-not_thunk_mixed_this

.global not_thunk_wrong_scratch
.type not_thunk_wrong_scratch, @function
not_thunk_wrong_scratch:
  mov r10, [rdi]
  add rdi, [r11 - 24]
  jmp target_wrong_scratch
.size not_thunk_wrong_scratch, .-not_thunk_wrong_scratch

.global not_thunk_zero_adjustment
.type not_thunk_zero_adjustment, @function
not_thunk_zero_adjustment:
  add rdi, 0
  jmp target_zero_adjustment
.size not_thunk_zero_adjustment, .-not_thunk_zero_adjustment

.global not_thunk_indirect_jump
.type not_thunk_indirect_jump, @function
not_thunk_indirect_jump:
  add rdi, 8
  jmp rax
.size not_thunk_indirect_jump, .-not_thunk_indirect_jump

target_fixed_add:
  mov eax, 1
  ret

target_fixed_sub:
  mov eax, 2
  ret

target_fixed_lea:
  mov eax, 3
  ret

target_virtual:
  mov eax, 4
  ret

target_combined:
  mov eax, 5
  ret

target_cet:
  mov eax, 6
  ret

target_sret_fixed:
  mov eax, 7
  ret

target_sret_virtual:
  mov eax, 8
  ret

target_sret_combined:
  mov eax, 9
  ret

target_wrong_this:
  mov eax, 10
  ret

target_mixed_this:
  mov eax, 11
  ret

target_wrong_scratch:
  mov eax, 12
  ret

target_zero_adjustment:
  mov eax, 13
  ret

// A one-line forwarding method, not an adjustor.  The MOV overwrites the this pointer, so the
// ADD does not adjust the pointer we were called with: the callee operates on a different
// object reached through a member.  This is the shape of std::locale::c_str(), which is
// "mov ecx, [ecx]; add ecx, 0x18; jmp std::_Yarn<char>::c_str()" at 0x401720 in
// ooex_vs2010/Lite/ooex7, rendered here in the specimen's 64-bit register width.  Promoting it
// to a thunk discards the method's own this pointer and its member at offset zero.
.global not_thunk_mov_add_jmp
.type not_thunk_mov_add_jmp, @function
not_thunk_mov_add_jmp:
  mov rcx, [rcx]
  add rcx, 24
  jmp target_mov_add_jmp
.size not_thunk_mov_add_jmp, .-not_thunk_mov_add_jmp

target_mov_add_jmp:
  mov eax, 14
  ret
