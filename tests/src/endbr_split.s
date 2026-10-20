// Copyright 2015-2026 Carnegie Mellon University.  See LICENSE file for terms.
//
// Small stripped ELF specimen for the ENDBR/prologue splitting regression test.
// Regenerate it from the repository root with:
//   as --64 tests/src/endbr_split.s -o /tmp/pharos-endbr-split.o
//   cc -no-pie -Wl,--build-id=none -o tests/endbr_split.exe /tmp/pharos-endbr-split.o
//   strip --strip-all tests/endbr_split.exe

.intel_syntax noprefix
.file "endbr_split.s"
.section .text

.global main
.type main, @function
main:
  call endbr_split_candidate
  call endbr_independent_body
  xor eax, eax
  ret
.size main, .-main

.p2align 4
.type endbr_split_candidate, @function
endbr_split_candidate:
  .byte 0xf3, 0x0f, 0x1e, 0xfa
  push rbp
  mov rbp, rsp
  xor eax, eax
  pop rbp
  ret
.size endbr_split_candidate, .-endbr_split_candidate

.p2align 4
.type endbr_preserved_marker, @function
endbr_preserved_marker:
  .byte 0xf3, 0x0f, 0x1e, 0xfa
.size endbr_preserved_marker, .-endbr_preserved_marker

// The direct call above gives this prologue an independent discovery reason.  It is therefore
// a legitimate entry and must not be folded backward over endbr_preserved_marker.
.type endbr_independent_body, @function
endbr_independent_body:
  push rbp
  mov rbp, rsp
  mov eax, 1
  pop rbp
  ret
.size endbr_independent_body, .-endbr_independent_body
