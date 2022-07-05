// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

// For timing our execution.
#include <time.h>
#include <unistd.h>

#include "rose.hpp"
#include <Rose/BinaryAnalysis/BinaryLoader.h>
#include <integerOps.h>

#include <Sawyer/ProgressBar.h>

#include "misc.hpp"
#include "options.hpp"
#include "partitioner.hpp"
#include "util.hpp"
#include "matcher.hpp"
#include "semantics.hpp"
#include "descriptors.hpp"
#include "masm.hpp"

#include <boost/algorithm/string.hpp> // for starts_with
#include <boost/optional/optional_io.hpp>
#include <boost/format.hpp>
#include <chrono>

#ifdef __GNUC__
// for non-portable backtrace code
#include <cxxabi.h>
extern "C" {
#include <execinfo.h>
}
#endif // __GNUC__

namespace pharos {

using Rose::BinaryAnalysis::BinaryLoader;

using Rose::BinaryAnalysis::SymbolicExpr::OP_ADD;
using Rose::BinaryAnalysis::SymbolicExpr::OP_ITE;

Sawyer::Message::Facility glog;

void set_glog_name(std::string const & name)
{
  glog.initialize(name);
}

TreeNodePtr operator+(const TreeNodePtr & a, int64_t b)
{
  constexpr auto bbits = sizeof(b) * CHAR_BIT;
  if (a) {
    auto bv = Sawyer::Container::BitVector(a->nBits());
    bv.fromInteger(uint64_t(b));
    if (a->nBits() > bbits) {
      bv.signExtend(bv.hull(),
                    Sawyer::Container::BitVector::BitRange::baseSize(0, bbits));
    }
    auto c = SymbolicExpr::makeIntegerConstant(bv);
    return InternalNode::instance(OP_ADD, a, c, Rose::BinaryAnalysis::SmtSolverPtr());
  }
  return SymbolicExpr::makeIntegerConstant(bbits, b);
}

// Here's a helper function for cleaning up the mess that is stack delta constants.  Because we
// chose to initialize ESP to zero rather than a variable, it's hard to tell what's a stack
// delta and what's a constant address.  The purpose of putting this code here is much like the
// functions above for architecture.  It gives us some specific text to search for to find
// places where we're obviously touching this bit of brokenness.  See also get_stack_const() in
// semantics.hpp.
bool filter_stack(rose_addr_t target_addr) {
  if (target_addr > 0x0000FFFF && target_addr < 0x80000000) return true;
  return false;
}

// Convert an SgUnsignedCharList into a hex C++ string.
std::string MyHex(const SgUnsignedCharList& data) {
  char buffer[8];
  std::string result = "";

  size_t n = data.size();
  for (size_t i = 0; i < n; i++) {
    sprintf(buffer, "%02X", data[i]);
    result += buffer;
  }
  return result;
}



// Cory is trying to enforce some consistency in how we print addresses so that we can control
// the format by changing only one (or at least just a few) places in the code.  There's no
// implicit claim that boost::format("0x%08X") is the "correct" answer, just that there should
// be some consistency, and that the whole std::hex / std::dec thing sucks...
std::string addr_str(rose_addr_t target_addr) {
  return boost::str(boost::format("0x%08X") % target_addr);
}

// Get the message levels from Sawyer::Message::Common.
using namespace Sawyer::Message::Common;

using AddrVector = std::vector<rose_addr_t>;

void customize_message_facility(Sawyer::Message::Facility facility, std::string name)
{
  facility.renameStreams(name);
  facility.initStreams(get_logging_destination());
}

// This should be a method on SgAsmX86Instruction and possibly on SgAsmInstruction as well.
bool insn_is_call(const SgAsmX86Instruction* insn) {
  if (insn == NULL) return false;
  else if (insn->get_kind() == x86_call) return true;
  else if (insn->get_kind() == x86_farcall) return true;
  else return false;
}

// Unconditional jumps (near and far).
bool insn_is_jmp(const SgAsmX86Instruction* insn) {
  if (insn == NULL) return false;
  else if (insn->get_kind() == x86_jmp) return true;
  else if (insn->get_kind() == x86_farjmp) return true;
  else return false;
}

// For detecting call and call-like unconditional jumps.
bool insn_is_call_or_jmp(const SgAsmX86Instruction* insn) {
  if (insn == NULL) return false;
  else if (insn->get_kind() == x86_call) return true;
  else if (insn->get_kind() == x86_farcall) return true;
  else if (insn->get_kind() == x86_jmp) return true;
  else if (insn->get_kind() == x86_farjmp) return true;
  else return false;
}

// I think we meant insn_is_call() in all of these cases...
bool insn_is_callNF(const SgAsmX86Instruction* insn) {
  if (insn == NULL) return false;
  else if (insn->get_kind() == x86_call) return true;
  else return false;
}

// This should be a method on SgAsmX86Instruction and possibly on SgAsmInstruction as well.
bool insn_is_jcc(const SgAsmX86Instruction* insn) {
  if (insn == NULL) return false;
  else if (insn->get_kind() >= x86_ja && insn->get_kind() <= x86_js) return true;
  else return false;
}

// This should be a method on SgAsmX86Instruction and possibly on SgAsmInstruction as well.
bool insn_is_branch(const SgAsmX86Instruction* insn) {
  // BUG? No far calls here?
  if (insn_is_callNF(insn)) return true;
  if (insn_is_jcc(insn)) return true;
  else return false;
}

// This should be a method on SgAsmX86Instruction and possibly on SgAsmInstruction as well.
bool insn_is_control_flow(const SgAsmInstruction* insn) {
  if (!insn) return false;

  // A bad start on some more multi-architecture support?
  const SgAsmX86Instruction *xinsn = isSgAsmX86Instruction(insn);
  if (!xinsn) return false;

  // Really support X86.
  if (xinsn->get_kind() == x86_ret) return true;
  if (xinsn->get_kind() == x86_call) return true;
  if (xinsn->get_kind() == x86_jmp) return true;
  if (xinsn->get_kind() == x86_farcall) return true;
  if (xinsn->get_kind() >= x86_ja && xinsn->get_kind() <= x86_js) return true;
  return false;
}

// Does this instruction have a valid repeat prefix (including repeating semantics)?
bool insn_is_repeat(const SgAsmX86Instruction* insn) {
  // Return false if given an invalid instruction pointer.
  if (!insn) return false;
  // Return true if it's one of the valid instruction that actually use the prefix.
  if (insn->get_kind() >= x86_rep_insb && insn->get_kind() <= x86_repne_scasw) return true;
  // Return false if the instruction does not have a repeat prefix, if it's part of the normal
  // (non-repeating) instruction encoding.  Finally, also return false if the instruction has a
  // repeat prefix but the instruction does not actually use it the instruction semantics.
  return false;
}

bool insn_is_nop(const SgAsmX86Instruction* insn) {
  // The function is a response to poor performance and accuracy problems in
  // SageInterface::isNOP().  We should really attempt to create an exhaustive list and handle
  // this issue comprehensively including prefix bytes and other odditities.  The immediate
  // goal was to produce correct answers for some important cases like "lea ecx, [ecx+0]", and
  // eliminate the performance problem in isNOP().

  const SgUnsignedCharList& bytes = insn->get_raw_bytes();
  size_t size = bytes.size();
  if (size < 1) return false;

  //   44 lea       ebx, [ebx+0]          ; BYTES  8D9B00000000
  //  143 lea       ecx, [ecx+0]          ; BYTES  8D4900
  //   24 lea       esp, [esp+0]          ; BYTES  8D642400
  //   45 lea       esp, [esp+0]          ; BYTES  8DA42400000000
  // 3086 mov       edi, edi              ; BYTES  8BFF
  //    2 nop                             ; BYTES  90

  // Perhaps there's a fancy C++11 way to do this efficicently.  In the mean time, this will
  // get the job done without having to think about it too hard, and it will be very efficient
  // as well.  Whether it will continute to scale well for maintenance is a unclear, but there
  // is a good chance that we'll continue to need "code" to prevent the list from growing very
  // large.  Until we know more, I deem this a reasonable approach.
  switch (bytes.at(0)) {
    // mov reg, reg 8BFF
   case 0x8b:
    if (size < 2) return false;
    switch (bytes.at(1)) {
     case 0xff: return true;
    }
    return false;
    // lea ...
   case 0x8d:
    if (size < 2) return false;
    switch (bytes.at(1)) {
      // one byte displacements?
     case 0x49:
      if (size < 3) return false;
      switch (bytes.at(2)) {
       case 0x00: return true;
      }
      return false;
      // two byte displacements?
     case 0x64:
      if (size < 3) return false;
      switch (bytes.at(2)) {
       case 0x24:
        if (size < 4) return false;
        switch (bytes.at(3)) {
         case 0x00: return true;
        }
        return false;
      }
      return false;
      // four byte displacements?
     case 0xA4:
      if (size < 3) return false;
      switch (bytes.at(2)) {
       case 0x24:
        if (size < 4) return false;
        switch (bytes.at(3)) {
         case 0x00:
          if (size < 5) return false;
          switch (bytes.at(4)) {
           case 0x00:
            if (size < 6) return false;
            switch (bytes.at(5)) {
             case 0x00:
              if (size < 7) return false;
              switch (bytes.at(6)) {
               case 0x00: return true;
              }
              return false;
            }
            return false;
          }
          return false;
        }
        return false;
      }
      return false;
      // four byte displacements?
     case 0x9B:
      if (size < 3) return false;
      switch (bytes.at(2)) {
       case 0x00:
        if (size < 4) return false;
        switch (bytes.at(3)) {
         case 0x00:
          if (size < 5) return false;
          switch (bytes.at(4)) {
           case 0x00:
            if (size < 6) return false;
            switch (bytes.at(5)) {
             case 0x00: return true;
            }
            return false;
          }
          return false;
        }
        return false;
      }
      return false;
    }
    return false;
    // xchg eax, eax
   case 0x90:
    return true;
  }
  return false;
}

// Get the fallthru address.  This should be one of the successors for every intruction except
// a return.  I don't know if this is the most correct way to do it, and it's possible that
// there should be some assertions for cases like RET, but it's close enough.
rose_addr_t insn_get_fallthru(SgAsmInstruction* insn) {
  return insn->get_address() + insn->get_raw_bytes().size();
}

// This is the counterpart to insn_get_fallthru(), except that here the intention is to return
// the one address that is NOT the fallthru address.  For call instructions that call to
// registers, this could be mutiple targets, but in the case of jumps, there should always be
// one or two non-fallthru successors.  There should probably be more assertions in this code.
// Not used now that I've created bb_get_successors()?
boost::optional<rose_addr_t> insn_get_branch_target(SgAsmInstruction* insn) {
  bool complete;
  rose_addr_t fallthru = insn_get_fallthru(insn);
  auto successors = insn->getSuccessors(complete);
  SgAsmX86Instruction *xinsn = isSgAsmX86Instruction(insn);
  bool isjmp = (isSgAsmX86Instruction(insn) != NULL && insn_is_jmp(xinsn));
  for (rose_addr_t target : successors.values()) {
    //GDEBUG << "INSN successor: " << addr_str(target) << LEND;
    if (isjmp || target != fallthru) return target;
  }
  return boost::none;
}

std::string insn_get_generic_category(SgAsmInstruction *insn) {
  std::string result = "UNCAT"; // if we haven't singled something out yet...
  // this code horribly x86 specific for now, but later needs to be able to handle ARM, etc.
  // The categories themselves are of course generic, and hopefully comprehensive enough but
  // can be expanded later.
  if (!isSgAsmX86Instruction(insn)) return result;

  // okay, I think a lot of these comparisons for x86 can be simplified by using the first
  // couple of chars in the mnemonic much of the time, so let's start there:
  std::string mnemonic = insn->get_mnemonic(); // this comes back lowercase, but may want to
                                               // force that at some point...

  // should I remove the "rep" prefix?  I think remove it from mnemonic, then add REP prefix to
  // the category?
  bool got_rep = false;
  if (boost::starts_with(mnemonic,"rep"))
  {
    //boost::erase_head(mnemonic,4); // that works for rep_ but not for repn?{e,z}_
    std::vector< std::string > SplitVec;
    boost::split(SplitVec,mnemonic,boost::is_any_of("_"));
    //prefix = SplitVec[0];
    mnemonic = SplitVec[1];
    got_rep = true;
  } else if (boost::starts_with(mnemonic,"far")) {  // WHY are "farCall" and "farJmp" being
                                                    // output as mnemonics???
    if (mnemonic[3] == 'C')
      mnemonic = "call";
    else
      mnemonic = "jmp";
  }

  // what about LOCK prefix?  XAQUIRE/XRELEASE?

  // probably best to swtich on the first char:
  switch (mnemonic[0])
  {
   case 'a':
    if (mnemonic[1] == 'a')
      result = "MATH";
    else if (mnemonic[1] == 'd')
    {
      if (mnemonic == "adc" || mnemonic == "add")
        result = "MATH";
      else // others are SIMD variants
        result = "SIMD";
    }
    else if (mnemonic[1] == 'e') // aes*
      result = "CRYPTO";
    else if (mnemonic[1] == 'n') // and*
    {
      if (mnemonic.size() <=4) // and & andn
        result = "LOGIC";
      else
        result = "SIMD";
    }
    // else stay uncat
    break;
   case 'b':
    if (mnemonic[1] == 'e')
      result = "LOGIC"; // bextr
    else if (mnemonic[1] == 'l')
      if (mnemonic[1] == 's')
        result = "LOGIC";
      else
        result = "SIMD";
    else if (mnemonic[1] == 's')
      if (mnemonic[2] == 'w')
        result = "XFER";
      else
        result = "LOGIC";
    else if (mnemonic[1] == 't')
      result = "LOGIC";
    else if (mnemonic[1] == 'z')
      result = "LOGIC";
    // else stay uncat
    break;
   case 'c':
    if (mnemonic[1] == 'a') // call
      result = "BR";
    else if (mnemonic[1] == 'b' ||
             mnemonic[1] == 'd' ||
             mnemonic[1] == 'q' ||
             mnemonic[1] == 'w') // all sign extend instructions...
      result = "XFER"; // I guess...
    //else if (mnemonic[1] == 'l') // all flags related or flushing cache
    //  result = ???
    else if (boost::starts_with(mnemonic,"cmov"))
      result = "XFER";
    else if (boost::starts_with(mnemonic,"cmp"))
    {
      if (mnemonic == "cmp")
        result = "CMP";
      else if (mnemonic[3] == 'x')
        result = "XFER"; // I guess....
      else if (mnemonic[3] == 'p')
        result = "SIMD";
      else if (mnemonic[3] == 's')
        result = "STR"; // there is actually a conflict here w/ CMPSD being STR or SIMD based
                        // on operands and there is a CMPSS that is SIMD only...but lets err on
                        // the likely more common case I assume, for now
    }
    else if (mnemonic[1] == 'l')
    {
      if (mnemonic[2] == 'd')
        result = "STR"; // CLD, let's call that STR related I guess
      else
        result = "SYS"; // most of the other CL* ones feel like SYS, I think...
    }
    else if (mnemonic[1] == 'o')
      result = "SIMD";
    else if (mnemonic[1] == 'p') // CPUID
      result = "SYS"; // I guess, maybe?
    else if (mnemonic[1] == 'r') // CRC32
      result = "MATH";
    else if (mnemonic[1] == 'v')
      result = "SIMD";
    // else stay uncat
    break;
   case 'd':
    if (mnemonic[1] < 'i' || mnemonic == "div")
      result = "MATH";
    else
      result = "SIMD";
    break;
   case 'e':
    if (mnemonic[1] == 'm') // EMMS
      result = "FLT";
    else if (mnemonic[1] == 'n') // ENTER
      result = "XFER"; // initially I picked BR, but it's really like (push ebp;sub esp,#)
                       // XFER+MATH (see LEAVE too)
    else // EXTRACTPS
      result = "SIMD";
    break;
   case 'f':
    result = "FLT";
    break;
   case 'g': // no g instructions in x86?
    break;
   case 'h':
    if (mnemonic == "HLT")
      result = "SYS";
    else
      result = "SIMD";
    break;
   case 'i':
    if (mnemonic[1] == 'd' || mnemonic[1] == 'm') // IDIV IMUL
      result = "MATH";
    else if (mnemonic[1] == 'n')
    {
      if (mnemonic.size() == 2) // IN
      {
        result = "I/O";
      }
      else if (mnemonic[2] == 'c') // INC
        result = "MATH";
      else if (mnemonic[2] == 's')
      {
        if (mnemonic.size() == 3 || // INS, INS{B,W,D}
            mnemonic[3] == 'b' ||
            mnemonic[3] == 'w' ||
            mnemonic[3] == 'd')
          result = "I/O"; // and/or STR?
        else
          result = "SIMD";
      }
      else if (mnemonic[2] == 't') // INT variants
        result = "BR"; // or SYS?
      else if (mnemonic[2] == 'v') // INV*
        result = "SYS";
    }
    else if (mnemonic[1] == 'r') // IRET variants
      result = "BR"; // or SYS?
    // that should cover the e range completely
    break;
   case 'j': // all jump variants
    result = "BR";
    // else stay uncat
    break;
   case 'k':
    // no k's really
    break;
   case 'l':
    if (mnemonic[1] == 'a')
      result = "XFER";
    else if (mnemonic[1] == 'd')
    {
      if (mnemonic[2] == 's') // LDS
        result = "XFER";
      else
        result = "SIMD";
    }
    else if (mnemonic[1] == 'e')
    {
      switch (mnemonic[2])
      {
       case 's':
        result = "XFER"; // LES
        break;
       case 'a':
        if (mnemonic.size() == 3)
          result = "MATH"; // LEA
        else
          result = "XFER"; // LEAVE ; initially I picked BR but it's really like (mov
                           // esp,ebp;pop ebp) XFER+XFER? (see ENTER too)
      }
    }
    else if (mnemonic[1] == 'g')
    {
      if (mnemonic.size() == 3) // LGS
        result = "XFER";
      else // must be LGDT
        result = "SYS";
    }
    else if (mnemonic[1] == 'i' ||
             mnemonic[1] == 'l' ||
             mnemonic[1] == 'm') // LIDT LLDT LMSW
      result = "SYS";
    else if (mnemonic[1] == 'o')
    {
      if (mnemonic[2] == 'd') // LODS*
        result = "STR";
      else // LOOP
        result = "BR";
    }
    else if (mnemonic[1] == 'z') // LZCNT
      result = "LOGIC";
    else if (mnemonic[2] == 's') // L{F,S}S
      result = "XFER";
    else // LSL, LTR
      result = "SYS";
    break;
   case 'm':
    if (mnemonic[1] == 'o') // let's start w/ 'o' because of MOV
    {
      if (mnemonic[2] == 'v')
      {
        if (mnemonic.size() == 3) // MOV
          result = "XFER";
        else if (mnemonic[3] == 's')
        {
          if (mnemonic.size() == 4) // MOVS
            result = "STR";
          else if (mnemonic[4] == 'b' ||
                   mnemonic[4] == 'w' ||
                   mnemonic[4] == 'd' ||
                   mnemonic[4] == 'q')
            result = "STR"; // note, collision w/ MOVSD between STR & SIMD
          else if (mnemonic[4] == 'x') // MOVSX*
            result = "XFER";
          else
            result = "SIMD";
        }
        else if (mnemonic[3] == 'z') // MOVZX*
          result = "XFER";
        else
          result = "SIMD";
      }
      else // MONITOR
        result = "SYS";
    }
    else if (mnemonic[1] == 'a' || mnemonic[1] == 'i') // MAX* MIN*
      result = "SIMD";
    else if (mnemonic[1] == 'f') // MFENCE
      result = "XFER";
    else if (mnemonic[1] == 'u')
    {
      if (mnemonic.size() == 3) // MUL
        result = "MATH";
      else if (mnemonic[3] == 'x') // MULX
        result = "MATH";
      else
        result = "SIMD";
    }
    else // MWAIT
      result = "SYS";
    break;
   case 'n':
    if (mnemonic[1] == 'e') // NEG
      result = "MATH";
    else if (mnemonic[2] == 'p') // NOP
      result = "NOP";
    else // NOT
      result = "LOGIC";
    break;
   case 'o':
    if (mnemonic.size() == 2) // OR
      result = "LOGIC";
    else if (mnemonic[1] == 'r')
      result = "SIMD"; // ORP{D,S}
    else if (mnemonic.size() == 3) // OUT
      result = "I/O";
    else // OUTS*
      result = "I/O"; // or STR?
    break;
   case 'p':
    if (mnemonic[1] == 'a')
    {
      if (mnemonic[1] == 'u') // PAUSE
        result = "SYS";
      else
        result = "SIMD"; // most of PA*
    }
    else if (mnemonic[1] == 'o')
    {
      if (mnemonic[2] == 'p') // POP*
        if (mnemonic.size() == 6) // POPCNT
          result = "LOGIC";
        else
          result = "XFER";
      else // POR
        result = "SIMD";
    }
    else if (mnemonic[1] == 'r') // PRE*
      result = "XFER"; // I guess?
    else if (boost::starts_with(mnemonic,"push"))
      result = "XFER";
    else if (mnemonic == "pdep" || mnemonic == "pext")
      result = "LOGIC";
    else
      result = "SIMD"; // LOTS of them in P*
    // else stay uncat
    break;
   case 'q':
    // no Q* in x86
    break;
   case 'r':
    if (mnemonic.size() == 3)
    {
      if (mnemonic[1] == 'e') // RET
        result = "BR";
      else if (mnemonic[1] == 's') // RSM
        result = "SYS";
      else // RCL/RCR/ROL/ROR
        result = "LOGIC";
    }
    else if (mnemonic[1] == 'd')
      result = "SYS";
    else if (mnemonic == "rorx")
      result = "LOGIC";
    else
      result = "SIMD";
    break;
   case 's': // much diversity here...
    if (mnemonic.size() == 3 && (mnemonic[1] == 'a' || mnemonic[1] == 'h')) // shifts
      result = "LOGIC";
    else if (mnemonic.size() == 4 && mnemonic[3] == 'x') // shifts
      result = "LOGIC";
    else if (mnemonic[1] == 'a') // SAHF only one not covered by the first two checks...
      result = "XFER"; // I guess?
    else if (mnemonic[1] == 'b')
      result = "MATH";
    else if (mnemonic[1] == 'c')
      result = "STR";
    else if (mnemonic[1] == 'e') // SETcc
      result = "LOGIC"; // maybe?
    else if (mnemonic[1] == 'f') // SFENCE
      result = "XFER"; // maybe?
    else if (mnemonic[1] == 'g' || // SGDT, SIDT, SLDT
             mnemonic[1] == 'i' ||
             mnemonic[1] == 'l')
      result = "SYS";
    else if (mnemonic[1] == 'h')
    {
      if (mnemonic[2] == 'a') // SHA*
        result = "CRYPTO";
      else if (mnemonic[3] == 'd')  // SH{L,R}D
        result = "LOGIC";
      else
        result = "SIMD";
    }
    else if (mnemonic[1] == 'h')
      result = "SYS";
    else if (mnemonic[1] == 'q')
      result = "SIMD";
    else if (mnemonic[1] == 't')
    {
      if (mnemonic[2] == 'd')
        result = "STR"; // STD, same logic for calling this STR as for CLD
      else if (mnemonic[2] == 'r' || mnemonic[2] == 'i') // STR STI
        result = "SYS";
      else if (mnemonic[2] == 'm')
        result = "FLT";
      else if (mnemonic[2] == 'o')
        result = "STR";
      // else uncat
    }
    else if (mnemonic[1] == 'u')
    {
      if (mnemonic.size() == 3) // SUB
        result = "MATH";
      else
        result = "SIMD";
    }
    else if (mnemonic[1] == 'w' || mnemonic[1] == 'y') // SWAPGS and SYS*
      result = "SYS";
    // else stay uncat
    break;
   case 't': // only 2 of these in x86?
    if (mnemonic[1] == 'e') // TEST
      result = "CMP";
    else // TZCNT
      result = "LOGIC";
    break;
   case 'u':
    if (mnemonic[1] == 'd') // UD2
      result = "SYS"; // or could leave uncat?
    else if (mnemonic != "unknown") // ROSE sometimes returns this????
      result = "SIMD";
    break;
   case 'v':
    if (mnemonic[1] == 'e' && mnemonic[2] == 'r')
      result = "SYS";
    else if (mnemonic[1] == 'm' && mnemonic[2] != 'a')
      result = "VMM";
    else
      result = "SIMD";
    break;
   case 'w':
    // only a couple of these, and they all look like SYS to me
    result = "SYS";
    break;
   case 'x':
    if (mnemonic == "xor")
      result = "LOGIC";
    else if (mnemonic == "xchg")
      result = "XFER";
    else if (mnemonic == "xadd")
      result = "MATH";
    else if (boost::starts_with(mnemonic,"xorp"))
      result = "SIMD";
    else if (boost::starts_with(mnemonic,"xlat"))
      result = "XFER";
    else
      result = "SYS";
    // else stay uncat
    break;
   case 'y':
    // no y in x86
    break;
   case 'z':
    // no z in x86
    break;
  }

  if (got_rep)
    result = "REP_" + result;

  return result;
}

const std::vector< std::string > get_all_insn_generic_categories()
{
  // array init is much nicer than vec init...  oh, but wait, in C++11 we can do this for
  // vectors now!
  static const std::vector< std::string > rvec = {
    "BR",
    "CMP",
    "CRYPTO",
    "FLT",
    "I/O",
    "LOGIC",
    "MATH",
    "SIMD",
    "STR",
    "SYS",
    "UNCAT",
    "VMM",
    "XFER"
  };
  return rvec; // return a copy of rvec
}

// Return X for an instruction of the form "jxx [X]".  This code is fairly ugly to be in the
// middle of some largeer algorithm.  Return zero if the instruction is not of the expected
// format.
rose_addr_t insn_get_jump_deref(SgAsmInstruction* insn) {
  SgAsmExpressionPtrList &ops = insn->get_operandList()->get_operands();
  if (ops.size() != 1) return 0;

  SgAsmMemoryReferenceExpression *memref = isSgAsmMemoryReferenceExpression(ops[0]);
  if (memref == NULL) return 0;

  SgAsmIntegerValueExpression *aref = isSgAsmIntegerValueExpression(memref->get_address());
  if (aref == NULL) return 0;

  return aref->get_absoluteValue();
}

const SgAsmInstruction* last_insn_in_block(const SgAsmBlock* bb) {
  const SgAsmStatementPtrList & insns = bb->get_statementList();
  if (insns.size() < 1) return NULL;
  const SgAsmInstruction *last_insn = isSgAsmInstruction(insns[insns.size() - 1]);
  return last_insn;
}

const SgAsmInstruction* first_insn_in_block(const SgAsmBlock* bb) {
  const SgAsmStatementPtrList & insns = bb->get_statementList();
  if (insns.size() < 1) return NULL;
  const SgAsmInstruction *first_insn = isSgAsmInstruction(insns[0]);
  return first_insn;
}

const SgAsmX86Instruction* first_x86insn_in_block(const SgAsmBlock* bb) {
  const SgAsmStatementPtrList & insns = bb->get_statementList();
  if (insns.size() < 1) return NULL;
  const SgAsmX86Instruction *first_insn = isSgAsmX86Instruction(insns[0]);
  return first_insn;
}

const SgAsmX86Instruction* last_x86insn_in_block(const SgAsmBlock* bb) {
  const SgAsmStatementPtrList & insns = bb->get_statementList();
  if (insns.size() < 1) return NULL;
  const SgAsmX86Instruction *last_insn = isSgAsmX86Instruction(insns[insns.size() - 1]);
  return last_insn;
}

// For situations where the DescriptorSet isn't available.
RegisterDescriptor get_arch_reg(RegisterDictionary const &regdict,
                                const std::string & name, size_t arch_bytes)
{
  // Wow.  Horrible embarassing hack.   We'll need to think about this much harder.
  // 64-bit
  if (name.size() > 1 and name[0] == 'e' and arch_bytes == 8) {
    std::string large_name = name;
    large_name[0] = 'r';
    return regdict.find(large_name);
  }
  // 32-bit (and assorted other failure cases)...
  return regdict.find(name);
}

// Merge the expressions represented by "other" into "this"
void AddConstantExtractor::merge(AddConstantExtractor && other)
{
  if (data.empty()) {
    data = std::move(other.data);
    return;
  }
  for (auto & key_value : other.data) {
    auto & local_constants = data[tget<const TreeNodePtr>(key_value)];
    local_constants.insert(std::begin(tget<constset_t>(key_value)),
                           std::end(tget<constset_t>(key_value)));
  }
}

// Add the expression represented by "other" into "this"
void AddConstantExtractor::add(AddConstantExtractor && other)
{
  // If other has no data, return
  if (other.data.empty()) {
    return;
  }

  // If I have no data, use other's data
  if (data.empty()) {
    data = std::move(other.data);
    return;
  }

  datamap_t new_data;

  // For each pair of my data and other's data...
  for (auto & my_data : data) {
    for (auto & other_data : other.data) {

      // Construct the new variable portion
      TreeNodePtr n;
      if (!my_data.first) {
        // If I have no variable portion, use other's
        n = tget<const TreeNodePtr>(other_data);
      } else if (!tget<const TreeNodePtr>(other_data)) {
        // If other has no variable portion, use mine
        n = tget<const TreeNodePtr>(my_data);
      } else {
        // Use the sum of our variable portions
        n = InternalNode::instance(OP_ADD, tget<const TreeNodePtr>(my_data),
                                   tget<const TreeNodePtr>(other_data));
      }

      // Get the constant set for this variable portion
      auto & constants = new_data[n];

      // Insert the power-set of my constants to other's constants
      for (auto a : tget<constset_t>(my_data)) {
        for (auto b : tget<constset_t>(other_data)) {
          constants.insert(a + b);
        }
      }
    }
  }

  // swap my data for the new data
  data = std::move(new_data);
}

template <typename T>
using Incomplete = matcher::Flags<INCOMPLETE, T>;

AddConstantExtractor::AddConstantExtractor(const TreeNodePtr& tn) {
  using namespace matcher;

  LeafNodePtr lp = tn->isLeafNode();
  if (lp) {
    // If this is a constant, insert as a null variable portion with single-value constant set
    if (lp->isIntegerConstant() && lp->nBits() <= 64) {
      int64_t val = IntegerOps::signExtend2(*lp->toUnsigned(), lp->nBits(), 8*sizeof(int64_t));
      // TODO: replace with val = *lp->toSigned() once that is fixed in Rose
      data.emplace(std::make_pair(TreeNodePtr(), constset_t{val}));
      return;
    }
    // Add other leaf nodes as non-constant portions;
    data.emplace(tn, constset_t{0});
    return;
  }

  // If this is an ITE, merge the AddConstantExtractor of the true and false branches
  TreeNodePtr t, f;
  auto ite_m = Matcher<Expr<Op<OP_ITE>, Incomplete<Var>, Ref<Any>, Ref<Any>>>{t, f};
  if (ite_m(tn)) {
    AddConstantExtractor a(t);
    a.merge(AddConstantExtractor(f));
    data = std::move(a.data);
    return;
  }

  // If this is an ADD, add the constant extraction of each child
  InternalNodePtr in;
  auto add_m = Matcher<Ref<Expr<Op<OP_ADD>, ArgList>>>(in);
  if (add_m(tn)) {
    for (auto & child : in->children()) {
      add(AddConstantExtractor(child));
    }
    return;
  }

  // Otherwise, just add as variable portion
  data.emplace(tn, constset_t{0});
}

const TreeNodePtr & AddConstantExtractor::variable_portion() const
{
  if (data.empty()) {
    static const TreeNodePtr empty{};
    return empty;
  }
  return tget<const TreeNodePtr>(*std::begin(data));
}

int64_t AddConstantExtractor::constant_portion() const
{
  if (!data.empty()) {
    auto & v = tget<constset_t>(*std::begin(data));
    if (!v.empty()) {
      return *std::begin(v);
    }
  }
  return 0;
}

bool AddConstantExtractor::well_formed() const
{
  // Well formed, right now, means that there is only one entry and that the variable_portion()
  // returns non-null,
  if (data.size() == 1) {
    auto const & value = *std::begin(data);
    if (tget<const TreeNodePtr>(value) && tget<constset_t>(value).size() == 1) {
      return true;
    }
  }
  return false;
}

void backtrace(Sawyer::Message::Facility & log, Sawyer::Message::Importance level, int maxlen)
{
#ifdef __GNUC__
  // create and fill the buffer of backtrace addresses
  std::unique_ptr<void *[]> buffer(new void *[maxlen]);
  int n = ::backtrace(buffer.get(), maxlen);

  // get the backtrace as an array of strings
  auto deleter = [](char **v){ std::free(v); };
  std::unique_ptr<char*[], decltype(deleter)> trace_array(
    backtrace_symbols(buffer.get(), n), deleter);

  // Output the trace array
  log[level] && log[level] << "Backtrace:\n";
  for (int i = 1; i < n; ++i) {
    std::string trace(trace_array[i]);

    // Find the symbol in the trace for demangling
    auto open_paren = trace.find('(');
    if (open_paren != std::string::npos) {
      auto begin_symbol = open_paren + 1;
      auto end_symbol = trace.find_first_of("+)", begin_symbol);
      assert(end_symbol != std::string::npos);
      auto symbol = trace.substr(begin_symbol, end_symbol - begin_symbol);

      // demangle the symbol
      int status;
      auto delc = [](char *v){ std::free(v); };
      std::unique_ptr<char, decltype(delc)> demangled(
        abi::__cxa_demangle(symbol.c_str(), nullptr, nullptr, &status), delc);

      // re-insert demangled symbol into the trace
      if (demangled) {
        assert(status == 0);
        trace.replace(begin_symbol, end_symbol - begin_symbol,
                      demangled.get());
      }
    }

    // Output the trace
    log[level] && log[level] << "| " << trace << '\n';
  }
  log[level] && log[level] << LEND;
#endif // __GNUC__
}

rose_addr_t
address_from_node(LeafNodePtr leaf) {
  assert(leaf && leaf->isIntegerConstant());
  return static_cast<rose_addr_t>(*leaf->toUnsigned());
}

void print_expression(std::ostream & stream, TreeNode & e)
{
  stream << e;
}

void print_expression(TreeNode & e) {
  print_expression(std::cout, e);
}

void print_expression(std::ostream & stream, TreeNodePtr & e)
{
  if (!e) {
    stream << "null";
  } else {
    print_expression(stream, *e);
  }
}

void print_expression(TreeNodePtr & e) {
  print_expression(std::cout, e);
}

void print_expression(std::ostream & stream, SymbolicSemantics::SValue const & e)
{
  TreeNodePtr p = e.get_expression();
  print_expression(stream, p);
}

void print_expression(SymbolicSemantics::SValue const & e)
{
  TreeNodePtr p = e.get_expression();
  print_expression(p);
}

void print_expression(std::ostream & stream, SymbolicSemantics::SValuePtr const & e)
{
  print_expression(stream, *e);
}

void print_expression(SymbolicSemantics::SValuePtr const & e)
{
  print_expression(*e);
}

template void debug_print_expression(std::ostream & stream, TreeNode & e);
template void debug_print_expression(TreeNode & e);
template void debug_print_expression(std::ostream & stream, TreeNodePtr & e);
template void debug_print_expression(TreeNodePtr & e);
template void debug_print_expression(
  std::ostream & stream, SymbolicSemantics::SValue const & e);
template void debug_print_expression(SymbolicSemantics::SValue const & e);
template void debug_print_expression(
  std::ostream & stream, SymbolicSemantics::SValuePtr const & e);
template void debug_print_expression(SymbolicSemantics::SValuePtr const & e);

bool has_subexp (const TreeNodePtr haystack, const TreeNodePtr needle) {

  using Rose::BinaryAnalysis::SymbolicExpr::VisitAction;
  using Rose::BinaryAnalysis::SymbolicExpr::Visitor;
  using Rose::BinaryAnalysis::SymbolicExpr::CONTINUE;
  using Rose::BinaryAnalysis::SymbolicExpr::TERMINATE;

  struct SubxVisitor : Visitor {
    
    TreeNodePtr needle_;

    SubxVisitor(const TreeNodePtr &needle) : needle_(needle) {}

    virtual VisitAction preVisit(const TreeNodePtr &expr) override {
      if (expr->isEquivalentTo(needle_)) {
        return TERMINATE;
      }
      return CONTINUE;
    }
    virtual VisitAction postVisit(const TreeNodePtr&) override {
      return CONTINUE;
    }
  };

  SubxVisitor read_subx(needle);

  // search if this write includes the read. If it does, then it is not fake
  return (haystack->depthFirstTraversal(read_subx) == Rose::BinaryAnalysis::SymbolicExpr::TERMINATE);
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
