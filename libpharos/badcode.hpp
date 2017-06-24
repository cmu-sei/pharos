// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_BadCode_H
#define Pharos_BadCode_H

namespace pharos {

class BadCodeMetrics {

protected:

  bool isUnusualInstruction(SgAsmX86Instruction *insn) {
    X86InstructionKind k = insn->get_kind();

    if (k >= x86_unknown_instruction && k <= x86_aas) return true;
    if (k == x86_arpl || k == x86_bound || k == x86_in || k == x86_insb || k == x86_insd || k == x86_insw) return true;
    if (k >= x86_clflush && k <= x86_cmc) return true;
    if (k == x86_cpuid || k == x86_cqo) return true;
    if (k == x86_daa || k == x86_das || k == x86_enter || k ==x86_hlt) return true;
    if (k >= x86_out && k <= x86_outsw) return true;
    if (k >= x86_skinit && k <= x86_stmxcsr) return true;
    if (k >= x86_syscall && k <= x86_sysret) return true;
    if (k >= x86_ucomisd && k <= x86_wrmsr) return true;
    if (k >= x86_int && k <= x86_int3) return true;

    return false;

  }

  bool sameInstruction(SgAsmX86Instruction *a, SgAsmX86Instruction *b) {
    assert(a && b);
    SgUnsignedCharList ab = a->get_raw_bytes();
    SgUnsignedCharList bb = b->get_raw_bytes();

    if (ab.size() != bb.size()) return false;
    for (size_t x = 0; x < ab.size(); x++) {
      if (ab[x] != bb[x]) return false;
    }

    return true;
  }

  // This is currently Wes' creation.  Cory says that when we get to re-working this, we should
  // test for jumps to completely invalid addresses and also 2-operand jump instructions, both
  // of which are currently generating other errors and warnings in our code.
  bool isUnusualJmp(SgAsmStatementPtrList insns, size_t jmpindex) {
    assert (jmpindex < insns.size());

    SgAsmX86Instruction *jinsn = isSgAsmX86Instruction(insns[jmpindex]);
    if (!jinsn || jinsn->get_kind() == x86_jmp || jinsn->get_kind() == x86_jmpe)
      return false;

    if (jinsn->get_kind() >= x86_ja && jinsn->get_kind() <= x86_js) {
      if (jmpindex == 0 || isSgAsmX86Instruction(insns[jmpindex-1]) == NULL) return true;
      X86InstructionKind pkind = isSgAsmX86Instruction(insns[jmpindex-1])->get_kind();
      if (pkind == x86_cmp || pkind == x86_and || pkind == x86_or || pkind == x86_not ||
          pkind == x86_xor || pkind == x86_sbb || pkind == x86_sub || pkind == x86_add ||
          pkind == x86_adc || pkind == x86_mul || pkind == x86_div || pkind == x86_rcl ||
          pkind == x86_ror || pkind == x86_shl || pkind == x86_shld || pkind == x86_shr ||
          pkind == x86_shrd)
        return false;
    }


    return true;
  }

  size_t maxRepeated;
  size_t maxRare;
  size_t maxDead ;
  size_t maxUnusualJmp;

public:

  BadCodeMetrics(size_t maxRepeatedThreshold = 3,
                 size_t maxRareInsnsThreshold = 3,
                 size_t maxDeadCodeThreshold = 3,
                 size_t maxUnusualJmpThreshold = 99) {

    maxRepeated = maxRepeatedThreshold;
    maxRare =  maxRareInsnsThreshold;
    maxDead = maxDeadCodeThreshold;
    maxUnusualJmp = maxUnusualJmpThreshold;
  }

  bool isBadCode(SgAsmStatementPtrList insns,
                 size_t *repeatedInstructions = NULL,
                 size_t *numRareInstructions = NULL,
                 size_t *numDeadStores = NULL,
                 size_t *unusualJmps = NULL) {

    SgAsmX86Instruction *prevInsn = NULL;
    size_t repeated = 0, maxrepeated = 0;
    size_t rare = 0;
    size_t dead = 0;
    size_t badJmps = 0;

    SymbolicRiscOperatorsPtr rops = SymbolicRiscOperators::instance();
    size_t arch_bits = global_descriptor_set->get_arch_bits();
    DispatcherPtr dispatcher = RoseDispatcherX86::instance(rops, arch_bits, NULL);
    const RegisterDescriptor& eiprd = dispatcher->findRegister("eip", arch_bits);

    for (size_t q = 0; q < insns.size(); q++) {
      SgAsmX86Instruction *curInsn = isSgAsmX86Instruction(insns[q]);
      if (!curInsn) continue;
      if (prevInsn && sameInstruction(curInsn,prevInsn)) {
        repeated++;
        maxrepeated = maxrepeated > repeated ? maxrepeated : repeated;
      } else repeated = 0;

      prevInsn = curInsn;

      if (isUnusualInstruction(curInsn)) rare++;
      if (isUnusualJmp(insns,q)) badJmps++;


      std::set<std::string> writtenButNotRead;

      try {
        //Another forced EIP hack.  Possibly not needed in ROSE2 port?
        rose_addr_t iaddr = curInsn->get_address();
        SymbolicValuePtr iaddrptr = SymbolicValue::constant_instance(32, iaddr);
        rops->writeRegister(eiprd, iaddrptr);
        dispatcher->processInstruction(curInsn);

        for (size_t a = 0; a < rops->reads.size(); a++) {
          AbstractAccess aa = rops->reads[a];
          if (aa.is_gpr() && (aa.reg_name() != "eip" || aa.reg_name() != "esp" || aa.reg_name() != "ebp")
              && writtenButNotRead.find(aa.reg_name()) != writtenButNotRead.end()) {
            writtenButNotRead.erase(aa.reg_name());
          }
        }

        for (size_t a = 0; a < rops->writes.size(); a++) {
          AbstractAccess aa = rops->writes[a];
          if (aa.is_gpr() && (aa.reg_name() != "eip" || aa.reg_name() != "esp" || aa.reg_name() != "ebp")) {
            if (writtenButNotRead.find(aa.reg_name()) != writtenButNotRead.end())
              dead++;
            writtenButNotRead.insert(aa.reg_name());
          }
        }

      } catch (...) {}

      if (maxrepeated >= maxRepeated ||
          rare >= maxRare ||
          dead >= maxDead ||
          badJmps >= maxUnusualJmp)
        break;
    }

    //GDEBUG << "Evaluating - Dead Stores: " <<  dead << " Repeated Insns: " << maxrepeated
    //       << " Bad Cond Jumps: " << badJmps << " Unusual Insns: " << rare << LEND;

    if (repeatedInstructions)
      *repeatedInstructions = maxrepeated;

    if (numRareInstructions)
      *numRareInstructions = rare;

    if (numDeadStores)
      *numDeadStores = dead;

    if (unusualJmps)
      *unusualJmps = badJmps;

    if (maxrepeated >= maxRepeated ||
        rare >= maxRare ||
        dead >= maxDead ||
        badJmps >= maxUnusualJmp)
      return true;

    return false;
  }
};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
