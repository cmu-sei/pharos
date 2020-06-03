// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_BadCode_H
#define Pharos_BadCode_H

namespace pharos {

class DescriptorSet;

// This is currently Wes' creation.  Cory says that when we get to re-working this, we should
// test for jumps to completely invalid addresses and also 2-operand jump instructions, both
// of which are currently generating other errors and warnings in our code.
class BadCodeMetrics {

 protected:

  bool isUnusualInstruction(const SgAsmX86Instruction *insn) const;
  bool sameInstruction(const SgAsmX86Instruction *a, const SgAsmX86Instruction *b) const;
  bool isUnusualJmp(SgAsmStatementPtrList insns, size_t jmpindex) const;

  size_t maxRepeated;
  size_t maxRare;
  size_t maxDead ;
  size_t maxUnusualJmp;

 public:

  // Needed because we instantiate a rops object...  should we?
  DescriptorSet& ds;

  BadCodeMetrics(
    DescriptorSet& d,
    size_t maxRepeatedThreshold = 3,
    size_t maxRareInsnsThreshold = 3,
    size_t maxDeadCodeThreshold = 3,
    size_t maxUnusualJmpThreshold = 99) : ds(d) {

    maxRepeated = maxRepeatedThreshold;
    maxRare =  maxRareInsnsThreshold;
    maxDead = maxDeadCodeThreshold;
    maxUnusualJmp = maxUnusualJmpThreshold;
  }

  bool isBadCode(SgAsmStatementPtrList insns,
                 size_t *repeatedInstructions = NULL,
                 size_t *numRareInstructions = NULL,
                 size_t *numDeadStores = NULL,
                 size_t *unusualJmps = NULL);
};

// Check if the block is "bad".  This is intended usual interface.
bool check_for_bad_code(DescriptorSet& ds, const SgAsmBlock* block);

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
