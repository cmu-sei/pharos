// Copyright 2015-2024 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Nop_H
#define Pharos_Nop_H

// This file contains utility functions for ROSE and the like.

#include "rose.hpp"
#include <Rose/BinaryAnalysis/NoOperation.h>
#include "descriptors.hpp"

// A hash for instruction bytes for our list of NOPs.
namespace std {
template <> struct hash<SgUnsignedCharList>
{
  std::size_t operator()(SgUnsignedCharList const & x) const {
    std::size_t seed = x.size();
    for (auto i : x) {
      seed ^= i + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    }
    return seed;
  }
};
}

namespace pharos {

// Return true if the instruction is an x86/x64 NOP.
bool insn_is_nop(const SgAsmX86Instruction* insn, const DescriptorSet& ds);

// Return true if the block is an alignment code block.
bool block_is_align(
  SgAsmBlock* bb,
  const DescriptorSet& ds,
  const Rose::BinaryAnalysis::NoOperation& nop_detector);
} // namespace pharos

#endif // Pharos_Nop_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
