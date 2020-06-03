// Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_PDG_H
#define Pharos_PDG_H
#include <sstream>

// Forward declaration for circular include problems.
namespace pharos {
class PDG;
} // namespace pharos

#include "defuse.hpp"
#include "cdg.hpp"

namespace pharos {

// PDG node
struct PDGNode {
  // Instruction that this node represents
  SgAsmX86Instruction* insn;
  // Data dependencies
  DUChain ddeps;
  // Control flow dependencies
  InsnSet cdeps;
};

// Comparator for inserting PDG node into map and sets
struct ltPDGNode {
  bool operator()(PDGNode a, PDGNode b) const {
    return a.insn->get_address() < b.insn->get_address();
  }
};

using Slice = std::set<PDGNode, ltPDGNode>;
using StringSet = std::set<std::string>;
using Addr2StringSetMap = std::map<rose_addr_t, StringSet>;
using AddrVector = std::vector<rose_addr_t>;
using StringVector = std::vector<std::string>;

using MnemonicCode = uint16_t;
using FunctionID = uint32_t;

class PDG {

 protected:
  DescriptorSet& ds;

  // The function descriptor that we're analyzing.
  FunctionDescriptor* fd;

  // Keep these private so that only this API writes to them.
  DUAnalysis du;
  CDG cdg;

  Addr2InsnSetMap control_deps;

  std::string getInstructionString(SgAsmX86Instruction *insn, AddrVector &constants) const;
  StringVector getInstructionString(SgAsmX86Instruction *insn) const;
  std::string makeVariableStr(rose_addr_t addr) const;
  void buildDotNode(SgAsmX86Instruction *cur_insn, std::stringstream &sout, X86InsnSet& processed) const;
  void toDot(std::string dotOutputFile) const;
  void hashSubPaths(SgAsmX86Instruction *cur_insn, std::string path, X86InsnSet processed,
                    StringVector& hashedPaths, size_t maxSubPathLen, size_t curLen,
                    StringVector* ss_dump = NULL, AddrSet filter_addresses = AddrSet(),
                    Addr2StringSetMap filter_constants = Addr2StringSetMap(),
                    bool includeSubPath = true) const;

  StringVector getPaths(size_t maxSubPathLen) const;
  std::string dumpOperand(SgAsmExpression *exp, AddrVector& constants) const;
  std::string dumpOperands(SgAsmX86Instruction *insn, AddrVector& constants) const;
  size_t hashSlice(SgAsmX86Instruction *insn, size_t nHashFunc, std::vector<unsigned int> & hashes) const;
  size_t getNumInstr() const;

  // Get a chop? Not really a chop?
  X86InsnSet chop_insns(SgAsmX86Instruction *insn) const;
  AccessMap chop_full(SgAsmX86Instruction *insn) const;

  // A convenient way to get a single read (with some error checking).
  AbstractAccess get_single_mem_read(rose_addr_t addr) const;

 public:

  PDG(DescriptorSet& ds, FunctionDescriptor& f);
  //~PDG();

  // Only export the usedef analysis read-only.
  const DUAnalysis& get_usedef() const { return du; }
  // Only export the control dependency graph read-only. (Unused)
  const CDG& get_cdg() const { return cdg; }

  // Must be public for buildKeys() in indexer.cpp.
  Addr2InsnSetMap getControlDeps() const { return control_deps; }

  // Get a slice for specified instruction.
  // This has a peculiar API -- returning a string and updating the passed reference.
  // Perhaps there should be two methods here.
  std::string getSlice(SgAsmX86Instruction *insn, Slice &s) const;

  // Return the hash.  Must be public for FunctionDescriptor::get_pdg_hash(), which should be
  // used as the official API instead.
  std::string getWeightedMaxHash(size_t nHashFunc) const;

  size_t get_delta_failures() const {
    return du.get_delta_failures();
  }

};

} // namespace pharos

#endif  // Pharos_PDG_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
