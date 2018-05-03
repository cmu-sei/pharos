// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_PDG_H
#define Pharos_PDG_H
#include <sstream>

// Forward declaration for circular include problems.
namespace pharos {
class PDG;
} // namespace pharos

#include "defuse.hpp"
#include "sptrack.hpp"
#include "cdg.hpp"

namespace pharos {

// PDG node
struct PDGNode {
  // Instruction that this node represents
  SgAsmx86Instruction* insn;
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

typedef std::set<PDGNode, ltPDGNode> Slice;
typedef std::set<std::string> StringSet;
typedef std::map<rose_addr_t, StringSet> Addr2StringSetMap;
typedef std::vector<rose_addr_t> AddrVector;
typedef std::vector<std::string> StringVector;

typedef uint16_t MnemonicCode;
typedef uint32_t FunctionID;

class PDG {

protected:
  // The function descriptor that we're analyzing.
  FunctionDescriptor* fd;

  // Keep these private so that only this API writes to them.
  DUAnalysis du;
  CDG cdg;

  Insn2InsnSetMap control_deps;

  std::string getInstructionString(SgAsmx86Instruction *insn, AddrVector &constants);
  StringVector getInstructionString(SgAsmx86Instruction *insn);
  std::string makeVariableStr(SgAsmx86Instruction *cur_insn);
  void buildDotNode(SgAsmx86Instruction *cur_insn, std::stringstream &sout, X86InsnSet& processed);
  void toDot(std::string dotOutputFile);
  void hashSubPaths(SgAsmx86Instruction *cur_insn, std::string path, X86InsnSet processed,
                    StringVector& hashedPaths, size_t maxSubPathLen, size_t curLen,
                    StringVector* ss_dump = NULL, AddrSet filter_addresses = AddrSet(),
                    Addr2StringSetMap filter_constants = Addr2StringSetMap(),
                    bool includeSubPath = true);

  StringVector getPaths(size_t maxSubPathLen);
  std::string dumpOperand(SgAsmExpression *exp, AddrVector& constants);
  std::string dumpOperands(SgAsmx86Instruction *insn, AddrVector& constants);
  size_t hashSlice(SgAsmx86Instruction *insn, size_t nHashFunc, std::vector<unsigned int> & hashes);
  size_t getNumInstr();

  // Get a chop? Not really a chop?
  X86InsnSet chop_insns(SgAsmx86Instruction *insn);
  AccessMap chop_full(SgAsmx86Instruction *insn);

  // A convenient way to get a single read (with some error checking).
  AbstractAccess get_single_mem_read(SgAsmx86Instruction* insn);

public:

  PDG(FunctionDescriptor* f, spTracker* sp_tracker);
  //~PDG();

  // Only export the usedef analysis read-only.
  const DUAnalysis& get_usedef() const { return du; }
  // Only export the control dependency graph read-only. (Unused)
  const CDG& get_cdg() const { return cdg; }

  // Must be public for buildKeys() in indexer.cpp.
  Insn2InsnSetMap getControlDeps() { return control_deps; }

  // Get a slice for specified instruction.
  // This has a peculiar API -- returning a string and updating the passed reference.
  // Perhaps there should be two methods here.
  std::string getSlice(SgAsmx86Instruction *insn, Slice &s);

  // Return the hash.  Must be public for FunctionDescriptor::get_pdg_hash(), which should be
  // used as the official API instead.
  std::string getWeightedMaxHash(size_t nHashFunc);

};

} // namespace pharos

#endif  // Pharos_PDG_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
