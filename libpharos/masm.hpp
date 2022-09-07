// Copyright 2015-2022 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_MASM_H
#define Pharos_MASM_H

#include <stdio.h>
#include <iomanip>

#include "rose.hpp"
#include <AstTraversal.h>

#include "descriptors.hpp"

namespace pharos {

// duplicative :-(
using AddrSet = std::set<rose_addr_t>;

// ======================================================================
// A traversal class to build the label map.  A global instance of this
// class is used to avoid having to pass
// ======================================================================
using ImportLabelMap = std::map<rose_addr_t, std::string>;
using RoseLabelMap = Rose::BinaryAnalysis::AsmUnparser::LabelMap;

class DebugLabelMap: public AstPreOrderTraversal
{
  RoseLabelMap labels;
  ImportLabelMap imports;

 public:

  DebugLabelMap() { }
  DebugLabelMap(SgProject *p) {
    this->traverse(p);
  }
  const RoseLabelMap* get_labels() { return &labels; }
  const ImportLabelMap* get_imports() { return &imports; }
  virtual void preOrderVisit(SgNode* n);
  virtual void dump_labels();
};

extern DebugLabelMap global_label_map;

// This is what's primarily intended to be called externally.
std::string debug_instruction(const SgAsmInstruction *inst, const unsigned int max_bytes = 0,
                              const RoseLabelMap *labels = global_label_map.get_labels());
std::string debug_function(const FunctionDescriptor* fd, const unsigned int max_bytes,
                           const bool basic_block_lines, const bool show_reasons,
                           const RoseLabelMap *labels = global_label_map.get_labels());

// ======================================================================
// The Disassembly Dumper Traversal
// ======================================================================

class DebugDisasm: public AstSimpleProcessing
{
 public:
  const DescriptorSet& ds;
  unsigned int hex_bytes;
  bool basic_block_lines;
  bool show_reasons;
  bool labels_built;
  unsigned int fcnt;
  AddrSet target_addrs;
  AddrSet found_addrs;

  DebugDisasm(const DescriptorSet& d) : ds(d) {
    hex_bytes = 0;
    basic_block_lines = false;
    show_reasons = false;
    labels_built = false;
    fcnt = 0;
  }
  virtual void visit(SgNode* n);
  virtual void atTraversalEnd();
};

// These are the support functions required to debug an instruction line.
// Call them if they're useful, but I don't expect them to be.
std::string debug_opcode_bytes(const SgUnsignedCharList& data, const unsigned int max_bytes);
std::string masm_unparseX86Expression(SgAsmExpression *expr,
                                      const RoseLabelMap *labels = global_label_map.get_labels());
std::string masm_unparseX86Expression(SgAsmExpression *expr, SgAsmX86Instruction *insn, bool leaMode,
                                      const RoseLabelMap *labels = global_label_map.get_labels());
std::string masm_unparseExpression(
  const SgAsmInstruction *insn,
  const SgAsmExpression *expr,
  RegisterDictionaryPtrArg rdict,
  const RoseLabelMap *labels = global_label_map.get_labels()
  );
std::string masm_x86TypeToPtrName(SgAsmType* ty);
std::string masm_x86ValToLabel(uint64_t val, const RoseLabelMap *labels = global_label_map.get_labels());

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
