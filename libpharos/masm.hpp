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
using RoseLabelMap = Rose::BinaryAnalysis::Unparser::LabelMap;


extern RoseLabelMap global_label_map;

// This is what's primarily intended to be called externally.
std::string debug_instruction(const SgAsmInstruction *inst, const unsigned int max_bytes = 0,
                              const RoseLabelMap *labels = &global_label_map);
std::string debug_function(const FunctionDescriptor* fd, const unsigned int max_bytes,
                           const bool basic_block_lines, const bool show_reasons,
                           const RoseLabelMap *labels = &global_label_map);


// These are the support functions required to debug an instruction line.
// Call them if they're useful, but I don't expect them to be.
std::string debug_opcode_bytes(const SgUnsignedCharList& data, const unsigned int max_bytes);
std::string masm_unparseX86Expression(SgAsmExpression *expr,
                                      const RoseLabelMap *labels = &global_label_map);
std::string masm_unparseX86Expression(SgAsmExpression *expr, SgAsmX86Instruction *insn, bool leaMode,
                                      const RoseLabelMap *labels = &global_label_map);
std::string masm_unparseExpression(
  const SgAsmInstruction *insn,
  const SgAsmExpression *expr,
  RegisterDictionaryPtrArg rdict,
  const RoseLabelMap *labels = &global_label_map
  );
std::string masm_x86TypeToPtrName(SgAsmType* ty);
std::string masm_x86ValToLabel(uint64_t val, const RoseLabelMap *labels = &global_label_map);

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
