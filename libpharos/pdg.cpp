// Copyright 2015-2022 Carnegie Mellon University.  See LICENSE file for terms.

#include "pdg.hpp"
#include "md5.hpp"
#include "masm.hpp"

namespace pharos {

PDG::PDG(DescriptorSet& ds_, FunctionDescriptor& f) :
  ds(ds_), du(ds_, f), cdg(ds_, f)
{
  // We always have a function descriptor, and it always has a real function, or we won't
  // (shouldn't) have been called.
  fd = &f;
  assert(fd->get_func() != NULL);
  assert(fd->get_p2func() != NULL);

  // Get the control flow dependencies
  control_deps = cdg.getControlDependencies();
}

// This is a reminder to more fully understand where PDGs are created that are not freed.
// Possibly a problem with the bottom up order sorting?
//PDG::~PDG() {
//ODEBUG << "Deleting the PDG for " << fd->address_string() << LEND;
//}

// This is a convenience function for the situation in which you expect (know?) that there is
// is a single memory read for an instruction.  It most cases, it finds the single memory read
// access and returns it.  When there are no reads of any kind for the instruction, there are
// no memory reads for the instruction, or there are multiple memory reads for teh instruction,
// this function returns an invalid abstract access.  Not currently called from anywhere.
AbstractAccess PDG::get_single_mem_read(rose_addr_t addr) const {
  auto mem_reads = du.get_mem_reads(addr);
  auto i = std::begin(mem_reads);
  if (i == std::end(mem_reads)) {
    // More memory reads, return an invalid abstract access.
    return AbstractAccess();
  }
  const AbstractAccess & aa = *i;
  if (++i != std::end(mem_reads)) {
    // More than one memory read, return and invalid abstract access.
    return AbstractAccess();
  }
  return aa;
}

// This is kind stupid, and performs poorly, but Cory's goal was to cleanup the API a bit, and
// understand where we needed the full structure, and where we just needed the instructions.
// This function is apparently unused at present.
X86InsnSet PDG::chop_insns(SgAsmX86Instruction *insn) const {
  STRACE << "Chopping intruction: " << debug_instruction(insn) << LEND;
  X86InsnSet insns;
  AccessMap tainted = chop_full(insn);
  for (const AccessMap::value_type &p : tainted) {
    SgAsmInstruction* ginsn = ds.get_insn(p.first);
    SgAsmX86Instruction* xinsn = isSgAsmX86Instruction(ginsn);
    // Certainly only tested on X86 instructions.
    assert(xinsn);
    insns.insert(xinsn);
    STRACE << "  Chopped: " << debug_instruction(ginsn) << LEND;
  }
  return insns;
}

// Chop used to return an ordered vector.  The problem was that the order wasn't really correct
// so Cory changed it to be an unordered map.  The right fix is probably to have a separate
// method that takes an AccessMap as a parameter and returns the intructions in the appropriate
// order for symbolic emaulation.  This function is apparently unused at present.
AccessMap PDG::chop_full(SgAsmX86Instruction *insn) const {
  AccessMap taintedInsns;
  assert(insn != NULL);

  X86InsnSet processed;
  X86InsnVector workQueue;
  workQueue.push_back(insn);

  LeafNodePtrSet ids2track;

  while (workQueue.size() > 0) {
    SgAsmX86Instruction *cur = workQueue[0];

    if (processed.find(cur) != processed.end()) {
      workQueue.erase(workQueue.begin());
      continue;
    }

    processed.insert(cur);
    workQueue.erase(workQueue.begin());

    // Check to make sure the instruction reads a GPR, flag or memory address defined by the
    // instruction being chopped
    AbstractAccessVector accesses;

    rose_addr_t caddr = cur->get_address();
    if (cur == insn) {
      // if (insn_is_call(cur)) SDEBUG << "We're chopping a call " << debug_instruction(cur) << LEND;
      // SDEBUG << "Starting chop from " << debug_instruction(insn) << LEND;
      for (const AbstractAccess& aa : du.get_writes(caddr)) {
        if (aa.is_reg() && insn_is_callNF(cur) &&
            unparseX86Register(aa.register_descriptor, {}) == "esp") continue;

        LeafNodePtrSet vars = aa.value->get_expression()->getVariables();
        ids2track.insert(vars.begin(),vars.end());
      }
    }
    else {
      // SDEBUG << "**" << debug_instruction(cur) << " ";
      for (const AbstractAccess& aa : du.get_reads(caddr)) {
        LeafNodePtrSet vars = aa.value->get_expression()->getVariables();

        for (LeafNodePtrSet::iterator it = vars.begin(); it != vars.end(); it++) {
          for (LeafNodePtrSet::iterator xit = ids2track.begin(); xit != ids2track.end(); xit++) {
            // SDEBUG << "Reg comparison Comparing id2track " << *(*xit)
            //        << " with seen GPR value " << *(*it) << LEND;
            if ((*xit)->isEquivalentTo(*it)) {
              accesses.push_back(aa);
              break;
            }
          }
        }
      }

      if (accesses.size() > 0) {
        taintedInsns[caddr] = accesses;
      } else continue;
    }

    const DUChain* curdeps = du.get_dependents(caddr);
    if (curdeps != NULL) {
      for (const Definition& def : *curdeps) {
        if (def.definer != cur) {
          workQueue.push_back(def.definer);
          // SDEBUG << "Adding " << debug_instruction(duit->definer) << LEND;
        }
      }
    }
  }
  return taintedInsns;
}

// Instruction string with abstracted operands
std::string PDG::getInstructionString(SgAsmX86Instruction *insn, AddrVector& constants) const {
  return insn->get_mnemonic() + dumpOperands(insn,constants);
}

// Return a list with the disassembly of this instruction
// Each string contains the mnenomic and 0 or more concrete values for constants
// The first string does not contain concrete values for constants (i.e., CMP [REG+CONSTANT], CONSTANT)
StringVector PDG::getInstructionString(SgAsmX86Instruction *insn) const {
  AddrVector constants;
  StringVector insn_str;

  std::string mnem = insn->get_mnemonic();
  std::string operand_str = dumpOperands(insn,constants);

  // We need to generate every permutation of the instruction string with the different
  // constant values subbed in
  for (size_t a = 0; a < (size_t)(1 << constants.size()); a++) {
    size_t l = a, y = 0;
    std::string op_str_k = operand_str;

    while (l > 0) {
      if (l & 1) {
        std::stringstream convert1,convert2;
        convert1 << y;
        std::string k_term = "CONSTANT"+convert1.str();
        size_t pos = op_str_k.find(k_term);
        assert(pos != std::string::npos);
        convert2 << constants[y];
        op_str_k = op_str_k.substr(0,pos) + convert2.str() + op_str_k.substr(pos+k_term.length());
      }
      l = l >> 1;
      y++;
    }

    insn_str.push_back(mnem+op_str_k);
  }

  return insn_str;
}

// Only called from buildDotNode, which is only used from toDot().
std::string PDG::makeVariableStr(rose_addr_t addr) const {
  std::stringstream variable;
  // The variable representing this node in the graph
  variable << "N" << addr;
  return variable.str();
}

// Only called from toDot, which is unused!
void PDG::buildDotNode(
  SgAsmX86Instruction *cur_insn, std::stringstream &sout, X86InsnSet& processed) const
{
  if (cur_insn == NULL || processed.find(cur_insn) != processed.end()) return;
  processed.insert(cur_insn);

  rose_addr_t caddr = cur_insn->get_address();
  std::string curvar = makeVariableStr(caddr);
  AddrVector constants;

  // Create the label for the node
  sout << curvar << " [label=\""
       << debug_instruction(cur_insn) + "\\n" + getInstructionString(cur_insn,constants) + "\"];\n";

  // du.cleanupDependencies();
  const Addr2DUChainMap& data_deps = du.get_dependencies();

  // Create the data flow edges
  if (data_deps.find(caddr) != data_deps.end()) {
    for (const Definition& def : data_deps.at(caddr)) {
      SgAsmX86Instruction* definer = def.definer;
      if (definer == NULL) continue;
      sout << curvar << " -> " << makeVariableStr(definer->get_address()) << " [label=\"d\"];\n";
      buildDotNode(definer, sout, processed);
    }
  }

  // Create the control flow edges
  if (control_deps.find(caddr) != control_deps.end()) {
    for (SgAsmInstruction* ginsn : control_deps.at(caddr)) {
      SgAsmX86Instruction *cinsn = isSgAsmX86Instruction(ginsn);
      assert(cinsn);
      sout << curvar << " -> " << makeVariableStr(cinsn->get_address()) << " [label=\"c\"];\n";
      buildDotNode(cinsn, sout, processed);
    }
  }
}

// Unused!
void PDG::toDot(std::string dotOutputFile) const {
  X86InsnSet processed;
  std::stringstream sout;

  // Dot header
  sout << "digraph PDG {\nnode [ shape = box ];\n";

  // Create a node for each instruction
  for (SgAsmStatement* bs : fd->get_func()->get_statementList()) {
    SgAsmBlock *bb = isSgAsmBlock(bs);
    assert(bb);
    for (SgAsmStatement* is : bb->get_statementList()) {
      SgAsmX86Instruction *insn = isSgAsmX86Instruction(is);
      buildDotNode(insn,sout,processed);
    }
  }

  // Dot footer
  sout << "}\n";

  // Flush the string stream to disk
  FILE *fout = fopen(dotOutputFile.c_str(), "w");
  assert(fout != NULL);
  fputs(sout.str().c_str(), fout);
  fclose(fout);
}

void PDG::hashSubPaths(SgAsmX86Instruction *cur_insn, std::string path, X86InsnSet processed,
                       StringVector &hashedPaths, size_t maxSubPathLen, size_t curLen,
                       StringVector *ss_dump, AddrSet filter_addresses,
                       Addr2StringSetMap filter_constants, bool includeSubPath) const {
  if (cur_insn == NULL || processed.find(cur_insn) != processed.end())
    return;

  rose_addr_t caddr = cur_insn->get_address();

  processed.insert(cur_insn);
  if (ss_dump && includeSubPath) {
    if (filter_addresses.size() > 0 && filter_addresses.find(caddr) == filter_addresses.end())
      includeSubPath = false;
    //else
    //  (*ss_dump).push_back("# Subpath hashes for: " + debug_instruction(cur_insn));
  }

  const Addr2DUChainMap& data_deps = du.get_dependencies();

  // Add the current node to the path and hash
  StringVector ins_str = getInstructionString(cur_insn);

  for (size_t q = 0; q < ins_str.size(); q++) {
    std::string new_path = path + ins_str[q];

    // Iterate through the constants specified by the user
    if (includeSubPath && filter_constants.size() > 0 &&
        filter_constants.find(caddr) != filter_constants.end()) {
      bool found = false;
      for (StringSet::iterator cit = filter_constants[caddr].begin();
           cit != filter_constants[caddr].end(); cit++) {
        std::string term = *cit;
        assert(term.length() > 0);

        // If the constant is required (i.e., not preceded with '!') and ins_str
        // contains that constant in abstract form, skip the path
        if ((term[0] == '!' && ins_str[q].find(term.substr(1)) == std::string::npos) ||
            (term[0] != '!' && ins_str[q].find(term) != std::string::npos)) {
          found = true;
          break;
        }
      }
      if (found) {
        continue;
      }
    }

    if (ss_dump && includeSubPath) {
      // If this path extends an old one, remove the old one
      if (filter_addresses.size() > 0 && curLen > 1) {
        assert((*ss_dump).size() > 0);
        SDEBUG << "Erasing " + (*ss_dump)[(*ss_dump).size()-1] << " curLen "
               << curLen << " size " << (*ss_dump).size() << LEND;
        (*ss_dump).erase((*ss_dump).begin()+(*ss_dump).size()-1);
      }

      (*ss_dump).push_back(new_path);
    }

    hashedPaths.push_back(new_path);

    // Hash the data flow edges
    // getSlice uses uppercase C and D, while here uses lowercase, why?
    if (curLen < maxSubPathLen && data_deps.find(caddr) != data_deps.end()) {
      for (const Definition& def : data_deps.at(caddr)) {
        SgAsmX86Instruction* definer = def.definer;
        if (definer == NULL) continue;
        hashSubPaths(definer, new_path + "-d->", processed, hashedPaths, maxSubPathLen,
                     curLen + 1, ss_dump, filter_addresses, filter_constants ,includeSubPath);
      }
    }

    // Create the control flow edges
    if (curLen < maxSubPathLen && control_deps.find(caddr) != control_deps.end()) {
      for (InsnSet::iterator it = control_deps.at(caddr).begin();
           it != control_deps.at(caddr).end(); it++)
      {
        SgAsmX86Instruction *cinsn = isSgAsmX86Instruction(*it);
        assert(cinsn);
        hashSubPaths(cinsn, new_path + "-c->", processed, hashedPaths, maxSubPathLen,
                     curLen + 1, ss_dump, filter_addresses, filter_constants,includeSubPath);
      }
    }
  }
}

// Unused!
StringVector PDG::getPaths(size_t maxSubPathLen) const {
  StringVector hashes;

  for (SgAsmStatement* bs : fd->get_func()->get_statementList()) {
    SgAsmBlock *bb = isSgAsmBlock(bs);
    assert(bb);
    for (SgAsmStatement* is : bb->get_statementList()) {
      SgAsmX86Instruction *insn = isSgAsmX86Instruction(is);
      X86InsnSet processed;
      hashSubPaths(insn, "", processed, hashes, maxSubPathLen, 1);
    }
  }

  return hashes;
}

// Comparator for inserting InsnBoolPairs into sets.
// Only needed in getSlice(), and perhaps not even there...
using InsnBoolPair = std::pair<SgAsmX86Instruction *, bool>;
struct ltAsmInsn {
  bool operator()(InsnBoolPair a, InsnBoolPair b) const {
    return a.first->get_address() < b.first->get_address();
  }
};

std::string PDG::getSlice(SgAsmX86Instruction *insn, Slice &s) const {
  if (insn == NULL) return "";

  for (Slice::iterator it = s.begin(); it != s.end(); it++) {
    if (insn == (*it).insn) return "";
  }

  AddrVector constants;
  std::string slice_str = getInstructionString(insn, constants);
  std::string insn_str = slice_str;
  PDGNode pn;
  pn.insn = insn;

  const Addr2DUChainMap& data_deps = du.get_dependencies();

  rose_addr_t iaddr = insn->get_address();
  // Add the data and control dependencies for this node
  if (data_deps.find(iaddr) != data_deps.end()) {
    pn.ddeps = data_deps.at(iaddr);
  }
  if (control_deps.find(iaddr) != control_deps.end()) {
    pn.cdeps = control_deps.at(iaddr);
  }
  s.insert(pn);

  using InsnBoolPairSet = std::set<InsnBoolPair, ltAsmInsn>;

  InsnBoolPairSet dependencies;

  // Insert the data-dependencies of this instruction
  if (data_deps.find(iaddr) != data_deps.end()) {
    for (const Definition& def : data_deps.at(iaddr)) {
      if (def.definer) dependencies.insert(InsnBoolPair(def.definer, true));
    }
  }

  // Insert the control dependencies of this block
  if (control_deps.find(iaddr) != control_deps.end()) {
    for (SgAsmInstruction* i : control_deps.at(iaddr)) {
      if (isSgAsmX86Instruction(i))
        dependencies.insert(InsnBoolPair(isSgAsmX86Instruction(i), false));
    }
  }

  // Build the dependency string and visit the instructions in address order
  for (const InsnBoolPair &b : dependencies) {
    // Represent a data-dependency edge
    AddrVector constants2;
    if (b.second && b.first != NULL) {
      slice_str += insn_str + "-D->" + getInstructionString(b.first, constants2);
    } else if (b.first != NULL) {
      slice_str += insn_str + "-C->" + getInstructionString(b.first, constants2);
    }

    // Recurse!
    slice_str += getSlice(b.first, s);
  }

  return slice_str;
}

std::string PDG::dumpOperand(SgAsmExpression *exp, AddrVector& constants) const {

  if (isSgAsmIntegerValueExpression(exp)) {
    std::ostringstream convert;
    convert << constants.size();
    constants.push_back(isSgAsmIntegerValueExpression(exp)->get_absoluteValue());
    return "CONSTANT" + convert.str();
  } else if (isSgAsmRegisterReferenceExpression(exp)) {
    return "REG";
  } else if (isSgAsmMemoryReferenceExpression(exp)) {
    return "[" + dumpOperand(isSgAsmMemoryReferenceExpression(exp)->get_address(),constants) + "]";
  } else if (isSgAsmBinaryAdd(exp)) {
    return dumpOperand(isSgAsmBinaryAdd(exp)->get_lhs(),constants) + "+" +
      dumpOperand(isSgAsmBinaryAdd(exp)->get_rhs(),constants);
  } else if (isSgAsmBinaryMultiply(exp)) {
    return dumpOperand(isSgAsmBinaryMultiply(exp)->get_lhs(),constants) + "*" +
      dumpOperand(isSgAsmBinaryMultiply(exp)->get_rhs(),constants);
  } else if (isSgAsmBinarySubtract(exp)) {
    return dumpOperand(isSgAsmBinarySubtract(exp)->get_lhs(),constants) + "-" +
      dumpOperand(isSgAsmBinarySubtract(exp)->get_rhs(),constants);
  } else if (isSgAsmBinaryDivide(exp)) {
    return dumpOperand(isSgAsmBinaryDivide(exp)->get_lhs(),constants) + "/" +
      dumpOperand(isSgAsmBinaryDivide(exp)->get_rhs(),constants);
  } else if (isSgAsmBinaryMod(exp)) {
    return dumpOperand(isSgAsmBinaryMod(exp)->get_lhs(),constants) + "%" +
      dumpOperand(isSgAsmBinaryMod(exp)->get_rhs(),constants);
  } else {
    SERROR << "Warning: unhandled operand\n";
    return "UNOWN";
  }
}

std::string PDG::dumpOperands(SgAsmX86Instruction *insn, AddrVector& constants) const {
  std::string opstr = "";
  SgAsmExpressionPtrList ops = insn->get_operandList()->get_operands();

  for (size_t x = 0; x < ops.size(); x++) {
    if (opstr.length() > 0) opstr = opstr + ", ";
    else opstr = opstr + " ";
    opstr = opstr + dumpOperand(ops[x],constants);
  }

  return opstr;
}

size_t PDG::hashSlice(
  SgAsmX86Instruction *insn, size_t nHashFunc, std::vector<unsigned int> & hashes) const
{
  Slice s;
  std::string slice_str = getSlice(insn,s);
  size_t count = s.size();

  SDEBUG << "Slice string: " << slice_str << LEND;

  // The seed for each hash function is a hash function number concatenated
  // to the mnem_str string
  for (size_t x = 0; x < nHashFunc; x++ ) {
    std::ostringstream convert;
    convert << x;
    std::string temp = slice_str + convert.str();
    MD5 md5(temp);
    std::vector<uint8_t> bytes = md5.finalize().bytes();

    // Really?  Just the first four bytes of the hash?  Ick.  If we need to convert it to an
    // int, we could have used a lighter weight hash than MD5 and the results migth have even
    // been better.  To make matter even worse, the previous implementation was hardware
    // architecture size and byte order dependent until we hardcoded the order of the bytes.

    uint32_t b0 = (uint32_t)bytes[0];
    uint32_t b1 = (uint32_t)bytes[1] << 8;
    uint32_t b2 = (uint32_t)bytes[2] << 16;
    uint32_t b3 = (uint32_t)bytes[3] << 24;

    unsigned int first_dword = b0 + b1 + b2 + b3;
    hashes.push_back(first_dword);
  }

  return count;
}

// Return the number of instructions in the entire function, by summing each basic block.
// Private.  Called only from getWeightedMaxHash().
size_t PDG::getNumInstr() const {
  size_t c = 0;
  for (SgAsmStatement* bs : fd->get_func()->get_statementList()) {
    SgAsmBlock *bb = isSgAsmBlock(bs);
    assert(bb);
    SgAsmStatementPtrList & insns = bb->get_statementList();
    c += insns.size();
  }
  return c;
}

// Computed the weighted max hash (PDG hash) for a function.  Public because it's called from
// FunctionDescriptor::get_pdg_hash().
std::string PDG::getWeightedMaxHash(size_t nHashFunc) const {
  using UIntVector = std::vector<unsigned int>;
  std::vector<UIntVector> slice_hashes;
  size_t ninstr = getNumInstr();
  size_t slice_num = 0;
  // Hash of the empty string.
  if (ninstr == 0) return std::string("D41D8CD98F00B204E9800998ECF8427E");

  for (SgAsmStatement* bs : fd->get_func()->get_statementList()) {
    SgAsmBlock *bb = isSgAsmBlock(bs);
    assert(bb);

    for (SgAsmStatement* is : bb->get_statementList()) {
      SgAsmX86Instruction *insn = isSgAsmX86Instruction(is);
      UIntVector hashes;

      STRACE << "=============================================================" << LEND;
      STRACE << "Instruction: " << debug_instruction(insn) << LEND;

      size_t count = hashSlice(insn,nHashFunc,hashes);
      if (count == 0) continue;
      float weight = (float)count/(float)ninstr;
      if (!(weight <= 1 && weight > 0)) {
        SERROR << "PDG hash weight is improperly bounded: " << weight << LEND;
        weight = 1;
      }

      // Weight is the num instructions in slice / total num of instructions in function.
      // Weighted hash is weight * (hash of concatenated mnemonics of all instructions within
      // the slice).
      STRACE << "Slice # " << slice_num++ << " Weight " << weight
             << " instruction count " << count << " total " << ninstr << LEND;

      for (size_t j = 0; j < nHashFunc; j++) {
        hashes[j] = weight * hashes[j];
        STRACE << "Weighted hash " << j << " " << hashes[j] << LEND;
      }
      STRACE << "=============================================================" << LEND;

      slice_hashes.push_back(hashes);
    }
  }

  std::ostringstream convert;
  for (size_t y = 0; y < nHashFunc; y++) {
    unsigned int max = 0;
    //unsigned int max_index = 0;

    // Find the maximums for each hash function across all slices
    for (size_t x = 0; x < slice_hashes.size(); x++) {
      if (slice_hashes[x][y] > max) {
        max = slice_hashes[x][y];
        //max_index = x;
      }
    }

    // SDEBUG << "Max for hash function #" << y << " : " << max << " from slice " << max_index << LEND;
    convert << max;
  }

  // Return the MD5 of the concatenated hash functions
  return MD5(convert.str()).finalize().str();
}

// Cory's summary of Wes' backward slice algorithm...  Passed an instruction (insn) and an
// abstract access (aa) and some extra baggage.  Make a nearly complete copy of the defuse
// object for no good reason.  Two loops, one for reads[insn] and the other for writes[insn]
// which are very similar, where the purpose appears to be to prevent endless recursion when an
// instruction both reads and writes an address?  If we're not an LEA instruction, then for
// each operand do either: 1. If the operand is a constant add the instruction to the output,
// and return.  2. If the operand is for memory or a register recurse with the new operand.  If
// we are an LEA instruction, filter out local stack addresses by adding the instruction to the
// output and returning.  Then there's a comment that claims that there are 3 remaining
// scenarios for where the aa came from: 1. an instruction in this function created it.  2. It
// was passed to this function as a parameter. 3. It was returned to this function by a call.
// Set a boolean indicating if aa is possibly a parameter.  Limit recursion depth to what the
// caller requested.  Add all callers of the current function to a set.  For memory parameters,
// call findPushParam() and then recurse into each caller.  For register parameters, reach into
// the caller's PDG and find the last instruction to write to the register, and then recurse on
// it.  Handle return values by looking for symbolic value comments like "RC_of_".  Reach into
// the PDG for the called function, find the instruction that wrote to the return code, and
// then recurse.  The final case handles scenario 1 (locally defined value) by simply
// recursing.  Find pushParam appeared to use the logic that ESP was initialized to zero to
// determine whether a memory access looked like a parameter.

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
