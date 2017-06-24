// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#include <rose.h>
#include <libpharos/misc.hpp>
#include <libpharos/masm.hpp>
#include <libpharos/options.hpp>
#include <libpharos/riscops.hpp>
#include <libpharos/descriptors.hpp>

using namespace pharos;

// The global CERT message facility.
Sawyer::Message::Facility glog("MASM");

ProgOptDesc dumpmasm_options() {
  namespace po = boost::program_options;

  ProgOptDesc masmopt("Dump MASM v0.02 options");
  masmopt.add_options()
    ("hex-bytes,h",
     po::value<int>(),
     "number of hex bytes to show per instruction")
    ("basic-block-lines,l",
     "split basic blocks with lines")
    ("format",
     po::value<std::string>(),
     "write output in specified format")
    ("reasons,r",
     "split basic blocks with lines")
    ;
  return masmopt;
}

using Rose::BinaryAnalysis::AsmUnparser;

class CSVAsmUnparser: public AsmUnparser {
public:
  CSVAsmUnparser() : AsmUnparser() {
    init();
  }

  class InsnUnparser: public UnparserCallback {
  public:
    virtual bool operator()(bool enabled, const InsnArgs &args);
  } insn_unparser;

  class StaticDataUnparser: public UnparserCallback {
  public:
    virtual bool operator()(bool enabled, const StaticDataArgs &args);
  } data_unparser;

  virtual void init();
};

void CSVAsmUnparser::init() {
  // Clear the existing lists.
  insn_callbacks.clear();
  basicblock_callbacks.clear();
  staticdata_callbacks.clear();
  datablock_callbacks.clear();
  function_callbacks.clear();
  interp_callbacks.clear();

  organization = ORGANIZED_BY_ADDRESS;

  // We only need to callbacks for the CSV format (instruction and static data).
  insn_callbacks.unparse
    .append(&insn_unparser);

  staticdata_callbacks.unparse
    .append(&data_unparser);
}

bool
CSVAsmUnparser::InsnUnparser::operator()(bool enabled, const InsnArgs &args)
{
  if (enabled) {
    SgAsmInstruction* insn = args.insn;
    SgAsmFunction *func = SageInterface::getEnclosingNode<SgAsmFunction>(insn);
    std::string opbytes = debug_opcode_bytes(insn->get_raw_bytes(), 99999);

    SgAsmOperandList *oplist = insn->get_operandList();
    SgAsmExpressionPtrList& elist = oplist->get_operands();
    std::string opstr = "";
    for (SgAsmExpressionPtrList::iterator exp = elist.begin(); exp != elist.end(); ++exp) {
      opstr.append(masm_unparseX86Expression(*exp, NULL).c_str());
      if(exp != elist.end() -1)
        opstr.append(", ");
    }

    args.output << addr_str(insn->get_address()) << ",\"INSN\","
                << addr_str(func->get_entry_va()) << ",\""
                << opbytes << "\",\""
                << insn->get_mnemonic().c_str() << "\",\""
                << opstr << "\"" << LEND;
  }
  return enabled;
}

bool
CSVAsmUnparser::StaticDataUnparser::operator()(bool enabled, const StaticDataArgs &args)
{
  if (enabled) {
    SgAsmBlock *block = isSgAsmBlock(args.data->get_parent()); // look only to immediate parent
    SgAsmFunction *func = SageInterface::getEnclosingNode<SgAsmFunction>(block);
    std::string str_repr = "---";
    std::string opbytes = debug_opcode_bytes(args.data->get_raw_bytes(), args.data->get_size());
    std::string dtype = "DATA";
    std::string mnemonic = "db";
    std::string opstr = "???";
    rose_addr_t entry_va = func->get_entry_va();

    args.output << addr_str(args.data->get_address()) << ",\"" << dtype << "\","
                << addr_str(entry_va) << ",\""
                << opbytes << "\",\""
                << mnemonic << "\",\""
                << opstr << "\"" << LEND;
  }
  return enabled;
}

// This is nothing more than a reminder to create a real IDA format unparser.   Cory
class IDAAsmUnparser: public AsmUnparser {
public:
  size_t op_code_bytes;
  bool stack_pointer;

  IDAAsmUnparser() : AsmUnparser() {
    init();
  }
  virtual void init();
};

void IDAAsmUnparser::init() {
  organization = ORGANIZED_BY_ADDRESS;

  insn_callbacks.pre
    .append(&insnBlockSeparation)           /* used only for ORGANIZED_BY_ADDRESS */
    .append(&insnSkipBackBegin)             /* used only for ORGANIZED_BY_ADDRESS */
    .append(&insnFuncEntry)                 /* used only for ORGANIZED_BY_ADDRESS */
    .append(&insnRawBytes)
    .append(&insnBlockEntry)                /* used only for ORGANIZED_BY_ADDRESS */
    .append(&insnStackDelta);
  insn_callbacks.unparse
    .append(&insnBody);
  insn_callbacks.post
    .append(&insnNoEffect)
    .append(&insnComment)
    .append(&insnLineTermination)
    .append(&insnSkipBackEnd);              /* used only for ORGANIZED_BY_ADDRESS */

  basicblock_callbacks.pre
    .append(&basicBlockReasons)
    .append(&basicBlockPredecessors);
  basicblock_callbacks.unparse
    .append(&basicBlockBody);               /* used only for ORGANIZED_BY_AST */
  basicblock_callbacks.post
    .append(&basicBlockOutgoingStackDelta)
    .append(&basicBlockSuccessors)
    .append(&basicBlockLineTermination)
    .append(&basicBlockCleanup);

  staticdata_callbacks.pre
    .append(&staticDataBlockSeparation)     /* used only for ORGANIZED_BY_ADDRESS */
    .append(&staticDataSkipBackBegin)       /* used only for ORGANIZED_BY_ADDRESS */
    .append(&staticDataRawBytes)
    .append(&staticDataBlockEntry);         /* used only for ORGANIZED_BY_ADDRESS */
  staticdata_callbacks.unparse
    .append(&staticDataDetails)
    .append(&staticDataComment);
  staticdata_callbacks.post
    .append(&staticDataLineTermination)
    .append(&staticDataDisassembler)
    .append(&staticDataSkipBackEnd);        /* used only for ORGANIZED_BY_ADDRESS */

  datablock_callbacks.unparse
    .append(&dataBlockBody)                 /* used only for ORGANIZED_BY_AST */
    .append(&dataBlockLineTermination);

  function_callbacks.pre
    .append(&functionEntryAddress)
    .append(&functionSeparator)
    .append(&functionReasons)
    .append(&functionName)
    .append(&functionLineTermination)
    .append(&functionComment)
    .append(&functionPredecessors)
    .append(&functionSuccessors)
    .append(&functionAttributes)
    .append(&functionLineTermination);
  function_callbacks.unparse
    .append(&functionBody);                 /* used only for ORGANIZED_BY_AST */

  interp_callbacks.pre
    .append(&interpName);
  interp_callbacks.unparse
    .append(&interpBody);
}

int main(int argc, char* argv[])
{
  DebugDisasm debug_disassembly;
  // We want 8 bytes of hexadecimal op-codes.
  debug_disassembly.hex_bytes = 8;
  //debug_disassembly.basic_block_lines = false;
  //debug_disassembly.show_reasons = false;

  ProgOptDesc dmod = dumpmasm_options();
  ProgOptDesc csod = cert_standard_options();
  dmod.add(csod);
  ProgOptVarMap vm = parse_cert_options(argc, argv, dmod);

  // Find calls, functions, and imports.
  DescriptorSet ds(vm);
  SgAsmInterpretation* interp = ds.get_interp();
  if (interp == NULL) {
    GFATAL << "Unable to analyze file (no executable content found)." << LEND;
    return EXIT_FAILURE;
  }

  // A lot of things have changed since Cory initially wrote the first dumpmasm implementation.
  // Now for better compatability with the rest of our infrastructure, I think I'd like to use
  // the function descriptors in the descriptor set.  This in turn should probably be using the
  // Partitioner2 infrastructure, which is why I'm writing this code.  We should also override
  // the unparser to produce a truly MASM compliant unparser.  For my immediate needs, the
  // default ROSE unparser AST traversal is more complete, and sufficient.
  if (vm.count("format")) {
    std::string format = vm["format"].as<std::string>();

    if (format == "csv") {
      CSVAsmUnparser unparser;
      unparser.unparse(std::cout, interp);
    }
    else if (format == "ida") {
      IDAAsmUnparser unparser;
      unparser.unparse(std::cout, interp);
    }
    else if (format == "rose") {
      AsmUnparser unparser;
      unparser.unparse(std::cout, interp);
    }
  }
  else {
    // This is the old way of doing it.  It should be replaced with the various formats
    // above, and the useful options integrated into all formats.  Eventually, these can
    // become options on the standard recursiveDisassemble, or we can find a way to
    // intergrate most of that code into our custom tool as well.
    if (vm.count("hex-bytes")) {
      debug_disassembly.hex_bytes = vm["hex-bytes"].as<int>();
      OINFO << "Showing " << debug_disassembly.hex_bytes << " hex bytes per instruction." << LEND;
    }
    if (vm.count("basic-block-lines")) {
      debug_disassembly.basic_block_lines = true;
      OINFO << "Displaying basic block lines." << LEND;
    }
    if (vm.count("reasons")) {
      debug_disassembly.show_reasons = true;
      OINFO << "Displaying basic block reasons."<< LEND;
    }

    debug_disassembly.target_addrs = option_addr_list(vm, "include-func");

    // Call the traversal starting at the project node of the AST
    debug_disassembly.traverse(interp, preorder);
  }
  global_rops.reset();
  exit(0);
}
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
