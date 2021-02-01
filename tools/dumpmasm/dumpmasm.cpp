// Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include <rose.h>
#include <libpharos/misc.hpp>
#include <libpharos/masm.hpp>
#include <libpharos/options.hpp>
#include <libpharos/riscops.hpp>
#include <libpharos/descriptors.hpp>

using namespace pharos;

// These options are all bogus right now.  FIXME!
ProgOptDesc dumpmasm_options() {
  namespace po = boost::program_options;

  ProgOptDesc masmopt("DumpMASM options");
  masmopt.add_options()
    ("format",
     po::value<std::string>(),
     "write output in specified format")
    ;
  return masmopt;
}

void
csv_output_insn(const P2::Partitioner& partitioner, const P2::AddressUser& au)
{
  // If the address user is not a basic block/instruction we're done.
  if (!au.isBasicBlock()) return;

  SgAsmInstruction* insn = au.insn();
  if (!insn) {
    GERROR << "Basic block address user had a NULL instruction pointer?" << LEND;
    return;
  }
  std::string opbytes = debug_opcode_bytes(insn->get_raw_bytes(), 99999);

  std::string opstr = "";
  SgAsmOperandList *oplist = insn->get_operandList();
  if (!oplist) {
    GERROR << "NULL oplist pointer?" << LEND;
    return;
  }
  else {
    SgAsmExpressionPtrList& elist = oplist->get_operands();
    for (SgAsmExpressionPtrList::iterator exp = elist.begin(); exp != elist.end(); ++exp) {
      opstr.append(masm_unparseX86Expression(*exp, NULL).c_str());
      if(exp != elist.end() - 1)
        opstr.append(", ");
    }
  }

  for (const P2::BasicBlock::Ptr& bb : au.basicBlocks()) {
    if (!bb) {
      GERROR << "NULL basic block pointer at instruction address "
             << addr_str(insn->get_address()) << LEND;
      continue;
    }

    //std::vector<P2::Function::Ptr> funcs = partitioner.functionsOwningBasicBlock(insn->get_address());
    std::vector<P2::Function::Ptr> funcs = partitioner.functionsOwningBasicBlock(bb->address());
    for (const P2::Function::Ptr& func : funcs) {
      if (!func) {
        GERROR << "NULL function pointer in basic block?" << LEND;
        continue;
      }
      std::cout << "\"PART\"," << addr_str(insn->get_address())
                << ",\"INSN\"," << addr_str(func->address()) << ",\""
                << opbytes << "\",\""
                << insn->get_mnemonic().c_str() << "\",\""
                << opstr << "\"" << LEND;
    }
  }
}

void
csv_output_data(const P2::Partitioner& partitioner, const P2::AddressUser& au)
{
  if (!au.isDataBlock()) return;

  const P2::DataBlock::Ptr& db = au.dataBlock();

  if (!db) {
    GERROR << "Owned datablock had a NULL data block pointer?" << LEND;
    return;
  }

  std::ostringstream os;
  Memory mem(partitioner.memoryMap());
  std::string bytes = mem.read_hex_string(db->address(), Bytes(db->size()));

  std::vector<P2::Function::Ptr> const & funcs = db->attachedFunctionOwners();
  if (funcs.size() == 0) {
    std::cout << "\"PART\"," << addr_str(db->address())
              << ",\"DATA\"," << addr_str(0) << ",\""
              << bytes << "\",\"db\",\"???\"" << LEND;
  }
  else {
    for (const P2::Function::Ptr& func : funcs) {
      if (!func) {
        GERROR << "NULL function pointer in data block?" << LEND;
        continue;
      }
      std::cout << "\"PART\"," << addr_str(db->address())
                << ",\"DATA\"," << addr_str(func->address()) << ",\""
                << bytes << "\",\"db\",\"???\"" << LEND;
    }
  }
}

void csv_output_flow(const ProgramDependencyGraph& pdg_graph)
{
  const ProgramDependencyGraph::Vertex& i = *(pdg_graph.get_indeterminate());

  for (auto edge : pdg_graph.edges()) {
    const PD::PDGVertex& source = edge.source()->value();

    // Report the indeterminate target vertex a little differently.
    std::string target_str;
    if (edge.target()->id() == i.id()) {
      target_str = "\"UNKNOWN\"";
    }
    else {
      const PD::PDGVertex& target = edge.target()->value();
      target_str = addr_str(target.get_address());
    }

    const PD::PDGEdge& pedge = edge.value();
    PD::PDGEdgeType etype = pedge.get_type();
    std::string type_str;
    if (etype == PD::E_CALL)                 type_str = "CALL";
    else if (etype == PD::E_INDIRECT_CALL)   type_str = "ICALL";
    else if (etype == PD::E_FALLTHRU)        type_str = "FALLTHRU";
    else if (etype == PD::E_BRANCH)          type_str = "BRANCH";
    else if (etype == PD::E_INDIRECT_BRANCH) type_str = "IBRANCH";
    else if (etype == PD::E_REPEAT)          type_str = "REPEAT";
    else if (etype == PD::E_RETURN)          type_str = "RETURN";
    else if (etype == PD::E_NOT_TAKEN)       type_str = "NOT_TAKEN";
    else if (etype == PD::E_CALL_FALLTHRU)   type_str = "CALL_FALL";
    else                                     type_str = "OTHER";

    std::cout << "\"FLOW\"," << addr_str(source.get_address()) << ","
              << target_str << ",\"" << type_str << "\"" << LEND;
  }
}

int dumpmasm_main(int argc, char* argv[])
{
  ProgOptDesc dmod = dumpmasm_options();
  ProgOptDesc csod = cert_standard_options();
  dmod.add(csod);
  ProgOptVarMap vm = parse_cert_options(argc, argv, dmod);

  // Find calls, functions, and imports.
  DescriptorSet ds(vm);

  std::string format = "csv";
  if (vm.count("format")) {
    format = vm["format"].as<std::string>();
  }

  const P2::Partitioner& partitioner = ds.get_partitioner();
  const P2::AddressUsageMap& aum = partitioner.aum();

  // The address users
  auto users = aum.overlapping(aum.hull()).addressUsers();
  //P2::AddressUsers& users = aum.overlapping(aum.hull()).addressUsers();
  for (const P2::AddressUser& au : users) {
    csv_output_insn(partitioner, au);
    csv_output_data(partitioner, au);
    if (!au.isBasicBlock() && !au.isDataBlock()) {
      GERROR << "Address user is neither a basic block nor a data block." << LEND;
    }
  }
  csv_output_flow(ds.get_new_pdg_graph());

  OINFO << "Dumpmasm completed successfully." << LEND;

  return 0;
}

int main(int argc, char* argv[]) {
  return pharos_main("MASM", dumpmasm_main, argc, argv);
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
