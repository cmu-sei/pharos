// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

// For timing our execution.
#include <time.h>
#include <unistd.h>

#include <rose.h>
#include <YicesSolver.h>
#include <BinaryLoader.h>

#include <MemoryMap.h>
#include <Sawyer/ProgressBar.h>
#include <integerOps.h>

#include "misc.hpp"
#include "options.hpp"
#include "partitioner.hpp"
#include "util.hpp"

#include <cxxabi.h>
extern "C" {
#include <execinfo.h>
}

// Get the message levels from Sawyer::Message::Common.
using namespace Sawyer::Message::Common;

typedef rose::BinaryAnalysis::YicesSolver YicesSolver;
typedef std::vector<rose_addr_t> AddrVector;

// This ought to be a method on Register Descriptor...
bool RegisterDescriptorLtCmp(const RegisterDescriptor a, const RegisterDescriptor b) {
  if (a.get_major() == b.get_major()) {
    if (a.get_major() == x86_regclass_flags)
      return a.get_offset() < b.get_offset();
    else return a.get_minor() < b.get_minor();
  } else return a.get_major() < b.get_major();
}

// Compute the elapsed time between two timespecs.
double tdiff(timespec start, timespec end)
{
  timespec temp;
  if ((end.tv_nsec - start.tv_nsec) < 0) {
    temp.tv_sec = end.tv_sec - start.tv_sec - 1;
    temp.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
  } else {
    temp.tv_sec = end.tv_sec - start.tv_sec;
    temp.tv_nsec = end.tv_nsec - start.tv_nsec;
  }
  double elapsed = temp.tv_sec + (double(temp.tv_nsec) / 1000000000.0);
  return elapsed;
}

void customize_message_facility(ProgOptVarMap& vm, Sawyer::Message::Facility facility, std::string name) {
  // Create a sink associated with standard output.
  Sawyer::Message::FdSinkPtr mout = Sawyer::Message::FdSink::instance(1);
  if (!color_terminal() || vm.count("batch")) {
    ODEBUG << "Forcing non-color logging." << LEND;
    mout->overridePropertiesNS().useColor = false;
  }
  // Create a prefix object so that we can modify prefix properties.
  Sawyer::Message::PrefixPtr prefix = Sawyer::Message::Prefix::instance();
  prefix = prefix->showProgramName(false)->showElapsedTime(false);
  // It's sometimes useful to also disable the faciltiy and importance.
  //prefix = prefix->showFacilityName(Sawyer::Message::NEVER)->showImportance(false);

  // Get the options logging facility working with the standard options.
  facility.renameStreams(name);
  facility.initStreams(mout->prefix(prefix));
}

static SgAsmBlock *
buildAst(P2::Engine &engine, const P2::Partitioner &partitioner) {
    static SgAsmBlock *gblock = NULL;
    if (NULL==gblock)
        gblock = P2::Modules::buildAst(partitioner, engine.interpretation());
    return gblock;
}

SgAsmInterpretation* get_partitioner2_interpretation(ProgOptVarMap& vm) {
  timespec start_ts;

  clock_gettime(CLOCK_REALTIME, &start_ts);
  OINFO << "Using experimental version two of function partitioner!" << LEND;

  // Use a partitioning engine since this makes this tool much easier to write.
  //CERTEngine engine;
  P2::Engine engine;
  engine.memoryIsExecutable(true);
  engine.deExecuteZeros(64);
  // It's VERY unclear right now whether enabling semantics helps or hinders.  There are some
  // known bugs in enabling it, probably because it hasn't been well tested (Robb has it off by
  // default because of the performance impact).  On the Objdigger test suite, it doesn't
  // impact the object detections regardless of the setting, but it does add and remove a wide
  // variety of other messages about unexpected conditions.
  engine.usingSemantics(true);

  // Enable Robb's standard thunk splitting logic.
  engine.splittingThunks(true);
  // Assume that functions always return.
  engine.functionReturnAnalysis(rose::BinaryAnalysis::Partitioner2::Engine::MAYRETURN_ALWAYS_YES);

  // Parse the command-line
  std::vector<std::string> specimen_names;
  specimen_names.push_back(vm["file"].as<std::string>());

  if (specimen_names.empty())
    throw std::runtime_error("no specimen specified; see --help");

  // Load the specimen as raw data or an ELF or PE container.
  MemoryMap map = engine.loadSpecimens(specimen_names);
  SgAsmInterpretation *interp = engine.interpretation();
  // Applies memoryIsExecutable and deExecutesZeros() settings.
  engine.adjustMemoryMap();

  // This changes the permissions of all segments in the program to add the permissions in the
  // first parameter, and remove the permissions in the second parameter.
  //engine.memoryMap().dump(std::cerr);
  // Retired in favor of memoryisExecutable() below.
  //engine.memoryMap().any().changeAccess(MemoryMap::READ_WRITE_EXECUTE, MemoryMap::NO_ACCESS);
  //engine.memoryMap().dump(std::cerr);

  // Create a partitioner that's tuned for a certain architecture, and then tune it even more
  // depending on our command-line.
  P2::Partitioner partitioner = engine.createPartitioner();
  // Enable our custom CFG debugger.
  // partitioner.cfgAdjustmentCallbacks().append(Monitor::instance());
  size_t arch_bits = partitioner.instructionProvider().instructionPointerRegister().get_nbits();
  if (arch_bits != 32) {
    OFATAL << "Only 32-bit Windows PE executables are supported at this time." << LEND;
    return NULL;
  }

  customize_message_facility(vm, P2::mlog, "PRT2");
  P2::mlog[Sawyer::Message::FATAL].enable();
  P2::mlog[Sawyer::Message::ERROR].enable();
  P2::mlog[Sawyer::Message::MARCH].enable();
  if (vm.count("pdebug")) {
    ODEBUG << "Partitioner debugging enabled." << LEND;
    // Set the time limit to zero seconds to report everything.
    P2::mlog[Sawyer::Message::WARN].enable();
    P2::mlog[Sawyer::Message::INFO].enable();
    P2::mlog[Sawyer::Message::DEBUG].enable();
  }

  // Show what we'll be working on (stdout for the record, and diagnostics also)
  //partitioner.memoryMap().dump(mlog[INFO]);

  // Run the partitioner
  engine.runPartitioner(partitioner);
  // Enable progress bars only if the output is to a terminal...
  if (isatty(1) && vm.count("batch") == 0) {
    partitioner.enableProgressReports(true);
  }
  if (partitioner.functions().empty() && engine.startingVas().empty()) {
    OINFO <<"no starting points for recursive disassembly; perhaps you need --start?\n";
    return NULL;
  }

  // We should probably save an instruction provider in the global descriptor set instead of
  // making a map of addresses to instructions in the global descriptor set.  Unfortunately,
  // this approach is much less convenient in Partitioner1 than in Partitioner2, so it'll
  // probably have to wait until we retire Partitioner1.

  // global_descriptor_set.instruction_provider = &(partitioner.instructionProvider());
  // Don't create new instructions after this point...
  // global_descriptor_set.instruction_provider->disableDisassembler();

  SgAsmBlock* block = buildAst(engine, partitioner);

  GTRACE << "done calling partitioner2" << LEND;

  GTRACE << "calling set_global_block" << LEND;
  interp->set_global_block(block);
  GTRACE << "done calling set_global_block, calling set_parent" << LEND;
  block->set_parent(interp);
  GTRACE << "done calling set_parent" << LEND;

  timespec end_ts;
  clock_gettime(CLOCK_REALTIME, &end_ts);
  OINFO << "ROSE disassembly complete, " << tdiff(start_ts, end_ts) << " seconds elapsed." << LEND;

  return interp;
}

// Build a ROSE project from a specified set of command line options.
// This is now the "standard" way to initiliaze our front end.
SgAsmInterpretation* get_interpretation(ProgOptVarMap& vm) {
  bool p2 = vm.count("partitioner2");
  if (!p2) {
    auto v = vm.config().path_get("pharos.partitioner");
    p2 = v && (v.Scalar() == "2");
  }
  if (p2) {
    return get_partitioner2_interpretation(vm);
  }

  timespec start_ts;
  clock_gettime(CLOCK_REALTIME, &start_ts);

  // apparently passing the '-rose:partitioner_config FILENAME' along to
  // frontend doesn't suffice, we need to configure our Partitioner as well?
  //bool grab_partitioner_config(false);

  SgProject *project = NULL;
  SgAsmInterpretation *interp = NULL;
  try {
    GTRACE << "Calling ROSE frontend()" << LEND;
    std::vector<std::string> args;
    args.push_back("bogus");
    args.push_back("-rose:read_executable_file_format_only");
    args.push_back(vm["file"].as<std::string>());
    // Annoyingly, this still issues assertions for things as predicatable as file names that
    // do not exist.  When given a C++ source file, it asserts on not having been compiled with
    // the C++ frontend.  If we want graceful error handling, we'll need to replace this call
    // with our own code to do whatever it does...
    project = frontend(args);
    GTRACE << "Returned from calling ROSE frontend()" << LEND;
    if (project == NULL) {
      OFATAL << "Failed to obtain ROSE project handle." << LEND;
      return NULL;
    }

    // Find the PE32 interpretation.  Skip the 16-bit DOS stub.
    interp = GetWin32Interpretation(project);
    if (interp == NULL) {
      OFATAL << "Failed to obtain PE32 interpretation." << LEND;
      return NULL;
    }

    // Create a sink associated with standard output.
    Sawyer::Message::FdSinkPtr mout = Sawyer::Message::FdSink::instance(1);
    if (!color_terminal() || vm.count("batch")) {
      mout->overridePropertiesNS().useColor = false;
    }
    // Create a prefix object so that we can modify prefix properties.
    Sawyer::Message::PrefixPtr prefix = Sawyer::Message::Prefix::instance();
    prefix = prefix->showProgramName(false)->showElapsedTime(false);

    // Clear the memory map if we already have one?  Cory asks, why would we have one?
    MemoryMap *map = interp->get_map();
    if (map != NULL) map->clear();
    // (Re)load the file? It's unclear to Cory what this code really does...
    BinaryLoader *loader = BinaryLoader::lookup(interp)->clone();

    // Rename the loader streams so the formatting matches ours.
    loader->mlog.renameStreams("LOAD");
    // Apply the prefix to the loader log stream.
    loader->mlog.initStreams(mout->prefix(prefix));
    // Enable errors and warnings?  Not needed?
    loader->mlog[Sawyer::Message::FATAL].enable();
    loader->mlog[Sawyer::Message::ERROR].enable();
    // While MARCH is still in INFO, we need this for compatability.
    loader->mlog[Sawyer::Message::WARN].enable();
    loader->mlog[Sawyer::Message::INFO].enable();

    if (vm.count("ldebug")) {
      // Loader debugging is currently broken until we learn more about Sawyer.
      // Log loader messages to standard out (although in Robb's format, not ours).
      //loader->mlog.initStreams(Sawyer::Message::FdSink::instance(1));
    }

    // Make the progress bar a little more responsive...
    Sawyer::ProgressBarSettings::initialDelay(2.0);
    Sawyer::ProgressBarSettings::minimumUpdateInterval(0.5);

    loader->set_perform_remap(true);
    loader->load(interp);

    // Build (clone?) the disassembler
    GTRACE << "calling ROSE Disassembler::lookup" << LEND;
    RoseDisassembler *disassembler = RoseDisassembler::lookup(interp)->clone();
    GTRACE << "returned from calling ROSE Disassembler::lookup" << LEND;
    GTRACE << "calling ROSE Disassembler::set_search, etc" << LEND;
    if (disassembler->get_wordsize() != 4) {
      OFATAL << "Only 32-bit Windows PE executables are supported at this time." << LEND;
      return NULL;
    }

    // Now get the map for real, and complain if we can't.
    map = interp->get_map();
    if (map == NULL) {
      OFATAL << "Failed to get memory map." << LEND;
      return NULL;
    }

    unsigned insn_search = RoseDisassembler::SEARCH_DEFAULT; // FUNCSYMS + FOLLOWING
    // insn_search |= Disassembler::SEARCH_IMMEDIATE;
    // insn_search |= Disassembler::SEARCH_NONEXE;
    // insn_search |= Disassembler::SEARCH_UNUSED;
    if (vm.count("dsearch")) {
      BOOST_FOREACH(std::string kw, vm["dsearch"].as<StrVector>()) {
        ODEBUG << "Enabling disassembler search criteria '" << kw << "'... (not really)."<< LEND;
      }
    }

    disassembler->set_search(insn_search);
    disassembler->set_alignment(1); // what does this do?

    // Rename the disasembler streams so the formatting matches ours.
    disassembler->mlog.renameStreams("DISA");
    // Apply the prefix to the disassembler log streams.
    disassembler->mlog.initStreams(mout->prefix(prefix));
    // Enable errors and warnings?  Not needed?
    disassembler->mlog[Sawyer::Message::FATAL].enable();
    disassembler->mlog[Sawyer::Message::ERROR].enable();
    // Enable progress bars only if the output is to a terminal...
    if (isatty(1) && vm.count("batch") == 0) {
      disassembler->mlog[Sawyer::Message::MARCH].enable();
    }

    if (vm.count("ddebug")) {
      ODEBUG << "Disassembler debugging enabled." << LEND;
      // Set the time limit to zero seconds to report everything.
      disassembler->set_progress_reporting(0.0);
      disassembler->mlog[Sawyer::Message::WARN].enable();
      disassembler->mlog[Sawyer::Message::INFO].enable();
    }
    else {
      disassembler->set_progress_reporting(120.0);
    }

    // We want the disassembler to look at memory addresses that have ANY permission, not just
    // those that are marked executable.  So we do this by default, unless the user requests
    // that we respect permissions.  This is further complicated by the fact that the argument
    // to set_protection() is a MASK for the required bits, and ROSE defaults to respecting,
    // rather than ignoring...
    if (vm.count("respect_protection") == 0) {
      disassembler->set_protection(0);
    }

    GTRACE << "returned from calling ROSE Disassembler::set_search, etc" << LEND;

    GTRACE << "setting up the partitioner" << LEND;
    // set up the partitioner
    RosePartitioner *partitioner(NULL);
    bool stockpart = vm.count("stockpart");
    if (!stockpart) {
      auto v = vm.config()["partitioner"];
      stockpart = v && (v.Scalar() == "stock");
    }
    if (stockpart) {
      ODEBUG << "Using stock ROSE partitioner instead of custom partitioner." << LEND;
      partitioner = new RosePartitioner();
    }
    else {
      partitioner = new CERTPartitioner();
    }

    //unsigned func_search = SgAsmFunction::FUNC_CALL_TARGET |
    // SgAsmFunction::FUNC_CALL_INSN | SgAsmFunction::FUNC_ENTRY_POINT |
    // SgAsmFunction::FUNC_IMPORT | SgAsmFunction::FUNC_SYMBOL;
    unsigned func_search = SgAsmFunction::FUNC_DEFAULT;
    if (vm.count("psearch")) {
      BOOST_FOREACH(std::string kw, vm["psearch"].as<StrVector>()) {
        ODEBUG << "Enabling partitioner search criteria '" << kw << "'... (not really)."<< LEND;
      }
    }
    partitioner->set_search(func_search);

    if (vm.count("pconfig")) {
      std::string pconfig = vm["pconfig"].as<std::string>();
      OINFO << "Loading partitioner config file: " << pconfig << LEND;
      partitioner->load_config(pconfig);
    }
    disassembler->set_partitioner(partitioner);

    // Rename the disasembler streams so the formatting matches ours.
    partitioner->mlog.renameStreams("PART");
    // Apply the prefix to the partitioner log streams.
    partitioner->mlog.initStreams(mout->prefix(prefix));
    // Enable errors and warnings?  Not needed?
    partitioner->mlog[Sawyer::Message::FATAL].enable();
    partitioner->mlog[Sawyer::Message::ERROR].enable();
    // Enable progress bars only if the output is to a terminal...
    if (isatty(1) && vm.count("batch") == 0) {
      partitioner->mlog[Sawyer::Message::MARCH].enable();
    }

    if (vm.count("pdebug")) {
      ODEBUG << "Partitioner debugging enabled." << LEND;
      // Set the time limit to zero seconds to report everything.
      partitioner->set_progress_reporting(0.0);
      partitioner->mlog[Sawyer::Message::WARN].enable();
      partitioner->mlog[Sawyer::Message::INFO].enable();
    }
    else {
      partitioner->set_progress_reporting(120.0);
    }

    // Configure the partitioner logging.

    // It appears that this code forces the creation of certain functions by the disassembler.
    // If that's true we should probably be seeding it with more than just the interpretation
    // enty points.  For example, functions provided in the user's JSON configuration file.
    // Cory also comments that this looks like it should be a partitioner extension, and not
    // here now that we have our own partitioner.
    GTRACE << "setting up the worklist" << LEND;
    // Go through the PE headers and look for entry points
    RoseDisassembler::AddressSet worklist;

    const SgAsmGenericHeaderPtrList &headers = interp->get_headers()->get_headers();
    for (SgAsmGenericHeaderPtrList::const_iterator hi=headers.begin(); hi!=headers.end(); ++hi) {
      // Seed disassembler work list with entry addresses
      SgRVAList entry_rvalist = (*hi)->get_entry_rvas();
      for (size_t i=0; i<entry_rvalist.size(); i++) {
        rose_addr_t entry_va = (*hi)->get_base_va() + entry_rvalist[i].get_rva();
        worklist.insert(entry_va);
        GTRACE << "Added entry_va " << addr_str(entry_va) << " to worklist." << LEND;
      }

      disassembler->search_function_symbols(&worklist, map, *hi);
    }
    GTRACE << "done setting up the worklist" << LEND;

    GTRACE << "calling partitioner" << LEND;
    SgAsmBlock *block  = partitioner->partition(interp, disassembler, map);
    GTRACE << "done calling partitioner" << LEND;

    // There's a new way to get the map of all VAs in program to instructions in the
    // Partitioner2 system, and since we never used the old map anyway, I'm just disabling this
    // features rather than porting it to the new code right now.
    // RoseDisassembler::InstructionMap insns = partitioner->get_instructions();
    // if (insnmap) *insnmap = insns;

    // Link instructions into AST if possible
    GTRACE << "calling set_global_block" << LEND;
    interp->set_global_block(block);
    GTRACE << "done calling set_global_block, calling set_parent" << LEND;
    block->set_parent(interp);
    GTRACE << "done calling set_parent" << LEND;

    delete loader;
    delete disassembler;
    delete partitioner;

  } catch (...) {
    OFATAL << "Caught exception, Rose disassembly failure..." << LEND;
    exit(2);
  }

  timespec end_ts;
  clock_gettime(CLOCK_REALTIME, &end_ts);
  OINFO << "ROSE disassembly complete, " << tdiff(start_ts, end_ts) << " seconds elapsed." << LEND;

  return interp;
}

// This should be turned into a nicer utility function.
SgAsmInterpretation* GetWin32Interpretation(SgProject* project) {
  // Only process the Win32 portion of the executable.
  // BUG? I'd prefer that this method not use querySubTree to obtain this list.
  std::vector<SgNode*> interps = NodeQuery::querySubTree(project, V_SgAsmInterpretation);
  if (interps.size() != 2) {
    OFATAL << "Target executable does not appear to be a valid Win32-PE file." << LEND;
    exit(2);
  }
  SgAsmInterpretation *interp = isSgAsmInterpretation(interps[1]);
  if (interp == NULL) {
    OFATAL << "Target executable does not appear to be a valid Win32-PE file." << LEND;
    exit(3);
  }
  return interp;
}

// This should be a method on SgAsmX86Instruction and possibly on SgAsmInstruction as well.
bool insn_is_call(const SgAsmx86Instruction* insn) {
  if (insn == NULL) return false;
  else if (insn->get_kind() == x86_call) return true;
  else if (insn->get_kind() == x86_farcall) return true;
  else return false;
}

// I think we meant insn_is_call() in all of these cases...
bool insn_is_callNF(const SgAsmx86Instruction* insn) {
  if (insn == NULL) return false;
  else if (insn->get_kind() == x86_call) return true;
  else return false;
}

// This should be a method on SgAsmX86Instruction and possibly on SgAsmInstruction as well.
bool insn_is_jcc(const SgAsmx86Instruction* insn) {
  if (insn == NULL) return false;
  else if (insn->get_kind() >= x86_ja && insn->get_kind() <= x86_js) return true;
  else return false;
}

// This should be a method on SgAsmX86Instruction and possibly on SgAsmInstruction as well.
bool insn_is_branch(const SgAsmx86Instruction* insn) {
  // BUG? No far calls here?
  if (insn_is_callNF(insn)) return true;
  if (insn_is_jcc(insn)) return true;
  else return false;
}

// This should be a method on SgAsmX86Instruction and possibly on SgAsmInstruction as well.
bool insn_is_control_flow(const SgAsmx86Instruction* insn) {
  if (insn == NULL) return false;
  else if (insn->get_kind() == x86_ret) return true;
  else if (insn->get_kind() == x86_call) return true;
  else if (insn->get_kind() == x86_jmp) return true;
  else if (insn->get_kind() == x86_farcall) return true;
  else if (insn->get_kind() >= x86_ja && insn->get_kind() <= x86_js) return true;
  else return false;
}

// Get the fallthru address.  This should be one of the successors for every intruction except
// a return.  I don't know if this is the most correct way to do it, and it's possible that
// there should be some assertions for cases like RET, but it's close enough.
rose_addr_t insn_get_fallthru(SgAsmInstruction* insn) {
  return insn->get_address() + insn->get_raw_bytes().size();
}

// This is icky, but better to hide the ickness here than repeat it everywhere that we need
// basic block successors.  The relationship between this and the instruction sucessors is
// still very confusing, and so we'll probably replace this eventually anyway.
AddrSet bb_get_successors(SgAsmBlock* bb) {
  AddrSet result;
  const SgAsmIntegerValuePtrList &targets = bb->get_successors();
  for (SgAsmIntegerValuePtrList::const_iterator tit=targets.begin(); tit!=targets.end(); ++tit) {
    SgAsmBlock *bb_successor = isSgAsmBlock((*tit)->get_baseNode());
    // bb_sucessor was actualy NULL.  I'm not sure why!
    if (bb_successor == NULL) continue;
    result.insert(bb_successor->get_address());
  }
  return result;
}

// This is the counterpart to insn_get_fallthru(), except that here the intention is to return
// the one address that is NOT the fallthru address.  For call instructions that call to
// registers, this could be mutiple targets, but in the case of jumps, there should always be
// one or two non-fallthru successors.  There should probably be more assertions in this code.
// Not used now that I've created bb_get_successors()?
rose_addr_t insn_get_branch_target(SgAsmInstruction* insn) {
  bool complete;
  rose_addr_t fallthru = insn_get_fallthru(insn);
  BOOST_FOREACH(rose_addr_t target, insn->getSuccessors(&complete)) {
    GDEBUG << "INSN successor: " << addr_str(target) << LEND;
    if (target == fallthru) continue;
    else return target;
  }
  assert("No non-fall thru edges found.");
  return 0xDEADBEEF;
}

// Return X for an instruction of the form "jxx [X]".  This code is fairly ugly to be in the
// middle of some largeer algorithm.  Return zero if the instruction is not of the expected
// format.
rose_addr_t insn_get_jump_deref(SgAsmInstruction* insn) {
  SgAsmExpressionPtrList &ops = insn->get_operandList()->get_operands();
  if (ops.size() != 1) return 0;

  SgAsmMemoryReferenceExpression *memref = isSgAsmMemoryReferenceExpression(ops[0]);
  if (memref == NULL) return 0;

  SgAsmIntegerValueExpression *aref = isSgAsmIntegerValueExpression(memref->get_address());
  if (aref == NULL) return 0;

  return aref->get_absoluteValue();
}

SgAsmBlock* insn_get_block(const SgAsmInstruction* insn) {
  if (insn == NULL) return NULL;
  return isSgAsmBlock(insn->get_parent());
}

SgAsmFunction* insn_get_func(const SgAsmInstruction* insn) {
  SgAsmBlock* block = insn_get_block(insn);
  if (block == NULL) return NULL;
  return isSgAsmFunction(block->get_parent());
}

using rose::BinaryAnalysis::SymbolicExpr::OP_ADD;

AddConstantExtractor::AddConstantExtractor(const TreeNodePtr& tn) {
  // By default we weren't well formed.
  well_formed = false;
  constant_portion = 0;
  variable_portion = tn;

  // To be well formed, the tree node must be an internal node.
  InternalNodePtr in = tn->isInteriorNode();
  if (in == NULL) {
    // We must be an leaf node if we're not an internal node.
    LeafNodePtr lp = tn->isLeafNode();
    // If we're a known leaf node, put the constant in the constant portion, and set the
    // variable portion to NULL.
    if (lp->isNumber()) {
      constant_portion = IntegerOps::signExtend2(lp->toInt(), lp->nBits(), 8*sizeof(int64_t));
      variable_portion = TreeNodePtr();
    }
    // If we weren't a known value, the default construction was correct.  Either way, we're done.
    return;
  }

  // To be well formed, we must be an ADD operation.
  if (in->getOperator() != OP_ADD) return;

  // We're going to accumulate all of the value of the expression here except for the constant
  // portion.
  rose::BinaryAnalysis::SymbolicExpr::Nodes values;

  // For each child in the add expression.
  BOOST_FOREACH(const TreeNodePtr& atn, in->children()) {
    LeafNodePtr lp = atn->isLeafNode();
    // We're looking for a constant leaf node.
    if (lp != NULL && lp->isNumber()) {
      // Mark that we found a constant inside the add expression.
      well_formed = true;
      // Cory chose to increase the constant portion by the known value because if there were
      // more than one constant in the expression, we'd want to sum all of the pieces since
      // we're dicarding them all.  This shouldn't happen because the simplifer should only
      // permit one constant in the list, but let's be defensive.
      constant_portion += IntegerOps::signExtend2(lp->toInt(), lp->nBits(), 8*sizeof(int64_t));
    }
    // All other cases become part of the variable portion.
    else {
      values.push_back(atn);
    }
  }

  // If we were well formed, we need to create the variable portion.
  if (well_formed) {
    size_t vars = values.size();
    // If there's no variable portion, we weren't well formed after all.  Set the variable
    // portion to NULL.
    if (vars == 0) {
      well_formed = false;
      variable_portion = TreeNodePtr();
    }
    // If there's exactly one other variable part (a very common case), just return that one
    // value as the variable portion.
    else if (vars == 1) {
      variable_portion = values[0];
    }
    // In other cases, we need to make a new ADD operation from the multiple variable parts.
    else {
      variable_portion = InternalNode::create(tn->nBits(), OP_ADD, values);
    }
  }
}

namespace pharos {

void backtrace(Sawyer::Message::Facility & log, Sawyer::Message::Importance level, int maxlen)
{
  // create and fill the buffer of backtrace addresses
  std::unique_ptr<void *[]> buffer(new void *[maxlen]);
  int n = ::backtrace(buffer.get(), maxlen);

  // get the backtrace as an array of strings
  constexpr auto deleter = [](char **v){ std::free(v); };
  std::unique_ptr<char*[], decltype(deleter)> trace_array(
    backtrace_symbols(buffer.get(), n), deleter);

  // Output the trace array
  log[level] && log[level] << "Backtrace:\n";
  for (int i = 1; i < n; ++i) {
    std::string trace(trace_array[i]);

    // Find the symbol in the trace for demangling
    auto open_paren = trace.find('(');
    if (open_paren != std::string::npos) {
      auto begin_symbol = open_paren + 1;
      auto end_symbol = trace.find_first_of("+)", begin_symbol);
      assert(end_symbol != std::string::npos);
      auto symbol = trace.substr(begin_symbol, end_symbol - begin_symbol);

      // demangle the symbol
      int status;
      constexpr auto delc = [](char *v){ std::free(v); };
      std::unique_ptr<char, decltype(delc)> demangled(
        abi::__cxa_demangle(symbol.c_str(), nullptr, nullptr, &status), delc);

      // re-insert demangled symbol into the trace
      if (demangled) {
        assert(status == 0);
        trace.replace(begin_symbol, end_symbol - begin_symbol,
                       demangled.get());
      }
    }

    // Output the trace
    log[level] && log[level] << "| " << trace << '\n';
  }
  log[level] && log[level] << LEND;
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
