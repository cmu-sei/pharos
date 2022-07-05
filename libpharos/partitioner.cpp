// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#include <stdarg.h>
#include <stdexcept>
#include <fstream>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>

#include "partitioner.hpp"
#include "masm.hpp"
#include "util.hpp"
#include "limit.hpp"
#include "misc.hpp"
#include "options.hpp"

namespace pharos {

namespace bfs = boost::filesystem;
namespace bar = boost::archive;
namespace bio = boost::iostreams;

// This method now uses the new partitioner approach instead of the old AST approach.  This
// allows it to be called from more contexts.  This code is a bare function, so that it can
// be easily called on the stock partitioner as well.
void
report_partitioner_statistics(const P2::Partitioner& partitioner)
{
  size_t num_funcs = partitioner.nFunctions();
  size_t num_bbs = partitioner.nBasicBlocks();
  size_t num_dbs = partitioner.nDataBlocks();
  size_t num_insns = 0;
  size_t num_bytes = 0;

  for (const P2::BasicBlock::Ptr & bb : partitioner.basicBlocks()) {
    for (const SgAsmInstruction *insn : bb->instructions()) {
      num_insns++;
      num_bytes += insn->get_size();
    }
  }

  for (const P2::DataBlock::Ptr & db : partitioner.dataBlocksOverlapping(partitioner.aum().hull())) {
    num_bytes += db->size();
  }

  OINFO << "Partitioned " << num_bytes << " bytes, " << num_insns << " instructions, "
        << num_bbs << " basic blocks, " << num_dbs << " data blocks and "
        << num_funcs << " functions." << LEND;
}

// Just sort of copying and pasting from the ROSE examples here...  We're adding a pattern for
// a common tail-call optimization case where an object pointer in loaded into ECX, then
// adjusted by some offset into the object, and then finally a function is called with a JMP
// instruction.  The JMP is really conceptually a CALL, which is why this code is needed.
P2::ThunkDetection
isX86MovAddJmpThunk(UNUSED const P2::Partitioner &partitioner, const std::vector<SgAsmInstruction*> &insns) {
  if (insns.size() < 3)
    return {};
  SgAsmX86Instruction *mov = isSgAsmX86Instruction(insns[0]);
  if (!mov || mov->get_kind() != x86_mov)
    return {};
  const SgAsmExpressionPtrList &movArgs = mov->get_operandList()->get_operands();
  if (movArgs.size() != 2)
    return {};
  SgAsmDirectRegisterExpression *movArg0 = isSgAsmDirectRegisterExpression(movArgs[0]);
  if (!movArg0 || movArg0->get_descriptor().majorNumber() != x86_regclass_gpr ||
      movArg0->get_descriptor().minorNumber() != Rose::BinaryAnalysis::x86_gpr_cx)
    return {};

  // We didn't bother to restrict the type of the second operand.  It was a memory
  // dereference operation in the case that was encountered, but it's not clear what the
  // general constraint is.  It's probably sufficient that we're loading a value into ECX
  // (which is presumed to be an object pointer).
  //SgAsmIntegerValueExpression *movArg1 = isSgAsmIntegerValueExpression(movArgs[1]);
  //if (!movArg1)
  //    return 0;

  SgAsmX86Instruction *add = isSgAsmX86Instruction(insns[1]);
  if (!add || add->get_kind() != x86_add)
    return {};
  const SgAsmExpressionPtrList &addArgs = add->get_operandList()->get_operands();
  if (addArgs.size() != 2)
    return {};
  SgAsmDirectRegisterExpression *addArg0 = isSgAsmDirectRegisterExpression(addArgs[0]);
  if (!addArg0 || addArg0->get_descriptor().majorNumber() != x86_regclass_gpr ||
      addArg0->get_descriptor().minorNumber() != Rose::BinaryAnalysis::x86_gpr_cx)
    return {};
  SgAsmIntegerValueExpression *addArg1 = isSgAsmIntegerValueExpression(addArgs[1]);
  if (!addArg1)
    return {};

  SgAsmX86Instruction *jmp = isSgAsmX86Instruction(insns[2]);
  if (!jmp || jmp->get_kind() != x86_jmp)
    return {};
  const SgAsmExpressionPtrList &jmpArgs = jmp->get_operandList()->get_operands();
  if (jmpArgs.size() != 1)
    return {};
  SgAsmIntegerValueExpression *jmpArg0 = isSgAsmIntegerValueExpression(jmpArgs[0]);
  if (!jmpArg0)
    return {};
  using namespace std::string_literals;
  return {3, "pharos::isX86MovAddJmpThunk"s};
}

// ===============================================================================================
// Partitioner2
// ===============================================================================================

P2::Partitioner create_partitioner(const ProgOptVarMap& vm, P2::Engine* engine,
                                   std::vector<std::string> const & specimen_names)
{
  using clock = std::chrono::steady_clock;
  using time_point = std::chrono::time_point<clock>;
  using duration = std::chrono::duration<double>;

  // Mark all segments in the program as executable.  This is important in environments such as
  // Windows, where the segments can easily have their permissions altered after loading.
  // Enabling this feature alone in the stock partitioner can cause bad things to happen --
  // such as the creation of very large basic blocks full of zero instructions.
  if (vm.count("mark-executable")) {
    GINFO << "Marking all sections as executable during function partitioning." << LEND;
    engine->memoryIsExecutable(true);
  }

  // This change was required to fix an issue with incorrect computation of opaque predicates
  // that Cory is still trying to fully understand.
  engine->memoryDataAdjustment(P2::DATA_NO_CHANGE);

  // The standard rose approach of marking blocks of zeros as non-excutable doesn't work well,
  // because among other issues, it consumes zeros in valid instructions that are adjacent to
  // other blocks of zeros.  It might be useful to enable temporarily while troublshooting
  // other problems.
  // engine->deExecuteZeros(256);

  // It's VERY unclear right now whether enabling semantics helps or hinders.  There are some
  // known bugs in enabling it, probably because it hasn't been well tested (Robb has it off by
  // default because of the performance impact).  On the Objdigger test suite, it doesn't
  // impact the object detections regardless of the setting, but it does add and remove a wide
  // variety of other messages about unexpected conditions.  It definately affects performance
  // in a negative way, and should optional in some future code.
  bool disable_semantics = vm.count("no-semantics");
  if (!disable_semantics) {
    auto v = vm.config().path_get("pharos.partitioner_semantics");
    disable_semantics = v && (v.as<bool>() == false);
  }
  if (!disable_semantics) {
    GINFO << "Enabling semantic control flow analysis during function partitioning." << LEND;
    engine->usingSemantics(true);
  }
  else {
    GINFO << "Semantic control flow analysis disabled, analysis may be less correct." << LEND;
  }

  // We're leaving post analysis in general on right now, even though we've disabled all of the
  // passes.  We disabled these passes because they take additional CPU and don't provide any
  // benefit since we're not actually using them.
  engine->doingPostAnalysis(false);
  // Assume that functions always return.  We should enable this pass as soon as possible but
  // it led to some differences in our test suite that were complicated and difficult to fix.
  engine->doingPostFunctionMayReturn(false);
  engine->functionReturnAnalysis(Rose::BinaryAnalysis::Partitioner2::MAYRETURN_ALWAYS_YES);
  // We're not using ROSE's stack delta analysis or calling convention analysis because we have
  // our own.  We should consolidate these as soon as possible.
  engine->doingPostFunctionStackDelta(false);
  engine->doingPostCallingConvention(false);
  engine->doingPostFunctionNoop(false);

  // TODO mwd: This is needed to keep things from being exceptionally slow since Rose commit
  // 4f0db690696dcd4c6dfaf898504a75fcd76770a6
  engine->findingInterFunctionCalls(false);

  // We'll handle errors.  We don't want to unilaterally exit.
  engine->exitOnError(false);

  // Enable Robb's standard thunk splitting logic.  Needed for our debug test cases?
  engine->splittingThunks(true);

  // Disable Robb's demangler because it was exiting abruptly on some important files.
  engine->demangleNames(false);

  // Check the specimens
  if (specimen_names.empty()) {
    GFATAL << "no specimen specified; see --help" << LEND;
    std::exit(EXIT_FAILURE);
  }

  // Load the specimen as raw data or an ELF or PE container.
  MemoryMap::Ptr map;
  try {
    map = engine->loadSpecimens(specimen_names);
  } catch (SgAsmExecutableFileFormat::FormatError &e) {
    GFATAL << "Error while loading specimen: " << e.what () << LEND;
    std::exit(EXIT_FAILURE);
  } catch (std::exception const & e) {
    GFATAL << "Error while loading specimen: " << e.what () << LEND;
    std::exit(EXIT_FAILURE);
  }

  // Get the interpretation.
  SgAsmInterpretation* interp = engine->interpretation();

  // Mark the entry point segment as executable (unless the user asked us not to).
  if (vm.count("no-executable-entry") < 1 && interp) {
    for (const SgAsmGenericHeader *fileHeader : interp->get_headers()->get_headers()) {
      for (const rose_rva_t &rva : fileHeader->get_entry_rvas()) {
        // Get the address of the entry point.
        rose_addr_t va = rva.get_rva() + fileHeader->get_base_va();
        // A constraint containing just the entry point address.
        auto segments = map->at(va).segments();
        if (segments.empty()) {
          continue;
        }
        // The name of the segment that address is in.
        const std::string & name = segments.front().name();
        // A predicate for all addresses in a segment with the same name.
        NamePredicate name_constraint(name);
        // The map constraint matching the predicate (all addresses in the segment).
        // auto rather than:
        // class Sawyer::Container::AddressMapConstraints<Sawyer::Container::AddressMap<long unsigned int, unsigned char> >
        auto data_segment = map->segmentPredicate(&name_constraint);
        // Set ther permission to executable.
        data_segment.changeAccess(MemoryMap::EXECUTABLE, 0);
        GINFO << "Marked entry point address " << addr_str(va) << " in segment " << name
              << " as executable." << LEND;
      }
    }
  }

  SgAsmGenericHeader *hdr = interp->get_headers()->get_headers()[0];
  // Does the tool only support Windows PE files (aka OOAnalzyer)?
  boost::optional<bool> allow = vm.get<bool>("pharos.allow_non_pe");
  if (allow && !(*allow)) {
    // If so ensure that the input executable is of the correct file type.
    SgAsmPEFileHeader *pehdr = isSgAsmPEFileHeader(hdr);
    if (!pehdr) {
      // If this message is preventing you from testing OOAnalyzer on Linux ELF executables,
      // just remove this test.  OOAnalyzer _will_ do something on ELF executables produced by
      // GCC, just not the "right" thing.  Since too many public users of the OOAnalyzer tool
      // were not aware of this limitation, we felt that it would be better to disable the
      // feature entirely unless you were motivated enough to remove this test. :-)
      GFATAL << "This tool only suppports Windows Portable (PE) executable files." << LEND;
      std::exit(EXIT_FAILURE);
    }
  }


  // Create a partitioner that's tuned for a certain architecture, and then tune it even more
  // depending on our command-line.
  P2::Partitioner partitioner = engine->createPartitioner();

  // Enable our Monitor (previously for CFG debugging, now for timeout limit checking).
  partitioner.cfgAdjustmentCallbacks().append(Monitor::instance());

  size_t arch_bits = partitioner.instructionProvider().instructionPointerRegister().get_nbits();
  if (arch_bits != 32) {
    // What does the config file say about whether 64-bit analysis is supported for this tool?
    auto config_allow64 = vm.config().path_get("pharos.allow-64bit");
    // If it's not enabled in the config file, warn regardless of the command line option.
    if ((not config_allow64) or (not config_allow64.as<bool>())) {
      OWARN << "Non 32-bit Windows PE support is still highly experimental for this tool!" << LEND;
      if (not vm.count("allow-64bit")) {
        GFATAL << "Please specify --allow-64bit to allow the analysis of 64-bit executables." << LEND;
        std::exit(EXIT_FAILURE);
      }
    }
  }

  customize_message_facility(P2::mlog, "PRT2");
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

  // We used to load partitioner configs, with the --pconfig option, but that feature never got
  // ported to ROSE Partitioner2. :-(   It would be nice to have it back some day.

  // We also used to configure logging in the disassembler and the loader more or less the same
  // way that we're now configuring the logging in P2::mlog.  Is that perhaps why we've begun
  // receiving warnings about malformed PE files?   Does that matter?

  // Show what we'll be working on (stdout for the record, and diagnostics also)
  //partitioner.memoryMap().dump(mlog[INFO]);

  // Run the partitioner
  if (vm.count("serialize")) {
    // Partitioner data is or will be serialized

    // Try reading the serialized file, if it exists
    bfs::path path = vm["serialize"].as<bfs::path>();
    if (exists(path)) {
      OINFO << "Reading serialized data from " << path << "." << LEND;
      try {
        bfs::ifstream file(path, std::ios_base::in | std::ios_base::binary);
        if (!file) {
          GFATAL << "Could not open " << path << " for reading." << LEND;
          std::exit(EXIT_FAILURE);
        }
        bio::filtering_streambuf<bio::input> in;
        in.push(bio::gzip_decompressor());
        in.push(file);
        bar::binary_iarchive ia(in);
        std::string version;
        bool semantics_were_disabled;
        ia >> version >> semantics_were_disabled;
        if (version != ROSE_PACKAGE_VERSION) {
          if (vm.count("ignore-serialize-version")) {
            GWARN << "Serialized data was from a different version of Rose."
                  << "  Loading anyway as requested." << LEND;
            version = ROSE_PACKAGE_VERSION;
          } else {
            GFATAL << "Serialized data was from a different version of Rose.  Exiting.\n"
                   << "If you want to overwrite the file, remove the file " << path << '\n'
                   << "If you want to ignore this, use the --ignore-serialize-version switch."
                   << LEND;
            std::exit(EXIT_FAILURE);
          }
        }
        if (disable_semantics != semantics_were_disabled) {
          char const * onoff = semantics_were_disabled ? "disabled" : "enabled";
          GWARN << "Serialized data was generated with semantics " << onoff
                << ", which is which is contrary to how this program was run." << LEND;
        }
        time_point start_ts = clock::now();
        ia >> partitioner;
        duration secs = clock::now() - start_ts;
        OINFO << "Reading serialized data took " << secs.count() << " seconds." << LEND;
      } catch (boost::iostreams::gzip_error &e) {
        OFATAL << "Unable to read serialized data: " << e.what () << LEND;
        std::exit(EXIT_FAILURE);
      }
    } else {
      bfs::ofstream file(path, std::ios_base::out | std::ios_base::binary);
      if (!file) {
          GFATAL << "Could not open " << path << " for writing." << LEND;
          std::exit(EXIT_FAILURE);
      }
      // This is kind of yucky, but the inner try ensures that we remove the .serialize file.
      // The outer try then allows us to "really" handle the exceptions.
      try {
        try {
          // No serialized data.  Write it instead.
          time_point start_ts = clock::now();
          engine->runPartitioner(partitioner);
          time_point now = clock::now();
          duration secs = now - start_ts;
          start_ts = now;
          OINFO << "Function partitioning took " << secs.count() << " seconds." << LEND;
          OINFO << "Writing serialized data to " << path << "." << LEND;
          bio::filtering_streambuf<bio::output> out;
          out.push(bio::gzip_compressor());
          out.push(file);
          bar::binary_oarchive oa(out);
          oa << std::string{ROSE_PACKAGE_VERSION} << disable_semantics;
          oa << partitioner;
          secs = clock::now() - start_ts;
          OINFO << "Writing serialized data took " << secs.count() << " seconds." << LEND;
        } catch (...) {
          file.close();
          boost::system::error_code ec;
          if (!bfs::remove(path, ec)) {
            OWARN << "Could not remove incomplete serialization file " << path << LEND;
          }
          throw;
        }
      } catch (const Monitor::ResourceException &e) {
        OFATAL << "During partitioning: " << e.what () << LEND;
        std::exit(EXIT_FAILURE);
      }
    }
  } else {
    time_point start_ts = clock::now();
    try {
      engine->runPartitioner(partitioner);
    } catch (const Monitor::ResourceException &e) {
      OFATAL << LEND << "During partitioning: " << e.what () << LEND;
      std::exit(EXIT_FAILURE);
    }
    duration secs = clock::now() - start_ts;
    OINFO << "Pharos function partitioning took " << secs.count() << " seconds." << LEND;
  }

  // Report statistics for what we found in the partitioner.  This function needs to be called
  // from here and not from our custom partitioner so that we get statistics for the stock ROSE
  // partitioner as well.
  report_partitioner_statistics(partitioner);

  // Enable progress bars only if the output is to a terminal...
  if (interactive_logging()) {
    partitioner.progress(Rose::Progress::Ptr());
  }

  // This test may have been added because buildAst failed when the function list was empty.
  // Since we're no longer returning the interpretation, but the engine instead, we can
  // probably return the engine anyway (no AST?) and not crash... Hopefully.
  if (partitioner.functions().empty() && engine->functionStartingVas().empty()) {
    GERROR << "No starting points for recursive disassembly." << LEND;
    return partitioner;
  }

  return partitioner;
}

uint8_t CERTEngine::read_byte(rose_addr_t addr) {
  uint8_t byte;
  if (1 != memoryMap()->at(addr).limit(1).require(MemoryMap::EXECUTABLE).read(&byte).size()) {
    // This is a debug message and not an error because the user can't conclude anything useful from it.
    GDEBUG << "Failed to read byte at " << addr_str(addr) << LEND;
    throw std::out_of_range(std::string("Failed to read byte at ") + addr_str(addr));
  }
  return byte;
}

P2::DataBlock::Ptr
CERTEngine::try_making_padding_block(P2::Partitioner& partitioner, rose_addr_t addr, bool backwards) {
  // The padding data block that we're going to create (or return as a nulllptr).
  P2::DataBlock::Ptr dblock;

  // OINFO << "Started at address " << addr_str(addr) << " going backwards=" << backwards << LEND;

  rose_addr_t current = addr;
  uint8_t byte;
  uint8_t expected;

  // Read the first byte.
  try {
    expected = read_byte(current);
  }
  catch (std::exception& e) {
    // Trigger unexpected byte logic in next code block.  This probably never happens.
    expected = 0;
  }

  // If the first byte wasn't recognized as a "pad character" return immediately.
  if (expected != 0xCC && expected != 0x90) {
    // If the first byte does not have the correct value, we'll never be a padding block.  If
    // it does we'll either add the padding block, and be done, or it's actually correct for us
    // to revisit the issue later (hopefully in a forward direction).
    not_pad_gaps.insert(addr);
    return dblock;
  }

  // Decide which direction we're advancing in.
  int8_t direction;
  if (backwards)
    direction = -1;
  else
    direction = 1;

  // While there are more bytes of the same type, consume those as well.
  byte = expected;
  while (byte == expected) {
    // Advance (forwards or backwards) to the next byte.
    current += direction;
    // OINFO << "Advanced to address " << addr_str(current) << "." << LEND;
    try {
      byte = read_byte(current);
    }
    // Continue to try making a block if we read pas the end of the segment.
    catch (std::exception& e) {
      break;
    }
  }

  // We've read one byte past the last matching byte, so back up one byte.
  current -= direction;

  // Since we might be scanning backwards, determine which address is the start, and what the
  // number of bytes in the data block is.
  rose_addr_t start = std::min(addr, current);
  rose_addr_t end = std::max(addr, current);
  size_t num_bytes = end - start + 1;

  // When we're scanning in the forward direction, we presumably know that the previous block
  // did not flow into this block, because if it did we wouldn't be in a gap.  But if we're
  // scanning backwards we don't really know this, and so we must have at least two bytes,
  // because the the correct interpretation might be that a single byte was an actually
  // instruction.  Technically if there were multiple 0x90 NOPs, this could still be
  // incorrect. :-(
  if (backwards && num_bytes < 2) return dblock;

  // Create the data block, and attach it to the CFG.  We'll determine the correct function to
  // attach the block to in a final pass.
  dblock = P2::DataBlock::instanceBytes(start, num_bytes);
  partitioner.attachDataBlock(dblock);

  // NOTE: should really be marking this block as padding! The original Partitioner
  // would put a block reason on there of SgAsmBlock::BLK_PADDING but it looks like
  // Partitioner2 code doesn't do anything like this currently?  It has a generic
  // "Attributes" capability (key/val pairs) that looks like it'll be used for this
  // and other things, but it isn't used for anything currently?  And the P2
  // DataBlock structure does have a string "printableName()" method, but that just
  // is a manually generated answer every time you ask for it, can't set the name so
  // no hacky workaround potential there either.

  return dblock;
}

// Top and bottom allow the caller to enable and disable matching padding at the top and bottom
// of the gap respectively.  This probably isn't the most efficient approach, but it makes it
// easy to experiment with different approaches.
bool
CERTEngine::consume_padding(P2::Partitioner& partitioner, bool top, bool bottom) {
  // Have we changed anything?
  bool changed = false;

  // Find unused executable address intervals.  This may not be the most efficient way of doing
  // it, but we needed to generate unused once for each segment so that we didn't get gaps that
  // crossed segment boundaries.
  for (const MemoryMap::Node &node : partitioner.memoryMap()->nodes()) {
    auto seg = node.value();
    // Only consider executable segments.
    if ((seg.accessibility() & MemoryMap::EXECUTABLE) == 0) continue;
    // Get unused gaps _within_ this segment.
    AddressIntervalSet unused = partitioner.aum().unusedExtent(node.key());

    // For each unused interval.
    for (const AddressInterval &interval : unused.intervals()) {
      rose_addr_t least = interval.least();
      rose_addr_t greatest = interval.greatest();
      //OINFO << "Evaluating gap for padding blocks: " << addr_str(least) << " - " << addr_str(greatest) << LEND;

      // Look for padding at the start of the block going forward...
      if (top && !not_pad_gaps.exists(least)) {
        // Mark the end of this gap as having been analyzed, so we don't try again.
        P2::DataBlock::Ptr dblock = try_making_padding_block(partitioner, least);
        if (dblock) {
          changed = true;
          // If we consumed the entire gap, we should not check in the backwards direction.
          if (dblock->address() + dblock->size() >= greatest) {
            continue;
          }
        }
      }

      // Look for padding at the end of the block going backwards.  Strictly speaking the
      // not_pad_gaps test is a little bit incorrect because we're using the same address to
      // reflect both forward and backward searching.  That should be fine as long as we're only
      // doing one byte padding but if we started consuming NOP padding, we'd need two lists or a
      // more sophisticated approach.
      if (bottom && !not_pad_gaps.exists(greatest)) {
        // Mark the end of this gap as having been analyzed, so we don't try again.
        P2::DataBlock::Ptr dblock = try_making_padding_block(partitioner, greatest, true);
        if (dblock) changed = true;
      }
    }
  }

  return changed;
}

bool
CERTEngine::try_making_thunk(P2::Partitioner& partitioner, rose_addr_t address) {
  // If we've looked for thunks at this exact address once before, either we've already made
  // code or we've decided not to.  Nothing from subsequent analysis is going to change that
  // conclusion, so we're done.
  if (not_thunk_gaps.exists(address)) {
    return false;
  }

  // Mark this gap as having been analyzed already so that we don't try to analyze it again.
  not_thunk_gaps.insert(address);

  // Disassemble the instruction?
  SgAsmX86Instruction *insn = isSgAsmX86Instruction(partitioner.discoverInstruction(address));

  // If it's not a jump instruction, we're not interested.
  if (!insn || insn->get_kind() != x86_jmp) return false;

  P2::BasicBlock::Ptr bb = P2::BasicBlock::instance(address, partitioner);
  bb->append(partitioner, insn);

  bool complete;
  std::vector<rose_addr_t> successors = partitioner.basicBlockConcreteSuccessors(bb, &complete);
  if (successors.size() == 0) // to prevent a coredump...
    return false;
  rose_addr_t target = successors.front();

  // OINFO << "Thunk: " << addr_str(least) << LEND;
  unsigned reasons = SgAsmFunction::FUNC_THUNK | SgAsmFunction::FUNC_PATTERN;
  P2::Function::Ptr thunk_function = P2::Function::instance(address, reasons);
  partitioner.attachOrMergeFunction(thunk_function);

  // OINFO << "Remaking target function " << addr_str(target) << LEND;
  P2::Function::Ptr target_function = P2::Function::instance(target, SgAsmFunction::FUNC_GRAPH);
  partitioner.attachOrMergeFunction(target_function);

  return true;
}

// Top and bottom allow the caller to enable and disable matching thunks at the top and bottom
// of the gap respectively.  This probably isn't the most efficient approach, but it makes it
// easy to experiment with different approaches.
bool
CERTEngine::consume_thunks(P2::Partitioner& partitioner, bool top, bool bottom) {
  // Have we changed anything?
  bool changed = false;

  // Find unused executable address intervals.
  for (const MemoryMap::Node &node : partitioner.memoryMap()->nodes()) {
    auto seg = node.value();
    // Only consider executable segments.
    if ((seg.accessibility() & MemoryMap::EXECUTABLE) == 0) continue;
    // Get unused gaps _within_ this segment.
    AddressIntervalSet unused = partitioner.aum().unusedExtent(node.key());

    // For each unused interval.
    for (const AddressInterval &interval : unused.intervals()) {
      rose_addr_t least = interval.least();
      rose_addr_t greatest = interval.greatest();
      //OINFO << "Thunk Gap: " << addr_str(least) << " - " << addr_str(greatest) << LEND;

      if (top && try_making_thunk(partitioner, least)) changed = true;

      // Now check for a thunk at the end of the gap as well.  Here we've hard-coded an
      // instruction legth of 5, and that's horrible.
      if (greatest < 5) continue; // TODO: (mwd) Fix for 64-bit code
      rose_addr_t target = greatest - 4;
      if (target <= least) continue;

      if (bottom && try_making_thunk(partitioner, target)) changed = true;
    }
  }

  //if (changed) P2::Engine::runPartitionerRecursive(partitioner);

  return changed;
}

SgAsmX86Instruction* non_overlapping_instruction(const P2::Partitioner& partitioner, rose_addr_t addr) {
  // First check to see if there's an existing instruction.  If so return it.  This circumvents
  // the overlap check later which should include the starting address during checks for
  // overlapping data blocks, but exclude existing instructions.
  P2::AddressUser oau = partitioner.instructionExists(addr);
  if (oau.insn()) {
    SgAsmInstruction* insn = oau.insn();
    //OINFO << "NOI already exists at " << addr_str(addr) << " : " << debug_instruction(insn, 9) << LEND;
    return isSgAsmX86Instruction(insn);
  }

  // Find an existing instruction, or try creating one if it does not exist.
  SgAsmInstruction* insn = partitioner.discoverInstruction(addr);
  // If we couldn't create an instruction, then there's just no instruction here.
  if (!insn || insn->isUnknown()) {
    //OINFO << "Failed to create non-overlapping instruction at " << addr_str(addr) << LEND;
    return nullptr;
  }
  // It must also be an X86 instruction, because this whole module is X86 specific.
  SgAsmX86Instruction* xinsn = isSgAsmX86Instruction(insn);
  if (!xinsn) {
    //OINFO << "Failed to create X86 non-overlapping instruction at " << addr_str(addr) << LEND;
    return nullptr;
  }
  // Now check to see if this instruction overlaps with another.
  rose_addr_t end_addr = addr + insn->get_size() - 1;
  AddressInterval ii(AddressInterval::hull(addr, end_addr));
  bool overlap = partitioner.aum().anyExists(ii);
  if (overlap) {
    //OINFO << "  Rejecting instruction at " << addr_str(addr)
    //      << " because it overlaps with something else." << LEND;
    return nullptr;
  }
  // And if it does not, return it.
  return xinsn;
}

bool
CERTEngine::bad_code(const P2::Partitioner& partitioner, const P2::BasicBlock::Ptr bb) const {
  if (!bb || bb->nInstructions() == 0) {
    // This condition doesn't represent "bad" code, just non-existent code.  For reasons that
    // are unclear, we're sometimes producing blocks with no instructions, and in this case, we
    // do _not_ want to make a data block, which is what happens in practice if we return true.
    return false;
  }

  SgAsmInstruction* lastinsn = bb->instructions()[bb->nInstructions() - 1];

  // True if we know all of the successors for the instruction.
  bool complete;
  // Get the list of successor addresses.
  auto successors = lastinsn->getSuccessors(complete);

  for (rose_addr_t successor : successors.values()) {
    SgAsmX86Instruction* xinsn = non_overlapping_instruction(partitioner, successor);
    if (!xinsn) {
      //OINFO << "Bad code at " << addr_str(bb->address())
      //      << " because no instruction at successor " << addr_str(successor) << LEND;
      return true;
    }
  }

  //OINFO << "The code at " << addr_str(bb->address()) << " was valid." << LEND;
  return false;
}

class SpeculativeBasicBlock {
 private:
  P2::Partitioner& partitioner;
  rose_addr_t addr;
  rose_addr_t end;
 public:
  P2::BasicBlock::Ptr bb;
  rose_addr_t successor = 0;
  rose_addr_t fallthru = 0;
  bool already_existed = false;
  bool was_call = false;

  SpeculativeBasicBlock(P2::Partitioner& p, rose_addr_t a, rose_addr_t e) :
    partitioner(p), addr(a), end(e) {}

  // Analyze the block.  Return true if the block was valid, and code should be made.
  // Also fill in various member fields to control "higher level logic".
  bool analyze() {
    // If a block already exists return it.
    bb = partitioner.basicBlockExists(addr);
    if (bb) {
      //OINFO << "Basic block at " << addr_str(addr) << " already existed." << LEND;
      already_existed = true;
      return true;
    }

    // Otherwise create one, and we're going to add isntructions to it.
    bb = P2::BasicBlock::instance(addr, partitioner);

    rose_addr_t current = addr;
    while (current < end) {
      // This might be duplicative, but don't create blocks of zeros.
      RefuseZeroCode::Ptr zero_code_detector = RefuseZeroCode::instance();
      if (zero_code_detector->check_zeros(partitioner, current, bb)) {
        //OINFO << "Refused to make arbitrary code because of zeros at " << addr_str(current) << LEND;
        return false;
      }

      // If we've flowed into an existing instruction, that's valid.
      if (partitioner.instructionExists(current)) {
        //OINFO << "Found existing instruction at: " << addr_str(current) << LEND;
        successor = 0;
        return true;
      }

      // Disassemble the instruction?
      SgAsmX86Instruction *insn = non_overlapping_instruction(partitioner, current);
      //OINFO << "Made instruction at " << addr_str(current) << LEND;

      // If we couldn't create a valid, non overlapping instruction, that's fairly good
      // evidence that this entire gap is not really code.
      if (!insn) {
        //OINFO << "Unable to make a non overlapping instruction at " << addr_str(current) << LEND;
        return false;
      }

      // Stop making code at INT3 instructions.  This heuristic is because data occasionally
      // occurs after the function and before the padding, and if the "code" flows into the
      // padding, this will correctly signal that this block is data not code.
      if (insn->get_mnemonic() == "int3") {
        //OINFO << "Found int3 instruction found at " << addr_str(insn->get_address()) << LEND;
        SgAsmX86Instruction* ninsn = non_overlapping_instruction(partitioner, current+1);
        if (ninsn && ninsn->get_mnemonic() == "int3") {
          //OINFO << "Followed by another int3 instruction at " << addr_str(ninsn->get_address()) << LEND;
          return false;
        }
      }

      // It looks like this instruction is a valid one, so keep it.
      bb->append(partitioner, insn);

      // Compute the fallthru address for this function.
      // This is exposed to our caller so we know how many instructions we consumed.
      fallthru = insn->get_address() + insn->get_size();

      bool end_of_block = false;
      bool complete;
      SgAsmX86Instruction* xinsn = isSgAsmX86Instruction(insn);
      for (rose_addr_t s : partitioner.basicBlockConcreteSuccessors(bb, &complete)) {

        //OINFO << "Successor of " << addr_str(current) << " is " << addr_str(s) << LEND;
        // We're interested in any non-fallthru successors.
        if (s != fallthru) {
          // Any successor that's not the fallthru marks the end of the basic block.
          end_of_block = true;
          // Check if the successor is valid.

          // If the instruction is a call, the successor of interest is the fallthru (we're
          // assuming that the call returns).  The code that check the legitimacy of the
          // successor should really be invoked on call targets as well, but there's currently
          // a bug in ROSE where --use-semanics causes "call [import]" to incorrectly return a
          // bogus successor.  That in turn incorrectly suppresses the creation of this basic
          // block, so until that's fixed we're just going to assume that all call targets are
          // valid.
          if (insn_is_call(insn)) {
            //OINFO << "Successor of interest (call) is: " << addr_str(fallthru) << LEND;
            was_call = true;
            successor = fallthru;
          }
          // It turns out that the same problem occurs for jmp [import]...
          else if (xinsn && xinsn->get_kind() == x86_jmp) {
            successor = 0;
            fallthru = 0;
          }
          // If the instruction is not a call, then the successor is the successor of interest,
          // but the block is only valid if the the target is valid.
          else {
            SgAsmX86Instruction *sinsn = non_overlapping_instruction(partitioner, s);
            if (!sinsn) {
              //OINFO << "Unable to make a non overlapping successor at " << addr_str(current) << LEND;
              return false;
            }
            else {
              //OINFO << "Successor of interest is: " << addr_str(s) << LEND;
              successor = s;
            }
          }
        }
      }

      // If we're at the end of the block we're done.
      if (end_of_block) {
        //OINFO << "End of block at " << addr_str(current) << LEND;
        return true;
      }

      // An indeterminate successor also marks the end of the basic block, and is valid, but has
      // no successor of interest.
      if (!complete) {
        //OINFO << "Instruction at " << addr_str(current) << " has incomplete successors." << LEND;
        return true;
      }

      // If we're about flow into a known data block, we're not really an instruction.
      if (partitioner.aum().overlapping(fallthru).dataBlockUsers().size()) {
        //OINFO << "Instruction at " << addr_str(current) << " flows into a known data block "
        //      << "(and is therefore not really an instruction)." << LEND;
        return false;
      }

      // Go to the next instruction, we'll check whether it overlaps with anything at the start
      // of the loop.
      current = fallthru;
    }

    // If we reached the end exactly, then we're a valid basic block, and our successor of
    // interest is the current address (the one we fell through to from the last isntruction).
    //OINFO << "Reached the end of the gap while speculatively making code at: " << addr_str(current) << LEND;
    successor = current;
    return true;
  }

};

bool
CERTEngine::create_arbitrary_code(P2::Partitioner& partitioner) {
  // Have we changed anything?
  bool changed = false;
  bool ever_changed = false;

  // Find unused executable address intervals.
  AddressIntervalSet executableSpace;
  for (const MemoryMap::Node &node : partitioner.memoryMap()->nodes()) {
    if ((node.value().accessibility() & MemoryMap::EXECUTABLE) != 0)
      executableSpace.insert(node.key());
  }

  while (true) {
    AddressIntervalSet unused = partitioner.aum().unusedExtent(executableSpace);

    // For each unused interval.
    for (const AddressInterval &interval : unused.intervals()) {
      rose_addr_t least = interval.least();
      rose_addr_t greatest = interval.greatest();

      // If we've considered making code at this exact address once before, either we've already
      // made code or we've decided not to.  Nothing from subsequent analysis is going to change
      // that conclusion, so we're done.
      if (not_code_gaps.exists(least)) {
        GDEBUG << "Arbitrary code gap: " << addr_str(least) << " - " << addr_str(greatest)
               << " -- previously analyzed." << LEND;
        continue;
      }

      //OINFO << "Arbitrary code gap: " << addr_str(least) << " - " << addr_str(greatest) << LEND;

      // Mark this gap as having been analyzed already so that we don't try to analyze it again.
      not_code_gaps.insert(least);

      // We're going to look at each address.
      rose_addr_t current = least;

      // Check to see if there's a padding block next (there should be, but still can be?)
      P2::DataBlock::Ptr ipblock = try_making_padding_block(partitioner, least);
      if (ipblock) {
        //OINFO << "Made padding block in code gap at " << addr_str(least) << LEND;
        // Make our next block after the padding.
        current = ipblock->address() + ipblock->size();
        //OINFO << "Advancing to next address at " << addr_str(current) << LEND;
      }

      // For each address in the block (or until we don't have a fallthru edge)...
      while (current < greatest) {
        SpeculativeBasicBlock sbb(partitioner, current, greatest + 1);
        bool valid = sbb.analyze();

        // Check to make sure that the basic block meets other criteria for being valid code.
        if (valid) {
          valid = !bad_code(partitioner, sbb.bb);
        }

        // If it wasn't a valid block we're done with this gap.
        if (!valid) {
          //OINFO << "Block at " << addr_str(current) << " was not valid code." << LEND;

          P2::DataBlock::Ptr dblock = try_making_padding_block(partitioner, current);
          if (dblock) break;

          rose_addr_t end = current;
          while (true) {
            try {
              if (read_byte(end) == 0xCC) break;
              if (end == greatest) break;
              ++end;
            }
            catch (const Monitor::ResourceException &e) {
              // Make sure we keep propagating ResourceExceptions back up to the caller so we
              // can terminate.
              throw;
            }
            // ejs: Why is this here? What exceptions is it supposed to be catching?
            catch (std::exception& e) {
              break;
            }
          }
          size_t len = end - current + 1;

          P2::DataBlock::Ptr resized_dblock = P2::DataBlock::instanceBytes(current, len);
          partitioner.attachDataBlock(resized_dblock);
          //OINFO << "Data block at " << addr_str(dblock->address()) << " was "
          //      << dblock->size() << " bytes long." << LEND;
          break;
        }
        // If there was already a block at this address, we're done with this gap.
        if (sbb.already_existed) {
          //OINFO << "Block at " << addr_str(current) << " already existed." << LEND;
          break;
        }

        //OINFO << "Valid block starts at " << addr_str(current) << LEND;

        bool block_only = false;

        // Now try to decide which function to attach this block to.
        P2::Function::Ptr function;
        // If there's a function _entry_ point at the address in question, make this block into a
        // separate function because it follows the tail call optimization pattern.  But if the
        // successor merely belongs to a function, then assign this new block to that existing
        // function (a common pattern in execption handlers that jump to return blocks).
        //OINFO << "Checking for function at successor of interest: " << addr_str(sbb.successor) << LEND;
        if (sbb.successor) {
          P2::Function::Ptr entryfunc = partitioner.functionExists(sbb.successor);
          if (entryfunc) {
            //OINFO << "Address " << addr_str(sbb.successor)
            //      << " flows directly into  " << addr_str(entryfunc->address()) << LEND;
          }
          else {
            //OINFO << "Evaluating owners of successor of interest: " << addr_str(sbb.successor) << LEND;
            // Is there a basic block at our successor, if so attach that function.
            P2::BasicBlock::Ptr existing_bblock = partitioner.basicBlockExists(sbb.successor);
            if (existing_bblock) {
              //OINFO << "Basic block exists, checking for functions..." << LEND;
              for (P2::Function::Ptr f : partitioner.functionsOwningBasicBlock(existing_bblock)) {
                function = f;
                //OINFO << "Address " << addr_str(sbb.successor)
                //      << " is owned by " << addr_str(function->address()) << LEND;
              }
              // If we found a block but not a function, try something experimental!
              if (!function) block_only = true;
            }
            else {
              //OINFO << "Basic block at " << addr_str(sbb.successor) << " does not exist!" << LEND;
            }
          }
        }

        // Before making a code block, check to see if there's a data block.
        if (partitioner.aum().overlapping(current).dataBlockUsers().size()) {
          //OINFO << "There's already a data block at " << addr_str(current)
          //      << " so we're not going to make a code block." << LEND;
          break;
        }

        if (block_only) {
          // OINFO << "Attaching a bare basic block at " << addr_str(current) << LEND;
          P2::BasicBlock::Ptr new_block = partitioner.discoverBasicBlock(current);
          partitioner.attachBasicBlock(new_block);
        }
        else {
          // If we're not found a function to attach the block to already.
          if (!function) {
            //OINFO << "Checking for existing function at " << addr_str(current) << LEND;
            function = partitioner.functionExists(current);
            if (!function) {
              unsigned reasons = SgAsmFunction::FUNC_USERDEF;
              function = P2::Function::instance(current, reasons);
              partitioner.attachFunction(function);
              //size_t new_placeholders = partitioner.attachFunction(function);
              //OINFO << "Creating new function at " << addr_str(current) << " had "
              //      << new_placeholders << " new placeholders." << LEND;
            }
          }

          partitioner.detachFunction(function);
          partitioner.insertPlaceholder(current);
          function->insertBasicBlock(current);
          while (makeNextBasicBlock(partitioner)) /*void*/;
          partitioner.discoverFunctionBasicBlocks(function);
          partitioner.attachFunction(function);
        }

        // We need to rerun the the full partitioner, because we've changed things.
        changed = true;
        ever_changed = true;

        // If the last instruction of our block was a call, defer further work on this block
        // until the full partitioner has had a chance to follow more complex control flow.
        if (sbb.was_call) break;

        // Another way to signal that we're done with the gap is to not have a fallthru.
        if (sbb.fallthru == 0) break;

        // Make our next speculative block at the fallthru address.
        current = sbb.fallthru;
        //OINFO << "Making next block at " << addr_str(current) << LEND;

        // Check to see if there's a padding block next.
        P2::DataBlock::Ptr dblock = try_making_padding_block(partitioner, current);
        if (dblock) {
          //OINFO << "Code detected padding block at " << addr_str(current) << LEND;
          // Make our next block after the padding.
          current = dblock->address() + dblock->size();
          //OINFO << "Instead, making next block at " << addr_str(current) << LEND;
        }
      }

      //OINFO << "Reached end of gap: " << addr_str(least) << " - " << addr_str(greatest) << LEND;
    }

    if (!changed) break;
    changed = false;
  }

  // Having pointed the partitioner at a bunch of gaps, less invoke it again, and have it make
  // code at all of the locations simultaneously.  This is suboptimal since they might
  // contradict each other, but invoking the paritioner after each gap was far too slow when
  // there were lots of gaps.  Additionally, we (still) have the problem that the gap code
  // might flow into the middle of existing basic blocks causing large changes than we intend.
  if (ever_changed) {
    GDEBUG << "Starting arbitrary code run of partitioner..." << LEND;
    P2::Engine::runPartitionerRecursive(partitioner);
    GDEBUG << "Finished arbitrary code run of partitioner..." << LEND;
  }

  return ever_changed;
}

void
CERTEngine::runPartitioner(P2::Partitioner &partitioner) {
  P2::Engine::runPartitioner(partitioner);

  // For each padding block, assign the data block to the function that preceeds it.  The
  // functions will exist now, because this is literally the last code we run during
  // partitioning.

  // The stock ROSE partitioner normally attaches padding to the function after the block, but
  // this is annoying because that results in the wrong answer for jump tables and other
  // unidentified data which usually follows the function that it is associated with in most
  // compilers.
  const P2::AddressUsageMap& aum = partitioner.aum();

  // The address users
  auto users = aum.overlapping(aum.hull()).addressUsers();
  for (const P2::AddressUser& au : users) {
    if (!au.isDataBlock()) continue;
    const P2::DataBlock::Ptr db = au.dataBlock();
    if (!db) continue;

    rose_addr_t addr = db->address();
    //OINFO << "Found a data block address user at " << addr_str(addr) << LEND;

    // The address of the byte before the padding.
    rose_addr_t pre_addr = addr - 1;

    const AddressInterval ai(pre_addr);
    for (const P2::Function::Ptr & func : partitioner.functionsOverlapping(ai)) {
      // Attach the data block to the function.
      partitioner.attachDataBlockToFunction(
        P2::DataBlock::instanceBytes(addr, db->size()), func);
      //OINFO << "Attaching data block at " << addr_str(addr) << " to function "
      //      << addr_str(func->address()) << LEND;
    }
  }

  //OINFO << "Custom partitioner 2 final pass complete." << LEND;
}

void
CERTEngine::runPartitionerRecursive(P2::Partitioner& partitioner) {
  using clock = std::chrono::steady_clock;
  using time_point = std::chrono::time_point<clock>;
  using duration = std::chrono::duration<double>;

  time_point start_ts = clock::now();

  // Pass one.  Do all the "usual" things the partitioner does.  This includes following flow
  // control, creating functions from matched prologues, creating functions from data segment
  // addresses (disabled by default).  It then does "additional" work, like finding dead code
  // (branches not taken due to opaque predicates), and making code and data from gaps inside a
  // function.

  // In this pass, we'll permit overlapping code because we're (mostly) not doing speculative
  // things.
  overlapping_code_detector->set_refusing(false);

  P2::Engine::runPartitionerRecursive(partitioner);

  GDEBUG << "Making functions for Prologue phase!" << LEND;

  // Create functions at the places suggested by our jump to prologue matcher.
  jump_to_prologue_matcher->make_functions(partitioner);

  // From this point on, our behavior is too speculative to permit overlapping code.
  overlapping_code_detector->set_refusing(true);

  duration secs = clock::now() - start_ts;
  OINFO << "ROSE stock partitioning took " << secs.count() << " seconds." << LEND;
  report_partitioner_statistics(partitioner);

  // Disable these...
  partitioner.functionPrologueMatchers().clear();

  GDEBUG << "Starting FIRST iteration!" << LEND;

  // Pass two. Once all of that is complete, we want to do our own custom passes.  This logic
  // should really be worklist driven because the current implementation of looking at every
  // gap for every type of action is pretty inefficient.
  bool changed = true;
  while (changed) {
    changed = false;
    changed |= consume_thunks(partitioner, true, false);
    changed |= consume_padding(partitioner, true, true);

    // We only want to "make arbitary code" when the safer options are exhausted.
    if (!changed) {
      changed |= create_arbitrary_code(partitioner);
    }

    // Our prologue matcher is still installed, so we might have found more prologues.
    jump_to_prologue_matcher->make_functions(partitioner);

    GDEBUG << "" << LEND;
  }

  // Now add the prologue matchers back, and analyze one more time.
  // It unclear whether this helped much, but it's difficult for me to believe that it hurts.
  partitioner.functionPrologueMatchers().push_back(P2::ModulesX86::MatchHotPatchPrologue::instance());
  partitioner.functionPrologueMatchers().push_back(P2::ModulesX86::MatchStandardPrologue::instance());
  partitioner.functionPrologueMatchers().push_back(P2::ModulesX86::MatchAbbreviatedPrologue::instance());
  partitioner.functionPrologueMatchers().push_back(P2::ModulesX86::MatchEnterPrologue::instance());

  // Disabled for the same reason as in createTunedPartitioner().
  //partitioner.functionPrologueMatchers().push_back(
  //  P2::Modules::MatchThunk::instance(functionMatcherThunks()));

  P2::Engine::runPartitionerRecursive(partitioner);

  GDEBUG << "Custom partitioner 2 recursive pass complete." << LEND;
}

#if 0
bool
MatchInterFunctionGap::match(const P2::Partitioner &partitioner, rose_addr_t anchor) {
  // If there's an instruction at this address, there's not need to create another.
  if (partitioner.instructionExists(anchor)) {
    OINFO << "MatchInterFunctionGap(" << addr_str(anchor) << ") -- insn exists" << LEND;
    return false;
  }

  // If anyone is already using this address for anything, we don't want to use it.
  if (!(partitioner.aum().overlapping(anchor).isEmpty())) {
    OINFO << "MatchInterFunctionGap(" << addr_str(anchor) << ") -- already in use" << LEND;
    return false;
  }

  // If nobody is using the previous byte for anything, then we're not "adjacent" to existing
  // code, and we don't want to
  if (partitioner.aum().overlapping(anchor - 1).isEmpty()) {
    //OINFO << "MatchInterFunctionGap(" << addr_str(anchor) << ") -- not adjacent" << LEND;
    return false;
  }

  // Disassemble the instruction?
  SgAsmX86Instruction *insn = isSgAsmX86Instruction(partitioner.discoverInstruction(anchor));

  if (!insn) {
    OINFO << "MatchInterFunctionGap(" << addr_str(anchor) << ") -- no valid instruction" << LEND;
    return false;
  }

  if (insn->get_kind() == x86_add) {
    OINFO << "MatchInterFunctionGap(" << addr_str(anchor) << ") -- rejected (add/zeros): "
          << debug_instruction(insn) << LEND;
    return false;
  }
  if (insn->get_kind() == x86_int3) {
    OINFO << "MatchInterFunctionGap(" << addr_str(anchor) << ") -- rejected (int3): "
          << debug_instruction(insn) << LEND;
    return false;
  }

  if (insn->get_kind() != x86_jmp)
    function_ = P2::Function::instance(anchor, SgAsmFunction::FUNC_THUNK | SgAsmFunction::FUNC_PATTERN);
  else
    function_ = P2::Function::instance(anchor, SgAsmFunction::FUNC_PATTERN);

  OINFO << "MatchInterFunctionGap(" << addr_str(anchor) << ") -- made code from: "
        << debug_instruction(insn) << LEND;

  return true;
}
#endif

// This section of code provided multiple experimental approaces to ensure that thunks (jumps
// to the entry point of a function) are NOT coalesced into the function's first basic block,
// since this alters the entry point of the function, which is likely to be inconvenient when
// later more advanced analysis find references to the true entry point of the function.


// This approach attempts to use the standard prologue matching facility to make code from any
// jump instruction found in the program image.
bool
MatchThunkPrologue::match(const P2::Partitioner &partitioner, rose_addr_t anchor) {
  // If the instruction already exists, there's no need to create another?
  if (partitioner.instructionExists(anchor))
    return false;

  // Disassemble the instruction?
  SgAsmX86Instruction *insn = isSgAsmX86Instruction(partitioner.discoverInstruction(anchor));

  // If it's not a jump instruction, we're not interested.
  if (!insn || insn->get_kind() != x86_jmp)
    return false;

  // We should add some additional criteria to further reduce false positives.

  // We found a jmp instruction! Make a function out of it!
  GDEBUG << "Making thunk function from: " << debug_instruction(insn) << LEND;
  function_ = P2::Function::instance(
    anchor, SgAsmFunction::FUNC_THUNK | SgAsmFunction::FUNC_PATTERN);
  return true;
}

bool
RefuseZeroCode::check_zeros(const P2::Partitioner& partitioner,
                            rose_addr_t address, const P2::BasicBlock::Ptr& bblock) {
  SgAsmInstruction *insn = partitioner.discoverInstruction(address);
  // Quick fail if we're a normal instruction.
  if (!check_zero_insn(insn)) return false;

  // A more general approach to finding an arbitrary number of zero instructions.
  rose_addr_t current = address + 2;
  size_t found = 1;
  while (check_zero_insn(insn) && found < threshold) {
    current += 2;
    insn = partitioner.discoverInstruction(current);
    found++;
  }

  // If we've failed on address alone, we're done.
  if (found >= threshold) return true;

  // If not, we need to look at the accumulated instructions in the basic block.
  for (auto binsn : bblock->instructions()) {
    if (check_zero_insn(binsn)) found++;
  }

  // If we've failed on address alone, we're done.
  if (found >= threshold) return true;

  // Otherwise, we're not at the threshold yet.
  return false;
}

bool
check_zero_insn(SgAsmInstruction *insn) {
  // If we're given a bad instruction, return false.
  if (!insn) return false;
  // If the size isn't two bytes, return false.
  if (insn->get_size() != 2) return false;
  // If the bytes aren't all zero, return false.
  for (auto byte : insn->get_raw_bytes()) {
    if (byte != 0) return false;
  }
  // We're a zero instruction!
  return true;
}

bool
RefuseZeroCode::operator()(bool chain, const Args &args) {
  if (chain) {
    size_t last = args.bblock->instructions().size();
    if (last < 1)
      return chain;
    SgAsmX86Instruction* insn = isSgAsmX86Instruction(args.bblock->instructions()[last-1]);
    if (insn == NULL)
      return chain;
    if (check_zeros(args.partitioner, insn->get_address(), args.bblock)) {
      GDEBUG << "Refused to make code from zeros at: " << addr_str(insn->get_address()) << LEND;
      args.results.terminate = TERMINATE_PRIOR;
    }
  }
  return chain;
}

bool
RefuseOverlappingCode::operator()(bool chain, const Args &args) {
  if (chain) {
    // If we're not really enabled, we're done.
    if (!refusing)
      return chain;
    size_t last = args.bblock->instructions().size();
    if (last < 1)
      return chain;
    SgAsmX86Instruction* insn = isSgAsmX86Instruction(args.bblock->instructions()[last-1]);
    if (insn == NULL)
      return chain;

    // Would this approach be better here?
    // if (!(partitioner.aum().overlapping(anchor).isEmpty())) {
    for (size_t o = 1; o < insn->get_size(); o++) {
      rose_addr_t addr = insn->get_address() + o;
      if (args.partitioner.instructionExists(addr)) {
        GDEBUG << "Instruction at " << addr_str(addr) << " already exists, no overlapping code!" << LEND;
        args.results.terminate = TERMINATE_PRIOR;
      }
      break;
    }
  }
  return chain;
}

bool
MatchJmpToPrologue::operator()(bool chain, const Args &args) {
  if (chain) {
    // We're only interested in unconditional jump instructions.
    size_t last = args.bblock->instructions().size();
    if (last < 1)
      return chain;
    SgAsmX86Instruction* insn = isSgAsmX86Instruction(args.bblock->instructions()[last-1]);
    if (insn == NULL)
      return chain;
    if (insn->get_kind() != x86_jmp)
      return chain;

    //OINFO << "MatchJmpToPrologue found jump instruction: " << debug_instruction(insn) << LEND;

    bool found_prologues = false;

    // If we've found one, lets look at the successor(s?).
    bool complete;
    std::vector<rose_addr_t> successors = args.partitioner.basicBlockConcreteSuccessors(args.bblock, &complete);
    for (rose_addr_t s : successors) {
      // The case that we're really interested in is the one where the function doesn't exist.
      // We want to look to see if it matches a prologue and if it does, then mark it as such.
      // We couldn't use the standard prologue matchers because they insisted on looking only
      // at _new_ bytes, and we're interested in whether the potentially existing bytes match a
      // prologue.
      rose_addr_t current = s;
      //OINFO << "MatchJmpToPrologue successor: " << addr_str(current) << LEND;

      // If there's a "mov edi, edi", that's ok, but not required.
      SgAsmX86Instruction *pinsn = isSgAsmX86Instruction(args.partitioner.discoverInstruction(current));
      if (P2::ModulesX86::matchMovDiDi(args.partitioner, pinsn)) {
        //OINFO << "MatchJmpToPrologue found 'mov edi, edi' at: " << addr_str(pinsn->get_address()) << LEND;
        current = pinsn->get_address() + pinsn->get_size();
        pinsn = isSgAsmX86Instruction(args.partitioner.discoverInstruction(current));
      }

      // We must have a "push ebp" instruction.
      if (!P2::ModulesX86::matchPushBp(args.partitioner, pinsn)) {
        continue;
      }

      //OINFO << "MatchJmpToPrologue found 'push ebp' at: " << addr_str(pinsn->get_address()) << LEND;
      current = pinsn->get_address() + pinsn->get_size();
      pinsn = isSgAsmX86Instruction(args.partitioner.discoverInstruction(current));
      // We must have a "mov esp, ebp" instruction.
      if (!P2::ModulesX86::matchMovBpSp(args.partitioner, pinsn))
        continue;

      //OINFO << "MatchJmpToPrologue match at: " << addr_str(s) << LEND;
      found_prologues = true;
      prologues.insert(s);
    }

    // Curiously, we can't actually return TERMINATE_NOW without breaking our code.  Cory has
    // no idea why really...
    if (found_prologues) {
      // Turns out that we _can't_ do this for some reason?
      // args.results.terminate = TERMINATE_NOW;
      // Are we supposed to return false to ensure that our result is used?
      // return false;
    }
  }
  return chain;
}

void
MatchJmpToPrologue::make_functions(P2::Partitioner &partitioner) {
  for (rose_addr_t addr : prologues) {
    //OINFO << "MatchJmpToPrologue function created at: " << addr_str(addr) << LEND;
    P2::Function::Ptr function = P2::Function::instance(addr, SgAsmFunction::FUNC_PATTERN);
    partitioner.attachOrMergeFunction(function);
  }
  prologues.clear();
}

#if 0
// This custom BasicBlockCallback is derived from PreventDiscontiguousBlocks (?), except that
// it has been modified to experiment with BasicBlockCall backs.
bool
ThunkDetacher::operator()(bool chain, const Args &args) {
  if (chain) {

    // This callback is invoked for each instruction added to the basic block, so our first
    // objective is to ignore all cases where we're not the first instruction in a new basic
    // block.
    size_t ninsns = args.bblock->nInstructions();
    // Thunks are always one instruction!
    if (ninsns != 1)
      return chain;

    // Also, we're only interested in jump instructions.
    SgAsmX86Instruction* insn = isSgAsmX86Instruction(args.bblock->instructions()[0]);
    if (insn == NULL)
      return chain;
    if (insn->get_kind() != x86_jmp)
      return chain;

    OINFO << "ThunkDetacher found jump instruction: " << debug_instruction(insn) << LEND;

    // I'm not sure what we were doing here.   Perhaps just copying code from Robb?
    bool complete;
    std::vector<rose_addr_t> successors = args.partitioner.basicBlockConcreteSuccessors(args.bblock, &complete);

    OINFO << "ThunkDetacher at " << args.bblock->printableName()
          << " has " << Rose::StringUtility::plural(args.bblock->instructions().size(),
                                                    "instructions")
          << " and " << Rose::StringUtility::plural(successors.size(), "successors") << LEND;

    if (complete && 1==successors.size()) {
      P2::ControlFlowGraph::ConstVertexIterator vertex =
        args.partitioner.findPlaceholder(args.bblock->address());

      for (const P2::ControlFlowGraph::Edge& edge : vertex->inEdges()) {
        const P2::ControlFlowGraph::Vertex &source = *edge.source();
        P2::BasicBlock::Ptr sblock = source.value().bblock();
        //OINFO << "Predecessor block is " << sblock->printableName() << LEND;

        // Get the number of instructions in the predecessor basic block.
        size_t pninsns = sblock->nInstructions();

        if (pninsns > 0) {
          SgAsmX86Instruction* pred_insn = isSgAsmX86Instruction(sblock->instructions()[pninsns-1]);
          //OINFO << "Previous instruction is: " << debug_instruction(pred_insn) << LEND;
          rose_addr_t fall_thru = insn_get_fallthru(pred_insn);
          if (fall_thru == args.bblock->address()) {
            //OINFO << "Block " << args.bblock->printableName() << " is not really a thunk!" << LEND;
            return chain;
          }
        }
      }

      // This is a thunk.  Terminate the existing basic block now (at the jmp).  This might
      // also detach some unconditional jumps that are not thunks (e.g. the target of the jump
      // is not really the start of a function).  For right now I don't really care, but if
      // this turns out to be a problem we can use some other heuristics.  But we can't rely on
      // there being other in edges, or the default Partitioner2 will already do the right
      // thing.
      //OINFO <<" thunk detected\n";
      args.results.terminate = TERMINATE_NOW;

      // We also want to make sure that the target address will become a function. We can't
      // modify the partitioner while we're inside the callback, so save them up for later.  We
      // save the addresses, but we could have also created the Function objects (just not
      // attach them to the partitioner).
      jmpVas.insert(insn->get_address());
      targetVas.insert(successors[0]);
    }
  }

  return chain;
}

void
ThunkDetacher::makeFunctions(P2::Partitioner &partitioner) {
  // Make each JMP a function.  This could be a little dangerous: if we split off a JMP even
  // though it wasn't a thunk, we would end up making it a function of its own even though it
  // isn't really.  Perhaps this is where we should add the additional heuristics.
  for (rose_addr_t va : jmpVas) {
    P2::Function::Ptr function = P2::Function::instance(va, SgAsmFunction::FUNC_THUNK);
    partitioner.attachOrMergeFunction(function);
  }

  // Make each JMP target a function.
  for (rose_addr_t va : targetVas) {
    P2::Function::Ptr function = P2::Function::instance(va);
    partitioner.attachOrMergeFunction(function);
  }
}
#endif

P2::Partitioner
CERTEngine::createTunedPartitioner() {

  //OINFO << "Creating custom partitioner!" << LEND;
  P2::Partitioner partitioner = P2::Engine::createTunedPartitioner();

  // We're building out own list of Prolog matchers because MatchRetPadPush does things that we
  // did not find helpful (like skipping "mov edi,edi" instructions as padding).
  partitioner.functionPrologueMatchers().clear();
  partitioner.functionPrologueMatchers().push_back(P2::ModulesX86::MatchHotPatchPrologue::instance());
  partitioner.functionPrologueMatchers().push_back(P2::ModulesX86::MatchStandardPrologue::instance());
  partitioner.functionPrologueMatchers().push_back(P2::ModulesX86::MatchAbbreviatedPrologue::instance());
  partitioner.functionPrologueMatchers().push_back(P2::ModulesX86::MatchEnterPrologue::instance());

  // We're explicitly disabling the function Prologue thunk matchers here.  In our opinion
  // "matching" on thunks by scanning the program image space is counter productive, and that
  // logic should only be used to "split" thunks from otehr functions.
  //partitioner.functionPrologueMatchers().push_back(
  //  P2::Modules::MatchThunk::instance(functionMatcherThunks()));

  // See comment above about MatchRetPadPush...
  //partitioner.functionPrologueMatchers().push_back(ModulesX86::MatchRetPadPush::instance());

  // Add another thunk splitting predicate.
  const P2::ThunkPredicates::Ptr thunk_splitters = functionSplittingThunks();
  P2::ThunkPredicates::Ptr new_thunk_splitters = P2::ThunkPredicates::instance();
  for (auto pred : thunk_splitters->predicates()) {
    new_thunk_splitters->predicates().push_back(pred);
  }
  new_thunk_splitters->predicates().push_back(isX86MovAddJmpThunk);
  functionSplittingThunks(new_thunk_splitters);

  // Register a basic block callback that will track jumps to prologues.
  jump_to_prologue_matcher = MatchJmpToPrologue::instance();
  partitioner.basicBlockCallbacks().append(jump_to_prologue_matcher);
  partitioner.basicBlockCallbacks().append(RefuseZeroCode::instance());
  overlapping_code_detector = RefuseOverlappingCode::instance();
  partitioner.basicBlockCallbacks().append(overlapping_code_detector);

  return partitioner;
}

// ==========================================================================================

// For the Superset engine, the partioning algorithm is very simple.
void
SupersetEngine::runPartitioner(P2::Partitioner &partitioner) {
  OINFO << "Running the superset partitioning algorithm." << LEND;

  Rose::BinaryAnalysis::InstructionProvider& ip = partitioner.instructionProvider();

  auto mmap = partitioner.memoryMap();

  // The minimum and maximum addresses that we visited.
  rose_addr_t least = 0;  //
  rose_addr_t greatest = 0;

  // The memory map is IntervalMap, which maps Intervals to Buffers.  Each Interval and Buffer
  // represents a contiguous, identically protected region of program memory.  The Interval
  // itself is also iterable, and contains the addresses of the region.
  for (Sawyer::Container::Interval<rose_addr_t> interval : mmap->intervals()) {

    rose_addr_t l = interval.least();
    rose_addr_t g = interval.greatest();
    GINFO << "Disassembling segment " << addr_str(l) << " - " << addr_str(g) << LEND;
    if (l < least || least == 0) least = l;
    if (g > greatest) greatest = g;

    for (rose_addr_t addr : interval) {
      // Too verbose to be of much use.
      //GDEBUG << "Disassembling " << addr_str(addr) << LEND;

      // Disassemble the instruction, and store it in the instruction provider cache.
      SgAsmInstruction* insn = ip[addr];

      // If there's no instruction at that address, move on to the next one.
      if (!insn || insn->isUnknown()) continue;

      OINFO << boost::str(boost::format("%-60s") % debug_instruction(insn, 12)); // No LEND!

      // Get the successor from the instruction.  This code can't be here permanently, because
      // we need to create each instruction vertex in the graph before creating the edges, but
      // it's a start.
      bool complete;
      auto successors = insn->getSuccessors(complete);
      if (successors.size() > 0) {
        for (rose_addr_t saddr : successors.values()) {
          OINFO << addr_str(saddr) << " ";
        }
        OINFO << LEND;
      }
      else {
        OINFO << "None" << LEND;
      }
    }
  }

  GINFO << "Disassembled addresses " << addr_str(least) << " - " << addr_str(greatest) << LEND;
}

// ==========================================================================================

Monitor::Monitor()
{
  // Set the partitioner limits.
  get_global_limits().set_limits(partitioner_limit, PharosLimits::limit_type::PARTITIONER);
}

bool
Monitor::operator()(bool chain, const AttachedBasicBlock& /* args */) {
  // Calling this on every basic block attachement is probably wasteful.
  // The overhead appears to negligible based on testing hoever.
  partitioner_limit.increment_counter();
  LimitCode rstatus = partitioner_limit.check();
  if (rstatus != LimitSuccess) {
    std::stringstream ss;
    ss << "Partitioner " << partitioner_limit.get_message() << " exceeded: "
       << partitioner_limit.get_absolute_usage()
       << ", adjust with --maximum-memory";

    // This is an old comment:
    // Rather ungraceful exit here. :-(  I'm not sure how else to stop the partitioner.

    // ejs: I'm not sure what the above comment means.  Why not throw an exception?  We need to
    // throw an exception here so we can catch it and remove the .serialize file we may have
    // opened.
    throw ResourceException(ss.str());
  }
  //if (args.bblock)
  //  OINFO << "Attached basic block " << addr_str(args.bblock->address()) << LEND;
  return chain;
}

bool
Monitor::operator()(bool chain, const DetachedBasicBlock& /* args */) {
  //if (args.bblock)
  //  OINFO << "Detached basic block " << addr_str(args.bblock->address()) << LEND;
  return chain;
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
