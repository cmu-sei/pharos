// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#include <stdarg.h>
#include <stdexcept>
#include <fstream>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>

#include <rose.h>

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

// ===============================================================================================
// Partitioner2
// ===============================================================================================

// Local function only called from create_engine() and copied from ROSE (recursiveDisassemble?) code.
static SgAsmBlock *
buildAst(P2::Engine &engine, const P2::Partitioner &partitioner) {
    static SgAsmBlock *gblock = NULL;
    if (NULL==gblock)
        gblock = P2::Modules::buildAst(partitioner, engine.interpretation());
    return gblock;
}

P2::Partitioner create_partitioner(const ProgOptVarMap& vm, P2::Engine* engine) {
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

  // Enable Robb's standard thunk splitting logic.  Needed for our debug test cases?
  engine->splittingThunks(true);

  // Parse the command-line
  std::vector<std::string> specimen_names;
  specimen_names.push_back(vm["file"].as<std::string>());

  if (specimen_names.empty())
    throw std::runtime_error("no specimen specified; see --help");

  // Load the specimen as raw data or an ELF or PE container.
  MemoryMap::Ptr map = engine->loadSpecimens(specimen_names);

  // Get the interpretation.
  SgAsmInterpretation* interp = engine->interpretation();

  // Mark the entry point segment as executable (unless the user asked us not to).
  if (vm.count("no-executable-entry") < 1 && interp) {
    for (const SgAsmGenericHeader *fileHeader : interp->get_headers()->get_headers()) {
      for (const rose_rva_t &rva : fileHeader->get_entry_rvas()) {
        // Get the address of the entry point.
        rose_addr_t va = rva.get_rva() + fileHeader->get_base_va();
        // A constraint containing just the entry point address.
        auto const & entry_seg = *map->at(va).segments().begin();
        // The name of the segment that address is in.
        const std::string & name = entry_seg.name();
        // A predicate for all addresses in a segment with the same name.
        NamePredicate name_constraint(name);
        // The map constraint matching the predicate (all addresses in the segment).
        auto data_segment = map->segmentPredicate(&name_constraint);
        // Set ther permission to executable.
        data_segment.changeAccess(MemoryMap::EXECUTABLE, 0);
        GINFO << "Marked entry point address " << addr_str(va) << " in segment " << name
              << " as executable." << LEND;
      }
    }
  }

  // Create a partitioner that's tuned for a certain architecture, and then tune it even more
  // depending on our command-line.
  P2::Partitioner partitioner = engine->createPartitioner();

  // Enable our custom CFG debugger.
  // partitioner.cfgAdjustmentCallbacks().append(Monitor::instance());

  size_t arch_bits = partitioner.instructionProvider().instructionPointerRegister().get_nbits();
  if (arch_bits != 32) {
    // What does the config file say about whether 64-bit analysis is supported for this tool?
    auto config_allow64 = vm.config().path_get("pharos.allow-64bit");
    // If it's not enabled in the config file, warn regardless of the command line option.
    if ((not config_allow64) or (not config_allow64.as<bool>())) {
      GWARN << "Non 32-bit Windows PE support is still highly experimental for this tool!" << LEND;
      if (not vm.count("allow-64bit")) {
        GFATAL << "Please specify --allow-64bit to allow the analysis of 64-bit executables." << LEND;
        throw std::invalid_argument("Program analysis aborted.");
      }
    }
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
    bfs::path path(vm["serialize"].as<std::string>());
    if (exists(path)) {
      OINFO << "Reading serialized data from " << path << "." << LEND;
      bfs::ifstream file(path);
      bio::filtering_streambuf<bio::input> in;
      in.push(bio::gzip_decompressor());
      in.push(file);
      bar::binary_iarchive ia(in);
      std::string version;
      ia >> version;
      if (version != version_number()) {
        if (vm.count("ignore-serialize-version")) {
          GWARN << "Serialized data was from a different version of Rose."
                << "  Loading anyway as requested." << LEND;
          version = version_number();
        } else {
          GFATAL << "Serialized data was from a different version of Rose.  Exiting.\n"
                 << "If you want to overwrite the file, remove the file " << path << '\n'
                 << "If you want to ignore this, use the --ignore-serialize-version switch."
                 << LEND;
          exit(EXIT_FAILURE);
        }
      }
      time_point start_ts = clock::now();
      ia >> partitioner;
      duration secs = clock::now() - start_ts;
      OINFO << "Reading serialized data took " << secs.count() << " seconds." << LEND;
    } else {
      // No serialized data.  Write it instead.
      time_point start_ts = clock::now();
      engine->runPartitioner(partitioner);
      time_point now = clock::now();
      duration secs = now - start_ts;
      start_ts = now;
      OINFO << "Function partitioning took " << secs.count() << " seconds." << LEND;
      OINFO << "Writing serialized data to " << path << "." << LEND;
      bfs::ofstream file(path);
      bio::filtering_streambuf<bio::output> out;
      out.push(bio::gzip_compressor());
      out.push(file);
      bar::binary_oarchive oa(out);
      oa << version_number();
      oa << partitioner;
      secs = clock::now() - start_ts;
      OINFO << "Writing serialized data took " << secs.count() << " seconds." << LEND;
    }
  } else {
    time_point start_ts = clock::now();
    engine->runPartitioner(partitioner);
    duration secs = clock::now() - start_ts;
    OINFO << "Function partitioning took " << secs.count() << " seconds." << LEND;
  }

  // Enable progress bars only if the output is to a terminal...
  if (!isatty(global_logging_fileno) || vm.count("batch")) {
    partitioner.progress(Rose::Progress::Ptr());
  }

  // This test may have been added because buildAst failed when the function list was empty.
  // Since we're no longer returning the interpretation, but the engine instead, we can
  // probably return the engine anyway (no AST?) and not crash... Hopefully.
  if (partitioner.functions().empty() && engine->startingVas().empty()) {
    GERROR << "No starting points for recursive disassembly." << LEND;
    return partitioner;
  }

  // We should probably save an instruction provider in the global descriptor set instead of
  // making a map of addresses to instructions in the global descriptor set.  Unfortunately,
  // this approach is much less convenient in Partitioner1 than in Partitioner2, so it'll
  // probably have to wait until we retire Partitioner1.

  // global_descriptor_set.instruction_provider = &(partitioner.instructionProvider());
  // Don't create new instructions after this point...
  // global_descriptor_set.instruction_provider->disableDisassembler();

  if (interp == NULL) {
    OERROR << "Unable to obtain program interpretation." << LEND;
  }
  SgAsmBlock* block = buildAst(*engine, partitioner);
  if (block == NULL) {
    OFATAL << "Unable to build AST, no code was found." << LEND;
  }

  if (block != NULL and interp != NULL) {
    GTRACE << "done calling partitioner2" << LEND;
    GTRACE << "calling set_global_block" << LEND;
    interp->set_global_block(block);
    GTRACE << "done calling set_global_block, calling set_parent" << LEND;
    block->set_parent(interp);
    GTRACE << "done calling set_parent" << LEND;
  }

  return partitioner;
}

uint8_t CERTEngine::read_byte(rose_addr_t addr) {
  uint8_t byte;
  if (1 != memoryMap()->at(addr).limit(1).require(MemoryMap::EXECUTABLE).read(&byte).size()) {
    GERROR << "Failed to read byte at " << addr_str(addr) << LEND;
    throw std::out_of_range(std::string("Failed to read byte at ") + addr_str(addr));
  }
  return byte;
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

    // The padding data block that we're going to create.
    P2::DataBlock::Ptr dblock;
    // For each unused interval.
    for (const AddressInterval &interval : unused.intervals()) {
      rose_addr_t least = interval.least();
      rose_addr_t greatest = interval.greatest();
      //OINFO << "Padding Gap: " << addr_str(least) << " - " << addr_str(greatest) << LEND;

      rose_addr_t current = least;
      uint8_t byte;
      uint8_t expected;
      // Look for padding at the start of the block going forward...
      if (top && not_pad_gaps.find(least) == not_pad_gaps.end()) {
        // Mark the end of this gap as having been analyzed, so we don't try again.
        not_pad_gaps.insert(least);

        try {
          expected = read_byte(current);
        }
        catch (std::exception e) {
          GERROR << e.what() << LEND;
          continue; // not sure if continue or return is the right answer here...
        }
        if (expected == 0xCC || expected == 0x90) {
          byte = expected;
          while (byte == expected) {
            current++;
            try {
              byte = read_byte(current);
            }
            catch (std::exception e) {
              GERROR << e.what() << LEND;
              break; // not sure if break or return is the right answer here...
            }
          }
          //OINFO << "Padding block: " << addr_str(least) << " - " << addr_str(current) << LEND;
          // Find an appropriate function to attach the block to.  This might not actually be the
          // right way to do this.   Perhaps what we really mean is "the function owning this address".
          P2::Function::Ptr function;
          if (current == greatest + 1) function = partitioner.functionExists(greatest+1);
          if (!function) function = partitioner.functionExists(least-1);
          if (!function) function = pad_function;

          if (function) {
            //OINFO << "Attaching block to function:" << addr_str(function->address()) << LEND;
            // NOTE: should really be marking this block as padding! The original Partitioner
            // would put a block reason on there of SgAsmBlock::BLK_PADDING but it looks like
            // Partitioner2 code doesn't do anything like this currently?  It has a generic
            // "Attributes" capability (key/val pairs) that looks like it'll be used for this
            // and other things, but it isn't used for anything currently?  And the P2
            // DataBlock structure does have a string "printableName()" method, but that just
            // is a manually generated answer every time you ask for it, can't set the name so
            // no hacky workaround potential there either.
            dblock = partitioner.attachFunctionDataBlock(function, least, current-least);
            changed = true;
          }
          else {
            GERROR << "Failed to find a function to attach padding to." << LEND;
          }
        }
      }

      // If we consumed the entire block, we can attach it to the following function.
      if (current == greatest) {
        continue;
      }

      // Look for padding at the end of teh block going backwards.  Strictly speaking the
      // not_pad_gaps test is a little bit incorrect because we're using the same address to
      // reflect both forward and backward searching.  That should be fine as long as we're only
      // doing one byte padding but if we started consuming NOP padding, we'd need two lists or a
      // more sophisticated approach.
      if (bottom && not_pad_gaps.find(greatest) == not_pad_gaps.end()) {
        // Mark the end of this gap as having been analyzed, so we don't try again.
        not_pad_gaps.insert(greatest);
        current = greatest;
        try {
          expected = read_byte(current);
        }
        catch (std::exception e) {
          GERROR << e.what() << LEND;
          continue; // not sure if continue or return is the right answer here...
        }
        if (expected == 0xCC || expected == 0x90) {
          byte = expected;
          while (byte == expected) {
            current--;
            try {
              byte = read_byte(current);
            }
            catch (std::exception e) {
              GERROR << e.what() << LEND;
              break; // not sure if break or return is the right answer here...
            }
          }

          // Find an appropriate function to attach the block to.  This might not actually be the
          // right way to do this.   Perhaps what we really mean is "the function owning this address".
          P2::Function::Ptr function = partitioner.functionExists(greatest+1);
          if (!function) function = partitioner.functionExists(least-1);
          if (!function) function = pad_function;

          if (function) {
            //OINFO << "Attaching block to function:" << addr_str(function->address()) << LEND;
            dblock = partitioner.attachFunctionDataBlock(function, current+1, greatest-current);
            changed = true;
          }
          else {
            GERROR << "Failed to find a function to attach padding to." << LEND;
          }
        }
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
  if (not_thunk_gaps.find(address) != not_thunk_gaps.end()) {
    return false;
  }

  // Mark this gap as having been analyzed already so that we don't try to analyze it again.
  not_thunk_gaps.insert(address);

  // Disassemble the instruction?
  SgAsmX86Instruction *insn = isSgAsmX86Instruction(partitioner.discoverInstruction(address));

  // If it's not a jump instruction, we're not interested.
  if (!insn || insn->get_kind() != x86_jmp) return false;

  P2::BasicBlock::Ptr bb = P2::BasicBlock::instance(address, &partitioner);
  bb->append(insn);

  bool complete;
  std::vector<rose_addr_t> successors = partitioner.basicBlockConcreteSuccessors(bb, &complete);
  if (successors.size() == 0) // to prevent a coredump...
    return false;
  rose_addr_t target = successors.front();

  // OINFO << "Thunk: " << addr_str(least) << LEND;
  unsigned reasons = SgAsmFunction::FUNC_THUNK | SgAsmFunction::FUNC_PATTERN;
  P2::Function::Ptr thunk_function = P2::Function::instance(address, reasons);
  partitioner.attachOrMergeFunction(thunk_function);

  //
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

  if (changed) {
    P2::Engine::runPartitionerRecursive(partitioner);
  }

  return changed;
}

bool
CERTEngine::bad_code(P2::BasicBlock::Ptr bb) {
  if (!bb || bb->nInstructions() == 0) {
    GDEBUG << "Bad code -- empty or invalid basic block." << LEND;
    return false;
  }

  return true;
}

bool
CERTEngine::create_arbitrary_code(P2::Partitioner& partitioner) {
  // Have we changed anything?
  bool changed = false;

  // Find unused executable address intervals.
  AddressIntervalSet executableSpace;
  for (const MemoryMap::Node &node : partitioner.memoryMap()->nodes()) {
    if ((node.value().accessibility() & MemoryMap::EXECUTABLE) != 0)
      executableSpace.insert(node.key());
  }
  AddressIntervalSet unused = partitioner.aum().unusedExtent(executableSpace);

  RefuseZeroCode::Ptr zero_code_detector = RefuseZeroCode::instance();

  // For each unused interval.
  for (const AddressInterval &interval : unused.intervals()) {
    rose_addr_t least = interval.least();
    rose_addr_t greatest = interval.greatest();

    // If we've considered making code at this exact address once before, either we've already
    // made code or we've decided not to.  Nothing from subsequent analysis is going to change
    // that conclusion, so we're done.
    if (not_code_gaps.find(least) != not_code_gaps.end()) {
      GDEBUG << "Arbitrary code gap: " << addr_str(least) << " - " << addr_str(greatest)
             << " -- previously analyzed." << LEND;
      continue;
    }

    GDEBUG << "Arbitrary code gap: " << addr_str(least) << " - " << addr_str(greatest) << LEND;

    // Mark this gap as having been analyzed already so that we don't try to analyze it again.
    not_code_gaps.insert(least);

    // We're going to look at each address.
    rose_addr_t current = least;
    // Have we decided to make code from the gap?
    bool make_code = true;

    // And then we'll make instructions and store them in this basic block.  The basic block is
    // not going to be attached to the partitioner until we've analyzed it for bad code and
    // made a basic decision about whether this block is really code.
    P2::BasicBlock::Ptr bb = P2::BasicBlock::instance(least, &partitioner);

    // For each address in the block (or until we don't have a fallthru edge)...
    while (current < greatest) {

      if (zero_code_detector->check_zeros(partitioner, current, bb)) {
        GDEBUG << "Refused to make arbitrary code because of zeros at " << addr_str(current) << LEND;
        make_code = false;
        break;
      }

      // Disassemble the instruction?
      SgAsmX86Instruction *insn = isSgAsmX86Instruction(partitioner.discoverInstruction(current));

      // If we couldn't create a valid instruction, that's fairly good evidence that we're not
      // really code.
      if (!insn) {
        GDEBUG << "Unable to make arbitrary code at " << addr_str(current) << LEND;
        make_code = false;
        break;
      }

      // It looks like this instruction is a valid one, so keep it.
      bb->append(insn);

      // The logic for following fallthru edges here is probably very wrong.  Cory's not sure
      // what the best way to do this is, since we explicitly want to check for a number of
      // unusual cases.  For example, we don't expect to pass out of the current gap while
      // following fallthru edges, we probably want to cheat a little and keep making
      // instructions that normall wouldn't be considered a true basic block and so on.
      bool found_fallthru = false;
      rose_addr_t fallthru = insn->get_address() + insn->get_size();
      // Possibly:   rose_addr_t fallthru = bb->fallthroughVa();

      // If we've overlapped with the following block, that's bad, and we're not going to
      // make code here.
      if (fallthru > (greatest + 1)) {
        GDEBUG << "Arbitrary code overlaps with next block at: " << addr_str(fallthru)
               << " greatest=" << addr_str(greatest) << LEND;
        make_code = false;
        break;
      }

      // Conduct various checks on our successors.  We're trying to ensure that the partitioner
      // won't immediately do bad things.
      bool complete;
      for (rose_addr_t s : partitioner.basicBlockConcreteSuccessors(bb, &complete)) {
        GDEBUG << "Arbitrary code successor of " << addr_str(current) << " is " << addr_str(s) << LEND;

        // If this instruction flow into an existing instruction, that's actually good news.
        if (partitioner.instructionExists(s)) continue;
        // But if it flows into the middle of an existing instruction, that's bad...
        if (!(partitioner.aum().overlapping(s).isEmpty())) {
          GDEBUG << "Aribtrary code rejected because it flows into the middle of an instruction." << LEND;
          make_code = false;
          break;
        }
      }

      // If we don't actually flow into the fall through address, we should stop making code
      // and assess whether the code is bad or not.
      if (!found_fallthru) {
        GDEBUG << "No fall thru found at: " << addr_str(current) << LEND;
        break;
      }

      // If we've ended exactly on the edge of the gap, that's fine and it means we're done
      // making code, and it's looking good to keep this code.
      if (fallthru == (greatest + 1)) {
        break;
      }

      // Make our next instruction at the fallthru address.
      current = fallthru;
    }

    // If we still think this might be code, ask the bad code analyzer.
    if (make_code) {
      make_code = bad_code(bb);
      // And if we _still_ think it's code, let's turn the partitioner loose on it.
      if (make_code) {
        GDEBUG << "Arbitrary code made: " << addr_str(least) << LEND;
        unsigned reasons = SgAsmFunction::FUNC_USERDEF;
        P2::Function::Ptr function = P2::Function::instance(least, reasons);
        partitioner.attachOrMergeFunction(function);

        // Right now we're going to try following flow from the recently examined code.  This
        // is dangerous because the partitioner might follow flow into code that's not really
        // code and then break up existing basic blocks or functions, which is very much
        // undesired.  We're currently hoping that this code is invoked infrequently enough
        // that this won't be a major problem, and this is the easiest way to find the rest of
        // a small function attached to the block that we just discovered.  If this approach
        // turns out to be a problem, there are several much better approaches that we've
        // discusssed to prevent bad things from happening here.
        GDEBUG << "Starting arbitrary code run of partitioner..." << LEND;
        P2::Engine::runPartitionerRecursive(partitioner);
        GDEBUG << "Finished arbitrary code run of partitioner..." << LEND;

        // If there's no code at the address that we just said to create code at the
        // partitioner must have concluded on it's own that this not in fact a valid basic
        // block.
        if (!partitioner.instructionExists(least)) {
          GDEBUG << "Instruction at " << addr_str(least) << " does not exist!" << LEND;
        }
        else {
          // Finally, on the unlikely chance that calling the partitioner did something
          // significant, let's stop making arbitrary code and return to our caller so that we
          // can resume doing safer things.  This could have bad performance if there's a very
          // large list of gaps that fail arbitrary code tests, since we'd keep processing them
          // over and over again on every iteration.  For right now, we're again assuming that
          // this routine isn't being invoked too many times.

          // Temporarily disabled for testing.  Please re-enable!
          // With this line enabled, our code goes into an endless loop!
          changed = true;
          break;
        }
      }
    }
  }
  return changed;
}

void
CERTEngine::runPartitionerRecursive(P2::Partitioner& partitioner) {
  using clock = std::chrono::steady_clock;
  using time_point = std::chrono::time_point<clock>;
  using duration = std::chrono::duration<double>;

  // Make an effort to find at least one function that we can attach padding to.
  SgAsmInterpretation* interp = interpretation();
  if (interp) {
    for (const SgAsmGenericHeader *fileHeader : interp->get_headers()->get_headers()) {
      for (const rose_rva_t &rva : fileHeader->get_entry_rvas()) {
        rose_addr_t va = rva.get_rva() + fileHeader->get_base_va();
        pad_function = partitioner.functionExists(va);
        if (pad_function) break;
      }
      if (pad_function) break;
    }
  }
  if (pad_function) {
    GDEBUG << "Fallback pad function: " << addr_str(pad_function->address()) << LEND;
  }

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
  OINFO << "Long delays until the next time stamp are caused by the Pharos custom partitioning" << LEND;
  OINFO << "algorithm and may be resolved by using the --stockpart option, but at the expense" << LEND;
  OINFO << "of possibly less complete function detection.  Using --no-semantics may also help." << LEND;

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

  //OINFO << "Dumping partitioner config." << LEND;
  //std::ofstream dump("pdump2.txt");
  //partitioner.dumpCfg(dump);

  // Now add the prologue matchers back, and analyze one more time.
  // It unclear whether this helped much, but it's difficult for me to believe that it hurts.
  partitioner.functionPrologueMatchers().push_back(P2::ModulesX86::MatchHotPatchPrologue::instance());
  partitioner.functionPrologueMatchers().push_back(P2::ModulesX86::MatchStandardPrologue::instance());
  partitioner.functionPrologueMatchers().push_back(P2::ModulesX86::MatchAbbreviatedPrologue::instance());
  partitioner.functionPrologueMatchers().push_back(P2::ModulesX86::MatchEnterPrologue::instance());
  partitioner.functionPrologueMatchers().push_back(P2::ModulesX86::MatchThunk::instance());

  P2::Engine::runPartitionerRecursive(partitioner);

  GDEBUG << "Custom partitioner 2 pass complete." << LEND;
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
    function_ = P2::Function::instance(anchor, SgAsmFunction::FUNC_THUNK | SgAsmFunction::FUNC_PATTERN);
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
  partitioner.functionPrologueMatchers().push_back(P2::ModulesX86::MatchThunk::instance());
  //partitioner.functionPrologueMatchers().push_back(ModulesX86::MatchRetPadPush::instance());

  // Register a basic block callback that will track jumps to prologues.
  jump_to_prologue_matcher = MatchJmpToPrologue::instance();
  partitioner.basicBlockCallbacks().append(jump_to_prologue_matcher);
  partitioner.basicBlockCallbacks().append(RefuseZeroCode::instance());
  overlapping_code_detector = RefuseOverlappingCode::instance();
  partitioner.basicBlockCallbacks().append(overlapping_code_detector);

  return partitioner;
}

void
CERTEngine::attachBlocksToFunctions(P2::Partitioner &partitioner) {
  //if (thunkDetacher_)
  //  thunkDetacher_->makeFunctions(partitioner);
  //OINFO << "Attaching blocks to functions" << LEND;
  P2::Engine::attachBlocksToFunctions(partitioner);
}

bool
Monitor::operator()(bool chain, const AttachedBasicBlock &args) {
  if (args.bblock)
    OINFO << "Attached basic block " << addr_str(args.bblock->address()) << LEND;
  return chain;
}

bool
Monitor::operator()(bool chain, const DetachedBasicBlock &args) {
  if (args.bblock)
    OINFO << "Detached basic block " << addr_str(args.bblock->address()) << LEND;
  return chain;
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
