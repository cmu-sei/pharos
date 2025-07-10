// Copyright 2015-2025 Carnegie Mellon University.  See LICENSE file for terms.

#include <libpharos/descriptors.hpp>
#include <libpharos/misc.hpp>
#include <libpharos/util.hpp>
#include <libpharos/riscops.hpp>
#include <libpharos/options.hpp>
#include <libpharos/pdg.hpp>
#include <libpharos/json.hpp>
#include <libpharos/bua.hpp>
#include <libpharos/masm.hpp>

#include <Sawyer/Message.h>
#include <Sawyer/ProgressBar.h>
#include <Rose/BinaryAnalysis/Architecture/X86.h>

#include <boost/graph/iteration_macros.hpp>
#include <boost/filesystem.hpp>

using namespace pharos;

namespace bf = boost::filesystem;

#define DEFAULT_MIN_INSTRUCTIONS 1

std::string filename;
std::string filemd5;

ProgOptDesc hash_options() {
  namespace po = boost::program_options;

  ProgOptDesc hashopt("fn2hash v0.04 options");
  hashopt.add_options()
    ("min-instructions,m",
     po::value<size_t>()->default_value(DEFAULT_MIN_INSTRUCTIONS),
     ("Minimum number of instructions needed to output data for a function"))
    ("extra-data,E", po::bool_switch(),
     "Output extra data in JSON format")
    ("basic-blocks,B", po::bool_switch(),
     "Output optional basic block level data in JSON format")
    ("json,j", po::value<bf::path>(),
     "Output as JSON to the given file.  ('-' means stdout)")
    ("pretty-json,p", po::value<unsigned>()->implicit_value(4),
     "Pretty-print json.  Argument is the indent width")
    ;
  return hashopt;
}

class ExtraFunctionHashData {
 public:
  unsigned int num_blocks; // basic blocks, that is
  unsigned int num_blocks_in_cfg;

  std::string mnemonics; // concatenated mnemonics
  std::string mnemcats; // concatenated mnemonic categories

  // Back in the IDA days of function hashing, we listed instructions in address order.  When
  // we implemented the ROSE algorithm we switched to listing the instructions in a
  // ROSE-based control flow order in an effort to produce better/fuzzier hashes, which is
  // what most of these extra hashes are about.  There was some debate about this at the
  // time, but when we tried to implement a compatible algorithm in Kaiju is when the
  // value/simplicity of address order became very clear.  Because there's a significant
  // backwards compatiblity issue here, the control flow ordering was preserved in these two
  // values, which can be controlled from a command line switch on fn2hash.
  std::string cf_exact_hash; // control flow ordered exact hash
  std::string cf_exact_bytes; // I'd rather use a vector<byte> here...
  std::string cf_pic_hash; // control flow ordered PIC hash
  std::string cf_pic_bytes; // I'd rather use a vector<byte> here...

  // The composite PIC hash is a variant of PIC w/ no control flow insn, basic blocks hashed
  // and func hashed by hashing those ordered hashes (ASCII values)...  This approach tries
  // to account for simple CFG changes.
  std::string composite_pic_hash;

  std::string mnemonic_hash; // variant of EHASH but only mnemonics (no operands) instead of insn bytes
  std::string mnemonic_category_hash; // variant of PHASH but only mnemonic categories
  std::string mnemonic_count_hash; // hash of the ordered mnemonic/count pairs
  std::string mnemonic_category_count_hash; // hash of the orderend mnemcat/count pairs

  std::map< std::string, uint32_t > mnemonic_counts;
  std::map< std::string, uint32_t > mnemonic_category_counts;

  std::vector< rose_addr_t > basic_block_addrs; // added in flow order (take len to get # bbs)
  std::vector< std::pair< rose_addr_t, rose_addr_t > > cfg_edges; // from->to pairs of bb addrs (empty if only 1 bb?)
  class BasicBlockHashData {
   public:
    //rose_addr_t addr; // eh, get addr from list above or map below
    std::string pic;
    std::string cpic;
    std::vector< std::string > mnemonics; // in insn order (take len to see how many insn in bb)
    std::vector< std::string > mnemonic_categories; // in insn order (take len to see how many insn in bb)
  };
  std::map< rose_addr_t, BasicBlockHashData > basic_block_hash_data;
};


// A function hash variant close to the Uberflirt EHASH/PHASH stuff, plus a new Composite PIC
// hash, and some "extra" hash types if requested.  Here's the basic gist:
//
// iterate over basic blocks in flow order (a consistent logical ordering)
//   iterate over instructions in block
//     add raw bytes to block ebytes
//     if extra
//       save mnemonic & mnemonic category info
//     if jmp/call/ret
//       ignore this completely for CPIC
//     else
//       look for integers operands in program range (more checks?) & replace w/ 00
//     add exact bytes to ebytes
//     add (modified) bytes to pbytes & cpicbytes
//   calc md5 of block cpicbytes
// md5 ebytes & pbytes
// sort all block cpic hash values, concat & hash to generate fn level CPIC

// TODO: replace x86 specific stuff w/ code that will work w/ other ISAs, should we ever start
// supporting those...  We might work with non-X86 architectures now, but we'll warn about it
// (once).
ExtraFunctionHashData compute_extra_function_hashes(
  FunctionDescriptor const & fd)
{
  static constexpr int entry_vertex = 0;
  ExtraFunctionHashData extra;

  // mwd: this code assumes this.  Is it guaranteed?
  assert(fd.get_func());
  auto * func = fd.get_func();
  auto & ds = fd.ds;

  const CFG& cfg = fd.get_pharos_cfg();

  // A non-trivial change was made here by Cory.  Previously we were using the ROSE
  // (unfiltered) control flow graph, but now we're using the Pharos (filtered) control flow
  // graph to compute the function hashes.  Of course this cna _change_ the hashes for
  // functions.  The choice to use the unfiltered CFG seems to have been based on an inability
  // to conveniently call get_pharos_cfg() here without doing the complete PDG analysis.  Since
  // that bug is now fixed, there's no reason this shouldn't be based on the the Pharos CFG,
  // especially since it updates the function descriptor with fields likethe count of basic
  // blocks that are would be inconsistent with other important pharos analyses.
  std::vector<CFGVertex> cfgblocks = fd.get_vertices_in_flow_order(cfg, entry_vertex);

  // ODEBUG produces too much in objdigger test output, so let's use trace for this:
  GTRACE << fd.address_string() << " fn has " << cfgblocks.size()
         << " basic blocks in control flow" << LEND;
  if (cfgblocks.size() == 0) {
    return extra;
  }

  SgAsmBlock *funceb = func->get_entryBlock();
  SgAsmBlock *cfgeb = get(boost::vertex_name, cfg, cfgblocks[entry_vertex]);
  // I don't think this should be possible:
  if (funceb == NULL) {
    GERROR << "CFB No entry block in function: " << fd.address_string() << LEND;
    return extra;
  }
  if (cfgeb == NULL) {
    GERROR << "CFB No entry block in flow order: " << fd.address_string() << LEND;
    return extra;
  }
  // and I *really* hope this isn't either:
  if (funceb != cfgeb) {
    GERROR << "CFB Entry blocks do not match! " << addr_str(funceb->get_address()) << "!="
           << addr_str(cfgeb->get_address()) << " in function: " << fd.address_string() << LEND;
    return extra;
  }

  extra.num_blocks = func->get_statementList().size();
  extra.num_blocks_in_cfg = cfgblocks.size();

  //std::set< std::string > bbcpics; // basic block PIC hashes for composite calc (no dupes)
  std::multiset< std::string > bbcpics; // basic block cPIC hashes for fn composite PIC calc (keep dupes)

  // moved these to "extra"
  //std::string mnemonics; // concatenated mnemonics
  //std::string mnemcats; // concatenated mnemonic categories

  // would like to output some debugging disassembly, build up a string that then gets dumped
  // to an appropriate output stream later:
  std::ostringstream dbg_disasm;
  dbg_disasm << "Debug Disassembly of Function " << fd.get_name()
             << " (" << fd.address_string() << ")" << std::endl;

  std::vector< rose_addr_t > bbaddrs;

  // iterate over all basic blocks in the function:
  for (size_t x = 0; x < extra.num_blocks_in_cfg; x++) {
    SgAsmBlock *bb = get(boost::vertex_name, cfg, cfgblocks[x]);
    P2::BasicBlock::Ptr block = ds.get_block(bb->get_address());
    assert(block != NULL);

    std::string bbcpicbytes; // CPIC bytes (no control flow insns)
    std::string bbpicbytes; // PIC bytes (control flow insns included)
    std::vector< std::string > bbmnemonics;
    std::vector< std::string > bbmnemcats;

    dbg_disasm << "\t; --- bb start ---" << std::endl; // show start of basic block
    // Iterate over the instructions in the basic block:
    //num_instructions += block->nInstructions();
    for (SgAsmInstruction* insn : block->instructions()) {
      // We're only X86 depdendent to the extent that we haven't thought about other architectures.
      //if (!isSgAsmX86Instruction(insn) && !arch_warned_once) {
      //  GERROR << "Non-X86 architectures are not supported!" << LEND;
      //  arch_warned_once = true;
      //}

      // Get the raw bytes...
      SgUnsignedCharList bytes = insn->get_rawBytes();
      //num_bytes += bytes.size();
      if (bytes.size() == 0) { // is this possible?
        GERROR << "CFB no raw bytes in instruction at " << addr_str(insn->get_address()) << LEND;
        continue;
      }

      // okay place for debugging dumping the diassembly?  Tried to use ROSE's "unparser" but
      // sadly the convenience unparser is not handling lea instructions correctly, but our
      // debug_instruction code does (will revisit using the paritioner's unparser at some
      // point):
      std::string insnDisasm = debug_instruction(insn,17);
      dbg_disasm
        //<< addr_str(insn->get_address()) << " "
        << insnDisasm
        //<< std::endl
        //<< "\t; EBYTES: " << MyHex(bytes)
        //<< std::endl
        ;

      // Just append all of the bytes to cf_exact_bytes.
      extra.cf_exact_bytes.insert(extra.cf_exact_bytes.end(), bytes.begin(), bytes.end());

      // For the various PIC bytes & hashes, it's more complicated...

      AddressIntervalSet chunks = fd.get_address_intervals();
      std::vector<uint8_t> wildcard = pic_insn(ds, chunks, insn, 4096);

      bool nulls = false;
      // okay, now know what to NULL out, so do it:
      for (size_t i = 0; i < bytes.size(); ++i) {
        if (wildcard[i] != 0xff) {
          bytes[i] &= wildcard[i];
          nulls = true;
          // save offsets so yara gen can use pic_bytes + offsets to wildcard correct bytes
          // pic_offsets.push_back(pic_bytes.size() + i);
        }
      }

      std::string pbstr = "(same)";
      if (nulls)
        pbstr = MyHex(bytes);

      dbg_disasm
        //<< "\t; PBYTES: " << MyHex(bytes)
        << ", PBYTES: " << pbstr
        //<< std::endl
        ;

      // PIC hash is based on same # and order of bytes as EHASH but w/ possible addrs nulled:
      extra.cf_pic_bytes.insert(extra.cf_pic_bytes.end(), bytes.begin(), bytes.end());

      std::string mnemonic = insn->get_mnemonic();
      // need to address some silliness with what ROSE adds to some mnemonics first:
      if (boost::starts_with(mnemonic,"far")) {  // WHY are "farCall" and "farJmp" being output as mnemonics???
        if (mnemonic[3] == 'C')
          mnemonic = "call";
        else
          mnemonic = "jmp";
      }

      // hmm...should I peel off the rep*_ prefix too, or leave it on there.  I think for
      // this part I can leave it on there, but for the category determination I'll strip it
      // out (in insn_get_generic_category).  There may be other prefixes that I should deal
      // with too, but ignoring for now...
      std::string mnemcat = insn_get_generic_category(insn);

      //SDEBUG << addr_str(insn->get_address()) << " " << mnemonic << LEND;
      //dbg_disasm << "\t; MNEMONIC: " << mnemonic;
      dbg_disasm << ", MNEM: " << mnemonic;
      //SDEBUG << addr_str(insn->get_address()) << " " << mnemcat << LEND;
      dbg_disasm << ", CAT: " << mnemcat << std::endl;

      bbmnemonics.push_back(mnemonic);
      bbmnemcats.push_back(mnemcat);
      extra.mnemonics += mnemonic;
      if (extra.mnemonic_counts.count(mnemonic) > 0)
        extra.mnemonic_counts[mnemonic] += 1;
      else
        extra.mnemonic_counts[mnemonic] = 1;

      extra.mnemcats += mnemcat;
      if (extra.mnemonic_category_counts.count(mnemcat) > 0)
        extra.mnemonic_category_counts[mnemcat] += 1;
      else
        extra.mnemonic_category_counts[mnemcat] = 1;

      // Composite PIC Hash has no control flow instructions at all, and will be calculated
      // by the hashes of the basic blocks sorted & concatenated, then that value hashed.
      if (!insn_is_control_flow(insn)) {
        bbcpicbytes.insert(bbcpicbytes.end(),bytes.begin(), bytes.end());
      }
      bbpicbytes.insert(bbpicbytes.end(),bytes.begin(), bytes.end());
      //SDEBUG << dbg_disasm.str() << LEND;
      SINFO << dbg_disasm.str() << LEND;
      dbg_disasm.clear();
      dbg_disasm.str("");
    }
    // bb insns done, calc (c)pic hash(es) for block
    std::string bbcpic = get_string_md5(bbcpicbytes).str();
    std::string bbpic = get_string_md5(bbpicbytes).str();
    SDEBUG << "basic block @" << addr_str(bb->get_address()) << " has pic hash " << bbpic
           << " and (c)pic hash " << bbcpic << LEND;
    bbcpics.insert(bbcpic); // used to calc fn cpic later
    bbaddrs.push_back(bb->get_address());
    ExtraFunctionHashData::BasicBlockHashData bbdat;
    bbdat.pic = bbpic;
    bbdat.cpic = bbcpic;
    bbdat.mnemonics = bbmnemonics;
    bbdat.mnemonic_categories = bbmnemcats;
    // These are the "control flow order" versions of the exact and PIC hashes that were
    // deprecated in 2023 in favor of a simple address ordering of the instructions.
    extra.cf_exact_hash = get_string_md5(extra.cf_exact_bytes).str();
    extra.cf_pic_hash = get_string_md5(extra.cf_pic_bytes).str();
    // we only do this once per bb, so it's not in the map yet:
    extra.basic_block_hash_data[bb->get_address()] = bbdat;
    //extra.basic_block_hash_data.insert(std::pair< rose_addr_t, ExtraFunctionHashData::BasicBlockHashData > (bb->get_address(),bbdat));
  }

  // bbs all processed, calc fn hashes
  //exact_hash = get_string_md5(exact_bytes).str();
  //pic_hash = get_string_md5(pic_bytes).str();
  std::string bbcpicsconcat;
  for (auto const& bbcpic: bbcpics) {
    bbcpicsconcat += bbcpic;
  }
  //OINFO << bbcpicsconcat << LEND;
  extra.composite_pic_hash = get_string_md5(bbcpicsconcat).str();

  GTRACE << "calculating 'extra' hashes" << LEND;
  extra.mnemonic_hash = get_string_md5(extra.mnemonics).str();
  extra.mnemonic_category_hash = get_string_md5(extra.mnemcats).str();
  std::string mnemonic_counts_str;
  for (auto const& mnemcount: extra.mnemonic_counts) {
    mnemonic_counts_str += mnemcount.first + std::to_string(mnemcount.second);
  }
  extra.mnemonic_count_hash = get_string_md5(mnemonic_counts_str).str();
  std::string mnemonic_category_counts_str;
  for (auto const& mnemcatcount: extra.mnemonic_category_counts) {
    mnemonic_category_counts_str += mnemcatcount.first + std::to_string(mnemcatcount.second);
  }
  extra.mnemonic_category_count_hash = get_string_md5(mnemonic_category_counts_str).str();
  // add bb stuff here too
  extra.basic_block_addrs = bbaddrs;
  // iterate over CFG to get edge data:
  BGL_FORALL_EDGES(edge, cfg, CFG) {
    CFGVertex src_vtx = boost::source(edge, cfg);
    SgAsmBlock *src_bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, src_vtx));
    CFGVertex tgt_vtx = boost::target(edge, cfg);
    SgAsmBlock *tgt_bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, tgt_vtx));
    std::pair< rose_addr_t, rose_addr_t > aedge; // will this be init to 0,0?
    if (src_bb)
      aedge.first = src_bb->get_address();
    if (tgt_bb)
      aedge.second = tgt_bb->get_address();
    extra.cfg_edges.push_back(aedge);
    GTRACE << "adding edge to cfg_edges: " << aedge.first << "->" << aedge.second << LEND;
  }
  return extra;
}


class HashAnalyzer : public BottomUpAnalyzer {
  CallingConventionMatcher matcher;
  size_t min_instructions;
  bool basic_blocks;
  bool extra_data;
  json::BuilderRef builder;
  json::ObjectRef main;
  json::ArrayRef analysis;
  std::unique_ptr<std::ofstream> fout;
  std::ostream *out = nullptr;
  size_t num_code_blocks = 0;
  size_t num_data_blocks = 0;

 public:
  HashAnalyzer(DescriptorSet& ds_, ProgOptVarMap& vm_) : BottomUpAnalyzer(ds_, vm_) {
    matcher.report();
    min_instructions = vm_["min-instructions"].as<size_t>();
    basic_blocks = vm_["basic-blocks"].as<bool>();
    extra_data = vm_["extra-data"].as<bool>();
    if (vm_.count("json")) {
      auto & fname = vm_["json"].as<bf::path>();
      if (fname.compare("-") == 0) {
        out = &std::cout;
      } else {
        fout = make_unique<std::ofstream>(fname.native());
        out = fout.get();
      }
      builder = json::simple_builder();
      main = builder->object();
      main->add("tool", "fn2hash");
      auto args = builder->array();
      for (auto arg : vm_.args()) {
        args->add(arg);
      }
      main->add("invocation", std::move(args));
      auto specs = vm["file"].as<Specimens>().specimens();
      if (specs.size() == 1) {
        main->add("analyzed_file", specs.front());
      } else {
        auto bspecs = builder->array();
        for (auto & spec : specs) {
          bspecs->add(spec);
        }
        main->add("analyzed_file", std::move(bspecs));
      }
      analysis = builder->array();
      if (vm.count("pretty-json")) {
        *out << json::pretty(vm["pretty-json"].as<unsigned>());
      }
    }
  }

  void emit_csv(FunctionDescriptor* fd) {
    // Emit a CSV line.
    std::cout << filemd5 << ","
              << fd->address_string() << ","
              << fd->get_exact_hash() << ","
              << fd->get_pic_hash() << ","
              << fd->get_num_bytes() << ","
              << fd->get_num_instructions() << ","
              << num_code_blocks << ","
              << num_data_blocks << std::endl;
  }

  void emit_json(FunctionDescriptor* fd) {
    // json output
    auto hashes = builder->object();
    hashes->add("filemd5", filemd5);
    hashes->add("fn_addr", fd->address_string());
    hashes->add("exact_hash", fd->get_exact_hash());
    hashes->add("pic_hash", fd->get_pic_hash());
    hashes->add("num_bytes", fd->get_num_bytes());
    hashes->add("num_instructions", fd->get_num_instructions());
    hashes->add("num_code_blocks", num_code_blocks);
    hashes->add("num_data_blocks", num_data_blocks);
    hashes->add("exact_bytes", to_hex(fd->get_exact_bytes()));
    hashes->add("pic_bytes", to_hex(fd->get_pic_bytes()));

    if (!extra_data) {
      analysis->add(std::move(hashes));
      return;
    }

    // mnemonic related & basic block level hash data...
    ExtraFunctionHashData extra = compute_extra_function_hashes(*fd);

    hashes->add("exact_bytes", to_hex(fd->get_exact_bytes()));
    hashes->add("pic_bytes", to_hex(fd->get_pic_bytes()));
    hashes->add("cf_exact_hash", extra.cf_exact_hash);
    hashes->add("cf_pic_hash", extra.cf_pic_hash);
    hashes->add("cf_exact_bytes", to_hex(extra.cf_exact_bytes));
    hashes->add("cf_pic_bytes", to_hex(extra.cf_pic_bytes));
    hashes->add("composite_pic_hash", extra.composite_pic_hash);
    hashes->add("mnemonic_hash", extra.mnemonic_hash);
    hashes->add("mnemonic_count_hash", extra.mnemonic_count_hash);
    hashes->add("mnemonic_category_hash", extra.mnemonic_category_hash);
    hashes->add("mnemonic_category_counts_hash", extra.mnemonic_category_count_hash);
    hashes->add("num_basic_blocks", extra.num_blocks);
    hashes->add("num_basic_blocks_in_cfg", extra.num_blocks_in_cfg);
    auto mcslist = builder->object();
    for (auto const & mc : extra.mnemonic_counts) {
      mcslist->add(mc.first, mc.second);
    }
    hashes->add("mnemonic_counts", std::move(mcslist));
    auto mccslist = builder->object();
    for (std::string mc: get_all_insn_generic_categories()) {
      auto count = extra.mnemonic_category_counts[mc];
      mccslist->add(std::move(mc), count);
    }
    hashes->add("mnemonic_category_counts", std::move(mccslist));
    if (basic_blocks) {
      auto blocks = builder->array();
      for (rose_addr_t addr: extra.basic_block_addrs) {
        auto & bbhd = extra.basic_block_hash_data[addr];
        auto num_insn = bbhd.mnemonics.size();
        auto bb = builder->object();
        bb->add("address", addr_str(addr));
        bb->add("num_instructions", num_insn);
        bb->add("pic_hash", bbhd.pic);
        bb->add("composite_pic_hash", bbhd.cpic);
        auto mnemonics = builder->array();
        for (decltype(num_insn) i = 0; i < num_insn; ++i) {
          auto mob = builder->object();
          mob->add("mnemonic", bbhd.mnemonics[i]);
          mob->add("category", bbhd.mnemonic_categories[i]);
          mnemonics->add(std::move(mob));
        }
        bb->add("mnemonics", std::move(mnemonics));
        blocks->add(std::move(bb));
      }
      hashes->add("opt_basic_block_data", std::move(blocks));

      auto edges = builder->array();
      for (std::pair< rose_addr_t, rose_addr_t > edge :  extra.cfg_edges) {
        auto edgeob = builder->object();
        edgeob->add("from", addr_str(edge.first));
        edgeob->add("to", addr_str(edge.second));
        edges->add(std::move(edgeob));
      }
      hashes->add("opt_bb_cfg", std::move(edges));
    }

#if 0 // leaving this out for now, need to revisit pdg hashing at some point...
    std::string pdg_hash = fd->get_pdg_hash();
    GDEBUG << "PDG hash for function " << fd->address_string() << " is " << pdg_hash << LEND;
#endif // 0

    analysis->add(std::move(hashes));
  }

  void visit(FunctionDescriptor* fd) override {
    fd->compute_function_hashes();

    if (fd->get_num_instructions() < min_instructions) {
      GDEBUG << "Skipping function @ "<< fd->address_string()
             << " due to minimum instruction count threshold" << LEND;
      return;
    }

    // Get these counts directly off the Partitioner2::Function.
    P2::FunctionPtr p2func = fd->get_p2func();
    if (p2func) {
      num_code_blocks = p2func->nBasicBlocks();
      num_data_blocks = p2func->nDataBlocks();
    }

    if (!builder) {
      emit_csv(fd);
      return;
    }

    emit_json(fd);
  }

  void finish() override {
    if (builder) {
      main->add("analysis", std::move(analysis));
      (*out) << *main;
    }
  }
};

static int fn2hash_main(int argc, char **argv) {
  ProgOptDesc hashod = hash_options();
  ProgOptDesc csod = cert_standard_options();
  hashod.add(csod);

  // Sawyer's messaging code actually ignores multiple newlines, condenses down into one?
  std::string proghelptext = "fn2hash calculates various function hashes for the functions in a program and dumps the data to stdout in the following CSV format:\n\n\tfilemd5,fn_addr,exact_hash,pic_hash,num_bytes,num_instructions,num_code_blocks,num_data_blocks\n";

  ProgOptVarMap vm = parse_cert_options(argc, argv, hashod, proghelptext);

  if (vm.count("json") == 0) {
    if (vm["extra-data"].as<bool>()) {
      OERROR << "To specify --extra-data, you must also specify --json." << LEND;
      return 1;
    }
    if (vm["basic-blocks"].as<bool>()) {
      OERROR << "To specify --basic-blocks, you must also specify --json (and --extra-data)." << LEND;
      return 1;
    }
  }

  auto & specs = vm["file"].as<Specimens>();
  filename = specs.name();
  filemd5 = specs.unique_identifier().str();
  OINFO << "Calculating function hashes for file: " << filename << " ; MD5: " << filemd5 << LEND;

  // Find calls, functions, and imports.
  DescriptorSet ds(vm);
  // Resolve imports, load API data, etc.
  // ds.resolve_imports();

  auto *arch = &*ds.get_architecture();
  if (!dynamic_cast<Rose::BinaryAnalysis::Architecture::X86 const *>(arch)) {
    GWARN << "Position independent code (PIC) hasing is not supported for the "
          << "'" << ds.get_arch_name() << "' architecture." << LEND;
    GWARN << "As a consequence, PIC hashes will match their exact hashes, "
          << "reducing the effectiveness of this tool." << LEND;
  }

  // let's see progress for each and every function:
  Sawyer::ProgressBarSettings::initialDelay(0.0);
  Sawyer::ProgressBarSettings::minimumUpdateInterval(0.0);

  HashAnalyzer ha(ds, vm);
  ha.analyze();

  OINFO << "fn2hash complete" << LEND;

  return 0;
}

int main(int argc, char **argv) {
  return pharos_main("HASH", fn2hash_main, argc, argv, STDERR_FILENO);
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
