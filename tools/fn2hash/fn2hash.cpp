// Copyright 2015-2025 Carnegie Mellon University.  See LICENSE file for terms.

#include <libpharos/descriptors.hpp>
#include <libpharos/misc.hpp>
#include <libpharos/util.hpp>
#include <libpharos/riscops.hpp>
#include <libpharos/options.hpp>
#include <libpharos/pdg.hpp>
#include <libpharos/json.hpp>
#include <libpharos/bua.hpp>

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
    ("basic-blocks,B", po::bool_switch(),
     "Output optional basic block level data")
    ("json,j", po::value<bf::path>(),
     "Output as JSON to the given file.  ('-' means stdout)")
    ("pretty-json,p", po::value<unsigned>()->implicit_value(4),
     "Pretty-print json.  Argument is the indent width")
    ;
  return hashopt;
}

class HashAnalyzer : public BottomUpAnalyzer {
  CallingConventionMatcher matcher;
  size_t min_instructions;
  bool basic_blocks;
  json::BuilderRef builder;
  json::ObjectRef main;
  json::ArrayRef analysis;
  std::unique_ptr<std::ofstream> fout;
  std::ostream *out = nullptr;

 public:
  HashAnalyzer(DescriptorSet& ds_, ProgOptVarMap& vm_) : BottomUpAnalyzer(ds_, vm_) {
    matcher.report();
    min_instructions = vm_["min-instructions"].as<size_t>();
    basic_blocks = vm_["basic-blocks"].as<bool>();
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
  void visit(FunctionDescriptor* fd) override {
    FunctionDescriptor::ExtraFunctionHashData extra; // mnemonic related & basic block level hash data...
    fd->compute_function_hashes(&extra);

    if (fd->get_num_instructions() < min_instructions) {
      ODEBUG << "Skipping function @ "<< fd->address_string()
             << " due to minimum instruction count threshold" << LEND;
      return;
    }

    std::string exact_hash = fd->get_exact_hash();
    std::string exact_bytes = fd->get_exact_bytes();

    GDEBUG << "Exact hash for function " << fd->address_string() << " is " << exact_hash << LEND;
    GDEBUG << "  Bytes: " << to_hex(exact_bytes) << LEND;

    std::string pic_hash = fd->get_pic_hash();
    std::string pic_bytes = fd->get_pic_bytes();

    GDEBUG << "PIC hash for function " << fd->address_string() << " is " << pic_hash << LEND;
    GDEBUG << "  Bytes: " << to_hex(pic_bytes) << LEND;

    if (pic_hash == exact_hash)
    {
      GDEBUG << "(note, PHASH == EHASH)" << LEND;
    }

    std::string composite_pic_hash = fd->get_composite_pic_hash();

    GDEBUG << "Composite PIC hash for function " << fd->address_string() << " is " << composite_pic_hash << LEND;

    // the rest of these all come from the "extra" parameter now:
    std::string mnemonic_hash = extra.mnemonic_hash;

    GDEBUG << "Mnemonic hash for function " << fd->address_string() << " is " << mnemonic_hash << LEND;

    std::string mnemonic_count_hash = extra.mnemonic_count_hash;

    GDEBUG << "Mnemonic count hash for function " << fd->address_string() << " is " << mnemonic_count_hash << LEND;
    GDEBUG << "  Counts:";
    std::string mnemcntstr;
    if (!builder) {
      for (auto const& mc: extra.mnemonic_counts)
      {
        GDEBUG << " " << mc.first << ":" << mc.second;
        mnemcntstr += mc.first + ":" + std::to_string(mc.second) + ";";
      }
      GDEBUG << LEND;
      mnemcntstr.pop_back(); // c++11 way to remove that last extra ';' char we added
    }

    std::string mnemonic_category_hash = extra.mnemonic_category_hash;

    GDEBUG << "Mnemonic category hash for function " << fd->address_string() << " is " << mnemonic_category_hash << LEND;
    std::string mnemonic_category_counts_hash = extra.mnemonic_category_count_hash;

    GDEBUG << "Mnemonic category counts hash for function " << fd->address_string() << " is " << mnemonic_category_counts_hash << LEND;
    GDEBUG << "  Counts:";

    // let's spit out the full "feature vector" for mnemcats:
    std::string mnemcatcntstr;
    std::map< std::string, uint32_t > mnemcatcounts = extra.mnemonic_category_counts;
    if (!builder) {
      // auto and refs were working against me here const wise:
      for (std::string mc: get_all_insn_generic_categories())
      {
        GDEBUG << " " << mc << ":" << mnemcatcounts[mc];
        mnemcatcntstr += mc + ":" + std::to_string(mnemcatcounts[mc]) + ";";
      }
      GDEBUG << LEND;
      mnemcatcntstr.pop_back(); // c++11 way to remove that last extra ';' char we added
    }

#if 0 // leaving this out for now, need to revisit pdg hashing at some point...
    std::string pdg_hash = fd->get_pdg_hash();
    GDEBUG << "PDG hash for function " << fd->address_string() << " is " << pdg_hash << LEND;
#endif // 0

    // dump the output string:
    if (!builder) {
      std::cout << filemd5 << ","
                << fd->address_string() << ","
                << fd->get_num_blocks() << ","
                << fd->get_num_blocks_in_cfg() << ","
                << fd->get_num_instructions() << ","
                << fd->get_num_bytes() << ","
                << exact_hash << ","
                << pic_hash << ","
                << composite_pic_hash << ","
                << mnemonic_hash << ","
                << mnemonic_count_hash << ","
                << mnemonic_category_hash << ","
                << mnemonic_category_counts_hash << ","
                << mnemcntstr << ","
                << mnemcatcntstr;
      if (basic_blocks) {
        std::string bbdata;
        for (rose_addr_t addr: extra.basic_block_addrs) {
          FunctionDescriptor::ExtraFunctionHashData::BasicBlockHashData &bbhd = extra.basic_block_hash_data[addr];
          uint32_t num_insn = bbhd.mnemonics.size();
          bbdata += addr_str(addr) + ":" + std::to_string(num_insn) + ":" + bbhd.pic + ":" + bbhd.cpic + ":";
          for (uint32_t i=0 ; i < num_insn ; ++i) {
            bbdata += bbhd.mnemonics[i] + "^" + bbhd.mnemonic_categories[i] + ";";
          }
          // do I need to ensure that the num insn in the block was at least 1 before popping?  I
          // don't *think* so, *pretty sure* prior stuff wouldn't have added the basic block if
          // it didn't have any insns...
          bbdata.pop_back(); // c++11 way to remove the last ; we added
          bbdata += "|";
        }
        // same *pretty sure* comment about the fn always having at least 1 bb...
        bbdata.pop_back(); // c++11 way to remove the last | we added

        std::string bbcfg;
        bool ntnl = false;
        for (std::pair< rose_addr_t, rose_addr_t > edge :  extra.cfg_edges)
        {
          ntnl = true;
          bbcfg += addr_str(edge.first) + ";" + addr_str(edge.second) + ":";
        }
        if (ntnl)
          bbcfg.pop_back();
        std::cout << "," << bbdata << "," << bbcfg;
      }
      std::cout << std::endl;

    } else {
      // json output
      auto hashes = builder->object();
      hashes->add("filemd5", filemd5);
      hashes->add("fn_addr", fd->address_string());
      hashes->add("num_basic_blocks", fd->get_num_blocks());
      hashes->add("num_basic_blocks_in_cfg", fd->get_num_blocks_in_cfg());
      hashes->add("num_instructions", fd->get_num_instructions());
      hashes->add("num_bytes", fd->get_num_bytes());
      hashes->add("exact_hash", exact_hash);
      hashes->add("exact_bytes", to_hex(exact_bytes));
      hashes->add("pic_hash", pic_hash);
      hashes->add("pic_bytes", to_hex(pic_bytes));
      hashes->add("composite_pic_hash", composite_pic_hash);
      hashes->add("mnemonic_hash", mnemonic_hash);
      hashes->add("mnemonic_count_hash", mnemonic_count_hash);
      hashes->add("mnemonic_category_hash", mnemonic_category_hash);
      hashes->add("mnemonic_category_counts_hash", mnemonic_category_counts_hash);
      auto mcslist = builder->object();
      for (auto const & mc : extra.mnemonic_counts) {
        mcslist->add(mc.first, mc.second);
      }
      hashes->add("mnemonic_counts", std::move(mcslist));
      auto mccslist = builder->object();
      for (std::string mc: get_all_insn_generic_categories()) {
        auto count = mnemcatcounts[mc];
        mccslist->add(std::move(mc), count);
      }
      hashes->add("mnemonic_category_counts", std::move(mccslist));
      if (basic_blocks) {
        auto blocks = builder->array();
        for (rose_addr_t addr: extra.basic_block_addrs) {
          FunctionDescriptor::ExtraFunctionHashData::BasicBlockHashData &bbhd =
            extra.basic_block_hash_data[addr];
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
      analysis->add(std::move(hashes));
    }
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
  std::string proghelptext = "fn2hash calculates various function hashes for the functions in a program and dumps the data to stdout in the following CSV format:\n\n\tfilemd5,fn_addr,num_basic_blocks,num_basic_blocks_in_cfg,num_instructions,num_bytes,exact_hash,pic_hash,composite_pic_hash,mnemonic_hash,mnemonic_count_hash,mnemonic_category_hash,mnemonic_category_counts_hash,mnemonic_count_string,mnemonic_category_count_string[,opt_basic_block_data,opt_bb_cfg]\n\nThe -B option adds basic block data over two new fields, the first with basic block individual data, the 2nd with the edges of the function control flow graph, formatted like so: 'addr1:numinsn:PIC:CPIC:mnem1^mnemcat1;mnem2^mnemcat2;mnem3^mnemcat3...|addr2...,addr1;addr2:addr3;addr4:...'\n\n";

  ProgOptVarMap vm = parse_cert_options(argc, argv, hashod, proghelptext);

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
