// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <rose.h>

#include <Sawyer/Message.h>
#include <Sawyer/ProgressBar.h>

#include <libpharos/descriptors.hpp>
#include <libpharos/misc.hpp>
#include <libpharos/util.hpp>
#include <libpharos/riscops.hpp>
#include <libpharos/options.hpp>
#include <libpharos/pdg.hpp>

using namespace pharos;

// The global CERT message facility.
Sawyer::Message::Facility glog("HASH");

std::string filename;
std::string filemd5;

ProgOptDesc hash_options() {
  namespace po = boost::program_options;

  ProgOptDesc hashopt("fn2hash v0.03 options");
  // no extra options to add right now...
  return hashopt;
}

class HashAnalyzer : public BottomUpAnalyzer {
  CallingConventionMatcher matcher;
public:
  HashAnalyzer(DescriptorSet* ds_, ProgOptVarMap& vm_) : BottomUpAnalyzer(ds_, vm_) {
    matcher.report();
  }
  void visit(FunctionDescriptor* fd) {
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

    std::string mnemonic_hash = fd->get_mnemonic_hash();

    GDEBUG << "Mnemonic hash for function " << fd->address_string() << " is " << mnemonic_hash << LEND;

    std::string mnemonic_count_hash = fd->get_mnemonic_count_hash();

    GDEBUG << "Mnemonic count hash for function " << fd->address_string() << " is " << mnemonic_count_hash << LEND;
    GDEBUG << "  Counts:";
    std::string mnemcntstr;
    for (auto const& mc: fd->get_mnemonic_counts())
    {
      GDEBUG << " " << mc.first << ":" << mc.second;
      mnemcntstr += mc.first + ":" + std::to_string(mc.second) + ";";
    }
    GDEBUG << LEND;
    mnemcntstr.pop_back(); // c++11 way to remove that last extra ';' char we added

    std::string mnemonic_category_hash = fd->get_mnemonic_category_hash();

    GDEBUG << "Mnemonic category hash for function " << fd->address_string() << " is " << mnemonic_category_hash << LEND;
    std::string mnemonic_category_counts_hash = fd->get_mnemonic_category_count_hash();

    GDEBUG << "Mnemonic category counts hash for function " << fd->address_string() << " is " << mnemonic_category_counts_hash << LEND;
    GDEBUG << "  Counts:";

    // let's spit out the full "feature vector" for mnemcats:
    std::string mnemcatcntstr;
    std::map< std::string, uint32_t > mnemcatcounts = fd->get_mnemonic_category_counts();
    // auto and refs were working against me here const wise:
    for (std::string mc: get_all_insn_generic_categories())
    {
      GDEBUG << " " << mc << ":" << mnemcatcounts[mc];
      mnemcatcntstr += mc + ":" + std::to_string(mnemcatcounts[mc]) + ";";
    }
    GDEBUG << LEND;
    mnemcatcntstr.pop_back(); // c++11 way to remove that last extra ';' char we added

#if 0 // leaving this out for now, need to revisit pdg hashing at some point...
    std::string pdg_hash = fd->get_pdg_hash();
    GDEBUG << "PDG hash for function " << fd->address_string() << " is " << pdg_hash << LEND;
#endif // 0

    // dump the output string:
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
              << mnemcatcntstr
              << std::endl;
  }
};

static int fn2hash_main(int argc, char **argv) {
  ProgOptDesc hashod = hash_options();
  ProgOptDesc csod = cert_standard_options();
  hashod.add(csod);

  // Sawyer's messaging code actually ignores multiple newlines, condenses down into one?
  std::string proghelptext = "fn2hash calculates various function hashes for the functions in a program and dumps the data to stdout in the following CSV format:\n\n\tfilemd5,fn_addr,num_basic_blocks,num_basic_blocks_in_cfg,num_instructions,num_bytes,exact_hash,pic_hash,composite_pic_hash,mnemonic_hash,mnemonic_count_hash,mnemonic_category_hash,mnemonic_category_counts_hash,mnemonic_count_string,mnemonic_category_count_string\n\n";

  ProgOptVarMap vm = parse_cert_options(argc, argv, hashod, proghelptext);

  filename = vm["file"].as<std::string>();
  filemd5 = get_file_md5(filename);
  OINFO << "Calculating function hashes for file: " << filename << " ; MD5: " << filemd5 << LEND;

  // Find calls, functions, and imports.
  DescriptorSet ds(vm);
  if (ds.get_interp() == NULL) {
    GFATAL << "Unable to analyze file (no executable content found)." << LEND;
    return EXIT_FAILURE;
  }
  // Load a config file overriding parts of the analysis.
  // (if this is generic, why isn't it in pharos_main?)
  if (vm.count("imports")) {
    std::string config_file = vm["imports"].as<std::string>();
    GINFO << "Loading analysis configuration file: " <<  config_file << LEND;
    ds.read_config(config_file);
  }
  // Load stack deltas from config files for imports.
  ds.resolve_imports();

  // let's see progress for each and every function:
  Sawyer::ProgressBarSettings::initialDelay(0.0);
  Sawyer::ProgressBarSettings::minimumUpdateInterval(0.0);

  HashAnalyzer ha(&ds, vm);
  ha.analyze();

  GDEBUG << "Complete." << LEND;

  return 0;
}

int main(int argc, char **argv) {
  return pharos_main(fn2hash_main, argc, argv, STDERR_FILENO);
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
