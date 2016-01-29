// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>

#include <rose.h>

#include "descriptors.hpp"
#include "misc.hpp"
#include "util.hpp"
#include "riscops.hpp"
#include "options.hpp"
#include "pdg.hpp"

// For md5name()
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

#define DEFAULT_MIN_INSTRUCTIONS 5

// The global CERT message facility.
Sawyer::Message::Facility glog("Fn2YARA");

namespace {

typedef std::vector<std::string> strvec_t;

ProgOptDesc fn2yara_options() {
  namespace po = boost::program_options;

  ProgOptDesc fn2yaraopt("fn2yara 0.02 Options");
  fn2yaraopt.add_options()
    ("output-filename,o", po::value<std::string>(),
     "output filename (defaults to the filename suffixed by .yara")
    ("min-instructions,m",
     po::value<size_t>()->default_value(DEFAULT_MIN_INSTRUCTIONS),
     ("Minimum number of instructions needed for an instruction block "
      "to be output for a function"))
    ("comparison,C", po::value<double>(),
     ("Output a yara rule that matches the given percentage of all "
      "functions in the program"))
    ("prefix,p", po::value<std::string>(),
     "Prefix for rule names")
    ("address-only,a", po::bool_switch(),
     ("Only output addresses of candidate functions, rather than rules.  "
      "Not in YARA format."))
    ("include-thunks", po::bool_switch(), "include thunks in output")
    ;
  return fn2yaraopt;
}

std::string md5name(const char *filename)
{
  std::string digest;
  CryptoPP::Weak::MD5 md5;
  CryptoPP::FileSource source(
    filename, true, new CryptoPP::HashFilter(
      md5, new CryptoPP::HexEncoder(
        new CryptoPP::StringSink(digest))));
  return digest;
}

class FnToYaraAnalyzer : public BottomUpAnalyzer {
 private:
  typedef SgUnsignedCharList::const_iterator iter_t;

  // The program being analyzed
  DescriptorSet *program;

  // Name of file being analyzed
  std::string basename;

  // Prefix of file names
  std::string prefix;

  // Whether to include thunks
  bool include_thunks;

  // Location of file being analyzed
  std::string outname;

  // Output stream
  std::ostream *out;

  // Output file
  std::ofstream *outfile = nullptr;

  // Rule count;
  size_t rule_count = 0;

  // Minimum number of instructions in a function before we consider emitting a rule
  size_t minimum_instr;

  // Whether to operate in comparison mode
  bool compare_mode = false;

  // Whether to only output addresses
  bool address_only = false;

  // Percentage that have to match in comparison mode
  double compare_percentage;

  // Count of function strings
  int string_count = 0;

  struct RuleString {
    std::string addr;
    std::string match;
    size_t count;

    RuleString(rose_addr_t addr_, const std::string & match_, size_t count_)
      : match(match_), count(count_)
    {
      std::ostringstream str;
      str << std::setw(8) << std::setfill('0') << std::hex << addr_;
      addr = str.str();
    }
  };

  // Represents a block of instructions
  class Block {
   private:
    typedef std::vector<rose_addr_t> vec_t;
    typedef vec_t::const_iterator    it_t;

    rose_addr_t addr;
    size_t size;
    vec_t addresses;

   public:
    bool add(const SgAsmx86Instruction *insn) {
      rose_addr_t a = insn->get_address();
      size_t      s = insn->get_size();
      if (addresses.empty()) {
        addr = a;
      } else if (addr + size != a) {
        return false;
      }
      addresses.push_back(a);
      size += s;
      return true;
    }

    bool empty() const {
      return addresses.empty();
    }

    bool contains(rose_addr_t a) const {
      // Optimization for incremental containment
      if (a < addr || ((int64_t)a - (int64_t)addr) >= (ssize_t)size) {
        return false;
      }
      return std::binary_search(addresses.begin(), addresses.end(), a);
    }

    rose_addr_t get_addr() const {
      return addr;
    }
  };

  // Visitor that keeps track of potential address candidates
  struct IntegerSearcher : public AstSimpleProcessing {
    std::vector<uint32_t> candidates;
    DescriptorSet *program;

    IntegerSearcher(DescriptorSet *_program) {
      program = _program;
    }

    void visit(SgNode *node) override {
      const SgAsmIntegerValueExpression *intexp =
        isSgAsmIntegerValueExpression(node);
      if (intexp) {
        uint64_t val = intexp->get_value();
        if (program->memory_in_image(rose_addr_t(val))) {
          // TODO: Make the following assert a warning
          assert((val >> 32) == 0); // 32-bit address
          candidates.push_back(val);
        }
      }
    }
  };

  void output_strings(const std::vector<RuleString> &matches)
  {
    BOOST_FOREACH(const RuleString &match, matches) {
      if (match.count >= minimum_instr) {
        *out << "    $Match_" << match.addr << " = " << match.match
             << LEND;
        ++string_count;
      } else {
        *out << "    // $Match_" << match.addr
             << " elided due to too few instructions ("
             << match.count << ')' << LEND;
      }
    }
  }

  // Output the matches as a Yara rule
  bool output_rule(const FunctionDescriptor *fd,
                   const std::vector<RuleString> &matches)
  {
    bool output = false;
    BOOST_FOREACH(const RuleString &match, matches) {
      if (match.count >= minimum_instr) {
        output = true;
        break;
      }
    }
    if (!output) {
      return false;
    }

    if (address_only) {
      *out << boost::str(boost::format("0x%08X") % fd->get_address())
           << LEND;
      return true;
    }

    std::string name = boost::str(boost::format("Func_%s_%08X") % prefix
                                  % fd->get_address());
    // header
    *out << "rule " << name << "\n"
         << "{\n"
         << "  strings:\n";

    // origin information
    boost::gregorian::date d(boost::gregorian::day_clock::local_day());
    *out << "    // File " << basename << " @ " << fd->address_string()
         << boost::str(boost::format(" (%d-%02d-%02d)\n") % d.year() % d.month() % d.day());

    // strings
    BOOST_FOREACH(const RuleString &match, matches) {
      if (match.count >= minimum_instr) {
        *out << "    $" << prefix << '_' << match.addr << " = " << match.match << "\n";
      } else {
        *out << "    // $" << prefix << '_' << match.addr
             << " elided due to too few instructions ("
             << match.count << ")\n";
      }
    }

    // condition
    *out << "  condition:\n"
         << "    all of them\n";

    // footer
    *out << '}' << std::endl;

    return true;
  }

 public:
   FnToYaraAnalyzer(DescriptorSet * ds_, ProgOptVarMap & vm_)
     : BottomUpAnalyzer(ds_, vm_), program(ds)
   {
     include_thunks = vm_["include-thunks"].as<bool>();
     address_only = vm_["address-only"].as<bool>();
     std::string filename = vm_["file"].as<std::string>();
     size_t slash = filename.find_last_of('/');
     if (slash == std::string::npos) {
       slash = 0;
     } else {
       ++slash;
     }
     basename = filename.substr(slash);
     if (vm_.count("output-filename")) {
       outname = vm_["output-filename"].as<std::string>();
     } else {
       outname = basename + ".yara";
     }
     minimum_instr = vm_["min-instructions"].as<size_t>();
     if (vm_.count("comparison")) {
       compare_mode = true;
       compare_percentage = vm_["comparison"].as<double>();
       if (compare_percentage <= 0.0 || compare_percentage > 100.0) {
         throw std::runtime_error("comparison option must be between 0 and 100");
       }
     }
     if (vm_.count("prefix")) {
       prefix = vm_["prefix"].as<std::string>();
       boost::algorithm::trim(prefix);
       if (prefix.empty()) {
         throw std::runtime_error("prefix must be non-empty");
       }
       auto bad = std::find_if_not(
         prefix.begin(), prefix.end(),
         [](char c){ return c == '_' || std::isalnum(c);});
       if (bad != prefix.end()) {
         throw std::runtime_error(
           boost::str(boost::format("illegal character '%c' in prefix") % *bad));
       }
       if (isdigit(prefix[0])) {
         throw std::runtime_error("first character of prefix may not be numeric");
       }
     } else {
       prefix = "md5_" + md5name(filename.c_str());
     }
   }

  ~FnToYaraAnalyzer() {
    delete outfile;
  }

  void start() override {
    if (address_only) {
      out = &std::cout;
    } else {
      outfile = new std::ofstream(outname);
      out = outfile;
    }
    if (compare_mode && !address_only) {
      std::string name(basename);
      std::transform(name.begin(), name.end(), name.begin(),
                     [](char c) { return std::isalnum(c) ? c : '_'; });
      if (std::isdigit(name[0])) {
        name = "FILE_" + name;
      }
      *out << "rule " << prefix << '_' << (int)compare_percentage
           << "_percent\n{\n  strings:" << std::endl;
    }
  }

  void finish() override {
    if (address_only) {
      *out << "Considered " << rule_count << " functions" << LEND;
    } else if (compare_mode) {
      *out << "\n  condition:\n    "
           << int(string_count * compare_percentage / 100.0)
           << " of them\n}" << std::endl;
      OINFO << "Wrote " << string_count << " strings to " << outname << LEND;
    } else {
      OINFO << "Wrote " << rule_count << " rules to " << outname << LEND;
    }
    if (outfile) {
      outfile->close();
    }
  }

  // Function visitor (called once per function)
  void visit(FunctionDescriptor *fd) override
  {
    // Ignore thunks
    if (!include_thunks && fd->is_thunk()) {
      return;
    }

    X86InsnVector insns = fd->get_insns_addr_order();
    GINFO << "(Function " << fd->address_string() << ")" << LEND;

    // Make a list of contiguous instruction blocks in the function
    std::vector<Block> blocks;
    assert(!insns.empty());
    blocks.push_back(Block());
    Block *b = &blocks.back();
    BOOST_FOREACH(const SgAsmx86Instruction *insn, insns) {
      if (!b->add(insn)) {
        blocks.push_back(Block());
        b = &blocks.back();
        b->add(insn);
      }
    }

    // Initialize the match string
    std::stringstream match;
    std::vector<RuleString> matches;
    match << "{ ";

    // Loop over instructions
    size_t instr_count = 0;
    std::vector<Block>::const_iterator cblock = blocks.begin();
    BOOST_FOREACH(SgAsmx86Instruction *insn, insns) {
      rose_addr_t addr = insn->get_address();

      // Iterate to next block, if necessary
      if (!cblock->contains(addr)) {
        // Close the current match string, and start a new one
        match << '}';
        matches.push_back(RuleString(cblock->get_addr(), match.str(),
                                     instr_count));
        instr_count = 0;
        match.clear();
        match.str("");
        match << "{ ";

        // Next block
        ++cblock;
        assert(cblock->contains(addr));
      }
      ++instr_count;

      // Get the raw bytes, and a vector of bool as to which bytes to wildcard away
      const SgUnsignedCharList &bytes = insn->get_raw_bytes();
      std::vector<bool> wildcard(bytes.size());

      GDEBUG << "(Instr: " << insn->get_mnemonic();

      // Build a list of address candidates in the instruction data
      IntegerSearcher searcher(program);
      searcher.traverse(insn, preorder);

      // Try to find the candidate addresses
      bool found = false;
      uint32_t val;
      // NOTE: assumes native byte order is the same as the byte order in the instruction
      const unsigned char *target_begin =
        reinterpret_cast<const unsigned char *>(&val);
      const unsigned char *target_end = target_begin + sizeof(val);
      BOOST_FOREACH(val, searcher.candidates) {
        iter_t loc = std::search(bytes.begin() + 1, bytes.end(),
                                 target_begin, target_end);
        if (loc != bytes.end()) {
          // A candidate was found, wildcard it
          found = true;
          size_t pos = loc - bytes.begin();
          for (size_t i = 0; i < sizeof(val); ++i) {
            wildcard[i + pos] = true;
          }
        }
      }

      // If no matches were found, search for addresses by offset at end of instruction (first
      // matching only)
      if (!found) {
        rose_addr_t eip = insn->get_address() + bytes.size();
        int32_t offset;
      // NOTE: assumes native byte order is the same as the byte order in the instruction
        target_begin = reinterpret_cast<const uint8_t *>(&offset);
        target_end = target_begin + sizeof(offset);
        BOOST_FOREACH(val, searcher.candidates) {
          if (!cblock->contains(rose_addr_t(val))) {
            offset = int64_t(val) - int64_t(eip);
            for (int i = 4; i > 0; i >>= 1) {
              // Match first i bytes of target with end of instruction
              // NOTE: assumes little-endian byte order
              if (std::equal(target_begin, target_begin + i, bytes.end() - i)) {
                // Found a match, wildcard it
                found = true;
                for (int j = 0; j < i; ++j) {
                  wildcard[bytes.size() - j - 1] = true;
                }
                break;
              }
            }
          }
        }
      }

      // Write out match data for instruction
      for (size_t i = 0; i < bytes.size(); ++i) {
        if (wildcard[i]) {
          match << "?? ";
        } else {
          match << std::setfill('0') << std::hex << std::setw(2)
                << int(bytes[i]) << ' ';
        }
      }
    }

    match << '}';
    matches.push_back(RuleString(cblock->get_addr(), match.str(), instr_count));

    if (compare_mode) {
      output_strings(matches);
    } else {
      // Output the rule
      if (output_rule(fd, matches)) {
        ++rule_count;
      }
    }
  }
};


int fn2yara_main(int argc, char **argv) {
  // Handle options
  ProgOptDesc f2yod = fn2yara_options();
  f2yod.add(cert_standard_options());
  ProgOptVarMap vm = parse_cert_options(argc, argv, f2yod);

  SgAsmInterpretation* interp = get_interpretation(vm);
  if (interp == NULL) {
    GINFO << "Could not load program" << LEND;
    return EXIT_FAILURE;
  }

  // Find calls, functions, and imports.
  DescriptorSet ds(interp, &vm);
  // Load a config file overriding parts of the analysis.
  if (vm.count("imports")) {
    std::string config_file = vm["imports"].as<std::string>();
    GINFO << "Loading analysis configuration file: " <<  config_file << LEND;
    ds.read_config(config_file);
  }
  global_rops = make_risc_ops();

  FnToYaraAnalyzer analyzer(&ds, vm);
  analyzer.analyze();

  OINFO << "Complete." << LEND;
  return EXIT_SUCCESS;
}
} // anonymous namespace

int main(int argc, char **argv)
{
  return pharos_main(fn2yara_main, argc, argv);
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
