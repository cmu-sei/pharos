// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/format.hpp>

#include <rose.h>
#include <Sawyer/Message.h>
#include <Sawyer/ProgressBar.h>

#include "options.hpp"
#include "util.hpp"
#include "descriptors.hpp"

// For logging options and other critically important "informational" messages.  This facility
// is meant to always be logged at level "INFO" and above.  The "WHERE" level includes optional
// messages, including the affirmative reporting of which options were detected.
Sawyer::Message::Facility olog("OPTI");

// Get the message levels from Sawyer::Message::Common.
using namespace Sawyer::Message::Common;

#define DEFAULT_VERBOSITY 3
#define MAXIMUM_VERBOSITY 14

ProgOptVarMap global_vm;

ProgOptDesc cert_standard_options() {
  namespace po = boost::program_options;

  ProgOptDesc certopt("CERT options");

  certopt.add_options()
    ("help,h",        "display help")
    ("imports,I",
     po::value<std::string>(),
     "analysis configuration file (JSON)")
    ("config,C",
     po::value<std::vector<std::string>>()->composing(),
     "pharos configuration file (can be specified multiple times)")
    ("no-user-file",
     "don't load the user's configuration file")
    ("no-site-file",
     "don't load the site's configuration file")
    ("include-func,i",
     po::value<StrVector>(),
     "limit analysis to a specific function")
    ("exclude-func,e",
     po::value<StrVector>(),
     "exclude analysis of a specific function")
    ("file,f",
     po::value<std::string>(),
     "executable to be analyzed")
    ("log",
     po::value<std::string>(),
     "log facility control string")
    ("batch,b", "suppress colors, progress bars, etc.")
    ("library,l",
     po::value<std::string>()->default_value(DEFAULT_LIB),
     "specify the path to the objdigger library")
    ("timeout", po::value<double>(),
     "specify the absolute defuse timeout value")
    ("reltimeout", po::value<double>(),
     "specify the relative defuse timeout value")
    ("ptimeout", po::value<double>(),
     "specify the absolute partitioner timeout value")
    ("preltimeout", po::value<double>(),
     "specify the relative partitioner timeout value")
    ("maxmem", po::value<double>(),
     "specify the absolute max memory usage value")
    ("relmaxmem", po::value<double>(),
     "specify the relative max memory usage value")
    ("counterlimit", po::value<int>(),
     "specify the counter limit value")
    ("funccounterlimit", po::value<int>(),
     "specify the function counter limit value")
    ("verbose,v",
     po::value<int>()->implicit_value(DEFAULT_VERBOSITY),
     //po::value<int>()->default_value(DEFAULT_VERBOSITY),
     boost::str(boost::format("enable verbose logging (1-%d, default %d)") % MAXIMUM_VERBOSITY % DEFAULT_VERBOSITY).c_str())
    ;
  ;

  ProgOptDesc roseopt("ROSE options");
  roseopt.add_options()
    ("pconfig",
     po::value<std::string>(),
     "partitioner configuration file")
    ("psearch",
     po::value<StrVector>(),
     "partitioner search heuristics")
    ("dsearch",
     po::value<StrVector>(),
     "disassembler search heuristics")
    ("stockpart",
     "use stock partitioner instead of our modified one")
    ("partitioner2",
     "use stock partitioner2 instead of our modified one")
    ("ldebug",
     "enable loader debugging")
    ("ddebug",
     "enable disassembler debugging")
    ("pdebug",
     "enable partitioner debugging")
    ("respect-protections",
     "respect segment protections")
    ("rose-version",
     "output ROSE version information and exit immediately")
    ;

  certopt.add(roseopt);
  return certopt;
}

ProgOptVarMap parse_cert_options(int argc, char** argv, ProgOptDesc od) {
  namespace po = boost::program_options;

  ProgOptVarMap vm;

  ProgPosOptDesc posopt;
  posopt.add("file", -1);

  Sawyer::Message::FdSinkPtr mout = Sawyer::Message::FdSink::instance(1);

  // Create a prefix object so that we can modify prefix properties.
  Sawyer::Message::PrefixPtr prefix = Sawyer::Message::Prefix::instance();
  prefix = prefix->showProgramName(false)->showElapsedTime(false);
  // It's sometimes useful to also disable the faciltiy and importance.
  //prefix = prefix->showFacilityName(Sawyer::Message::NEVER)->showImportance(false);

  // Get the options logging facility working with the standard options.
  olog.initStreams(mout->prefix(prefix));
  // Initialize the global log with the appropriate filters.  Set this up before option
  // processing.
  glog.initStreams(mout->prefix(prefix));

  po::store(po::command_line_parser(argc, argv).
            options(od).positional(posopt).run(), vm);
  po::notify(vm);

  boost::filesystem::path program = argv[0];
  vm.config(pharos::Config::load_config(
              program.filename().native(),
              vm.count("no-site-file") ? nullptr : "/etc/pharos.yaml",
              vm.count("no-site-file") ? nullptr : "PHAROS_CONFIG",
              vm.count("no-user-file") ? nullptr : ".pharos.yaml"));
  if (vm.count("config")) {
    for (auto & filename : vm["config"].as<std::vector<std::string>>()) {
      vm.config().mergeFile(filename);
    }
  }

  // ----------------------------------------------------------------------------------------
  // Configure the rest of the logging facilities
  // ----------------------------------------------------------------------------------------

  rose::Diagnostics::initialize();

  // Create a sink associated with standard output.
  if (!color_terminal() || vm.count("batch")) {
    mout->overridePropertiesNS().useColor = false;
  }

  // Add the options logging facility to the known facilities.
  Sawyer::Message::mfacilities.insert(olog);
  // We can now log to olog if we need to...

  if (vm.count("help")) {
    OFATAL << od << LEND;
    exit(3);
  }

  if (vm.count("rose-version")) {
    OFATAL << version_message() << LEND;
    exit(3);
  }

  // Add the global logging facility to the known facilities.
  Sawyer::Message::mfacilities.insert(glog);
  // Initialize the semantics log with the appropriate filters.
  slog.initStreams(mout->prefix(prefix));
  // Add the semantic logging facility to the known facilities.
  Sawyer::Message::mfacilities.insert(slog);

  // Set the default verbosity to only emit errors and and fatal messages.
  Sawyer::Message::mfacilities.control("none, >=error");
  // Since the line above doesn't seem to work as expected...
  glog[Sawyer::Message::WARN].disable();
  slog[Sawyer::Message::WARN].disable();

  // The options log is the exception to the rule that only errors and above are reported.
  olog[Sawyer::Message::WARN].enable();
  olog[Sawyer::Message::INFO].enable();
  if (isatty(1)) {
    olog[Sawyer::Message::MARCH].enable();
  }

  // If the user has modified the verbosity level, let's try to get the logging right before we
  // emit any messages at all.
  if (vm.count("verbose") && vm.count("log")) {
    OERROR << "Verbosity option overridden by explicit --log parameter." << LEND;
  }
  else {
    auto verbosity_opt = vm.get<int>("verbose", "pharos.verbosity");
    if (verbosity_opt) {
      // Cory would like to control whether timestamps are displayed on log messages with the
      //--timing option, but that's an option on objdigger only at present.
      int verbosity = *verbosity_opt;

      if (verbosity < 0) {
        OERROR << "Valid verbosity levels are 1-" << MAXIMUM_VERBOSITY << ", using 1." << LEND;
        verbosity = 1;
      }

      if (verbosity > MAXIMUM_VERBOSITY) {
        OERROR << "Valid verbosity levels are 1-" << MAXIMUM_VERBOSITY << ", using "
               << MAXIMUM_VERBOSITY << "." << LEND;
        verbosity = MAXIMUM_VERBOSITY;
      }

      // Enable warnings in the main program.
      glog[Sawyer::Message::WARN].enable(verbosity >= 1);
      // Enable informational messages from the main program.
      glog[Sawyer::Message::INFO].enable(verbosity >= 2);
      // Positively report options, including this one.
      olog[Sawyer::Message::WHERE].enable(verbosity >= 3);
      if (verbosity >= 3) {
        ODEBUG << "Verbose logging level set to " << verbosity << "." << LEND;
      }

      // Enable warnings from the semantics facility.
      slog[Sawyer::Message::WARN].enable(verbosity >= 4);
      // Enable (our) debugging from the main program.
      glog[Sawyer::Message::WHERE].enable(verbosity >= 5);
      // Enable informational messages from the semantics facility.
      slog[Sawyer::Message::INFO].enable(verbosity >= 6);
      // Enable more debugging from the main program.
      glog[Sawyer::Message::TRACE].enable(verbosity >= 7);
      // Enable everything from the main program.
      glog[Sawyer::Message::DEBUG].enable(verbosity >= 8);
      // Enable (our) debugging from the semantics facility.
      slog[Sawyer::Message::WHERE].enable(verbosity >= 9);
      // Enable more debugging in the options parsing code.
      olog[Sawyer::Message::TRACE].enable(verbosity >= 10);
      // Enable everything from the options parsing code.
      olog[Sawyer::Message::DEBUG].enable(verbosity >= 11);
      // Enable more debugging from the semantics facility.
      slog[Sawyer::Message::TRACE].enable(verbosity >= 12);
      // Enable everything from the semantics facility.
      slog[Sawyer::Message::DEBUG].enable(verbosity >= 13);

      // Enable everything everywhere...
      if (verbosity >= MAXIMUM_VERBOSITY) {
        Sawyer::Message::mfacilities.control("all");
      }
    }
  }

  // If the user chose to "override" the logging configuration, do that now instead.
  if (vm.count("log") > 0) {
    std::string cntrl = vm["log"].as<std::string>();
    // Now configure our logging.
    std::string error = Sawyer::Message::mfacilities.control(cntrl);
    if (error != "") {
      OERROR << "Control string error:" << error << LEND;
      // Rather than leave the logging in an unusual state, let's force a rational configuration.
      Sawyer::Message::mfacilities.control("none, >=error, OPTI(>=info)");
    }
  }

  // If we're actively debugging options parsing, test the logging infrastructure now.
  if (olog[TRACE]) {
    SWARN  << "Semantics WARN messages are enabled." << LEND;
    SINFO  << "Semantics INFO messages are enabled." << LEND;
    SDEBUG << "Semantics DEBUG/WHERE messages are enabled." << LEND;
    STRACE << "Semantics TRACE messages are enabled." << LEND;
    SCRAZY << "Semantics CRAZY/DEBUG messages are enabled." << LEND;
    GWARN  << "Main program WARN messages are enabled." << LEND;
    GINFO  << "Main program INFO messages are enabled." << LEND;
    GDEBUG << "Main program DEBUG/WHERE messages are enabled." << LEND;
    GTRACE << "Main program TRACE messages are enabled." << LEND;
    GCRAZY << "Main program CRAZY/DEBUG messages are enabled." << LEND;
  }

  if (vm.count("file")) {
    OINFO << "Analyzing executable: " << vm["file"].as<std::string>() << LEND;
  }
  else {
    OFATAL << "You must specifiy at least one executable to analyze." << LEND;
    exit(3);
  }

  if (vm.count("include-func")) {
    BOOST_FOREACH(std::string astr, vm["include-func"].as<StrVector>()) {
      rose_addr_t addr = parse_number(astr);
      ODEBUG << "Limiting analysis to function: " << addr_str(addr) << LEND;
    }
  }

  if (vm.count("exclude-func")) {
    BOOST_FOREACH(std::string astr, vm["exclude-func"].as<StrVector>()) {
      rose_addr_t addr = parse_number(astr);
      ODEBUG << "Excluding function: " << addr_str(addr) << LEND;
    }
  }

  // We might want to investigate allowing unknown options for pasthru to ROSE
  // http://www.boost.org/doc/libs/1_53_0/doc/html/program_options/howto.html

  global_vm = vm; // so libpharos can get at this stuff without having to pass options all around...

  return vm;
}

ProgOptVarMap& get_global_options_vm()
{
  return global_vm;
}

// Convert a vector of string into a set of rose_addr_t, out of option var map.
AddrSet option_addr_list(ProgOptVarMap& vm, const char *name) {
  AddrSet aset;
  if (vm.count(name) > 0) {
    BOOST_FOREACH(std::string as, vm[name].as<StrVector>()) {
      aset.insert(parse_number(as));
    }
  }
  return aset;
}

struct ProgressSuffix {
  const BottomUpAnalyzer* bua;
  ProgressSuffix(): bua(NULL) {}
  ProgressSuffix(const BottomUpAnalyzer *b): bua(b) {}
  void print(std::ostream &o) const {
    if (bua != NULL) {
      o << "/" << bua->total_funcs << " functions, processing: ";
      o << addr_str(bua->current_func);
    }
  }
};

std::ostream& operator<<(std::ostream &o, const ProgressSuffix &suffix) {
  suffix.print(o);
  return o;
}

BottomUpAnalyzer::BottomUpAnalyzer(DescriptorSet* ds_, ProgOptVarMap& vm_) {
  ds = ds_;
  vm = vm_;

  total_funcs = 0;
  processed_funcs = 0;
  current_func = 0;
}

// Update the progress bar to show our progress.
void BottomUpAnalyzer::update_progress() const {
  static Sawyer::ProgressBar<size_t, ProgressSuffix> *progressBar = NULL;
  if (!progressBar)
    progressBar = new Sawyer::ProgressBar<size_t, ProgressSuffix>(olog[Sawyer::Message::MARCH], "");
  progressBar->suffix(ProgressSuffix(this));
  progressBar->value(processed_funcs);
}

// The default visitor simply computes the PDG and returns.
void BottomUpAnalyzer::visit(FunctionDescriptor *fd) {
  try {
    fd->get_pdg();
  } catch(...) {
    GERROR << "Error building PDG (caught exception)" << LEND;
  }
}

// The default start is a NOP.
void BottomUpAnalyzer::start() {
  GDEBUG << "Starting bottom up function analysis." << LEND;
}

// The default finish is a NOP.
void BottomUpAnalyzer::finish() {
  GDEBUG << "Finishing bottom up function analysis." << LEND;
}

void BottomUpAnalyzer::analyze() {
  // User overridden start() method.
  start();

  AddrSet selected_funcs = option_addr_list(vm, "include-func");
  BOOST_FOREACH(rose_addr_t a, selected_funcs) {
    ODEBUG << "Limiting analysis to function: " << addr_str(a) << LEND;
  }
  size_t selected = selected_funcs.size();
  bool filtering = false;
  if (selected > 0) filtering = true;
  AddrSet excluded_funcs = option_addr_list(vm, "exclude-func");
  GDEBUG << "Filtering is " << filtering << LEND;
  BOOST_FOREACH(const rose_addr_t addr, excluded_funcs) {
    GINFO << "Function " << addr_str(addr) << " excluded" << LEND;
  }

  FuncDescVector ordered_funcs = ds->funcs_in_bottom_up_order();
  total_funcs = ordered_funcs.size();
  processed_funcs = 0;
  BOOST_FOREACH(FunctionDescriptor* fd, ordered_funcs) {
    // If we're limiting analysis to specific functions, do that now.
    AddrSet::iterator fit = selected_funcs.find(fd->get_address());
    if (filtering) {
      if (fit == selected_funcs.end()) {
        // If we're only including specific functions, exclude all others. Log this at a much
        // lower level because there could be lots of filtered functions, and the user might
        // find listing them all annoying.
        fd->set_excluded();
        GTRACE << "Function " << fd->address_string() << " excluded" << LEND;
        continue;
      }
      selected_funcs.erase(fit);
    }
    // Now check to see if we're explicitly excluding the function.
    fit = excluded_funcs.find(fd->get_address());
    if (fit != excluded_funcs.end()) {
      fd->set_excluded();
      GINFO << "Function " << fd->address_string() << " excluded" << LEND;
      continue;
    }

    current_func = fd->get_address();
    update_progress();
    GDEBUG << "Visiting function " << fd->address_string() << LEND;
    // Visit the function.
    visit(fd);
    processed_funcs++;
  }

  if (filtering && selected_funcs.size() != 0) {
    GERROR << "Found only " << processed_funcs << " functions of " << selected
           << " specifically requested for analysis." << LEND;
  }

  // User overridden finish() method.
  finish();
}
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
