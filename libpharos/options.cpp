// Copyright 2015-2018 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>

#include <rose.h>
#include <Sawyer/Message.h>
#include <Sawyer/ProgressBar.h>

#include "options.hpp"
#include "util.hpp"
#include "descriptors.hpp"
#include "masm.hpp"
#include "revision.hpp"
#include "build.hpp"
#include "apidb.hpp"

// these next ones needed for global obj cleanup...
#include "riscops.hpp"
#include "vftable.hpp"

// for non portable unhandled exception stuff in pharos_main:
#ifdef __GNUC__
#include <cstdlib>
#include <cxxabi.h>
using namespace __cxxabiv1;
#endif

namespace pharos {

namespace bf = boost::filesystem;

using prolog::plog;

// This is library path from the command line or the default value.
namespace {
bf::path library_path;
}

int global_logging_fileno = STDOUT_FILENO;

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

  ProgOptDesc certopt("CERT/Pharos options");

  // Don't forget to update the documentation if you change this list!
  certopt.add_options()
    ("help,h",        "display help")

    // Important options affecting lots of programs?
    ("verbose,v",
     po::value<int>()->implicit_value(DEFAULT_VERBOSITY),
     //po::value<int>()->default_value(DEFAULT_VERBOSITY),
     boost::str(boost::format("enable verbose logging (1-%d, default %d)")
                % MAXIMUM_VERBOSITY % DEFAULT_VERBOSITY).c_str())
    ("batch,b", "suppress colors, progress bars, etc.")

    // Increasingly important?  And possibly going away before too much longer?
    ("allow-64bit", "allow analysis of 64-bit executables")

    // The inclusion and exclusion of specific functions (commonly used?)
    ("include-func,i",
     po::value<StrVector>(),
     "limit analysis to a specific function")
    ("exclude-func,e",
     po::value<StrVector>(),
     "exclude analysis of a specific function")

    // These are options controlling the configuration of the Pharos system.
    ("config,C",
     po::value<std::vector<std::string>>()->composing(),
     "pharos configuration file (can be specified multiple times)")
    ("dump-config",
     "display current active config parameters")
    ("no-user-file",
     "don't load the user's configuration file")
    ("no-site-file",
     "don't load the site's configuration file")
    ("apidb", po::value<std::vector<std::string>>(),
     "path to sqlite or JSON file containing API and type information")
    ("library,l",
     po::value<std::string>(),
     "specify the path to the pharos library directory")

    // Timeouts affecting the "core" analysis pass.
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
    ("blockcounterlimit", po::value<int>(),
     "limit the number of instructions per basic block")
    ("funccounterlimit", po::value<int>(),
     "limit the number of blocks (roughly) per function")

    // Crufty old stuff that may not even be real anymore?
    ("imports,I",
     po::value<std::string>(),
     "analysis configuration file (JSON)")

    // Almost unused option to work around performance issues when enabled by default.
    ("analyze-types",
     "generate prolog type information")
    ("type-file",
     po::value<std::string>(),
     "name of type (prolog) facts file")

    // Historical...  Do we even need this anymore?
    ("file,f",
     po::value<std::string>(),
     "executable to be analyzed")
    ;
  ;

  // Don't forget to update the documentation if you change this list!

  // These are really partitioner options or maybe options that are mostly just passed along to
  // control standard ROSE behavior.
  ProgOptDesc roseopt("ROSE options");
  roseopt.add_options()
    ("serialize", po::value<std::string>(),
     "File which caches function partitioning information")
    ("ignore-serialize-version",
     "Reject version mismatch errors when reading a serialized file")
    ("stockpart",
     "use stock ROSE partitioner without the Pharos changes")
    ("no-semantics",
     "disable semantic analysis during parititioning")
    ("pdebug",
     "enable partitioner debugging")
    ("no-executable-entry",
     "do not mark the entry point segment as executable")
    ("mark-executable",
     "mark all segments as executable during partitioning")
    ("log",
     po::value<std::string>(),
     "log facility control string")
#if 0  // maybe eventually...
    ("threads",
     po::value<unsigned int>(),
     "enable threaded processing")
#endif
    ("rose-version",
     "output ROSE version information and exit immediately")
    ;

  // Don't forget to update the documentation if you change this list!

  certopt.add(roseopt);
  return certopt;
}

ProgOptVarMap parse_cert_options_generic(
  int argc, char** argv, ProgOptDesc od, ProgPosOptDesc posopt,
  const std::string & proghelptext)
{
  namespace po = boost::program_options;

  // Try to locate the library root
  auto av0path = bf::path(argv[0]);
  auto prog_loc = av0path.parent_path();
  if (prog_loc.empty()) {
    // Need to look for executable in system path
    // This is unix-specific
    const char *penv = std::getenv("PATH");
    if (penv) {
      for (auto i =
             boost::make_split_iterator(penv, boost::first_finder(":", boost::is_equal()));
           i != decltype(i)(); ++i)
      {
        auto pdir = bf::path(i->begin(), i->end());
        if (bf::is_regular_file(pdir / av0path)) {
          prog_loc = bf::canonical(pdir);
          break;
        }
      }
    }
  } else {
    prog_loc = bf::canonical(prog_loc);
  }

  // This is the root of the installation path, the repository of the current working directory.
  // This path is not exposed in the API because it's only needed for etc/pharos.yaml (below).
  bf::path root_loc;
  // This is share/pharos subdirectory or the current working directory in release builds.
  // If CMakeFiles is found in development builds, it's the repository root directory.
  bf::path lib_root;

  if (prog_loc.filename() == "bin") {
    // Assume the install root is one directory below.
    root_loc = prog_loc.parent_path();
    lib_root = root_loc / "share/pharos";
  } else {
    // This is disabled in release builds to prevent PHAROS_BUILD_LOCATION from ending up in
    // the binary
    if (exists(prog_loc / "CMakeFiles")) {
      root_loc = lib_root = (PHAROS_BUILD_LOCATION "/share");
    } else
    {
      root_loc = lib_root = bf::current_path();
    }
  }

  ProgOptVarMap vm;

  Sawyer::Message::FdSinkPtr mout = Sawyer::Message::FdSink::instance(global_logging_fileno);

  // Create a prefix object so that we can modify prefix properties.
  Sawyer::Message::PrefixPtr prefix = Sawyer::Message::Prefix::instance();
  prefix = prefix->showProgramName(false)->showElapsedTime(false);
  // It's sometimes useful to also disable the faciltiy and importance.
  //prefix = prefix->showFacilityName(Sawyer::Message::NEVER)->showImportance(false);

  // Get the options logging facility working with the standard options.
  olog.initStreams(mout->prefix(prefix));
  // Initialize the global log with the appropriate filters.  Set this up before option
  // processing.
  glog().initStreams(mout->prefix(prefix));

  po::store(po::command_line_parser(argc, argv).
            options(od).positional(posopt).run(), vm);

  bf::path program = argv[0];
  vm.config(pharos::Config::load_config(
              program.filename().native(),
              vm.count("no-site-file") ? nullptr : (root_loc / "etc/pharos.yaml").c_str(),
              vm.count("no-site-file") ? nullptr : "PHAROS_CONFIG",
              vm.count("no-user-file") ? nullptr : ".pharos.yaml"));
  if (vm.count("config")) {
    for (auto & filename : vm["config"].as<std::vector<std::string>>()) {
      vm.config().mergeFile(filename);
    }
  }
  if (vm.count("dump-config")) {
    // Use cout, so it can easily be copied to a file
    std::cout << vm.config() << LEND;
    exit(3);
  }

  // Once the command line options have been processed we can determine the library path.
  auto lv = vm.get<std::string>("library", "pharos.library");
  library_path = lv ? *lv : lib_root;

  // ----------------------------------------------------------------------------------------
  // Configure the rest of the logging facilities
  // ----------------------------------------------------------------------------------------

  Rose::Diagnostics::initialize();
  Sawyer::ProgressBarSettings::initialDelay(3.0);
  Sawyer::ProgressBarSettings::minimumUpdateInterval(1.0);

  // Create a sink associated with standard output.
  if (!color_terminal() || vm.count("batch")) {
    mout->overridePropertiesNS().useColor = false;
  }

  // Add the options logging facility to the known facilities.
  Sawyer::Message::mfacilities.insert(olog);
  // We can now log to olog if we need to...

  if (vm.count("help")) {
    if (!proghelptext.empty()) {
      std::cout << proghelptext << "\n\n";
    }
    std::cout << od;
    std::cout << "\nRevID: " << pharos::REVISION << std::endl;
    exit(3);
  }

  if (vm.count("rose-version")) {
    std::cout << version_message() << std::endl;
    exit(3);
  }

  // We complain about non-included required options here.
  po::notify(vm);

  // Add the global logging facility to the known facilities.
  Sawyer::Message::mfacilities.insert(glog());
  // Initialize the semantics log with the appropriate filters.
  slog.initStreams(mout->prefix(prefix));
  // Add the semantic logging facility to the known facilities.
  Sawyer::Message::mfacilities.insert(slog);
  // Initialize the prolog
  plog.initStreams(mout->prefix(prefix));
  // Add the prolog logging facility to the known facilities.
  Sawyer::Message::mfacilities.insert(plog);

  auto & apidblog = APIDictionary::initDiagnostics();

  // Set the default verbosity to only emit errors and and fatal messages.
  Sawyer::Message::mfacilities.control("none, >=error");
  // Since the line above doesn't seem to work as expected...
  glog[Sawyer::Message::WARN].disable();
  slog[Sawyer::Message::WARN].disable();
  plog[Sawyer::Message::WARN].disable();

  // The options log is the exception to the rule that only errors and above are reported.
  olog[Sawyer::Message::WARN].enable();
  olog[Sawyer::Message::INFO].enable();
  if (isatty(global_logging_fileno)) {
    olog[Sawyer::Message::MARCH].enable();
  }

  // apidb
  apidblog[Sawyer::Message::WARN].enable();

  // If the user has modified the verbosity level, let's try to get the logging right before we
  // emit any messages at all.
  auto verbosity_opt = vm.get<int>("verbose", "pharos.verbosity");
  if (verbosity_opt) {
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

    // Prolog logging levels
    plog[Sawyer::Message::ERROR].enable(true);
    plog[Sawyer::Message::FATAL].enable(true);
    plog[Sawyer::Message::WARN].enable(verbosity >= 4);
    plog[Sawyer::Message::INFO].enable(verbosity >= 6);
    plog[Sawyer::Message::TRACE].enable(verbosity >= 12);
    plog[Sawyer::Message::DEBUG].enable(verbosity >= 13);

    // Enable everything everywhere...
    if (verbosity >= MAXIMUM_VERBOSITY) {
      Sawyer::Message::mfacilities.control("all");
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

  if (vm.count("include-func")) {
    for (const std::string & astr : vm["include-func"].as<StrVector>()) {
      rose_addr_t addr = parse_number(astr);
      ODEBUG << "Limiting analysis to function: " << addr_str(addr) << LEND;
    }
  }

  if (vm.count("exclude-func")) {
    for (const std::string & astr : vm["exclude-func"].as<StrVector>()) {
      rose_addr_t addr = parse_number(astr);
      ODEBUG << "Excluding function: " << addr_str(addr) << LEND;
    }
  }

  // We might want to investigate allowing unknown options for pasthru to ROSE
  // http://www.boost.org/doc/libs/1_53_0/doc/html/program_options/howto.html

  global_vm = vm; // so libpharos can get at this stuff without having to pass options all
                  // around...

  return vm;
}

ProgOptVarMap parse_cert_options(int argc, char** argv, ProgOptDesc od,
                                 const std::string & proghelptext)
{
  ProgPosOptDesc posopt;
  posopt.add("file", -1);
  auto vm = parse_cert_options_generic(argc, argv, od, posopt, proghelptext);
  if (vm.count("file")) {
    OINFO << "Analyzing executable: " << vm["file"].as<std::string>() << LEND;
  }
  else {
    OFATAL << "You must specify at least one executable to analyze." << LEND;
    exit(3);
  }
  return vm;
}

const bf::path& get_library_path()
{
  return library_path;
}

ProgOptVarMap& get_global_options_vm()
{
  return global_vm;
}

// Convert a vector of string into a set of rose_addr_t, out of option var map.
AddrSet option_addr_list(ProgOptVarMap& vm, const char *name) {
  AddrSet aset;
  if (vm.count(name) > 0) {
    for (const std::string & as : vm[name].as<StrVector>()) {
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
   // try {
    fd->get_pdg();
  // } catch(...) {
  //   GERROR << "Error building PDG (caught exception)" << LEND;
  // }
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
  for (rose_addr_t a : selected_funcs) {
    ODEBUG << "Limiting analysis to function: " << addr_str(a) << LEND;
  }
  size_t selected = selected_funcs.size();
  bool filtering = false;
  if (selected > 0) filtering = true;
  AddrSet excluded_funcs = option_addr_list(vm, "exclude-func");
  GDEBUG << "Filtering is " << filtering << LEND;
  for (const rose_addr_t addr : excluded_funcs) {
    GINFO << "Function " << addr_str(addr) << " excluded" << LEND;
  }

  FuncDescVector ordered_funcs = ds->funcs_in_bottom_up_order();
  total_funcs = ordered_funcs.size();
  processed_funcs = 0;
  for (FunctionDescriptor* fd : ordered_funcs) {
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

void cleanup_our_globals() {
  // need to clean up some static globals that are or get things in them dynamically allocated,
  // to prevent static object ctor/dtor order problems w/ statically linked exec from crashing
  // in various ways at exit time during static object destruction:
  global_rops.reset(); // riscops.hpp
}

static void report_exception(const std::exception & e, int level = 0)
{
  if (level == 0) {
    GFATAL << "Pharos main error: ";
  }  else {
    GFATAL << std::string(level, ' ') << "Reason: ";
  }
  GFATAL << e.what() << LEND;
  try {
    std::rethrow_if_nested(e);
  } catch (const std::exception & e2) {
    report_exception(e2, level + 1);
  } catch (...) {
    // Do nothing
  }
}

int pharos_main(std::string const & glog_, main_func_ptr fn,
                int argc, char **argv, int logging_fileno)
{
  set_glog_name(glog_);

  int rc = 0;
  atexit(cleanup_our_globals);

  global_logging_fileno = logging_fileno;

  ROSE_INITIALIZE;

  if (getenv(PHAROS_PASS_EXCEPTIONS_ENV)) {
    rc = fn(argc, argv);
  } else {
    try {
      rc = fn(argc, argv);
    } catch (const std::exception &e) {
      report_exception(e);
      rc = EXIT_FAILURE;
    } catch (...) {
#ifdef __GNUC__
      // totally non portable gcc specific stuff, courtesy of here:
      // http://stackoverflow.com/questions/4885334/c-finding-the-type-of-a-caught-default-exception/24997351#24997351
      std::string uxname(__cxa_current_exception_type()->name());
      int status = 0;
      char * buff = __cxxabiv1::__cxa_demangle(uxname.c_str(), NULL, NULL, &status);
      GFATAL << "Pharos main error, caught an unexpected exception named " << buff << LEND;
      std::free(buff);
#else
      GFATAL << "Pharos main error, caught an unexpected exception" << LEND;
#endif // __GNUC__
      rc = EXIT_FAILURE;
    }
  }

  return rc;
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
