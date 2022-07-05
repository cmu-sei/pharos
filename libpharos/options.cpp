// Copyright 2015-2022 Carnegie Mellon University.  See LICENSE file for terms.

#include <algorithm>
#include <iterator>
#include <cstring>
#include <sstream>
#include <wordexp.h>

#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/range/algorithm.hpp>
#include <boost/range/algorithm_ext/insert.hpp>
#include <boost/range/adaptor/map.hpp>

#include <Sawyer/ProgressBar.h>

#if PHAROS_ROSE_VARIABLE_ID_HACK
#include <Rose/BinaryAnalysis/SymbolicExpr.h>
#endif

#include "options.hpp"
#include "util.hpp"
#include "descriptors.hpp"
#include "masm.hpp"
#include "revision.hpp"
#include "apidb.hpp"
#include "limit.hpp"
#include "semantics.hpp"
#include "path.hpp"
#include "bua.hpp"

// these next ones needed for global obj cleanup...
#include "riscops.hpp"
#include "vftable.hpp"

// for non portable unhandled exception stuff in pharos_main:
#ifdef __GNUC__
#include <cstdlib>
#include <cxxabi.h>
using namespace __cxxabiv1;
#endif

namespace boost {
namespace filesystem {
void validate(boost::any& v,
              std::vector<std::string> const & values,
              boost::filesystem::path *, int)
{
  using namespace boost::program_options;
  validators::check_first_occurrence(v);
  std::string const & s = validators::get_single_string(values);
  wordexp_t we;
  int rv = wordexp(s.c_str(), &we, (WRDE_NOCMD | WRDE_UNDEF));
  if (rv != 0 || we.we_wordc != 1) {
    throw validation_error(validation_error::invalid_option_value);
  }
  auto deleter = [](wordexp_t *w) { wordfree(w); };
  std::unique_ptr<wordexp_t, decltype(deleter)> we_guard(&we, deleter);
  v = boost::any(boost::filesystem::path(we.we_wordv[0]));
}

}}

namespace pharos {

namespace bf = boost::filesystem;

using prolog::plog;

// This is library path from the command line or the default value.
namespace {
bf::path library_path;

int global_logging_fileno = -1;
LogDestination global_logging_destination;
bool global_logging_iteractive = false;
}

bool interactive_logging() {
  return global_logging_iteractive;
}

LogDestination get_logging_destination()
{
  if (global_logging_destination) {
    return global_logging_destination;
  }
  Sawyer::Message::PrefixPtr prefix = Sawyer::Message::Prefix::instance();
  prefix = prefix->showProgramName(false);
  // It's sometimes useful to also disable the faciltiy and importance.
  //prefix = prefix->showFacilityName(Sawyer::Message::NEVER)->showImportance(false);

  if (global_logging_fileno < 0) {
    global_logging_fileno = STDOUT_FILENO;
  }
  global_logging_destination =
    Sawyer::Message::FdSink::instance(global_logging_fileno, prefix);

  return global_logging_destination;
}

// For logging options and other critically important "informational" messages.  This facility
// is meant to always be logged at level "INFO" and above.  The "WHERE" level includes optional
// messages, including the affirmative reporting of which options were detected.
Sawyer::Message::Facility olog;

// Get the message levels from Sawyer::Message::Common.
using namespace Sawyer::Message::Common;

#define DEFAULT_VERBOSITY 3
#define MAXIMUM_VERBOSITY 14

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
    ("timing", po::bool_switch(), "Include duration field in log messages")
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
     po::value<std::vector<bf::path>>()->composing(),
     "pharos configuration file (can be specified multiple times)")
    ("option",
     po::value<std::vector<std::string>>()->composing(),
     "configuration value specification, key1.key2=value, (can be specified multiple times)")
    ("dump-config",
     "display current active config parameters")
    ("no-user-file",
     "don't load the user's configuration file")
    ("no-site-file",
     "don't load the site's configuration file")
    ("apidb", po::value<std::vector<bf::path>>(),
     "path to sqlite or JSON file containing API and type information")
    ("library,l",
     po::value<bf::path>(),
     "specify the path to the pharos library directory")

    // Timeouts affecting the "core" analysis pass.
    ("timeout", po::value<double>(),
     "time limit (sec) for the entire analysis")
    ("per-function-timeout", po::value<double>(),
     "CPU limit (sec) per function")
    ("partitioner-timeout", po::value<double>(),
     "time limit (sec) for the partitioner")
    ("maximum-memory", po::value<double>(),
     "maximum memory (Mib) for the entire anlaysis")
    ("per-function-maximum-memory", po::value<double>(),
     "maximum memory (Mib) per function")
    ("maximum-instructions-per-block", po::value<int>(),
     "limit the number of instructions per basic block")
    ("maximum-iterations-per-function", po::value<int>(),
     "limit the number of CFG iterations per function")
    ("maximum-nodes-per-condition", po::value<int>(),
     "limit the number of tree nodes per ITE condition")

    ("threads", po::value<int>()->implicit_value(1),
     ("Number of threads to use, if this program uses threads.  "
      "A value of zero means to use all available processors.  "
      "A negative value means to use that many less than the number of available processors."))

    // Historical...  Do we even need this anymore?
    ("file,f",
     po::value<bf::path>(),
     "executable to be analyzed")
    ;
  ;

  // Don't forget to update the documentation if you change this list!

  // These are really partitioner options or maybe options that are mostly just passed along to
  // control standard ROSE behavior.
  ProgOptDesc roseopt("ROSE/Partitioner options");
  roseopt.add_options()
    ("partitioner", po::value<std::string>(),
     "specify the function parititioner")
    ("serialize", po::value<bf::path>(),
     "file which caches function partitioning information")
    ("ignore-serialize-version",
     "reject version mismatch errors when reading a serialized file")
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
    ("stockpart",
     "deprecated, use --parititioner=rose")
    ("rose-version",
     "output ROSE version information and exit immediately")
    ;

  // Don't forget to update the documentation if you change this list!

  certopt.add(roseopt);
  return certopt;
}

static ProgOptDesc cert_hidden_options()
{
  namespace po = boost::program_options;

  ProgOptDesc certhiddenopt("CERT Hidden options");

  // Don't forget to update the documentation if you change this list!
  certhiddenopt.add_options()
    ("maxmem", po::value<double>(),
     "the old maximum-memory")
    ("relmaxmem", po::value<double>(),
     "the old per-function-maximum-memory")
    ("ptimeout", po::value<double>(),
     "the old partitioner-timeout")
    ("blockcounterlimit", po::value<int>(),
     "the old maximum-instructions-per-block")
    ("funccounterlimit", po::value<int>(),
     "the old maximum-iterations-per-function")
    ("propagate-conditions",
     "Flag to preserve and propagate conditions when analyzing basic blocks")
    ;
  ;
  return certhiddenopt;
}

ProgOptVarMap::ProgOptVarMap(int argc, char **argv)
{
  std::copy_n(argv, argc, std::back_inserter(_args));
}

std::string ProgOptVarMap::command_line() const
{
  std::ostringstream os;
  for (auto arg : _args) {
    if (os.tellp() != 0) {
      os << ' ';
    }
    if (std::strchr(arg, ' ')) {
      os << '\'' << arg << '\'';
    }
  }
  return os.str();
}

static ProgOptVarMap parse_cert_options_internal(
  int argc, char** argv,
  ProgOptDesc partial_desc,
  const std::string & proghelptext,
  boost::optional<ProgPosOptDesc> posopt,
  Sawyer::Message::UnformattedSinkPtr destination)
{
  namespace po = boost::program_options;

  bool fileopt = false;
  if (!posopt) {
    fileopt = true;
    posopt = ProgPosOptDesc().add("file", -1);
  }

  if (destination) {
    global_logging_destination = destination;
    global_logging_fileno = -1;
  }

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

  // Assume the install root is one directory below.
  root_loc = prog_loc.parent_path();
  lib_root = root_loc / "share/pharos";

  ProgOptVarMap vm(argc, argv);;

  // Register our custom callback for determining if two expressions may be equal.
  set_may_equal_callback();

  get_logging_destination()->prefix()->showElapsedTime(false);

  // Get the options logging facility working with the standard options.
  olog.initialize("OPTI");
  olog.initStreams(get_logging_destination());
  // Initialize the global log with the appropriate filters.  Set this up before option
  // processing.
  glog.initStreams(get_logging_destination());

  ProgOptDesc od;
  od.add(partial_desc);
  od.add(cert_hidden_options());

  po::store(po::command_line_parser(argc, argv).
            options(od).positional(*posopt).run(), vm);

  bf::path program = argv[0];
  vm.config(pharos::Config::load_config(
              program.filename().native(),
              vm.count("no-site-file") ? nullptr : (root_loc / "etc/pharos.yaml").c_str(),
              vm.count("no-site-file") ? nullptr : "PHAROS_CONFIG",
              vm.count("no-user-file") ? nullptr : ".pharos.yaml"));
  if (vm.count("config")) {
    for (auto & filename : vm["config"].as<std::vector<bf::path>>()) {
      vm.config().mergeFile(filename.native());
    }
  }
  if (vm.count("option")) {
    for (auto & kv : vm["option"].as<std::vector<std::string>>()) {
      vm.config().mergeKeyValue(kv);
    }
  }
  if (vm.count("dump-config")) {
    // Use cout, so it can easily be copied to a file
    std::cout << vm.config() << LEND;
    exit(3);
  }

  global_logging_iteractive =
    global_logging_fileno >= 0 && isatty(global_logging_fileno) && !vm.count("batch");

  // Turn off color when color can't or shouldn't be used
  if (!color_terminal(global_logging_fileno) || vm.count("batch")) {
    get_logging_destination()->overridePropertiesNS().useColor = false;
  }

  get_logging_destination()->prefix()->showElapsedTime(vm["timing"].as<bool>());

  // Once the command line options have been processed we can determine the library path.
  auto lv = vm.get<bf::path>("library", "pharos.library");
  library_path = lv ? *lv : lib_root;

#if PHAROS_ROSE_VARIABLE_ID_HACK
  // Ensure that variable IDs are allocated in a deterministic fashion when running
  // single-threaded
  auto level_opt = vm.get<int>("threads", "concurrency_level");
  if (!level_opt || *level_opt == 1) {
    Rose::BinaryAnalysis::SymbolicExpr::serializeVariableIds = true;
  }
#endif


  // ----------------------------------------------------------------------------------------
  // Configure the rest of the logging facilities
  // ----------------------------------------------------------------------------------------

  Rose::Diagnostics::initialize();
  Sawyer::ProgressBarSettings::initialDelay(3.0);
  Sawyer::ProgressBarSettings::minimumUpdateInterval(1.0);

  // Add the options logging facility to the known facilities.
  Sawyer::Message::mfacilities.insert(olog);
  // We can now log to olog if we need to...

  if (vm.count("help")) {
    if (!proghelptext.empty()) {
      std::cout << proghelptext << "\n\n";
    }
    std::cout << partial_desc;
    std::cout << "\nRevID: " << pharos::REVISION << std::endl;
    exit(3);
  }

  if (vm.count("rose-version")) {
    std::cout << version_message() << std::endl;
    exit(3);
  }

  // We complain about non-included required options here.
  po::notify(vm);

  // Set global limits
  set_global_limits(vm);

  // Add the global logging facility to the known facilities.
  Sawyer::Message::mfacilities.insert(glog);
  // Initialize the semantics log with the appropriate filters.
  slog.initialize("FSEM");
  slog.initStreams(get_logging_destination());
  // Add the semantic logging facility to the known facilities.
  Sawyer::Message::mfacilities.insert(slog);
  // Initialize the prolog logging facility
  plog.initialize("PLOG");
  plog.initStreams(get_logging_destination());
  // Add the prolog logging facility to the known facilities.
  Sawyer::Message::mfacilities.insert(plog);

  // This was cleaner when it was a global initializer in types.cpp...
  init_type_logging();

  auto & apidblog = APIDictionary::initDiagnostics();
  BottomUpAnalyzer::initDiagnostics();

  // Set the default verbosity to only emit errors and and fatal messages.
  Sawyer::Message::mfacilities.control("none, >=error");
  // Since the line above doesn't seem to work as expected...
  slog[Sawyer::Message::WARN].disable();

  // We've recently decided to enable warnings as well.
  glog[Sawyer::Message::WARN].enable();
  // The options log is the exception to the rule that only errors and above are reported.
  olog[Sawyer::Message::WARN].enable();
  olog[Sawyer::Message::INFO].enable();

  if (interactive_logging()) {
    olog[Sawyer::Message::MARCH].enable();
  }

  // apidb
  apidblog[Sawyer::Message::WARN].enable();

  // Prolog logging levels
  plog[Sawyer::Message::ERROR].enable();
  plog[Sawyer::Message::FATAL].enable();
  plog[Sawyer::Message::WARN].enable();

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
    plog[Sawyer::Message::INFO].enable(verbosity >= 3);
    plog[Sawyer::Message::WHERE].enable(verbosity >= 6);
    plog[Sawyer::Message::TRACE].enable(verbosity >= 9);
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

  if (fileopt) {
    if (vm.count("file")) {
      OINFO << "Analyzing executable: " << vm["file"].as<bf::path>().native() << LEND;
    } else {
      OFATAL << "You must specify at least one executable to analyze." << LEND;
      exit(3);
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
  }

  bool propagate_conditions = (vm.count("propagate-conditions") > 0);
  if (propagate_conditions) {
    int limit = *vm.get<int>("maximum-nodes-per-condition", "pharos.maximum_nodes_per_condition");
    OINFO << "Propagating full conditions (up to " << limit
          << " terms) during function analysis." << LEND;
  }

  // Early checks to make sure APIDB files exist
  boost::optional<std::string> badfile = APIDictionary::verify_args(vm);
  if (badfile) {
    OFATAL << "Unable to read APIDB file: " << *badfile << LEND;
    exit (EXIT_FAILURE);
  }

  // We might want to investigate allowing unknown options for pasthru to ROSE
  // http://www.boost.org/doc/libs/1_53_0/doc/html/program_options/howto.html

  return vm;
}

ProgOptVarMap parse_cert_options(
  int argc, char** argv,
  ProgOptDesc od,
  const std::string & proghelptext,
  boost::optional<ProgPosOptDesc> posopt,
  Sawyer::Message::UnformattedSinkPtr destination) {
  try {
    return parse_cert_options_internal(argc, argv, od, proghelptext, posopt, destination);
  } catch (boost::program_options::error const &e) {
    OFATAL << "Error parsing arguments: " << e.what() << LEND;
    exit (EXIT_FAILURE);
  }
}

const bf::path& get_library_path()
{
  return library_path;
}

// Convert a vector of string into a set of rose_addr_t, out of option var map.
AddrSet option_addr_list(ProgOptVarMap const & vm, const char *name) {
  AddrSet aset;
  if (vm.count(name) > 0) {
    for (const std::string & as : vm[name].as<StrVector>()) {
      aset.insert(parse_number(as));
    }
  }
  return aset;
}

AddrSet get_selected_funcs(const DescriptorSet& ds, ProgOptVarMap const & vm) {
  AddrSet included_funcs = option_addr_list(vm, "include-func");

  // WTF?
  if (included_funcs.size () > 0) {
    for (rose_addr_t a : included_funcs) {
      ODEBUG << "Limiting analysis to function: " << addr_str(a) << LEND;
    }
  } else {
    auto & map = ds.get_func_map();
    std::transform(map.begin(), map.end(), std::inserter(included_funcs, included_funcs.end()),
                   [](FunctionDescriptorMap::const_reference x) { return x.first; });
    // There's a bug in boost::range::insert in boost 1.61 that causes failures in clang.
    // boost::insert (included_funcs, ds.get_func_map () | boost::adaptors::map_keys);
  }

  AddrSet excluded_funcs = option_addr_list(vm, "exclude-func");
  for (const rose_addr_t addr : excluded_funcs) {
    GINFO << "Function " << addr_str(addr) << " excluded" << LEND;
  }

  AddrSet selected_funcs;

  boost::set_difference (included_funcs, excluded_funcs, std::inserter (selected_funcs, selected_funcs.end ()));
  return selected_funcs;
}

void cleanup_our_globals() {
  // need to clean up some static globals that are or get things in them dynamically allocated,
  // to prevent static object ctor/dtor order problems w/ statically linked exec from crashing
  // in various ways at exit time during static object destruction:
  global_rops.reset(); // riscops.hpp
}

static void report_std_exception(const std::exception & e, int level = 0)
{
  if (level == 0) {
    GFATAL << "Pharos main error: ";
#ifdef __GNUC__
    int status;
    std::string ename (abi::__cxa_demangle(abi::__cxa_current_exception_type()->name(), 0, 0, &status));
    GFATAL << "(" << ename << ") ";
#endif
  }  else {
    GFATAL << std::string(level, ' ') << "Reason: ";
  }
  GFATAL << e.what() << LEND;
  try {
    std::rethrow_if_nested(e);
  } catch (const std::exception & e2) {
    report_std_exception(e2, level + 1);
  } catch (...) {
    // Do nothing
  }
}

static void report_exception(const std::exception_ptr ep)
{
  try {
    std::rethrow_exception (ep);
  } catch (const std::exception &e) {
    report_std_exception(e);
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
  }
}

static void pharos_terminate() {
  // Prevent loops
  std::set_terminate (std::terminate);

  // Report on the current exception
  report_exception (std::current_exception ());

  // Print the backtrace
  backtrace (glog, Sawyer::Message::FATAL);

  std::exit (EXIT_FAILURE);
}

int pharos_main(std::string const & glog_name, main_func_ptr fn,
                int argc, char **argv, int logging_fileno)
{
  glog.initialize(glog_name);

  int rc = 0;
  atexit(cleanup_our_globals);

  global_logging_fileno = logging_fileno;

  ROSE_INITIALIZE;

  if (!getenv(PHAROS_PASS_EXCEPTIONS_ENV))
    std::set_terminate (pharos_terminate);

  rc = fn(argc, argv);

  return rc;
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
