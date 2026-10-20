// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#include <libpharos/misc.hpp>
#include <libpharos/pdg.hpp>
#include <libpharos/descriptors.hpp>
#include <libpharos/options.hpp>
#include <libpharos/riscops.hpp>
#include <libpharos/ooanalyzer.hpp>

#include <boost/filesystem.hpp>

#define VERSION "1.0"

using namespace pharos;

namespace bf = boost::filesystem;

ProgOptDesc digger_options() {
  namespace po = boost::program_options;

  ProgOptDesc digopt("OOAnalyzer v" VERSION " options");
  digopt.add_options()
    ("json,j",
     po::value<bf::path>(),
     "specify the JSON output file")
    ("new-method,n",
     po::value<StrVector>(),
     "function at address is a new() method")
    ("delete-method",
     po::value<StrVector>(),
     "function at address is a delete() method")
    ("purecall",
     po::value<StrVector>(),
     "function at address is purecall")
    ("no-guessing",
     "do not perform hypothetical reasoning.  never use except for experiments")
    ("ignore-rtti",
     "ignore RTTI metadata if present")
    ("prolog-facts,F",
     po::value<bf::path>(),
     "specify the Prolog facts output file")
    ("prolog-results,R",
     po::value<bf::path>(),
     "specify the Prolog results output file")
    ("prolog-loglevel", po::value<int>(),
     "sets the prolog logging verbosity (1-7)")
    ("prolog-trace",
     "enable output of prolog commands, queries, and results")
    ;
  return digopt;
}

static int ooanalyzer_main(int argc, char **argv)
{
  // Parse options...
  ProgOptDesc digod = digger_options();
  ProgOptDesc csod = cert_standard_options();
  digod.add(csod);
  ProgOptVarMap vm = parse_cert_options(argc, argv, digod);

  OINFO << "OOAnalyzer version " << VERSION << "." << LEND;

  if (!vm.count("prolog-facts") && !vm.count("prolog-results") && !vm.count("json")) {
    GFATAL << "You must provide --json (for use with the IDA plugin) or --prolog-facts." << LEND;
    GFATAL << "If you use --prolog-facts you probably also want to use --prolog-results." << LEND;
    return EXIT_FAILURE;
  }

  // Find calls, functions, and imports.
  DescriptorSet ds(vm);

  // OOAnalyzer requires non-zero base address when not explicitly specified
  if (vm.count("base-address") == 0) {
    auto memmap = ds.memory.get_memmap();
    if (memmap && memmap->hull().least() == 0) {
      GFATAL << "OOAnalyzer requires a non-zero base address." << LEND;
      GFATAL << "The specimen has a base address of 0." << LEND;
      GFATAL << "Please use --base-address to specify a non-zero load address." << LEND;
      return EXIT_FAILURE;
    }
  }

  // Resolve imports, load API data, etc.
  ds.resolve_imports();

  // =====================================================================================
  // Object oriented program analysis
  // =====================================================================================

  // Build interprocedural PDGs
  OOAnalyzer ooa(ds, vm);
  ooa.analyze();

  if (!vm.count("prolog-results") && !vm.count("json")) {
    OWARN << "OOAnalyzer did not perform Prolog class analysis." << LEND;
  }
  OINFO << "OOAnalyzer analysis complete." << LEND;

  return 0;
}

int main(int argc, char* argv[]) {
  return pharos_main("OOAN", ooanalyzer_main, argc, argv);
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
