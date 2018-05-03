// Copyright 2015-2018 Carnegie Mellon University.  See LICENSE file for terms.

#include <rose.h>

#include <libpharos/misc.hpp>
#include <libpharos/pdg.hpp>
#include <libpharos/descriptors.hpp>
#include <libpharos/options.hpp>
#include <libpharos/riscops.hpp>
#include <libpharos/oojson_exporter.hpp>
#include <libpharos/ooanalyzer.hpp>
#include <libpharos/ooclass.hpp>

#define VERSION "0.13"

using namespace pharos;

// The global stack tracker.
spTracker *sp_tracker;

ProgOptDesc digger_options() {
  namespace po = boost::program_options;

  ProgOptDesc digopt("OOAnalyzer v" VERSION " options");
  digopt.add_options()
    ("json,j",
     po::value<std::string>(),
     "specify the JSON output file")
    ("new-method,n",
     po::value<StrVector>(),
     "function at address is a new() method")
    ("no-guessing",
     "do not perform hypothetical reasoning.  never use except for experiments")
    ("ignore-rtti",
     "ignore RTTI metadata if present")
    ("prolog-facts,F",
     po::value<std::string>(),
     "specify the Prolog facts output file")
    ("prolog-results,R",
     po::value<std::string>(),
     "specify the Prolog results output file")
    ("prolog-debug,d",
     "enable debugging in the Prolog analysis")
    ("prolog-trace",
     "enable output of prolog commands, queries, and results")
    ("prolog-low-level-tracing",
     "enable prolog's low-level tracing")
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

  if (!vm.count("prolog-facts") && !vm.count("json")) {
    GFATAL << "You must provide --json (for use with the IDA plugin) or --prolog-facts." << LEND;
    GFATAL << "If you use --prolog-facts you probably also want to use --prolog-results." << LEND;
    return EXIT_FAILURE;
  }

  // Chuck asked for this...
  AddrSet new_addrs = option_addr_list(vm, "new-method");

  // Find calls, functions, and imports.
  DescriptorSet ds(vm);
  if (ds.get_interp() == NULL) {
    GFATAL << "Unable to analyze file (no executable content found)." << LEND;
    return EXIT_FAILURE;
  }
  // Resolve imports, load API data, etc.
  ds.resolve_imports();

  sp_tracker = ds.get_spTracker();

  // =====================================================================================
  // Object oriented program analysis
  // =====================================================================================

  // Build interprocedural PDGs
  OOAnalyzer ooa(&ds, vm, new_addrs);
  ooa.analyze();
  std::vector<OOClassDescriptorPtr> ooclasses = ooa.get_result_classes();

  // If we didn't find any C++ classes, report that.
  if (ooclasses.size() == 0) {
    OERROR << "No C++ classes were detected in the program." << LEND;
  }
  else {
    if (vm.count("json")) {
      OOJsonExporter json(vm);
      json.generate_json(ooclasses);
      json.export_json();

    }
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
