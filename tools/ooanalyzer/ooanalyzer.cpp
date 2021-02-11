// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#include <rose.h>

#include <libpharos/misc.hpp>
#include <libpharos/pdg.hpp>
#include <libpharos/descriptors.hpp>
#include <libpharos/options.hpp>
#include <libpharos/riscops.hpp>
#include <libpharos/ooanalyzer.hpp>
#include <libpharos/ooclass.hpp>

#define VERSION "1.0"

using namespace pharos;

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
    ("delete-method",
     po::value<StrVector>(),
     "function at address is a delete() method")
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
    ("prolog-loglevel", po::value<int>(),
     "sets the prolog logging verbosity (1-7)")
    ("prolog-trace",
     "enable output of prolog commands, queries, and results")
    ;
  return digopt;
}

std::string
get_stats(std::vector<OOClassDescriptorPtr> ooclasses) {
  size_t method_count=0;
  size_t usage_count=0;
  size_t vcall_count=0;

  std::stringstream ss;

  for (const auto& c : ooclasses) {

    method_count += c->get_methods().size();

    for (const auto& vf : c->get_vftables()) {
      vcall_count += vf->get_virtual_call_targets().size();
    }
    for (const auto& m : c->get_members()) {
      if (m.second!=nullptr)
        usage_count += m.second->get_evidence().size();
    }
  }

  ss << ooclasses.size() << " classes, "
     << method_count << " methods, "
     << vcall_count << " virtual calls, and "
     << usage_count << " usage instructions." << LEND;

  return ss.str();
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

  // Chuck asked for this...
  AddrSet new_addrs = option_addr_list(vm, "new-method");

  // Find calls, functions, and imports.
  DescriptorSet ds(vm);
  // Resolve imports, load API data, etc.
  ds.resolve_imports();

  // =====================================================================================
  // Object oriented program analysis
  // =====================================================================================

  // Build interprocedural PDGs
  OOAnalyzer ooa(ds, vm, new_addrs);
  ooa.analyze();
  std::vector<OOClassDescriptorPtr> ooclasses = ooa.get_result_classes();

  // Handle the various configuration options

  if (!vm.count("prolog-results") && !vm.count("json")) {
    OWARN << "OOAnalyzer did not perform C++ class analysis." << LEND;
  }
  else {
    // Otherwise the results were computed so there is output
    if (ooclasses.size() == 0) {
      OERROR << "No C++ classes were detected in the program." << LEND;
    }
    else {
      OINFO << "OOAnalyzer analysis complete, found: " << get_stats(ooclasses) << LEND;
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
