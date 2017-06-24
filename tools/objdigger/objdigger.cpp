// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <rose.h>

#include <libpharos/misc.hpp>
#include <libpharos/pdg.hpp>
#include <libpharos/descriptors.hpp>
#include <libpharos/options.hpp>
#include <libpharos/riscops.hpp>
#include <libpharos/jsonoo.hpp>
#include <libpharos/ooanalyzer.hpp>

#define VERSION "0.12"

using namespace pharos;

// The global CERT message facility.
Sawyer::Message::Facility glog("OBJD");

// The global stack tracker.
spTracker *sp_tracker;

// Controls whether we're reporting timing.
namespace pharos {
extern bool global_timing;
}

ProgOptDesc digger_options() {
  namespace po = boost::program_options;

  ProgOptDesc digopt("Object Digger v" VERSION " options");
  digopt.add_options()
    ("new-method,n",
     po::value<StrVector>(),
     "function at address is a new() method")
    ("json,j",
     po::value<std::string>(),
     "specify the JSON output file")
    ("prolog-facts,F",
     po::value<std::string>(),
     "specify the Prolog facts output file")
    ("prolog-results,R",
     po::value<std::string>(),
     "specify the Prolog results output file")
    ("report,r",
     "report classes found to stdout")
    ("timing,t",
     "enable timing performance reporting")
    ;
  return digopt;
}

// print the results of the analysis.
void print_results(void) {

  for (const ClassDescriptorMap::value_type& ucpair : classes) {
    const ClassDescriptor& obj = ucpair.second;
    OINFO << "================================================================================" << LEND;
    OINFO << "Constructor: " << obj.get_name() << " (" << obj.address_string() << ")" << LEND;

    for (const MemberMap::value_type& mpair : obj.data_members) {
      const Member& member = mpair.second;
      member.debug();
    }
    OINFO << "Total object instance size: 0x" << std::hex << obj.get_size() << std::dec << LEND;


    for (const ThisCallMethod* tcm : obj.methods) {
      if (tcm->is_destructor()) {
        OINFO << "Destructor: " << tcm->address_string() << LEND;
      }
      else if (tcm->is_constructor()) {
        OINFO << "Constructor: " << tcm->address_string() << LEND;
      }
      else {
        OINFO << "Method: " << tcm->address_string() << LEND;
      }
    }
    for (const InheritedMethodMap::value_type& m : obj.inherited_methods) {
      OINFO << "Inherited Method: " << m.first->address_string()
            << " Offset: 0x" << std::hex << m.second << std::dec << LEND;
    }
  }
  OINFO << "================================================================================" << LEND;
}

static int objdigger_main(int argc, char **argv)
{
  // Parse options...
  ProgOptDesc digod = digger_options();
  ProgOptDesc csod = cert_standard_options();
  digod.add(csod);
  ProgOptVarMap vm = parse_cert_options(argc, argv, digod);

  OINFO << "Object Digger version " << VERSION << "." << LEND;

  // This is a bit hackish right now.  I should probably expose the whole var map globally, but
  // that would have greater dependencies than I want to think about right now.
  if (vm.count("timing")) {
    global_timing = true;
  }

  // Chuck asked for this...
  AddrSet new_addrs = option_addr_list(vm, "new-method");

  // Find calls, functions, and imports.
  DescriptorSet ds(vm);
  if (ds.get_interp() == NULL) {
    GFATAL << "Unable to analyze file (no executable content found)." << LEND;
    return EXIT_FAILURE;
  }
  // Load a config file overriding parts of the analysis.
  if (vm.count("imports")) {
    std::string config_file = vm["imports"].as<std::string>();
    GINFO << "Loading analysis configuration file: " <<  config_file << LEND;
    ds.read_config(config_file);
  }
  // Load stack deltas from config files for imports.
  ds.resolve_imports();

  sp_tracker = ds.get_spTracker();

  // =====================================================================================
  // Object oriented program analysis
  // =====================================================================================

  // Build interprocedural PDGs
  OOAnalyzer ooa(&ds, vm, new_addrs);
  ooa.analyze();

  // If we didn't find any C++ classes, report that.
  if (classes.size() == 0) {
    OERROR << "No C++ classes were detected in the program." << LEND;
  }
  else {
    if (vm.count("report")) {
      print_results();
    }
    if (vm.count("json")) {
      ObjdiggerJsonExporter json(vm);
      json.generate_json(classes);
      json.export_json();

    }
  }
  OINFO << "Object digger analysis complete." << LEND;

  return 0;
}

int main(int argc, char* argv[]) {
  return pharos_main(objdigger_main, argc, argv);
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
