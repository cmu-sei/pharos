// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#include <rose.h>

#include <boost/foreach.hpp>

#include "misc.hpp"
#include "pdg.hpp"
#include "descriptors.hpp"
#include "options.hpp"
#include "riscops.hpp"
#include "jsonoo.hpp"
#include "ooanalyzer.hpp"

#define VERSION "0.08"

// The global CERT message facility.
Sawyer::Message::Facility glog("OBJD");

// The global stack tracker.
spTracker *sp_tracker;

// Controls whether we're reporting timing.
extern bool global_timing;

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
    ("prolog,p",
     po::value<std::string>(),
     "specify the Prolog facts output file")
    ("report,r",
     "report classes found to stdout")
    ("timing,t",
     "enable timing performance reporting")
    ;
  return digopt;
}

// print the results of the analysis.
void print_results(void) {

  BOOST_FOREACH(const ClassDescriptorMap::value_type& ucpair, classes) {
    const ClassDescriptor& obj = ucpair.second;
    OINFO << "================================================================================" << LEND;
    OINFO << "Constructor: " << obj.get_name() << " (" << obj.address_string() << ")" << LEND;

    BOOST_FOREACH(const MemberMap::value_type& mpair, obj.data_members) {
      const Member& member = mpair.second;
      member.debug();
    }
    OINFO << "Total object instance size: 0x" << std::hex << obj.get_size() << std::dec << LEND;


    BOOST_FOREACH(ThisCallMethod* tcm, obj.methods) {
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
    BOOST_FOREACH(const InheritedMethodMap::value_type& m, obj.inherited_methods) {
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

  SgAsmInterpretation* interp = get_interpretation(vm);
  if (interp == NULL) return 1;

  // This is a bit hackish right now.  I should probably expose the whole var map globally, but
  // that would have greater dependencies than I want to think about right now.
  if (vm.count("timing")) {
    global_timing = true;
  }

  // Chuck asked for this...
  AddrSet new_addrs = option_addr_list(vm, "new-method");

  // Find calls, functions, and imports.
  DescriptorSet ds(interp, &vm);
  // Load a config file overriding parts of the analysis.
  if (vm.count("imports")) {
    std::string config_file = vm["imports"].as<std::string>();
    GINFO << "Loading analysis configuration file: " <<  config_file << LEND;
    ds.read_config(config_file);
  }
  // Load stack deltas from config files for imports.
  ds.resolve_imports();

  sp_tracker = ds.get_spTracker();

  // Initialize a global RISCOps object for using to read and write states.
  global_rops = make_risc_ops();

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
