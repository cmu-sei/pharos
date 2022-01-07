// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#include <libpharos/descriptors.hpp>
#include <libpharos/options.hpp>
#include <libpharos/bua.hpp>

#include <libpharos/apigraph.hpp>
#include <libpharos/apisig.hpp>

#include <boost/filesystem.hpp>

using namespace pharos;

namespace bf = boost::filesystem;

const std::string VERSION  = "1.01";

// add extra command line options for apianalyzer
ProgOptDesc apianalyzer_options() {
  namespace po = boost::program_options;

  std::string version_string = "ApiGraphGen v" + VERSION + " options";
  ProgOptDesc apiopt(version_string.c_str());

  apiopt.add_options()
    ("graphviz,G", po::value<bf::path>(), "specify the graphviz output file");

  return apiopt;
}

// Need to swtich this to use pharos_main.  Or better, make this functionality
// simply be a cmd line arg to apianalyzer instead of a separate exec.
int apigraphgen_main(int argc, char* argv[]) {

  ProgOptDesc apiod = apianalyzer_options();
  ProgOptDesc csod = cert_standard_options();
  apiod.add(csod);

  ProgOptVarMap vm = parse_cert_options(argc, argv, apiod);

  std::string gv_file = vm["graphviz"].as<bf::path>().native();

  // end configuration, begin analysis

  // Find calls, functions, and imports.
  DescriptorSet ds(vm);
  // Resolve imports, load API data, etc.
  ds.resolve_imports();

  // Build PDGs
  BottomUpAnalyzer bua(ds, vm);
  bua.analyze();

  // end analysis, start graph generation

  GINFO << "Starting API Graph generation" << LEND;

  ApiGraph graph(ds);
  size_t num_components = graph.Build();

  OINFO << "Completed API Graph generation with " << num_components << " components" << LEND;
  OINFO << "Writing graphviz to " << gv_file << LEND;

  std::ofstream graphviz_file(gv_file.c_str());

  graph.GenerateGraphViz(graphviz_file);

  OINFO << "ApiGraphGen complete." << LEND;
  global_rops.reset();

  return 0;
}

int main(int argc, char* argv[]) {
  return pharos_main("APIG", apigraphgen_main, argc, argv);
}
