// Copyright 2019-2021 Carnegie Mellon University.  See LICENSE file for terms.

#include <libpharos/descriptors.hpp>
#include <libpharos/spacer.hpp>
#include <boost/optional/optional_io.hpp>

const std::string version = "0.1";

using namespace pharos;

ProgOptDesc pathfinder_options() {
  namespace po = boost::program_options;

  ProgOptDesc pfopt("PathFinder version " + version + " options");
  pfopt.add_options()
    ("target,t", po::value<std::string>(), "The goal address")
    ("source,s", po::value<std::string>(), "The source address")
    ("engine,e", po::value<std::string>(), "The analysis engine (probably spacer)");

  return pfopt;
}

int pathfinder_main(int argc, char **argv) {

  set_glog_name("PF");

  // Handle options
  ProgOptDesc chcod = pathfinder_options();
  ProgOptDesc csod = cert_standard_options();
  chcod.add(csod);
  ProgOptVarMap vm = parse_cert_options(argc, argv, chcod);

  // Find calls, functions, and imports.
  DescriptorSet ds(vm);
  ds.resolve_imports();

  if (!vm.count ("source")) {
    throw std::invalid_argument ("You forgot to specify a source address.");
  }
  if (!vm.count ("target")) {
    throw std::invalid_argument ("You forgot to specify a target address.");
  }
  auto srcaddr = parse_number (vm["source"].as<std::string> ());
  auto tgtaddr = parse_number (vm["target"].as<std::string> ());
  auto engine = (vm.count("engine")) ? vm["engine"].as<std::string> () : "spacer";

  PharosZ3Solver z3;
  SpacerAnalyzer sa(ds, z3, engine);

  sa.setup_path_problem(srcaddr, tgtaddr);

  OINFO << "The CHC encoding is:\n";
  sa.output_problem(OINFO) << LEND;

  z3::check_result res = sa.solve_path_problem();

  OINFO << "---\nThe result is '" << res << "'" << LEND;
  if (res!= z3::unknown) {
    OINFO << "The answer is:\n";
    sa.output_solution(OINFO) << LEND;
  }

  return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
  return pharos_main("PF", pathfinder_main, argc, argv);
}
