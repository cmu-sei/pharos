// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Jeff Gennari
// Date: 2015-06-22
// Version: 2.0

#include <rose.h>
#include <stdio.h>
#include <iostream>
#include <fstream>

#include <libpharos/pdg.hpp>
#include <libpharos/misc.hpp>
#include <libpharos/descriptors.hpp>
#include <libpharos/masm.hpp>
#include <libpharos/defuse.hpp>
#include <libpharos/sptrack.hpp>
#include <libpharos/options.hpp>

#include <libpharos/apigraph.hpp>
#include <libpharos/apisig.hpp>

using namespace pharos;

// Controls whether we're reporting timing.
namespace pharos { extern bool global_timing; }

// The global CERT message facility.  This may change.
Sawyer::Message::Facility glog("APIA");

const std::string VERSION  = "2.0.06";

// add extra command line options for apianalyzer
ProgOptDesc apianalyzer_options() {
  namespace po = boost::program_options;

  std::string version_string = "ApiAnalyzer v" + VERSION + " options";
  ProgOptDesc apiopt(version_string.c_str());

  apiopt.add_options()
           ("sig_file,S", po::value<std::string>(), "Specify the API signature file")
           ("graphviz,G", po::value<std::string>(), "Specify the graphviz output file (for troubleshooting)")
           ("path,P", po::value<std::string>(), "Set the search path output level (nopath, sigpath, fullpath)")
           ("format,F", po::value<std::string>(), "Set output format: json or text")
           ("out_file,O", po::value<std::string>(), "Set output file")
           ("category,C", po::value<std::string>(), "Select signature categories for which to search");

  return apiopt;
}

void Usage() {

  OFATAL << "Please check required command line arguments with '$>./apianalyzer --help'"
         << LEND;
}

static int apianalyzer_main(int argc, char* argv[]) {

  ProgOptDesc apiod = apianalyzer_options();
  ProgOptDesc csod = cert_standard_options();
  apiod.add(csod);
  ProgOptVarMap vm = parse_cert_options(argc, argv, apiod);

  // This is a bit hackish right now.  I should probably expose the
  // whole var map globally, but that would have greater dependencies
  // than I want to think about right now.
  if (vm.count("timing")) {
    global_timing = true;
  }

  // the sig file is required if not just doing graphviz

  std::string sig_file;

  if (0==vm.count("sig_file")) {
    if (0==vm.count("graphviz")) {
      Usage();
      return -1;
    } else
    {
      OINFO << "No sig file specified, just doing graphviz generation" << LEND;
    }
  }
  else
  {
    sig_file = vm["sig_file"].as<std::string>();
  }


  ApiSigManager *sig_manager = new ApiSigManager(new ApiJsonSigParser());
  if (sig_manager == NULL) {
    OFATAL << "Could not create signature manager" << LEND;
    return -1;
  }

  if (sig_file != "" && sig_manager->LoadSigFile(sig_file) == false) {
    OFATAL << "Could not load signature file: " << sig_file << LEND;
    return -1;
  }

  // Configure output settings
  ApiOutputManager output_manager;

  // output format can be text or json
  bool mode_set = false;
  if (vm.count("format")!=0) {
    std::string fmt = vm["format"].as<std::string>();

    if (true == boost::iequals(fmt, "json")) {
      output_manager.SetOutputFormat(ApiOutputManager::OutputFormat::JSON);
      mode_set = true;
    }
    else if (true == boost::iequals(fmt, "text")) {
      output_manager.SetOutputFormat(ApiOutputManager::OutputFormat::TEXT);
      mode_set = true;
    }
  }
  if (!mode_set) {
    output_manager.SetOutputFormat(ApiOutputManager::OutputFormat::TEXT);
  }

  std::string sig_filter = "*";
  if (vm.count("category")!=0) {
    sig_filter = vm["category"].as<std::string>();
  }

  // this setting controls how the search tree is displayed
  bool path_set = false;
  if (vm.count("path")!=0) {
    std::string path_level = vm["path"].as<std::string>();

    if ("sigpath" == path_level) {
      output_manager.SetSearchTreeDiplayMode(ApiOutputManager::PathLevel::SIG_PATH);
      path_set = true;
    }
    else if ("fullpath" == path_level) {
      output_manager.SetSearchTreeDiplayMode(ApiOutputManager::PathLevel::FULL_PATH);
      path_set = true;
    }
  }
  if (!path_set){
    output_manager.SetSearchTreeDiplayMode(ApiOutputManager::PathLevel::NONE);
  }

  if (vm.count("out_file")!=0) {
    std::string ofile_name = vm["out_file"].as<std::string>();
    output_manager.SetOutputFile(ofile_name);
  }

  bool create_graphviz = false;
  std::string gv_file = "";
  if (vm.count("graphviz")!=0) {
    gv_file = vm["graphviz"].as<std::string>();
    create_graphviz = true;
  }

  OINFO << "Final configuration:" << LEND
        << " - Parsed " << sig_file << " and loaded "
        << sig_manager->GetSigCount() << " signatures" << LEND;

  if (output_manager.GetOutputMode() == ApiOutputManager::OutputMode::PRINT) {
    OINFO << " - Writing output to screen" << LEND;
  }
  else if (output_manager.GetOutputMode() == ApiOutputManager::OutputMode::FILE) {
    OINFO << " - Writing output to file: '" << output_manager.GetOutputFileName() << "'" << LEND;
  }

  if (output_manager.GetOutputFormat() == ApiOutputManager::OutputFormat::JSON) {
    OINFO << " - Output format: 'JSON'" << LEND;
  }
  else if (output_manager.GetOutputFormat() == ApiOutputManager::OutputFormat::TEXT) {
    OINFO << " - Output format: 'TEXT'" << LEND;
  }

  if (output_manager.GetPathLevel() == ApiOutputManager::PathLevel::NONE) {
    OINFO << " - Display signature match name only" << LEND;
  }
  else if (output_manager.GetPathLevel() == ApiOutputManager::PathLevel::SIG_PATH) {
    OINFO << " - Display signature match path" << LEND;
  }
  else if (output_manager.GetPathLevel() == ApiOutputManager::PathLevel::FULL_PATH) {
    OINFO << " - Display complete path" << LEND;
  }
  if (create_graphviz) {
    OINFO << " - Graphviz file: '" << gv_file << "'" << LEND;
  }

  if (sig_filter == "*") {
     OINFO << " - Display all signature categories" << LEND;
  }
  else {
    std::vector<std::string> filters;
    boost::split(filters, sig_filter, boost::is_any_of(", \t"),boost::token_compress_on);
    sig_manager->SetCategoryFilter(filters);

    OINFO << " - Signature categories(s): " << sig_filter << LEND;

  }

  // end configuration, begin analysis

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

  // Build PDGs
  BottomUpAnalyzer bua(&ds, vm);
  bua.analyze();

  // end analysis, start graph generation

  GINFO << "Starting API Graph generation" << LEND;

  ApiGraph graph;
  size_t num_components = graph.Build();

  OINFO << "Completed API graph generation with " << num_components << " functions" << LEND;

  // using boost's pointer vector removes the need to manage memory
  ApiSearchResultVector results;

  SigPtrVector sigs;
  sig_manager->GetSigs(&sigs);

  if (create_graphviz) {
    OINFO << "Generating graphviz file: " << gv_file << LEND;
    std::ofstream graphviz_file(gv_file.c_str());
    graph.GenerateGraphViz(graphviz_file);
    if (0==vm.count("sig_file"))
      exit(0);
  }

  OINFO << "Searching for API signatures" << LEND;

  ApiSearchManager search_manager(graph);
  search_manager.Search(sigs,results);

  if (!results.empty()) {
    OINFO << "-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
          << LEND
          << "Matched "<< results.size() << " signatures" << LEND;

    output_manager.GenerateOutput(results);
  }
  else {
    OINFO << "No signatures matched" << LEND;
  }

  OINFO <<  "-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        << LEND
        << "ApiAnalyzer complete." << LEND;

  if (sig_manager != NULL) delete sig_manager;
  sig_manager = NULL;

  return 0;
}

int main(int argc, char* argv[]) {
  return pharos_main(apianalyzer_main, argc, argv);
}

