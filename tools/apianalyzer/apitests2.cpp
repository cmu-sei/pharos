// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <rose.h>
#include <stdio.h>
#include <iostream>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graph_utility.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/graph/connected_components.hpp>
#include <time.h>

#include <libpharos/pdg.hpp>
#include <libpharos/misc.hpp>
#include <libpharos/descriptors.hpp>
#include <libpharos/masm.hpp>
#include <libpharos/defuse.hpp>
#include <libpharos/sptrack.hpp>
#include <libpharos/options.hpp>

#include <gtest/gtest.h>

#include <libpharos/apigraph.hpp>
#include <libpharos/apisig.hpp>

using namespace pharos;

Sawyer::Message::Facility glog("APIT");

// This is the main test fixture
class ApiAnalyzerTest2 : public testing::Test {

protected:

  ApiGraph api_graph_;

  ApiAnalyzerTest2() {  }

  virtual void SetUp() {
    // Code here will be called immediately after the constructor (right
    // before each test).
    api_graph_.Build();
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test (right
    // before the destructor).
    api_graph_.Reset();
  }

  void CheckResultTree(rose_addr_t component, std::string &expected_tree, ApiSearchResultVector &results) {

    std::string st = "";
     for (ApiSearchResultVector::iterator ri=results.begin(), end=results.end(); ri!=end; ri++) {
       if (ri->match_component_start == component) {
         for (std::vector<ApiWaypointDescriptor>::iterator pi=ri->search_tree.begin(); pi!=ri->search_tree.end(); pi++) {
           st += addr_str(pi->block->get_address());
         }
         break;
       }
     }
     // this is the correct search tree for the simple inter-procedural search
     EXPECT_EQ(expected_tree,st);
  }
};

// these are tests that concern the ApiCfgComponent class
class ApiAnalyzerInterproceduralTest : public ApiAnalyzerTest2 { };

TEST_F(ApiAnalyzerInterproceduralTest, TEST_SHOULD_NOT_FIND_INVALID_INTERPROCEDURAL_SIG) {
  // self-loop + additional APIs
  ApiSig sig;
  sig.name = "TEST_SHOULD_FIND_VALID_SIG_INTERPROCEDURAL";
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!GETSTARTUPINOFW"));
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!GARBAGE")); // Invalid

  sig.api_count = sig.api_calls.size();

  ApiSearchResultVector results;
  bool r = api_graph_.Search(sig, &results);

  EXPECT_FALSE(r);
  EXPECT_EQ(results.size(),0);

  ApiSig sig2;
   sig2.name = "TEST_SHOULD_FIND_VALID_SIG_INTERPROCEDURAL";
   sig2.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!GETSTARTUPINOFW"));
   sig2.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!READFILE")); // Invalid
   sig2.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!Garbage")); // Valid

   sig2.api_count = sig2.api_calls.size();

   ApiSearchResultVector results2;
   bool r2 = api_graph_.Search(sig2, &results2);

   EXPECT_FALSE(r2);
   EXPECT_EQ(results2.size(),0);
}

// This test is designed to force backtracking for a valid signature
TEST_F(ApiAnalyzerInterproceduralTest, TEST_SHOULD_HANDLE_INTERPROCEDURAL_BACKTRACKING) {

  // Sig4:Kernel32.DLL!GetTickCount,Kernel32.DLL!GetModuleHandleA,Kernel32.DLL!ExitProcess,Kernel32.DLL!CloseHandle

  ApiSig sig1;
  sig1.name = "TEST_SHOULD_HANDLE_INTERPROCEDURAL_BACKTRACKING1";
  sig1.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!GETTICKCOUNT"));
  sig1.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!GETMODULEHANDLEA"));
  sig1.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!EXITPROCESS"));
  sig1.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!CLOSEHANDLE"));

  sig1.api_count = sig1.api_calls.size();

  ApiSearchResultVector results1;
  bool r1 = api_graph_.Search(sig1, &results1);

  EXPECT_TRUE(r1);

  rose_addr_t component1 = 0x004013E0;
  std::string expected1 = "0x004013E00x004013B00x004013BC0x004013C7";
  CheckResultTree(component1, expected1, results1);

}

// this is a basic inter-procedural signature
TEST_F(ApiAnalyzerInterproceduralTest, TEST_SHOULD_FIND_VALID_INTERPROCEDURAL_SIG) {

  // self-loop + additional APIs
  ApiSig sig;
  sig.name = "TEST_SHOULD_FIND_VALID_SIG_INTERPROCEDURAL";
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!PEEKNAMEDPIPE"));
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!READFILE")); // This is in a sub-component
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!WRITEFILE"));

  sig.api_count = sig.api_calls.size();

  ApiSearchResultVector results;

  bool r = api_graph_.Search(sig, &results);

  EXPECT_TRUE(r);
  EXPECT_EQ(results.size(),1);

  rose_addr_t component = 0x00401160;
  std::string expected = "0x0040129A0x004010D00x004010A40x004010600x004010400x004010840x00401307";

  CheckResultTree(component, expected, results);
}

int main(int argc, char **argv) {

  ::testing::InitGoogleTest(&argc, argv);

  ProgOptVarMap vm = parse_cert_options(argc, argv, cert_standard_options());

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

  BottomUpAnalyzer bua(&ds, vm);
  bua.analyze();

  int rc = RUN_ALL_TESTS();
  global_rops.reset();
  return rc;
}
