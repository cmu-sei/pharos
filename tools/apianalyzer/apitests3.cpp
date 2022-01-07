// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#include <libpharos/pdg.hpp>
#include <libpharos/misc.hpp>
#include <libpharos/descriptors.hpp>
#include <libpharos/masm.hpp>
#include <libpharos/defuse.hpp>
#include <libpharos/sptrack.hpp>
#include <libpharos/options.hpp>
#include <libpharos/bua.hpp>

#include <libpharos/apigraph.hpp>
#include <libpharos/apisig.hpp>

#include <boost/filesystem.hpp>

#include <gtest/gtest.h>

using namespace pharos;

namespace bf = boost::filesystem;

const DescriptorSet* global_ds = nullptr;

std::string test_config = "";

// Thisis the main test fixture
class ApiParamTest : public testing::Test {

 protected:

  std::unique_ptr<ApiSigManager> sig_manager_;

  ApiGraph api_graph_;

  std::string json_file_;

  ApiParamTest() : api_graph_(*global_ds) {

    //;tests/apitests3_sig.json";
    json_file_ = test_config;

  }

  ApiSig GetSigToMatch(std::string target_sig) {
    ApiSigVector sigs;
    sig_manager_->GetSigs(sigs);
    for (ApiSig s : sigs) {
      if (s.name == target_sig) {
        return s;
      }
    }
    return ApiSig();
  }

  void CheckResultTree(rose_addr_t component, std::string &expected_tree, ApiSearchResultVector &results) {

    std::string st = "";
    bool found_component = false;

    for (ApiSearchResultVector::iterator ri=results.begin(), end=results.end(); ri!=end; ri++) {
      if (ri->match_component_start == component) {
        found_component = true;
        for (std::vector<ApiWaypointDescriptor>::iterator pi=ri->search_tree.begin(); pi!=ri->search_tree.end(); pi++) {
          st += addr_str(pi->block->get_address());
        }
        break;
      }
    }

    EXPECT_TRUE(found_component);

    // this is the correct search tree for the simple inter-procedural search
    EXPECT_EQ(expected_tree,st);
  }

  virtual void SetUp() {
    sig_manager_ =  make_unique<ApiSigManager>(std::make_shared<ApiJsonSigParser>());
    sig_manager_->LoadSigFile(json_file_);

    api_graph_.Build();
  }

  virtual void TearDown() {
    sig_manager_ = nullptr;
    api_graph_.Reset();
  }

};

TEST_F(ApiParamTest, TEST_MATCH_PARAM_INTRA_FUNCTION) {

  ApiSig sig = GetSigToMatch("TestParamSig");
  if (!sig.IsValid()) {
    FAIL() << "Could not find test signature!";
    return;
  }
  ApiSearchResultVector results;
  bool r = api_graph_.Search(sig, &results);

  EXPECT_TRUE(r);

  rose_addr_t component = 0x00401000;
  std::string expected = "0x0040113A0x0040117C";

  CheckResultTree(component, expected, results);
}

TEST_F(ApiParamTest, TEST_MATCH_PARAM_INTER_FUNCTION) {

  ApiSig sig = GetSigToMatch("TestParamSig");
  if (!sig.IsValid()) {
    FAIL() << "Could not find test signature!";
    return;
  }
  ApiSearchResultVector results;
  bool r = api_graph_.Search(sig, &results);

  EXPECT_TRUE(r);

  rose_addr_t component = 0x004012C0;
  std::string expected = "0x004013FA0x00401254";

  CheckResultTree(component, expected, results);
}

TEST_F(ApiParamTest,TEST_SHOULD_NOT_FIND_API_MATCH_WITH_PARAM_MISMATCH) {

  ApiSig sig = GetSigToMatch("TestParamSig");
  if (!sig.IsValid()) {
    FAIL() << "Could not find test signature!";
    return;
  }
  ApiSearchResultVector results;
  api_graph_.Search(sig, &results);

  // This should not match based on parameter mismatching
  for (ApiSearchResultVector::iterator ri=results.begin(), end=results.end(); ri!=end; ri++) {
    ASSERT_TRUE(ri->match_component_start != 0x04015B0);
  }
}

TEST_F(ApiParamTest,TEST_SHOULD_NOT_FIND_API_MATCH_WITH_RETVAL_MISMATCH) {

  ApiSig sig = GetSigToMatch("BadRetvalSig");
  if (!sig.IsValid()) {
    FAIL() << "Could not find test signature!";
    return;
  }
  ApiSearchResultVector results;
  api_graph_.Search(sig, &results);

  // This should not match based on parameter mismatching
  for (ApiSearchResultVector::iterator ri=results.begin(), end=results.end(); ri!=end; ri++) {
    ASSERT_TRUE(ri->match_component_start != 0x00401A10);
  }
}

TEST_F(ApiParamTest,TEST_SHOULD_CORRECTLY_HANDLE_OUT_PARAMS_INTRA) {

  ApiSig sig = GetSigToMatch("TestOutParamSig");
  if (!sig.IsValid()) {
    FAIL() << "Could not find test signature!";
    return;
  }

  ApiSearchResultVector results;
  bool r = api_graph_.Search(sig, &results);

  EXPECT_TRUE(r);

  rose_addr_t component = 0x004014F0;
  // 0x004014F0 calls CREATEPIPE
  // 0x00401553 calls READFILE
  // 0x00401575 calls WRITEFILE
  std::string search_tree = "0x004014F00x004015530x00401575";
  CheckResultTree(component, search_tree, results);
}


TEST_F (ApiParamTest,TEST_SHOULD_CORRECTLY_HANDLE_OUT_PARAMS_INTER) {
  ApiSig sig;
  sig.name = "TEST_SHOULD_FIND_VALID_SIG_INTERPROCEDURAL";
  sig.api_calls.push_back(ApiSigFunc("KERNEL32.DLL!CREATEPIPE"));
  sig.api_calls.push_back(ApiSigFunc("KERNEL32.DLL!READFILE"));
  sig.api_calls.push_back(ApiSigFunc("KERNEL32.DLL!WRITEFILE"));
  sig.api_count = sig.api_calls.size();

  ApiSearchResultVector results;
  api_graph_.Search(sig, &results);

  rose_addr_t component = 0x00401B10;
  std::string search_tree = "0x00401AD00x00401B360x00401B5B";
  CheckResultTree(component, search_tree, results);
}

TEST_F(ApiParamTest,TEST_SHOULD_CORRECTLY_HANDLE_MULTIPLE_IN_PARAMS) {

  ApiSig sig = GetSigToMatch("MultiParamTest2");
  if (!sig.IsValid()) {
    FAIL() << "Could not find test signature!";
    return;
  }

  ApiSearchResultVector results;
  bool r = api_graph_.Search(sig, &results);

  EXPECT_TRUE(r);

  rose_addr_t component = 0x00401A30;
  std::string search_tree = "0x00401A800x00401AA3";
  CheckResultTree(component, search_tree, results);

}

TEST_F(ApiParamTest,TEST_SHOULD_CORRECTLY_HANDLE_MULTIPLE_IN_PARAMS_WITH_SELFLOOP) {

  ApiSig sig = GetSigToMatch("MultiParamTest3");
  if (!sig.IsValid()) {
    FAIL() << "Could not find test signature!";
    return;
  }

  ApiSearchResultVector results;
  bool r = api_graph_.Search(sig, &results);

  EXPECT_TRUE(r);

  rose_addr_t component = 0x00401A30;
  std::string search_tree = "0x00401A800x00401AA30x00401AA3";

  CheckResultTree(component, search_tree, results);

}


TEST_F(ApiParamTest,TEST_SHOULD_MATCH_RETVAL_DIRECT_TO_PARAM) {

  ApiSig sig = GetSigToMatch("TestRetValSig");
  if (!sig.IsValid()) {
    FAIL() << "Could not find test signature!";
    return;
  }

  ApiSearchResultVector results;
  api_graph_.Search(sig, &results);

  rose_addr_t component = 0x00401890;
  std::string search_tree = "0x004018900x004018B7";

  CheckResultTree(component, search_tree, results);
}

TEST_F(ApiParamTest,TEST_SHOULD_MATCH_RETVAL_INTER_FUNC) {

  ApiSig sig = GetSigToMatch("TestRetValSig");
  if (!sig.IsValid()) {
    FAIL() << "Could not find test signature!";
    return;
  }

  ApiSearchResultVector results;
  bool res = api_graph_.Search(sig, &results);

  EXPECT_TRUE(res);

  rose_addr_t component = 0x004017F0;
  std::string search_tree = "0x004018800x00401814";

  CheckResultTree(component, search_tree, results);
}

TEST_F(ApiParamTest,TEST_SHOULD_MATCH_RETVAL_IN_LOCAL_VAR) {

  ApiSig sig = GetSigToMatch("TestRetValSig");
  if (!sig.IsValid()) {
    FAIL() << "Could not find test signature!";
    return;
  }

  ApiSearchResultVector results;
  api_graph_.Search(sig, &results);

  rose_addr_t component = 0x00401930;
  std::string search_tree = "0x004019300x0040195D";

  CheckResultTree(component, search_tree, results);
}

ProgOptDesc apitest3_options() {
  namespace po = boost::program_options;

  ProgOptDesc api3opt("ApiTests3 options");
  api3opt.add_options()
    ("test-config,t", po::value<bf::path>(), "The test signature file");
  return api3opt;
}

int main(int argc, char **argv) {

  ::testing::InitGoogleTest(&argc, argv);

  set_glog_name("API3");

  ProgOptDesc api3od = apitest3_options();
  ProgOptDesc csod = cert_standard_options();
  api3od.add(csod);
  ProgOptVarMap vm = parse_cert_options(argc, argv, api3od);

  // Find calls, functions, and imports.
  DescriptorSet ds(vm);
  // Resolve imports, load API data, etc.
  ds.resolve_imports();
  // Global for just this test program to make gtest happy.
  global_ds = &ds;

  test_config = vm["test-config"].as<bf::path>().native();

  // Generate PDGs and do the analysis
  BottomUpAnalyzer bua(ds, vm);
  bua.analyze();

  int rc = RUN_ALL_TESTS();
  global_rops.reset();
  return rc;
}
