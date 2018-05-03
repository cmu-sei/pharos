// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <rose.h>

#include <gtest/gtest.h>

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

Sawyer::Message::Facility glog("APIT");

// Thisis the main test fixture
class ApiParamTest : public testing::Test {

protected:

  ApiSigManager *sig_manager_;

  ApiGraph api_graph_;

  std::string json_file_;

  ApiParamTest() {

    json_file_ = "tests/apitests3_sig.json";

  }

  void GetSigToMatch(ApiSig &sig, std::string target_sig) {

    SigPtrVector sigs;
    sig_manager_->GetSigs(&sigs);
    for (const ApiSig &s : sigs) {
      if (s.name == target_sig) {
        sig = s;
        return;
      }
    }
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

    sig_manager_ = new ApiSigManager();
    sig_manager_->SetParser(new ApiJsonSigParser());
    sig_manager_->LoadSigFile(json_file_);


    api_graph_.Build();
  }

  virtual void TearDown() {

    if (sig_manager_!=NULL) delete sig_manager_;
    sig_manager_ = NULL;

    api_graph_.Reset();
  }

};

TEST_F(ApiParamTest, TEST_MATCH_PARAM_INTRA_FUNCTION) {

  ApiSig sig;
  GetSigToMatch(sig,"TestParamSig");

  ApiSearchResultVector results;
  bool r = api_graph_.Search(sig, &results);

  EXPECT_TRUE(r);

  rose_addr_t component = 0x00401000;
  std::string expected = "0x0040113A0x0040117C";

  CheckResultTree(component, expected, results);
}

TEST_F(ApiParamTest, TEST_MATCH_PARAM_INTER_FUNCTION) {

  ApiSig sig;
  GetSigToMatch(sig,"TestParamSig");

  ApiSearchResultVector results;
  bool r = api_graph_.Search(sig, &results);

  EXPECT_TRUE(r);

  rose_addr_t component = 0x004012C0;
  std::string expected = "0x004013FA0x00401254";

  CheckResultTree(component, expected, results);
}

TEST_F(ApiParamTest,TEST_SHOULD_NOT_FIND_API_MATCH_WITH_PARAM_MISMATCH) {

  ApiSig sig;
  GetSigToMatch(sig,"TestParamSig");

  ApiSearchResultVector results;
  api_graph_.Search(sig, &results);

  // This should not match based on parameter mismatching
  for (ApiSearchResultVector::iterator ri=results.begin(), end=results.end(); ri!=end; ri++) {
    ASSERT_TRUE(ri->match_component_start != 0x04015B0);
  }
}

TEST_F(ApiParamTest,TEST_SHOULD_NOT_FIND_API_MATCH_WITH_RETVAL_MISMATCH) {

  ApiSig sig;
  GetSigToMatch(sig,"BadRetvalSig");

  ApiSearchResultVector results;
  api_graph_.Search(sig, &results);

  // This should not match based on parameter mismatching
  for (ApiSearchResultVector::iterator ri=results.begin(), end=results.end(); ri!=end; ri++) {
    ASSERT_TRUE(ri->match_component_start != 0x00401A10);
  }
}

TEST_F(ApiParamTest,TEST_SHOULD_CORRECTLY_HANDLE_OUT_PARAMS_INTRA) {

  ApiSig sig;
  GetSigToMatch(sig,"TestOutParamSig");

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
   sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!CREATEPIPE"));
   sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!READFILE"));
   sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!WRITEFILE"));
   sig.api_count = sig.api_calls.size();

   ApiSearchResultVector results;
   api_graph_.Search(sig, &results);

   rose_addr_t component = 0x00401B10;
   std::string search_tree = "0x00401AD00x00401B360x00401B5B";
   CheckResultTree(component, search_tree, results);
}

TEST_F(ApiParamTest,TEST_SHOULD_CORRECTLY_HANDLE_MULTIPLE_IN_PARAMS) {

  ApiSig sig;
  GetSigToMatch(sig,"MultiParamTest2");

  ApiSearchResultVector results;
  bool r = api_graph_.Search(sig, &results);

  EXPECT_TRUE(r);

  rose_addr_t component = 0x00401A30;
  std::string search_tree = "0x00401A800x00401AA3";
  CheckResultTree(component, search_tree, results);

}

TEST_F(ApiParamTest,TEST_SHOULD_CORRECTLY_HANDLE_MULTIPLE_IN_PARAMS_WITH_SELFLOOP) {

  ApiSig sig;
  GetSigToMatch(sig,"MultiParamTest3");

  ApiSearchResultVector results;
  bool r = api_graph_.Search(sig, &results);

  EXPECT_TRUE(r);

  rose_addr_t component = 0x00401A30;
  std::string search_tree = "0x00401A800x00401AA30x00401AA3";

  CheckResultTree(component, search_tree, results);

}


TEST_F(ApiParamTest,TEST_SHOULD_MATCH_RETVAL_DIRECT_TO_PARAM) {

  ApiSig sig;
  GetSigToMatch(sig,"TestRetValSig");

  ApiSearchResultVector results;
  api_graph_.Search(sig, &results);

  rose_addr_t component = 0x00401890;
  std::string search_tree = "0x004018900x004018B7";

  CheckResultTree(component, search_tree, results);
}

TEST_F(ApiParamTest,TEST_SHOULD_MATCH_RETVAL_INTER_FUNC) {

  ApiSig sig;
  GetSigToMatch(sig,"TestRetValSig");

  ApiSearchResultVector results;
  bool res = api_graph_.Search(sig, &results);

  EXPECT_TRUE(res);

  rose_addr_t component = 0x004017F0;
  std::string search_tree = "0x004018800x00401814";

  CheckResultTree(component, search_tree, results);
}

TEST_F(ApiParamTest,TEST_SHOULD_MATCH_RETVAL_IN_LOCAL_VAR) {

  ApiSig sig;
  GetSigToMatch(sig,"TestRetValSig");

  ApiSearchResultVector results;
  api_graph_.Search(sig, &results);

  rose_addr_t component = 0x00401930;
  std::string search_tree = "0x004019300x0040195D";

  CheckResultTree(component, search_tree, results);
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
  // Resolve imports, load API data, etc.
  ds.resolve_imports();

  // Generate PDGs and do the analysis
  BottomUpAnalyzer bua(&ds, vm);
  bua.analyze();

  int rc = RUN_ALL_TESTS();
  global_rops.reset();
  return rc;
}
