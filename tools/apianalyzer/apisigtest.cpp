// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#include <libpharos/util.hpp>
#include <gtest/gtest.h>
#include <libpharos/apisig.hpp>

using namespace pharos;

// This is the main test fixture
class ApiSigTest : public testing::Test {

 protected:

  std::unique_ptr<ApiSigManager> sig_manager_;

  std::string json_file1_;

  ApiSigTest() {

    json_file1_ = "tests/json_test1.json";

  }

  virtual void SetUp() {
    sig_manager_ =  make_unique<ApiSigManager>(std::make_shared<ApiJsonSigParser>());
    sig_manager_->LoadSigFile(json_file1_);

  }

  virtual void TearDown() {
    sig_manager_ = nullptr;
  }

};

TEST_F(ApiSigTest, TEST_PARSE_VALID_SIG) {

  EXPECT_TRUE(sig_manager_->NumValidSigs() == 1);
  EXPECT_TRUE(sig_manager_->NumErrorSigs() == 0);
}

TEST_F(ApiSigTest, TEST_VALID_SIG_PARAMS) {

  ApiSigVector sigs;
  sig_manager_->GetSigs(sigs);

  for (const ApiSig & s : sigs) {

    if (boost::iequals(s.name,"TestSig1")) {
      for (const ApiSigFunc & f : s.api_calls) {
        if (boost::iequals(f.name,"TestAPI2") == true) {
          EXPECT_TRUE(f.has_params);
          EXPECT_FALSE(f.has_retval);

          EXPECT_TRUE(f.params.size() == 2);

          ApiSigFuncParam p1 = f.params.at(0);
          EXPECT_TRUE(boost::iequals(p1.name,"P1"));
          EXPECT_TRUE(p1.index == 0);
          EXPECT_TRUE(p1.type == ApiSigFuncParam::IN);

          ApiSigFuncParam p2 = f.params.at(1);
          EXPECT_TRUE(boost::iequals(p2.name,"P2"));
          EXPECT_TRUE(p2.index == 1);
          EXPECT_TRUE(p2.type == ApiSigFuncParam::OUT);

          return;
        }
      }
    }
  }
}


TEST_F(ApiSigTest, TEST_VALID_SIG_INFO) {

  ApiSigVector sigs;
  ApiSig sig;
  sig_manager_->GetSigs(sigs);

  for (ApiSig s : sigs) {
    sig = s;
    break;
  }

  // Test the meta data

  EXPECT_TRUE(boost::iequals(sig.name,"TestSig1"));
  EXPECT_TRUE(boost::iequals(sig.description,"Test a signature"));
  EXPECT_TRUE(boost::iequals(sig.category,"Test category"));
}

TEST_F(ApiSigTest, TEST_VALID_SIG_RETVAL) {
  sig_manager_->LoadSigFile(json_file1_);

  ApiSigVector sigs;
  sig_manager_->GetSigs(sigs);

  for (const ApiSig & s : sigs) {
    if (boost::iequals(s.name,"TestSig1")) {

      for (const ApiSigFunc & f : s.api_calls) {
        if (boost::iequals(f.name,"TestApi1") == true) {
          EXPECT_TRUE(f.has_retval);

          ApiSigParam rv = f.retval;
          EXPECT_TRUE(boost::iequals(rv.name,"R"));
          EXPECT_TRUE(rv.type == ApiSigFuncParam::RET);

          return;
        }
      }
    }
  }
}

int main(int argc, char **argv) {

  ::testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}
