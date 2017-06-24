// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.


#include <rose.h>

#include <gtest/gtest.h>
#include <libpharos/apisig.hpp>

using namespace pharos;

Sawyer::Message::Facility glog("APIT");


// Thisis the main test fixture
class ApiSigTest : public testing::Test {

protected:

  ApiSigManager *sig_manager_;

  std::string json_file1_;

  ApiSigTest() {

    json_file1_ = "tests/json_test1.json";

  }

  virtual void SetUp() {

    sig_manager_ = new ApiSigManager();
    sig_manager_->SetParser(new ApiJsonSigParser());
    sig_manager_->LoadSigFile(json_file1_);

  }

  virtual void TearDown() {
    delete sig_manager_;
  }

};

TEST_F(ApiSigTest, TEST_PARSE_VALID_SIG) {

  EXPECT_TRUE(sig_manager_->NumValidSigs() == 1);
  EXPECT_TRUE(sig_manager_->NumErrorSigs() == 0);
}

TEST_F(ApiSigTest, TEST_VALID_SIG_PARAMS) {

  SigPtrVector sigs;
  sig_manager_->GetSigs(&sigs);

  for (const ApiSig &s : sigs) {

    if (boost::iequals(s.name,"TestSig1")) {
      for (const ApiSigFunc & f : s.api_calls) {
        if (boost::iequals(f.name,"TestAPI2") == true) {
          EXPECT_TRUE(f.has_params);
          EXPECT_FALSE(f.has_retval);

          EXPECT_TRUE(f.params.size() == 2);

          ApiSigFuncParam p1 = f.params.at(0);
          EXPECT_TRUE(boost::iequals(p1.name,"P1"));
          EXPECT_TRUE(p1.index == 0);
          EXPECT_TRUE(p1.type == IN);

          ApiSigFuncParam p2 = f.params.at(1);
          EXPECT_TRUE(boost::iequals(p2.name,"P2"));
          EXPECT_TRUE(p2.index == 1);
          EXPECT_TRUE(p2.type == OUT);

          return;
        }
      }
    }
  }
}


TEST_F(ApiSigTest, TEST_VALID_SIG_INFO) {

  SigPtrVector sigs;
  ApiSig sig;
  sig_manager_->GetSigs(&sigs);

  for (const ApiSig &s : sigs) {
    sig = s;
    break;
  }

  // Test the meta data

  EXPECT_TRUE(boost::iequals(sig.name,"TestSig1"));
  EXPECT_TRUE(boost::iequals(sig.description,"Test a signature"));
  EXPECT_TRUE(boost::iequals(sig.category,"Test category"));
}


TEST_F(ApiSigTest, TEST_VALID_SIG_RETVAL) {

  sig_manager_->SetParser(new ApiJsonSigParser());
  sig_manager_->LoadSigFile(json_file1_);

  SigPtrVector sigs;
  sig_manager_->GetSigs(&sigs);

  for (const ApiSig &s : sigs) {
    if (boost::iequals(s.name,"TestSig1")) {

      for (const ApiSigFunc & f : s.api_calls) {
        if (boost::iequals(f.name,"TestApi1") == true) {
          EXPECT_TRUE(f.has_retval);

          ApiSigParam rv = f.retval;
          EXPECT_TRUE(boost::iequals(rv.name,"R"));
          EXPECT_TRUE(rv.type == RET);

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
