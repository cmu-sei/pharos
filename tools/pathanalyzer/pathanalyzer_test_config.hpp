// Copyright 2018-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include <rose.h>
#include <gtest/gtest.h>
#include <libpharos/typedb.cpp>
#include <libpharos/descriptors.hpp>
#include <libpharos/ir.hpp>
#include <libpharos/wp.hpp>
#include <libpharos/path.hpp>
#include <libpharos/descriptors.hpp>
#include <libpharos/bua.hpp>
#include <boost/algorithm/string/split.hpp>

using namespace pharos;
using namespace pharos::ir;

const std::string TEST_MARK = "test";
const std::string TEST_START_MARK = "start";
const std::string TEST_GOAL_MARK = "goal";
const std::string TEST_BAD_MARK = "bad";

struct PATestConfiguration {
  // The address of the function being tested
  rose_addr_t start, goal, bad;
  std::string name;
  int seed;
  PATestConfiguration(std::string n, int s = 0)
    : start(INVALID_ADDRESS), goal(INVALID_ADDRESS), bad(INVALID_ADDRESS), name(n), seed(s) { }

  std::string DebugString() const {
    std::stringstream ss;
    ss << "Test= '" << name
       << "' Start= " << addr_str(start)
       << " Goal= " << ((goal==INVALID_ADDRESS) ? "None" : addr_str(goal))
       << " Bad= " << ((bad==INVALID_ADDRESS) ? "None" : addr_str(bad));
    return ss.str();
  }
};

typedef std::vector<PATestConfiguration> TestConfigVector;
TestConfigVector test_config;

::std::ostream& operator<<(::std::ostream& os, const PATestConfiguration& cfg) {
  return os << cfg.DebugString();  // whatever needed to print bar to os
}

class PATestAnalyzer : public BottomUpAnalyzer {
 private:
  std::map<rose_addr_t, std::string> breadcrumbs_;

  CallParamInfoBuilder builder_;
  PATestConfiguration* config_;
  TestConfigVector test_config_;

 public:

  PATestAnalyzer(DescriptorSet& ds_, ProgOptVarMap & vm_)
    : BottomUpAnalyzer(ds_, vm_),  builder_(vm_, ds_.memory) {

    int s = 0;
    if (vm.count("seed")>0) {
      s = vm["seed"].as<int>();
    }
    test_config_.push_back(PATestConfiguration("test", s));
     config_ = &(test_config_.back());
  }

  void visit(FunctionDescriptor *fd) override {
    fd->get_pdg();
    auto callset = fd->get_outgoing_calls();
    for (CallDescriptor * call : callset) {
      for (rose_addr_t target : call->get_targets()) {
        OINFO << "Call target from " << call->address_string() << " to " << addr_str(target) << LEND;
        const FunctionDescriptor* tfd = ds.get_func(target);
        if (tfd) {
          const SgAsmFunction* func = tfd->get_func();
          if (func) {
            std::string name = func->get_name();
            OINFO << "Found call to " << name << " at " << call->address_string() << LEND;
            if (name == "_Z10path_startv") {
              OINFO << "Found path_start() call at " << call->address_string() << LEND;
              // This is a hack for Ed's code to avoid Jeff's breadcrumb calls
              auto insn = call->get_insn ();
              auto succ = insn->get_address () + insn->get_size ();
              // If we've already seen a call to path_start(), mark the test invalid and return.
              if (config_->start != INVALID_ADDRESS) {
                config_->start = INVALID_ADDRESS;
                return;
              }
              config_->start = succ;
            }
            if (name == "_Z9path_goalv") {
              OINFO << "Found path_goal() call at " << call->address_string() << LEND;
              // If we've already seen a call to path_goal(), mark the test invalid and return.
              if (config_->goal != INVALID_ADDRESS) {
                config_->goal = INVALID_ADDRESS;
                return;
              }
              config_->goal = call->get_address();
            }
            if (name == "_Z12path_nongoalv") {
              OINFO << "Found path_nongoal() call at " << call->address_string() << LEND;
              // If we've already seen a call to path_nongoal(), mark the test invalid and return.
              if (config_->bad != INVALID_ADDRESS) {
                config_->bad = INVALID_ADDRESS;
                return;
              }
              config_->bad = call->get_address();
            }
          }
        }
      }
    }
  }

  void finish () override {  }

  TestConfigVector get_test_config() {
    return test_config_;
  }
};

// This class is the test fixture used by all tests. Essentially, it
// contains the setup/teardown for each test case (nothing in this instance)
// and helper functions needed by the test cases. Currently, there is only
// one helper function: CountStkvars(). Eventually, there will be helpers to
// report the size, signed-ness, and type of variables
class PATestFixture : public ::testing::TestWithParam<PATestConfiguration> {

 public:

  PATestFixture() { /* Nothing to do here*/ }

  virtual ~PATestFixture() { /* Nothing to do here*/ }

  virtual void SetUp() { /*/ No setup needed */ }

  virtual void TearDown() { /* No teardown needed*/ }

  // Allow printing of test names when using parameterized tests
  struct PrintToStringParamName {
    template <class ParamType>
    std::string operator()( const testing::TestParamInfo<ParamType>& info ) const {
      auto config = static_cast<PATestConfiguration>(info.param);
      return config.name;
    }
  };
};

ProgOptDesc pathanalyzer_test_options() {
  namespace po = boost::program_options;

  ProgOptDesc ptopt("PathAnalyzer Test options");
  ptopt.add_options()
    ("disable-tests,d", po::value<std::string>(), "The comma-separated list of tests discovered in the binary to skip")
    ("include-tests,i", po::value<std::string>(), "The comma-separated list of tests discovered in the binary to include")
    ("seed,s", po::value<int>(), "The random seed for Z3.");

  return ptopt;
}

void configure_tests(PATestAnalyzer& pa, const ProgOptVarMap& ovm) {

  // set the configuration to be used by the tests
  test_config = pa.get_test_config();

  std::stringstream ss;
  ss << test_config.size() << " tests recovered from binary:\n";
  for (auto tc : test_config) {
    ss << " * " << tc.name << " (Start= " << addr_str(tc.start);
    if (tc.goal!=INVALID_ADDRESS) {
      ss << ", Goal= " << addr_str(tc.goal);
    }
    if (tc.bad!= INVALID_ADDRESS) {
      ss << ", Bad= "  <<  addr_str(tc.bad);
    }
    ss << ")\n";
  }
  OINFO << ss.str() << LEND;

  if (ovm.count("disable-tests")>0) {

    std::string skip_list = ovm["disable-tests"].as<std::string>();
    std::vector<std::string> skip_vector;

    boost::split(skip_vector, skip_list, boost::is_any_of(","), boost::token_compress_on);

    for (auto target : skip_vector) {
      auto tci = test_config.begin();
      while (tci != test_config.end()) {
        if (boost::iequals(tci->name, target) == true) {
          OINFO << "Disabling test: " << tci->name << LEND;
          tci = test_config.erase(tci);
        } else {
          ++tci;
        }
      }
    }
  }
  if (ovm.count("include-tests")>0) {

    std::string test_list = ovm["include-tests"].as<std::string>();
    std::vector<std::string> test_vector;

    boost::split(test_vector, test_list, boost::is_any_of(","), boost::token_compress_on);
    TestConfigVector include_test_config;

    for (auto target : test_vector) {
      auto tci = test_config.begin();
      while (tci != test_config.end()) {
        if (boost::iequals(tci->name, target) == true) {
          include_test_config.push_back(*tci);
          OINFO << "Including test: " << tci->name << LEND;
        }
        ++tci;
      }
    }
    test_config = include_test_config;
  }

  // If no test was found, then fail.
  if (test_config.size() == 0) {
    OFATAL << "No valid tests were found." << LEND;
    exit(1);
  }
}
