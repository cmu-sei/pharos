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
#include <boost/filesystem.hpp>

using namespace pharos;
using namespace pharos::ir;

struct PATestConfiguration {
  // The address of the function being tested
  rose_addr_t start, goal, bad;

  // the name of the test
  std::string name;

  // The method used to find the path.
  std::string method;

  // The file name where the goal SMT statements are stored for debugging.
  std::string goal_smt_file;
  // The file name where the nongoal SMT statements are stored for debugging.
  std::string nongoal_smt_file;

  int seed;
  PATestConfiguration(std::string n, std::string m = "none",
                      std::string gs = "", std::string ngs = "", int s = 0)
    : start(INVALID_ADDRESS), goal(INVALID_ADDRESS), bad(INVALID_ADDRESS),
      name(n), method(m), goal_smt_file(gs), nongoal_smt_file(ngs), seed(s) { }

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

    std::string goal_smt_file = "";
    if (vm.count("goal-smt")>0) {
      goal_smt_file = vm["goal-smt"].as<std::string>();
      OINFO << "Saving goal SMT to '" << goal_smt_file << "'" << LEND;
    }

    std::string nongoal_smt_file = "";
    if (vm.count("nongoal-smt")>0) {
      nongoal_smt_file = vm["nongoal-smt"].as<std::string>();
      OINFO << "Saving nongoal SMT to '" << nongoal_smt_file << "'" << LEND;
    }

    std::string method = "none";
    if (vm.count("method") > 0) {
      method = vm["method"].as<std::string>();
      OINFO << "Using method '" << method << "'" << LEND;
    }

    std::string test_name;
    if (vm.count("file") > 0) {
      using namespace boost::filesystem;
      test_name = basename (path (vm["file"].as<std::string>()));
    }

    test_config_.push_back(
      PATestConfiguration(test_name, method, goal_smt_file, nongoal_smt_file, s));
    config_ = &(test_config_.back());
  }

  void visit(FunctionDescriptor *fd) override {
    fd->get_pdg();

    // Ick.  This was much nicer back when we were calling fd->get_outgoing_calls(), but not
    // all of the calls are actually CALL instructions in -O2 in g++, so we need an approach
    // that works for finding all instructions and their control flow targets.  This is
    // probably a sign that get_outgoing_calls() is broken and needs some work, but that's
    // a bigger change.
    const CFG& cfg = fd->get_rose_cfg();
    for (auto vertex : fd->get_vertices_in_flow_order(cfg)) {
      SgNode *n = get(boost::vertex_name, cfg, vertex);
      SgAsmBlock *blk = isSgAsmBlock(n);
      assert(blk != NULL);
      for (size_t j = 0; j < blk->get_statementList().size(); ++j) {
        SgAsmStatement *stmt = blk->get_statementList()[j];
        SgAsmInstruction *insn = isSgAsmInstruction(stmt);
        SgAsmX86Instruction *xinsn = isSgAsmX86Instruction(stmt);
        // We're only interested in calls and jumps.
        if (!insn_is_call_or_jmp(xinsn)) continue;

        bool complete;
        for (rose_addr_t target : insn->getSuccessors(&complete)) {
          //OINFO << "Call/Jump from " << addr_str(insn->get_address()) << " to " << addr_str(target) << LEND;
          const FunctionDescriptor* tfd = ds.get_func(target);
          if (tfd) {
            const SgAsmFunction* func = tfd->get_func();
            if (func) {
              std::string name = func->get_name();
              //OINFO << "Found call to " << name << " at " << addr_str(insn->get_address()) << LEND;
              if (name == "_Z10path_startv" || name == "path_start") {
                OINFO << "Found path_start() call at " << addr_str(insn->get_address()) << LEND;

                // If we've already seen a call to path_start(), mark the test invalid and return.
                if (config_->start != INVALID_ADDRESS) {
                  OINFO << "Found duplicate path_start() call at " << addr_str(insn->get_address()) << LEND;
                  config_->start = INVALID_ADDRESS;
                  return;
                }

                // We used to start at the instruction following the call to path_start().  That
                // doesn't really work because if we're going to be using the stack, we'll need
                // to have a proper setup of the RSP & RBP registers.  So instead, we're just
                // going to use the path_start() call to mean that the start location is at the
                // beginning of the current function!  Hopefully this retroactive redefinition
                // won't cause too many problems, and if it does we may have to use something
                // better defined like that path_start() is always main().

                // auto start = insn->get_address () + insn->get_size ();
                config_->start = fd->get_address();
              }
              if (name == "_Z9path_goalv" || name == "path_goal") {
                OINFO << "Found path_goal() call at " << addr_str(insn->get_address()) << LEND;
                // If we've already seen a call to path_goal(), mark the test invalid and return.
                if (config_->goal != INVALID_ADDRESS && config_->goal != target) {
                  OINFO << "Found duplicate path_goal() call at " << addr_str(insn->get_address()) << LEND;
                  config_->goal = INVALID_ADDRESS;
                  return;
                }
                //config_->goal = insn->get_address();
                config_->goal = target;
              }
              if (name == "_Z12path_nongoalv" || name == "path_nongoal") {
                OINFO << "Found path_nongoal() call at " << addr_str(insn->get_address()) << LEND;
                // If we've already seen a call to path_nongoal(), mark the test invalid and return.
                if (config_->bad != INVALID_ADDRESS && config_->bad != target) {
                  OINFO << "Found duplicate path_nongoal() call at " << addr_str(insn->get_address()) << LEND;
                  config_->bad = INVALID_ADDRESS;
                  return;
                }
                config_->bad = target;
              }
            }
          }
        }
      }
    }
  }

  void finish () override { }

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
    ("disable-tests,d", po::value<std::string>(),
     "The comma-separated list of tests discovered in the binary to skip")
    ("include-tests,i", po::value<std::string>(),
     "The comma-separated list of tests discovered in the binary to include")
    ("seed,s", po::value<int>(), "The random seed for Z3")
    ("goal-smt", po::value<std::string>(),
     "The name of the file to save goal SMT output")
    ("nongoal-smt", po::value<std::string>(),
     "The name of the file to save nongoal SMT output")
    ("method,m", po::value<std::string>(),
     "The analysis method to use (fs, wp or spacer)");

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

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
