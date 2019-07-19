// Copyright 2018-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include <libpharos/spacer.hpp>
#include "pathanalyzer_test_config.hpp"

using namespace pharos;
using namespace pharos::ir;

const DescriptorSet* global_ds = nullptr;

// -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
// Instantiate tests with parameters read from the configuration file
INSTANTIATE_TEST_CASE_P(PathAnalyzerTestParameters, PATestFixture,
                        ::testing::ValuesIn(test_config),
                        PATestFixture::PrintToStringParamName());

// -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
// Start parameterized test cases for path finding

// XXX put this somewhere better
ImportRewriteSet get_imports () {
  return {
    // Because of in-lining, we may need to jump over a call to path_goal to reach the one we
    // selected.  As a result we need to include time.
    std::make_pair ("bogus.so", "time"),
    std::make_pair ("bogus.so", "rand"),
    std::make_pair ("bogus.so", "_Znwm"),
    std::make_pair ("MSVCR100D.dll", "rand"),
    std::make_pair ("ucrtbased.dll", "rand")
  };
}

TEST_P(PATestFixture, TestSpacer) {

  PATestConfiguration test = GetParam();

  if (test.name=="" || test.start==INVALID_ADDRESS ||
      (test.goal==INVALID_ADDRESS && test.bad==INVALID_ADDRESS)) {
    FAIL() << "Improper test configuration!";
    return;
  }

  try {
    PharosZ3Solver z3;
    z3.set_timeout(10000);
    if (test.seed != 0) {
      z3.set_seed(test.seed);
    }

    std::stringstream log_ss;
    log_ss << test.name << ".smt";

    z3.set_log_name(log_ss.str());

    SpacerAnalyzer sa(*global_ds, z3, get_imports(), "spacer");

    if (test.goal!=INVALID_ADDRESS) {
      ASSERT_TRUE(z3::sat == std::get<0>(sa.find_path_hierarchical(test.start, test.goal)))
        << "Could not find expected path using SPACER!";
    }
    else if (test.bad!=INVALID_ADDRESS) {
      ASSERT_FALSE(z3::sat == std::get<0>(sa.find_path_hierarchical(test.start, test.bad)))
        << "Found invalid path using SPACER!";
    }
  }
  catch (std::exception& ex) {
    OERROR << "Exception thrown: " << ex.what() << LEND;
  }
  catch (z3::exception& ex) {
    OERROR << "Exception thrown: " << ex << LEND;
  }
}

// End parameterized test cases for path finding
// -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

static int pathanalyzer_test_spacer_main(int argc, char **argv) {

  // Handle options
  namespace po = boost::program_options;
  ProgOptDesc pathod = pathanalyzer_test_options();
  ProgOptDesc csod = cert_standard_options();
  pathod.add(csod);
  ProgOptVarMap ovm = parse_cert_options(argc, argv, pathod);

  DescriptorSet ds(ovm);
  // Resolve imports, load API data, etc.
  ds.resolve_imports();
  // Global for just this test program to make gtest happy.
  global_ds = &ds;

  // This is not the most durable solution, but it works. JSG should move this into the testing
  // fixture
  //Z3_global_param_set("verbose", "10");

  PATestAnalyzer pa(ds, ovm);
  pa.analyze();

  configure_tests(pa, ovm);

  ::testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}

int main(int argc, char **argv) {
  return pharos_main("SPTE", pathanalyzer_test_spacer_main, argc, argv, STDERR_FILENO);
}


/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */

