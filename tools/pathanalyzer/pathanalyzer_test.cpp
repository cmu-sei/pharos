// Copyright 2018-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "pathanalyzer_test_config.hpp"

using namespace pharos;

const DescriptorSet* global_ds = nullptr;

// -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
// Instantiate tests with parameters read from the configuration file
INSTANTIATE_TEST_CASE_P(PathAnalyzerTestParameters, PATestFixture,
                        ::testing::ValuesIn(test_config),
                        PATestFixture::PrintToStringParamName());

// -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
// Start parameterized test cases for path finding

TEST_P(PATestFixture, TestPA) {

  PATestConfiguration test = GetParam();

  if (test.name=="" || test.start==INVALID_ADDRESS ||
      (test.goal==INVALID_ADDRESS && test.bad==INVALID_ADDRESS)) {
    FAIL() << "Improper configuration!";
    return;
  }

  // This path finder is automatic. It should be automatically recycled per test to avoid
  // cross-test contamination
  PathFinder path_finder(*global_ds);
  path_finder.save_z3_output(); // for reporting failures

  // This is a search for a goal
  if (test.goal!=INVALID_ADDRESS) {
     path_finder.find_path(test.start, test.goal);
     ASSERT_TRUE(path_finder.path_found())
       << "Could not find expected path!"
       << "Z3 representation:\n"
       << path_finder.get_z3_output();
  }
  else if (test.bad!=INVALID_ADDRESS) {
     path_finder.find_path(test.start, test.bad);
     ASSERT_FALSE(path_finder.path_found())
       << "Found invalid path!"
       << "Z3 representation:\n"
       << path_finder.get_z3_output();
  }
}
// End parameterized test cases for path finding
// -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

static int pathanalyzer_test_main(int argc, char **argv) {

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

  PATestAnalyzer pa(ds, ovm);
  pa.analyze();

  configure_tests(pa,  ovm);

  ::testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}

int main(int argc, char **argv) {
  return pharos_main("PATH", pathanalyzer_test_main, argc, argv, STDERR_FILENO);
}


/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
