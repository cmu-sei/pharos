// Copyright 2018-2019 Carnegie Mellon University.  See LICENSE file for terms.

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
bool wp_wrapper (const DescriptorSet& ds, rose_addr_t from, rose_addr_t to) {
  IR ir = get_inlined_cfg (CG::get_cg (ds), from, to);
  IRExprPtr post;
  ir = rewrite_imported_calls (ds, ir, {
      // Because of in-lining, we may need to jump over a call to path_goal to reach the one we
      // selected.  As a result we need to include time.
      std::make_pair ("bogus.so", "time"),
      std::make_pair ("bogus.so", "rand"),
      std::make_pair ("bogus.so", "_Znwm"),
      std::make_pair ("MSVCR100D.dll", "rand"),
      std::make_pair ("ucrtbased.dll", "rand")
        });
  std::tie (ir, post) = add_reached_postcondition (ir, {to});

  //std::cout << ir <<std::endl;

  // auto cfg = ir.get_cfg ();
  // boost::write_graphviz (std::cout, cfg,
  //                     boost::make_label_writer(boost::get(boost::vertex_ir_t(), cfg)),
  //                     boost::make_label_writer(boost::get(boost::edge_name_t(), cfg)));

  IRExprPtr wp = expand_lets (wp_cfg (ir, post));

  PharosZ3Solver solver;
  solver.memoization (false);
  solver.insert (wp);
  solver.z3Update ();

  assert (solver.z3Assertions ().size () == 1);
  std::cout << "Z3 WP: " << *solver.z3Solver() << std::endl;
  std::cout << "Calling Z3...." << std::endl;

  if (solver.check() == Rose::BinaryAnalysis::SmtSolver::Satisfiable::SAT_YES) {
    std::cout << "sat!" << std::endl;

    std::cout << "here's the model: " << solver.z3Solver()->get_model() << std::endl;
    return true;
  } else {
    std::cout << "unsat!" << std::endl;
    return false;
  }
}

TEST_P(PATestFixture, TestWP) {

  PATestConfiguration test = GetParam();

  if (test.name=="" || test.start==INVALID_ADDRESS ||
      (test.goal==INVALID_ADDRESS && test.bad==INVALID_ADDRESS)) {
    FAIL() << "Improper configuration!";
    return;
  }

  // This is a search for a goal
  if (test.goal!=INVALID_ADDRESS) {
    ASSERT_TRUE(wp_wrapper(*global_ds, test.start, test.goal))
                << "Could not find expected path using WP!";
  }
  else if (test.bad!=INVALID_ADDRESS) {
    ASSERT_FALSE(wp_wrapper(*global_ds, test.start, test.bad))
                << "Found invalid path using WP!";
  }
}

// End parameterized test cases for path finding
// -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

static int pathanalyzer_test_wp_main(int argc, char **argv) {

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

  configure_tests(pa, ovm);

  ::testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}

int main(int argc, char **argv) {
  return pharos_main("WPTE", pathanalyzer_test_wp_main, argc, argv, STDERR_FILENO);
}


/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */

