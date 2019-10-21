// Copyright 2018-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "pathanalyzer_test_config.hpp"
#include <libpharos/spacer.hpp>

using namespace pharos;

const DescriptorSet* global_ds = nullptr;

// -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
// Instantiate tests with parameters read from the configuration file
INSTANTIATE_TEST_CASE_P(PathAnalyzerTestParameters, PATestFixture,
                        ::testing::ValuesIn(test_config),
                        PATestFixture::PrintToStringParamName());

// -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
// Start parameterized test cases for path finding

bool fs_method(PATestConfiguration& test, rose_addr_t target, std::shared_ptr<std::ofstream> smt) {
  // This path finder is automatic. It should be automatically recycled per test to avoid
  // cross-test contamination
  PathFinder path_finder(*global_ds);
  // Turn on the saving of Z3 output.
  path_finder.save_z3_output();

  path_finder.find_path(test.start, target);

  // Now actually save the Z3 output?
  if (smt)
    *smt << path_finder.get_z3_output();

  return path_finder.path_found();
  //OINFO << "Z3 representation:\n" << path_finder.get_z3_output();
}

// Shared by wp and spacer.
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

bool wp_method(PATestConfiguration& test, rose_addr_t target, std::shared_ptr<std::ofstream> smt) {

  using namespace pharos::ir;

  IR ir = get_inlined_cfg (CG::get_cg (*global_ds), test.start, target);
  IRExprPtr post;
  ir = rewrite_imported_calls (*global_ds, ir, get_imports());
  ir = init_stackpointer (ir);
  std::tie (ir, post) = add_reached_postcondition (ir, {target});

  //std::cout << ir << std::endl;

  IRExprPtr wp = expand_lets (wp_cfg (ir, post));

  PharosZ3Solver solver;
  solver.memoization (false);
  solver.insert (wp);
  solver.z3Update ();

  assert (solver.z3Assertions ().size () == 1);
  //std::cout << "Z3 WP: " << *solver.z3Solver() << std::endl;
  //std::cout << "Calling Z3...." << std::endl;

  bool result = (solver.check() == Rose::BinaryAnalysis::SmtSolver::Satisfiable::SAT_YES);

  if (smt)
    *smt << *solver.z3Solver();

  // Save the contents of the solver (This was the WP way of doing it.
  //if (smt_file != "") {
  //  std::ofstream smt_stream(smt_file.c_str());
  //  smt_stream << ";; --- Z3 Start\n"
  //             << *solver.z3Solver()
  //             << ";; --- End\n"
  //    // convenience functions for checking the z3 model in output
  //             << "(check-sat)\n"
  //             << "(get-model)";
  //  smt_stream.close();
  //}

  return result;
}

bool spacer_method(PATestConfiguration& test, rose_addr_t target, std::shared_ptr<std::ofstream> smt) {

  using namespace pharos::ir;

  PharosZ3Solver z3;
  // The timeout doesn't seem to be doing anything, and is inconsistent with other tests.
  //z3.set_timeout(10000);
  if (test.seed != 0) {
    z3.set_seed(test.seed);
  }

  SpacerAnalyzer sa(*global_ds, z3, get_imports(), "spacer");

  auto result = sa.find_path_hierarchical (test.start, target);
  bool zresult = std::get<0> (result) == z3::sat;

#if 0
  boost::optional<z3::expr> answer = std::get<1> (result);
  if (answer) {
    std::cout << "Answer: " << *answer << std::endl;
  }
#endif

  if (smt)
    *smt << sa.to_string();

  return zresult;
}

TEST_P(PATestFixture, TestWP) {

  PATestConfiguration test = GetParam();

  if (test.name=="" || test.start==INVALID_ADDRESS || test.bad==INVALID_ADDRESS ||
      (test.goal==INVALID_ADDRESS && test.bad==INVALID_ADDRESS)) {
    // Rather than fail gracefully here, we want to abort so that's it's easier to
    // differentiate cases where compilation optimized away the path_nongoal() test.
    //FAIL() << "Improper configuration!";
    abort();
    return;
  }

  std::function<bool(PATestConfiguration&, rose_addr_t, std::shared_ptr<std::ofstream>)> method_func;

  if (test.method == "fs") method_func = fs_method;
  else if (test.method == "wp") method_func = wp_method;
  else if (test.method == "spacer") method_func = spacer_method;
  else {
    FAIL() << "Unrecognized method '" << test.method << "'.";
    return;
  }

  // Run the goal test (reachable goal is expected to be satisfiable).
  std::shared_ptr<std::ofstream> smt_stream;
  if (test.goal_smt_file != "") {
    smt_stream = make_unique<std::ofstream> (test.goal_smt_file);
  }

  bool goal_result = true;
  if (test.goal!=INVALID_ADDRESS) {
    auto timer = make_timer();
    try {
      goal_result = method_func(test, test.goal, smt_stream);
    }
    catch (const std::exception &e) {
      OERROR << "Exception thrown: " << e.what () << LEND;
      throw;
    }
    catch (const z3::exception &e) {
      OERROR << "Z3 exception thrown: " << e.msg () << LEND;
      // Re-throw as std exception so google test can print it
      throw std::runtime_error (std::string ("Z3: ") + e.msg ());
    }
    timer.stop();
    if (goal_result) {
      OINFO << "Correctly found path to goal in " << timer << " seconds." << LEND;
    }
    else {
      OERROR << "Could not find path to goal in " << timer << " seconds." << LEND;
    }
  }

  if (smt_stream) {
    smt_stream->close();
  }

  if (test.nongoal_smt_file != "") {
    smt_stream = make_unique<std::ofstream>(test.nongoal_smt_file);
  }

  // Run the nongoal test (unreachable goal is expected to not be satisfiable).
  bool nongoal_result = false;
  if (test.bad!=INVALID_ADDRESS) {
    auto timer = make_timer();
    nongoal_result = method_func(test, test.bad, smt_stream);
    timer.stop();
    if (nongoal_result) {
      OERROR << "Found invalid path to nongoal in " << timer << " seconds." << LEND;
    }
    else {
      OINFO << "Path to nongoal was correctly unsatisfiable in " << timer << " seconds." << LEND;
    }
  }

  if (smt_stream) {
    smt_stream->close();
  }

  bool result = goal_result && !nongoal_result;

  // This is a search for a goal
  ASSERT_TRUE(result) << "Compound test failed!";
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

  configure_tests(pa, ovm);

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
