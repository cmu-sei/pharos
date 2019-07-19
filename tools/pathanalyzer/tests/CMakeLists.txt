set(ALL_TESTS
  acyclic
  acyclic_nongoal
  bad_diff_func
  bound_loop_with_var
  compound_condition
  compound_condition_param
  compound_condition_param_v2
  compound_condition_v2
  compound_condition_v3
  condcall_one
  condcall_two
  empty
  exclusive_ite
  exclusive_ite_goal_in_else
  func_array_goal
  func_array_nongoal
  goal_diff_func
  global_var
  global_var_updates
  global_var_nongoal
  independent_ite
  independent_ite_param
  input_inside_bound_loop
  inter_func_narrow_to_wide_constraint
  inter_func_param
  inter_func_wide_to_narrow_constraint
  inter_rv
  invalid_compound_condition
  invalid_compound_condition_param
  invalid_compound_condition_v2
  invalid_condition
  invalid_inter_func
  invalid_nested_conditions
  linear_flow
  loop_even_odd
  loop_even_odd_nongoal
  multi_call_inter_cond
  multi_call_inter_cond_else
  multi_call_inter_seq
  multiple_ite
  multivar_compound_condition
  nested_condition
  nested_condition_v2
  nested_condition_v3
  nested_ite_condition
  nested_ite_condition_param
  nested_ite_condition_param_v2
  nested_ite_condition_v2
  nested_loop
  oo_simple_goal
  oo_simple_nongoal
  oo_virtual_func_goal
  oo_virtual_func_nongoal
  param_n_var_conpound_condition
  pointer_write
  pointer_write_nongoal
  rv_cond
  rv_same_var
  rv_seq
  rv_seq_v1
  rv_seq_v2
  seq_call_five
  seq_call_four
  seq_call_one
  seq_call_three
  seq_call_two
  seq_v4
  single_condition
  single_condition_param
  single_condition_param_v2
  single_condition_v2
  strcmp
  strcmp_nongoal
  unbound_loop_with_var
  var_values
  var_values_param
  # This makes it a little easier to manage the lists in CMake. Don't remove.
  fake_failed_test
  )

# Were these tests were split, renamed or just removed?
# invalid_inter_mem2, invalid_inter_mem3, multi_call_inter

# Please document why each test case fails as it's added to the list,
# so that we can keep track of why each test is "expected" to fail.

# Function summary approach
set(FS_FAILING_TESTS
  # We only unroll loops up to five iterations?
  acyclic
  strcmp
  # We don't support register variables?
  var_values
  # Reasons?
  bad_diff_func
  func_array_nongoal
  input_inside_bound_loop
  loop_even_odd
  pointer_write_nongoal
  # Began failing when we added a second iteration to loop.
  bound_loop_with_var
  # This makes it a little easier to manage the lists in CMake. Don't remove.
  fake_failed_test
  )

# Weakest precondition approach
set(WP_FAILING_TESTS
  # Fails because loops are not unrolled
  acyclic
  strcmp
  loop_even_odd
  bound_loop_with_var
  # IR does not support indirect calls
  func_array_nongoal
  # Times out for unknown reason (>90 seconds)
  input_inside_bound_loop
  # This makes it a little easier to manage the lists in CMake. Don't remove.
  fake_failed_test
  )

# SPACER approach
set(SPACER_FAILING_TESTS
  # Times out (>90 seconds).  Upstream problem in SPACER/Z3?  Reported to Arie?
  acyclic_nongoal
  # IR does not support indirect calls
  func_array_nongoal
  # This makes it a little easier to manage the lists in CMake. Don't remove.
  fake_failed_test
  )

set(FS_PASSING_TESTS ${ALL_TESTS})
set(WP_PASSING_TESTS ${ALL_TESTS})
set(SPACER_PASSING_TESTS ${ALL_TESTS})
list(REMOVE_ITEM FS_PASSING_TESTS ${FS_FAILING_TESTS})
list(REMOVE_ITEM WP_PASSING_TESTS ${WP_FAILING_TESTS})
list(REMOVE_ITEM SPACER_PASSING_TESTS ${SPACER_FAILING_TESTS})

set(PATHANALYZER_TEST_DIR "${CMAKE_SOURCE_DIR}/tests/pathanalyzer")

# Set PATHTEST_CXX_FLAGS to configure compilation flags for the test
# programs.  For example, try one or more of: -fomit-frame-pointer,
# -fno-inline-small-functions, -O1, -O2, -O3, -Os, -Og, etc.
set(PATHTEST_CXX_FLAGS "-O1" CACHE STRING "Compile options for pathanalyzer tests")
mark_as_advanced(PATHTEST_CXX_FLAGS)
string(TOUPPER "${CMAKE_BUILD_TYPE}" _buildtype)
set("CMAKE_CXX_FLAGS_${_buildtype}" "${PATHTEST_CXX_FLAGS}")

if(NOT TIMEOUT_SECS)
  set(TIMEOUT_SECS 120)
endif()

foreach(test ${ALL_TESTS})
  add_executable(${test} EXCLUDE_FROM_ALL ${test}.cpp)
  if (CROSS32BIT)
    add_executable(${test}_32 EXCLUDE_FROM_ALL ${test}.cpp)
    list(APPEND ALL_32BIT_TESTS ${test}_32)
    set_target_properties(${test}_32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
  endif()
endforeach()

add_custom_target(pathanalyzer_tests DEPENDS ${ALL_TESTS} ${ALL_32BIT_TESTS})

add_dependencies(tests pathanalyzer_tests)

set(PHAROS_RUN_PATHANALYZER_TESTS false CACHE BOOL "Run pathanalyzer tests (experimental)")
mark_as_advanced(PHAROS_RUN_PATHANALYZER_TESTS)
if (PHAROS_RUN_PATHANALYZER_TESTS)
  foreach(test ${SPACER_PASSING_TESTS})
    add_test(NAME pathanalyzer_spacer_${test}
      COMMAND pathanalyzer_spacer_test --allow-64bit --seed=42 ${PHAROS_TEST_OPS} ${test})
    set_tests_properties (pathanalyzer_spacer_${test}
      PROPERTIES TIMEOUT ${TIMEOUT_SECS} LABELS pathanalyzer)
    if (CROSS32BIT)
      add_test(NAME pathanalyzer_spacer_${test}_32
        COMMAND pathanalyzer_spacer_test --seed=42 ${PHAROS_TEST_OPS} ${test}_32)
      set_tests_properties (pathanalyzer_spacer_${test}_32
        PROPERTIES TIMEOUT ${TIMEOUT_SECS} LABELS pathanalyzer)
    endif()
  endforeach()
  
  foreach(test ${WP_PASSING_TESTS})
    add_test(NAME pathanalyzer_wp_${test}
      COMMAND pathanalyzer_wp_test --allow-64bit --seed=42 ${PHAROS_TEST_OPS} ${test})
    set_tests_properties (pathanalyzer_wp_${test}
      PROPERTIES TIMEOUT ${TIMEOUT_SECS} LABELS pathanalyzer)
    if (CROSS32BIT)
      add_test(NAME pathanalyzer_wp_${test}_32
        COMMAND pathanalyzer_wp_test --seed=42 ${PHAROS_TEST_OPS} ${test}_32)
      set_tests_properties (pathanalyzer_wp_${test}_32
        PROPERTIES TIMEOUT ${TIMEOUT_SECS} LABELS pathanalyzer)
    endif()
  endforeach()
  
  foreach(test ${FS_PASSING_TESTS})
    add_test(NAME pathanalyzer_fs_${test}
      COMMAND pathanalyzer_test --allow-64bit --seed=42 ${PHAROS_TEST_OPS} ${test})
    set_tests_properties (pathanalyzer_fs_${test}
      PROPERTIES TIMEOUT ${TIMEOUT_SECS} LABELS pathanalyzer)
    if (CROSS32BIT)
      add_test(NAME pathanalyzer_fs_${test}_32
        COMMAND pathanalyzer_test --seed=42 ${PHAROS_TEST_OPS} ${test}_32)
      set_tests_properties (pathanalyzer_fs_${test}_32
        PROPERTIES TIMEOUT ${TIMEOUT_SECS} LABELS pathanalyzer)
    endif()
  endforeach()
endif()
