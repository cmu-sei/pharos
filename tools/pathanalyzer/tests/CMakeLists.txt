set(ALL_TESTS
  bound_loop_with_var
  call_trace_v1
  call_trace_v2
  call_trace_v3
  call_trace_v4
  call_trace_v5
  call_trace_v6
  compound_condition_param_v1
  compound_condition_param_v2
  compound_condition_v1
  compound_condition_v2
  compound_condition_v3
  condcall_v1
  condcall_v2
  down_call_chain
  empty
  endless_loop
  exclusive_ite
  exclusive_ite_goal_in_else
  func_array
  global_var_v1
  global_var_v2
  global_var_v3
  independent_ite
  independent_ite_param
  input_inside_bound_loop
  input_inside_bound_loop_mod
  inter_func_narrow_to_wide_constraint
  inter_func_param
  inter_func_wide_to_narrow_constraint
  inter_rv
  linear_flow
  loop_even_odd
  multi_call_inter_cond
  multi_call_inter_cond_else
  multi_call_inter_seq
  multiple_ite
  multivar_compound_condition_v1
  multivar_compound_condition_v2
  nested_condition_v1
  nested_condition_v2
  nested_condition_v3
  nested_condition_v4
  nested_ite_condition_param_v1
  nested_ite_condition_param_v2
  nested_ite_condition_v1
  nested_ite_condition_v2
  nested_loop
  oo_simple
  oo_virtual_func
  pointer_write
  rv_cond
  rv_same_var
  rv_seq_v1
  rv_seq_v2
  rv_seq_v3
  single_condition_param_v1
  single_condition_param_v2
  single_condition_v1
  single_condition_v2
  strcmp
  unbound_loop_with_var
  up_and_down_v1
  var_values
  var_values_param
  recurse_v1
  recurse_v2
  explosive_conditions_v1 
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
  # strcmp
  # We don't support register variables?
  # var_values
  # Pharos control flow graph incomplete for indirect calls.
  func_array
  # Reasons?
  # loop_even_odd
  # Began failing when we added a second iteration to loop.
  # bound_loop_with_var
  # This makes it a little easier to manage the lists in CMake. Don't remove.
  fake_failed_test
  )

# Weakest precondition approach
set(WP_FAILING_TESTS
  # Fails because loops are not unrolled
  # strcmp
  # loop_even_odd
  # bound_loop_with_var
  # IR does not support indirect calls
  func_array
  # Times out because modulus is hard
  # input_inside_bound_loop_mod
  # This makes it a little easier to manage the lists in CMake. Don't remove.
  fake_failed_test
  )

# SPACER approach
set(SPACER_FAILING_TESTS
  # IR does not support indirect calls
  func_array
  # Times out because modulus is hard
  # input_inside_bound_loop_mod
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
  add_executable(${test}_64 EXCLUDE_FROM_ALL ${test}.cpp)
    list(APPEND ALL_64BIT_TESTS ${test}_64)
  if (CROSS32BIT)
    add_executable(${test}_32 EXCLUDE_FROM_ALL ${test}.cpp)
    list(APPEND ALL_32BIT_TESTS ${test}_32)
    set_target_properties(${test}_32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
  endif()
endforeach()

add_custom_target(pathanalyzer_tests DEPENDS ${ALL_64BIT_TESTS} ${ALL_32BIT_TESTS})

add_dependencies(tests pathanalyzer_tests)

set(PHAROS_RUN_PATHANALYZER_TESTS "" CACHE BOOL "Run pathanalyzer tests (experimental)")
mark_as_advanced(PHAROS_RUN_PATHANALYZER_TESTS)
if (PHAROS_RUN_PATHANALYZER_TESTS)
  foreach(test ${SPACER_PASSING_TESTS})
    add_test(NAME pathanalyzer_spacer_${test}_64
      COMMAND pathanalyzer_test --method=spacer --no-semantics --allow-64bit
              --goal-smt=${test}_goal_spacer_64.smt
              --nongoal-smt=${test}_nongoal_spacer_64.smt
              --seed=42 ${PHAROS_TEST_OPS} ${test}_64)
    set_tests_properties (pathanalyzer_spacer_${test}_64
      PROPERTIES TIMEOUT ${TIMEOUT_SECS} LABELS pathanalyzer)
    if (CROSS32BIT)
      add_test(NAME pathanalyzer_spacer_${test}_32
        COMMAND pathanalyzer_test --method=spacer --no-semantics
                --goal-smt=${test}_goal_spacer_32.smt
                --nongoal-smt=${test}_nongoal_spacer_32.smt
                --seed=42 ${PHAROS_TEST_OPS} ${test}_32)
      set_tests_properties (pathanalyzer_spacer_${test}_32
        PROPERTIES TIMEOUT ${TIMEOUT_SECS} LABELS pathanalyzer)
    endif()
  endforeach()

  foreach(test ${WP_PASSING_TESTS})
    add_test(NAME pathanalyzer_wp_${test}_64
      COMMAND pathanalyzer_test --method=wp --no-semantics --allow-64bit
              --goal-smt=${test}_goal_wp_64.smt
              --nongoal-smt=${test}_nongoal_wp_64.smt
              --seed=42 ${PHAROS_TEST_OPS} ${test}_64)
    set_tests_properties (pathanalyzer_wp_${test}_64
      PROPERTIES TIMEOUT ${TIMEOUT_SECS} LABELS pathanalyzer)
    if (CROSS32BIT)
      add_test(NAME pathanalyzer_wp_${test}_32
        COMMAND pathanalyzer_test --method=wp --no-semantics
                --goal-smt=${test}_goal_wp_32.smt
                --nongoal-smt=${test}_nongoal_wp_32.smt
                --seed=42 ${PHAROS_TEST_OPS} ${test}_32)
      set_tests_properties (pathanalyzer_wp_${test}_32
        PROPERTIES TIMEOUT ${TIMEOUT_SECS} LABELS pathanalyzer)
    endif()
  endforeach()

  foreach(test ${FS_PASSING_TESTS})
    add_test(NAME pathanalyzer_fs_${test}_64
      COMMAND pathanalyzer_test --method=fs --no-semantics --allow-64bit
              --propagate-conditions --maximum-nodes-per-condition=500000
              --goal-smt=${test}_goal_fs_64.smt
              --nongoal-smt=${test}_nongoal_fs_64.smt
              --seed=42 ${PHAROS_TEST_OPS} ${test}_64)
    set_tests_properties (pathanalyzer_fs_${test}_64
      PROPERTIES TIMEOUT ${TIMEOUT_SECS} LABELS pathanalyzer)
    if (CROSS32BIT)
      add_test(NAME pathanalyzer_fs_${test}_32
        COMMAND pathanalyzer_test --method=fs --no-semantics
                --propagate-conditions --maximum-nodes-per-condition=500000
                --goal-smt=${test}_goal_fs_32.smt
                --nongoal-smt=${test}_nongoal_fs_32.smt
                --seed=42 ${PHAROS_TEST_OPS} ${test}_32)
      set_tests_properties (pathanalyzer_fs_${test}_32
        PROPERTIES TIMEOUT ${TIMEOUT_SECS} LABELS pathanalyzer)
    endif()
  endforeach()
endif()
