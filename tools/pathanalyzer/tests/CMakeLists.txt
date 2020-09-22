set(ALL_TESTS
  args_v1
  assert_test_v1
  assert_test_v2
  assert_test_v3
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
  exception
  exclusive_ite
  exclusive_ite_goal_in_else
  explosive_conditions_v1
  fishyxml_v1
  fishyxml_v2
  fishyxml_v3
  func_array
  global_var_v1
  global_var_v2
  global_var_v3
  independent_ite
  independent_ite_param
  input_inside_bound_loop_v1
  input_inside_bound_loop_v2
  input_inside_bound_loop_v3
  input_inside_bound_loop_v4
  input_inside_bound_loop_v5
  input_inside_bound_loop_v6
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
  outlaw_v1
  outlaw_v2
  outlaw_v3
  outlaw_v4
  pointer_write
  recurse_v1
  recurse_v2
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
  stress_both
  stress_deep
  stress_wide
  switch_v1
  switch_v2
  switch_v3
  switch_v4
  switch_v5
  unbound_loop_with_var
  unused_params_v1
  unused_params_v2
  up_and_down_v1
  varargs
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

# SEAHORN approach
set(SEAHORN_FAILING_TESTS
  # Because no one else includes this test.
  func_array
  # This makes it a little easier to manage the lists in CMake. Don't remove.
  fake_failed_test
  )

set(FS_PASSING_TESTS ${ALL_TESTS})
set(WP_PASSING_TESTS ${ALL_TESTS})
set(SPACER_PASSING_TESTS ${ALL_TESTS})
set(SEAHORN_PASSING_TESTS ${ALL_TESTS})
list(REMOVE_ITEM FS_PASSING_TESTS ${FS_FAILING_TESTS})
list(REMOVE_ITEM WP_PASSING_TESTS ${WP_FAILING_TESTS})
list(REMOVE_ITEM SPACER_PASSING_TESTS ${SPACER_FAILING_TESTS})
list(REMOVE_ITEM SEAHORN_PASSING_TESTS ${SEAHORN_FAILING_TESTS})

set(PATHANALYZER_TEST_DIR "${CMAKE_SOURCE_DIR}/tests/pathanalyzer")

# Set PATHTEST_CXX_FLAGS to configure compilation flags for the test
# programs.  For example, try one or more of: -fomit-frame-pointer,
# -fno-inline-small-functions, -O1, -O2, -O3, -Os, -Og, etc.
set(PATHTEST_CXX_FLAGS "-O1" CACHE STRING "Compile options for pathanalyzer tests")
mark_as_advanced(PATHTEST_CXX_FLAGS)
string(TOUPPER "${CMAKE_BUILD_TYPE}" _buildtype)
set("CMAKE_CXX_FLAGS_${_buildtype}" "${PATHTEST_CXX_FLAGS}")

# Set PATHTEST_CROSS32BIT
set(PATHTEST_CROSS32BIT FALSE CACHE BOOL "Compile 32-bit pathanalyzer test programs")
mark_as_advanced(PATHTEST_CROSS32BIT)

# Set PATHTEST_TIMEOUT_SECS
set(PATHTEST_TIMEOUT_SECS 120 CACHE STRING "Timeout in seconds for pathanalyzer tests")
mark_as_advanced(PATHTEST_TIMEOUT_SECS)

set(PATHTEST_SEAHORN_SCRIPT "" CACHE FILEPATH "Path to seahorn/ghidrall test script")
mark_as_advanced(PATHTEST_SEAHORN_SCRIPT)

foreach(test ${ALL_TESTS})
  add_executable(${test}_64 EXCLUDE_FROM_ALL ${test}.cpp)
  target_link_libraries(${test}_64 api_library_64 dummy_library_64)
  list(APPEND ALL_64BIT_TESTS ${test}_64)
  if (PATHTEST_CROSS32BIT)
    add_executable(${test}_32 EXCLUDE_FROM_ALL ${test}.cpp)
    target_link_libraries(${test}_32 api_library_32 dummy_library_32)
    list(APPEND ALL_32BIT_TESTS ${test}_32)
    set_target_properties(${test}_32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
  endif()
endforeach()

add_custom_target(pathanalyzer_tests DEPENDS ${ALL_64BIT_TESTS} ${ALL_32BIT_TESTS})

# API dummy import library
add_library(dummy_library_64 SHARED dummy.cpp)
if (PATHTEST_CROSS32BIT)
  add_library(dummy_library_32 SHARED dummy.cpp)
  set_target_properties(dummy_library_32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()

# Real API library
add_library(api_library_64 STATIC apis.cpp)
if (PATHTEST_CROSS32BIT)
  add_library(api_library_32 STATIC apis.cpp)
  set_target_properties(api_library_32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()

add_dependencies(built_tests pathanalyzer_tests)

include(CMakeDependentOption)
cmake_dependent_option(PHAROS_RUN_PATHANALYZER_TESTS
  "Run pathanalyzer tests (experimental)" ON
  "PHAROS_BUILD_TESTS" OFF)
mark_as_advanced(PHAROS_RUN_PATHANALYZER_TESTS)

if (PHAROS_RUN_PATHANALYZER_TESTS)
  set(flavors "goal,64,--allow-64bit" "nongoal,64,--allow-64bit")
  if (PATHTEST_CROSS32BIT)
    list(APPEND flavors "goal,32" "nongoal,32")
  endif()
  foreach(flavor ${flavors})
    string(REPLACE "," ";" flavor "${flavor}")
    list(GET flavor 0 type)
    list(GET flavor 1 bits)
    list(LENGTH flavor len)
    if(len GREATER 2)
      list(GET flavor 2 args)
    else()
      set(args)
    endif()
    set(SEAHORN_GOAL)
    if (type STREQUAL "nongoal")
      set(SEAHORN_GOAL "--nongoal")
    endif()
    foreach(test ${SPACER_PASSING_TESTS})
      add_test(NAME pathanalyzer_spacer_${test}_${type}_${bits}
               COMMAND pathanalyzer_test --method=spacer --no-semantics ${args}
               --smt-file=${test}_spacer_${type}_${bits}.smt --${type}
               --seed=42 ${PHAROS_TEST_OPS} ${test}_${bits})
      set_tests_properties (pathanalyzer_spacer_${test}_${type}_${bits}
        PROPERTIES TIMEOUT ${PATHTEST_TIMEOUT_SECS}
        ENVIRONMENT "PHAROS_PASS_EXCEPTIONS=1" LABELS
        "pathanalyzer;pathanalyzer_${type};pathanalyzer_spacer;pathanalyzer_spacer_${type}")
    endforeach()
    foreach(test ${WP_PASSING_TESTS})
      add_test(NAME pathanalyzer_wp_${test}_${type}_${bits}
               COMMAND pathanalyzer_test --method=wp --no-semantics ${args}
               --smt-file=${test}_wp_${type}_${bits}.smt --${type}
               --seed=42 ${PHAROS_TEST_OPS} ${test}_${bits})
      set_tests_properties (pathanalyzer_wp_${test}_${type}_${bits}
        PROPERTIES TIMEOUT ${PATHTEST_TIMEOUT_SECS}
        ENVIRONMENT "PHAROS_PASS_EXCEPTIONS=1" LABELS
        "pathanalyzer;pathanalyzer_${type};pathanalyzer_wp;pathanalyzer_wp_${type}")
    endforeach()
    foreach(test ${FS_PASSING_TESTS})
      add_test(NAME pathanalyzer_fs_${test}_${type}_${bits}
               COMMAND pathanalyzer_test --method=fs --no-semantics ${args}
               --smt-file=${test}_fs_${type}_${bits}.smt --${type}
               --seed=42 ${PHAROS_TEST_OPS} ${test}_${bits})
      set_tests_properties (pathanalyzer_fs_${test}_${type}_${bits}
        PROPERTIES TIMEOUT ${PATHTEST_TIMEOUT_SECS}
        ENVIRONMENT "PHAROS_PASS_EXCEPTIONS=1" LABELS
        "pathanalyzer;pathanalyzer_${type};pathanalyzer_fs;pathanalyzer_fs_${type}")
    endforeach()
    if (PATHTEST_SEAHORN_SCRIPT)
      foreach(test ${SEAHORN_PASSING_TESTS})
        add_test(NAME pathanalyzer_sea_${test}_${type}_${bits}
          COMMAND "${PATHTEST_SEAHORN_SCRIPT}"
          --solver=chc --locals=byte_addressable ${SEAHORN_GOAL} --optimization=3
          --llvm-file=${test}_sea_${type}_${bits}.ll ${test}_${bits}
          --capture=${test}_sea_${type}_${bits}.output)
        set_tests_properties (pathanalyzer_sea_${test}_${type}_${bits}
          PROPERTIES TIMEOUT ${PATHTEST_TIMEOUT_SECS}
          LABELS "pathanalyzer;pathanalyzer_${type};pathanalyzer_sea;pathanalyzer_sea_${type}")
      endforeach()
    endif()
  endforeach()
endif()

# Local Variables:
# mode: cmake
# End:
