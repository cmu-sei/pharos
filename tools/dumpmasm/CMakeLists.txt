link_libraries(pharos)
add_executable(dumpmasm dumpmasm.cpp)
install(TARGETS dumpmasm DESTINATION bin)

# Tests

file(GLOB_RECURSE DUMPMASM_PART2PREV RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "*.part2prev")

foreach(previous ${DUMPMASM_PART2PREV})
  get_filename_component(basename "${previous}" NAME_WE)
  get_filename_component(reldir "${previous}" DIRECTORY)


  string(REPLACE "tests/" "" tgt_name "${reldir}/${basename}")
  string(REPLACE "/" "_" und_name "${tgt_name}")

  add_test(NAME "partitioner_test_${und_name}"
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/tests/partitioner-test.py"
    "--build-dir" ${CMAKE_BINARY_DIR} "--git-dir" ${CMAKE_SOURCE_DIR} "${tgt_name}"
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
    set_tests_properties("partitioner_test_${und_name}" PROPERTIES LABELS partitioner)
endforeach()
