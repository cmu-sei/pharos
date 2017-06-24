link_libraries(pharos)
add_executable(objdigger objdigger.cpp)
install(TARGETS objdigger DESTINATION bin)
install(PROGRAMS ida/PyObjdigger.py DESTINATION bin)

# Everything below this line is for running the tests

file(GLOB OBJDIGGER_DEBUG_PREVIOUS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  "tests/*/Debug/*.previous")
file(GLOB OBJDIGGER_RELEASE_PREVIOUS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  "tests/*/Release/*.previous")
file(GLOB OBJDIGGER_LITE_PREVIOUS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  "tests/*/Lite/*.previous")

set(OBJDIGGER_TEST_PREVIOUS ${OBJDIGGER_DEBUG_PREVIOUS} ${OBJDIGGER_LITE_PREVIOUS})

foreach(previous ${OBJDIGGER_TEST_PREVIOUS})
  get_filename_component(basename "${previous}" NAME_WE)
  get_filename_component(reldir "${previous}" DIRECTORY)

  string(REPLACE "tests/" "" tgt_name "${reldir}/${basename}")
  string(REPLACE "/" "_" und_name ${tgt_name})

  add_test(NAME "objdigger_test_${und_name}"
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/ooanalyzer-test.py
    "--build-dir" ${CMAKE_BINARY_DIR} "--git-dir" ${CMAKE_SOURCE_DIR} ${tgt_name}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
  set_tests_properties("objdigger_test_${und_name}" PROPERTIES LABELS objdigger)

  add_test(NAME "objprolog_test_${und_name}"
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/ooanalyzer-test.py
    "--build-dir" ${CMAKE_BINARY_DIR} "--git-dir" ${CMAKE_SOURCE_DIR}
    "--xsb-path" "${XSB_PROGRAM}" -p ${tgt_name}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
  set_tests_properties("objprolog_test_${und_name}" PROPERTIES LABELS objprolog)

endforeach()

# Set test costs for tests that take longer to run.
# This should make these tests run earlier
set_property(TEST objdigger_test_ooex_vs2010_Lite_ooex7 PROPERTY COST 201.11)
set_property(TEST objdigger_test_ooex_vs2010_Lite_oo    PROPERTY COST 139.44)
set_property(TEST objdigger_test_ooex_vs2010_Lite_poly  PROPERTY COST 136.94)
set_property(TEST objprolog_test_ooex_vs2010_Lite_ooex7 PROPERTY COST 8.57)
set_property(TEST objprolog_test_ooex_vs2010_Lite_oo    PROPERTY COST 8.78)
set_property(TEST objprolog_test_ooex_vs2010_Lite_poly  PROPERTY COST 18.17)
