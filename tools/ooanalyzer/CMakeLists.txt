link_libraries(pharos)
add_executable(ooanalyzer ooanalyzer.cpp)
install(TARGETS ooanalyzer DESTINATION bin)
install(PROGRAMS ida/OOAnalyzer.py DESTINATION bin)
build_pharos_pod(ooanalyzer-man ooanalyzer.pod 1)
build_pharos_pod(ooanalyzer-plugin-man ooanalyzer-plugin.pod 1)

# Everything below this line is for running the tests

file(GLOB OOANALYZER_DEBUG_PREVIOUS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  "tests/*/Debug/*.results")
file(GLOB OOANALYZER_RELEASE_PREVIOUS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  "tests/*/Release/*.results")
file(GLOB OOANALYZER_LITE_PREVIOUS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  "tests/*/Lite/*.results")

set(OOANALYZER_TEST_PREVIOUS ${OOANALYZER_DEBUG_PREVIOUS} ${OOANALYZER_LITE_PREVIOUS})

find_package(XSB REQUIRED)

foreach(previous ${OOANALYZER_TEST_PREVIOUS})
  get_filename_component(basename "${previous}" NAME_WE)
  get_filename_component(reldir "${previous}" DIRECTORY)

  string(REPLACE "tests/" "" tgt_name "${reldir}/${basename}")
  string(REPLACE "/" "_" und_name ${tgt_name})

  add_test(NAME "ooanalyzer_test_${und_name}"
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/ooanalyzer-test.py
    "--build-dir" ${CMAKE_BINARY_DIR} "--git-dir" ${CMAKE_SOURCE_DIR} ${tgt_name}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
  set_tests_properties("ooanalyzer_test_${und_name}" PROPERTIES LABELS ooanalyzer)

  add_test(NAME "ooprolog_test_${und_name}"
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/ooanalyzer-test.py
    "--build-dir" ${CMAKE_BINARY_DIR} "--git-dir" ${CMAKE_SOURCE_DIR}
    "--xsb-path" "${XSB_PROGRAM}" -v -p ${tgt_name}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
  set_tests_properties("ooprolog_test_${und_name}" PROPERTIES LABELS ooprolog)

endforeach()

# Set test costs for tests that take longer to run.
# This should make these tests run earlier
set_property(TEST ooanalyzer_test_ooex_vs2010_Lite_ooex7 PROPERTY COST 201.11)
set_property(TEST ooanalyzer_test_ooex_vs2010_Lite_oo    PROPERTY COST 139.44)
set_property(TEST ooanalyzer_test_ooex_vs2010_Lite_poly  PROPERTY COST 136.94)
set_property(TEST ooprolog_test_ooex_vs2010_Lite_ooex7   PROPERTY COST 8.57)
set_property(TEST ooprolog_test_ooex_vs2010_Lite_oo      PROPERTY COST 8.78)
set_property(TEST ooprolog_test_ooex_vs2010_Lite_poly    PROPERTY COST 18.17)
