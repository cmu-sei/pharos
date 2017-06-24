link_libraries(pharos)

add_executable(apianalyzer apianalyzer.cpp)
install(TARGETS apianalyzer DESTINATION bin)
install(FILES sig.json DESTINATION share/pharos/apianalyzer
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

#add_executable(apigraphgen apigraphgen.cpp)

set(APIANALYZER_TEST_DIR "${CMAKE_SOURCE_DIR}/tests/ApiAnalyzer")

add_executable(apitests1 apitests1.cpp)
target_link_libraries(apitests1 gtest)
add_test(NAME apitests1_test COMMAND apitests1 ${PHAROS_TEST_OPS}
  "${APIANALYZER_TEST_DIR}/ApiGraphTestProgram1.exe")

add_executable(apitests2 apitests2.cpp)
target_link_libraries(apitests2 gtest)
add_test(NAME apitests2_test COMMAND apitests2 ${PHAROS_TEST_OPS}
  "${APIANALYZER_TEST_DIR}/ApiGraphTestProgram2.exe")


add_executable(apitests3 apitests3.cpp)
target_link_libraries(apitests3 gtest)
add_test(NAME apitests3_test COMMAND apitests3 ${PHAROS_TEST_OPS}
  "${APIANALYZER_TEST_DIR}/ApiGraphTestProgram3.exe"
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(apisigtest apisigtest.cpp)
target_link_libraries(apisigtest gtest)
add_test(NAME apisigtest_test COMMAND apisigtest
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

set_tests_properties(apitests1_test apitests2_test apitests3_test apisigtest_test
  PROPERTIES LABELS apitests)
