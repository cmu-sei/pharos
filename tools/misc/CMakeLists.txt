add_executable(mkir mkir.cpp)
target_link_libraries(mkir pharos)
install(TARGETS mkir DESTINATION bin)
build_pharos_pod(mkir-man mkir.pod 1)

configure_file(prolog_test.hh.in prolog_test.hh)
configure_file(prolog_test.P prolog_test.P COPYONLY)
add_executable(prolog_test prolog_test.cpp)
target_include_directories(prolog_test PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(prolog_test pharos)

add_executable(partition partition.cpp)
target_link_libraries(partition pharos)
install(TARGETS partition DESTINATION bin)

# Adjusting thunk recognition tests.  There are two specimens, one per word size, because the
# calling conventions differ: AMD64 passes the object pointer in a register, i386 on the stack.
# thunktests picks its case table from the specimen's architecture.
add_executable(thunktests thunktests.cpp)
target_link_libraries(thunktests pharos gtest)
add_test(NAME thunktests_test COMMAND thunktests ${PHAROS_TEST_OPS}
  --allow-64bit "${CMAKE_SOURCE_DIR}/tests/itanium_thunks.exe")
set_tests_properties(thunktests_test PROPERTIES LABELS thunktests)
add_test(NAME thunktests_x86_test COMMAND thunktests ${PHAROS_TEST_OPS}
  --base-address=0x400000 "${CMAKE_SOURCE_DIR}/tests/x86_thunks.exe")
set_tests_properties(thunktests_x86_test PROPERTIES LABELS thunktests)
