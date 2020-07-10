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
