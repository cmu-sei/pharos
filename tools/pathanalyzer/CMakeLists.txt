add_executable(pathanalyzer pathanalyzer.cpp)
target_link_libraries(pathanalyzer pharos)

# Removed as install target due to its experimental nature
#install(TARGETS pathanalyzer DESTINATION bin)

add_executable(pathfinder pathfinder.cpp)
target_link_libraries(pathfinder pharos)

# Removed as install target due to its experimental nature
#install(TARGETS pathfinder DESTINATION bin)

add_executable(merge_test merge_test.cpp)
target_link_libraries(merge_test pharos gtest)

add_executable(znode_test znode_test.cpp)
target_link_libraries(znode_test pharos gtest)

add_executable(pathanalyzer_test pathanalyzer_test.cpp)
target_link_libraries(pathanalyzer_test pharos)

build_pharos_pod(pathanalyzer-man pathanalyzer.pod 1)

add_subdirectory(tests)

add_test(NAME znode_test COMMAND znode_test ${PHAROS_TEST_OPS})
