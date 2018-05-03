link_libraries(pharos)
add_executable(callanalyzer callanalyzer.cpp)
install(TARGETS callanalyzer DESTINATION bin)
build_pharos_pod(callanalyzer-man callanalyzer.pod 1)
