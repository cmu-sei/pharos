add_executable(apilookup apilookup.cpp)
target_link_libraries(apilookup pharos)
install(TARGETS apilookup DESTINATION bin)
build_pharos_pod(apilookup-man apilookup.pod 1)
