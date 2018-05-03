link_libraries(pharos)
add_executable(fn2yara fn2yara.cpp)
install(TARGETS fn2yara DESTINATION bin)
build_pharos_pod(fn2yara-man fn2yara.pod 1)
