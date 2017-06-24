link_libraries(pharos)
add_executable(fn2yara fn2yara.cpp)
install(TARGETS fn2yara DESTINATION bin)
