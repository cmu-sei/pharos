link_libraries(pharos)
add_executable(fn2hash fn2hash.cpp)
install(TARGETS fn2hash DESTINATION bin)
install(PROGRAMS fse.py DESTINATION bin)
