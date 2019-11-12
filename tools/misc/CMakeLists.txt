add_executable(mkir mkir.cpp)
target_link_libraries(mkir pharos)
install(TARGETS mkir DESTINATION bin)
build_pharos_pod(mkir-man mkir.pod 1)
