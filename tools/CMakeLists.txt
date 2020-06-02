add_subdirectory(apianalyzer)
add_subdirectory(dumpmasm)
add_subdirectory(fn2hash)
add_subdirectory(fn2yara)
add_subdirectory(callanalyzer)
add_subdirectory(ooanalyzer)
add_subdirectory(pathanalyzer)
add_subdirectory(apilookup)
add_subdirectory(misc)

# This file being in this directory allows binaries in subdirectories to find the proper
# library files
configure_file(pharos.yaml.in etc/pharos.yaml)
