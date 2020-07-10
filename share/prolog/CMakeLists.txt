find_package(SWIPL REQUIRED)
message(STATUS "Found SWIPL: ${SWIPL_EXECUTABLE} (found version ${SWIPL_VERSION})")
set(SWIPL_PROGRAM "${SWIPL_EXECUTABLE}")

set(PHAROS_OOLOGLEVEL 6 CACHE STRING "Default log level, set to 7 for trace")
mark_as_advanced(PHAROS_OOLOGLEVEL)

add_subdirectory(oorules)
