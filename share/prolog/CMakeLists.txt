find_package(SWIPL REQUIRED)
message(STATUS "Found SWIPL: ${SWIPL_EXECUTABLE} (found version ${SWIPL_VERSION})")
set(SWIPL_PROGRAM "${SWIPL_EXECUTABLE}")

add_subdirectory(oorules)
