# In order to make release or debug builds, set CMAKE_BUILD_TYPE to Release or Debug.
# In order to change the install prefix, set CMAKE_INSTALL_PREFIX.

# User customizations can be placed in this directory in a file named "local.cmake".

cmake_minimum_required(VERSION 3.5)

# <Package>_ROOT variables are now added to the path by default.  We
# were explicitly using our _ROOT variables for this purpose, so the
# "NEW" policy should be fine, although we might want to revisit
# whether we should be doing things differently under the new policy.
if(POLICY CMP0074)
  cmake_policy(SET CMP0074 NEW)
endif()

# Handle option without warnings in newer cmake
if(POLICY CMP0077)
  cmake_policy(SET CMP0077 NEW)
endif()

project(pharos CXX C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
  "Debug" "Release" "RelWithDebInfo" "MinSizeRel")

include(AddCXXCompilerFlags)
add_cxx_compiler_flags(-pedantic -pedantic-errors -Wall -Wextra -Wshadow -Wstrict-aliasing -Wno-misleading-indentation "-ftemplate-depth=1024" "-ftrack-macro-expansion=0")

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH true)
set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")
set(BUILD_SHARED_LIBS true)

# Load the user's customizations, then the site customization, then
# the local customization.  This lets the local customization take
# precedence over site when setting cache variables, and when setting
# non-cache variables.
include("${CMAKE_CURRENT_SOURCE_DIR}/local.cmake" OPTIONAL)
include("${CMAKE_CURRENT_SOURCE_DIR}/site.cmake" OPTIONAL)
include("${CMAKE_CURRENT_SOURCE_DIR}/local.cmake" OPTIONAL)

set(ROSE_ROOT  "" CACHE PATH "The root directory of the ROSE library")
set(BOOST_ROOT "" CACHE PATH "The root directory of the Boost installation")
set(Z3_ROOT  "" CACHE PATH "The root directory of the Z3 installation")
set(YamlCpp_ROOT "" CACHE PATH "The root directory of the yaml-cpp installation")

include("${CMAKE_CURRENT_SOURCE_DIR}/site.cmake" OPTIONAL)
include("${CMAKE_CURRENT_SOURCE_DIR}/local.cmake" OPTIONAL)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

message(STATUS "Using Build Type: ${CMAKE_BUILD_TYPE}")

set(CMAKE_CXX_EXTENSIONS off)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED on)
set(THREADS_PREFER_PTHREAD_FLAG on)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(PHAROS_RELEASE true)
endif()

# Rose

# Anyone modifying this version should also manually modify libpharos/version.hpp.in.  They
# should set the PHAROS_ROSE_MINIMUM_VERSION variable to match.
set(PHAROS_ROSE_MINIMUM_VERSION 0.11.39.6)

find_package(Rose ${PHAROS_ROSE_MINIMUM_VERSION} REQUIRED)

# Find git
find_package(Git REQUIRED)

# Global testing parameters
enable_testing()
add_subdirectory(tests)
set(PHAROS_TEST_OPS --no-site-file --no-user-file ${TESTCONFIG_SWITCH})
set(CTEST_TEST_TIMEOUT 300)     # 5 minutes

# Add pod building
include(BuildPharosPod)

# Turn on or off the building of executables that are used as inputs to the testing process.
# Most of our tests run on pre-built executables that are comitted in the repository and do not
# require building.  Having this variable be off will disable any tests that depend on the
# non-prebuilt test programs.
option(PHAROS_BUILD_TESTS "Builds optional test files" OFF)
mark_as_advanced(PHAROS_BUILD_TESTS)
if (PHAROS_BUILD_TESTS)
  add_custom_target(built_tests ALL)
else()
  add_custom_target(built_tests)
endif()

option(PHAROS_BROKEN_THREADS "Turns off multi-threding and mutexes" OFF)
if(PHAROS_BROKEN_THREADS)
  add_definitions(-DPHAROS_BROKEN_THREADS)
endif()

# Add gtests
add_subdirectory(gtest)

option(PHAROS_FAIL_ON_WARNING "Cause compilation to fail if a warning is generated" OFF)
if(PHAROS_FAIL_ON_WARNING)
  add_cxx_compiler_flags(-Werror)
endif()

# Add directories
add_subdirectory(libpharos)
add_subdirectory(tools)
add_subdirectory(share)

install(FILES README.md CONTRIBUTING.md LICENSE.md INSTALL.md DESTINATION share/doc/pharos
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
