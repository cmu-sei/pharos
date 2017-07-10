# In order to make static builds, set PHAROS_STATIC to true.
# In order to make release or debug builds, set CMAKE_BUILD_TYPE to Release or Debug.
# In order to change the install prefix, set CMAKE_INSTALL_PREFIX.

# User customizations can be placed in this directory in a file named "local.cmake".

cmake_minimum_required(VERSION 3.5)

project(pharos CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
  "Debug" "Release" "RelWithDebInfo" "MinSizeRel")

include(AddCXXCompilerFlags)
add_cxx_compiler_flags(-Wall -Wextra -Wshadow -Wstrict-aliasing)

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH true)

# Load the user's customizations, then the site customization, then
# the local customization.  This lets the local customization take
# precedence over site when setting cache variables, and when setting
# non-cache variables.
include("${CMAKE_CURRENT_SOURCE_DIR}/local.cmake" OPTIONAL)
include("${CMAKE_CURRENT_SOURCE_DIR}/site.cmake" OPTIONAL)
include("${CMAKE_CURRENT_SOURCE_DIR}/local.cmake" OPTIONAL)

set(ROSE_ROOT  "" CACHE PATH "The root directory of the ROSE library")
set(BOOST_ROOT "" CACHE PATH "The root directory of the Boost installation")
set(YICES_ROOT  "" CACHE PATH "The root directory of the YICES library")
set(XSB_ROOT  "" CACHE PATH "The root directory of the XSB installation")
set(XSB_ARCH  "x86_64-unknown-linux-gnu" CACHE STRING
  "The architecture of the XSB installation")
set(yaml-cpp_ROOT "" CACHE PATH "The root directory of the yaml-cpp installation")
set(PHAROS_STATIC false CACHE BOOL "Whether to build statically")

message("-- Using Build Type: ${CMAKE_BUILD_TYPE}")


set(CMAKE_CXX_EXTENSIONS off)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED on)
set(THREADS_PREFER_PTHREAD_FLAG on)

if(PHAROS_STATIC)
  set(ROSE_STATIC true)
  set(CRYPTOPP_STATIC true)
  set(SQLITE_STATIC true)
  set(YICES_STATIC true)
  set(Boost_USE_STATIC_LIBS true)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Xlinker -zmuldefs")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(PHAROS_RELEASE true)
endif()


# Rose
find_package(Rose REQUIRED)

# Find git
find_package(Git)

# Global testing parameters
enable_testing()
add_subdirectory(tests)
set(PHAROS_TEST_OPS --no-site-file --no-user-file ${TESTCONFIG_SWITCH})
set(CTEST_TEST_TIMEOUT 300)     # 5 minutes

# Add pod building
include(BuildPharosPod)

# Add directories
add_subdirectory(libpharos)
add_subdirectory(tools)
add_subdirectory(gtest)
add_subdirectory(prolog)
add_subdirectory(apidb)
add_subdirectory(typedb)

install(DIRECTORY configs DESTINATION share/pharos)
install(FILES README.md COPYRIGHT.md LICENSE.md DESTINATION share/doc/pharos
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
