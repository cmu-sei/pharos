# This file is the site.cmake for the public release 
# It provides hints about what needs to be set to build Pharos

# Specify the paths to important packages.
set(ROSE_ROOT  "/usr/local"
  CACHE PATH "The root directory of the ROSE library")
set(BOOST_ROOT "/usr/local"
  CACHE PATH "The root directory of the Boost installation")
set(yaml-cpp_ROOT "/usr/local"
  CACHE PATH "The root directory of the yaml-cpp installation")

if(NOT PHAROS_BUILD_XSB)
  set(XSB_ROOT  "/usr/local/xsb-3.7.0"
    CACHE PATH "The root directory of the XSB installation")
  set(XSB_ARCH  "x86_64-unknown-linux-gnu"
    CACHE PATH "The architecture of the XSB installation")
endif()

# Our flags for normal and debug builds
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O1 -g -Wno-misleading-indentation")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -ggdb3 -Wno-misleading-indentation")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -s -Wno-misleading-indentation")
set(CMAKE_CXX_FLAGS "-O3 -s -Wno-misleading-indentation")

# Optional (if you want stack tracebacks during debugging)
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -rdynamic")

set(PHAROS_STATIC false CACHE BOOL "Whether to build statically")
