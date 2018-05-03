find_package(Git REQUIRED)

message("")
message(STATUS "*** Could not locate a usable ROSE library ***")

if(ROSE_ROOT)
  set(ROSE_PREFIX ${ROSE_ROOT})
else()
  set(ROSE_PREFIX ${CMAKE_INSTALL_PREFIX})
endif()
set(ROSE_SOURCE_DIR ${CMAKE_SOURCE_DIR}/rose)
set(ROSE_BUILDROOT ${CMAKE_BINARY_DIR}/subbuild/rose)
set(ROSE_BUILD_DIR ${ROSE_BUILDROOT}/build)

file(MAKE_DIRECTORY ${ROSE_BUILDROOT})
configure_file(${CMAKE_SOURCE_DIR}/cmake/rose-CMakeLists.txt ${ROSE_BUILDROOT}/CMakeLists.txt
  @ONLY)
set(build-filename build-rose.cmake)
set(install-filename install-rose.cmake)

set(file ${CMAKE_BINARY_DIR}/${build-filename})
set(code [=[
set(args)
set(ROSE_ROOT @ROSE_ROOT@)
if(NOT ROSE_ROOT)
  set(ROSE_ROOT @CMAKE_INSTALL_PREFIX@)
endif()
set(args "-DROSE_PREFIX=${ROSE_ROOT}")
set(buildargs)
if(PARALLEL)
  set(buildargs "--" "-j" ${PARALLEL})
endif()
set(BOOST_ROOT @BOOST_ROOT@)
if (BOOST_ROOT)
  list(APPEND args "-DBOOST_ROOT=${BOOST_ROOT}")
endif()
set(YAML_CPP_ROOT @YAML_CPP_ROOT@)
if (YAML_CPP_ROOT)
  list(APPEND args "-DYAML_CPP_ROOT=${YAML_CPP_ROOT}")
endif()
set(Z3_ROOT @Z3_ROOT@)
if (Z3_ROOT)
  list(APPEND args "-DZ3_ROOT=${Z3_ROOT}")
endif()
execute_process(
  COMMAND ${CMAKE_COMMAND} ${args} .
  WORKING_DIRECTORY @ROSE_BUILDROOT@
  RESULT_VARIABLE err)
if(NOT err EQUAL 0)
  message(FATAL_ERROR "Could not set up ROSE build")
endif()
execute_process(
  COMMAND ${CMAKE_COMMAND} --build . --target rose-build-tools ${buildargs}
  WORKING_DIRECTORY @ROSE_BUILDROOT@
  RESULT_VARIABLE err)
if(NOT err EQUAL 0)
  message(FATAL_ERROR "Could not build ROSE")
endif()
message("
***************************************************************************
Rose has successfully built and can now be installed.  You can do this with
the following command:
  ${CMAKE_COMMAND} -P ./@install-filename@
***************************************************************************
")
]=])
string(CONFIGURE "${code}" data @ONLY)
file(WRITE "${file}" "${data}")

set(file ${CMAKE_BINARY_DIR}/${install-filename})
set(code [=[
set(buildargs)
if(PARALLEL)
  set(buildargs "--" "-j" ${PARALLEL})
endif()
execute_process(
  COMMAND @CMAKE_COMMAND@ --build . --target rose-install
  WORKING_DIRECTORY @ROSE_BUILDROOT@
  RESULT_VARIABLE err)
if(NOT err EQUAL 0)
  message(FATAL_ERROR "Could not install rose")
endif()
message("
***************************************************************************
Now you should re-run cmake for the pharos project.  You may need to clean
the build in order to cmake to recognize the new files.   You can do this
by typing:

    rm -rf *

in the cmake build directory, and then re-running cmake, including the
-DROSE_ROOT=<location> option if needed.
***************************************************************************
")
]=])
string(CONFIGURE "${code}" data @ONLY)
file(WRITE "${file}" "${data}")

message("
****************************************************************************
To build rose for an install into ${ROSE_PREFIX}, run the following command:
  ${CMAKE_COMMAND} -P ./${build-filename}

To build for an install into a different location <prefix>, run:
  ${CMAKE_COMMAND} -DROSE_ROOT=<prefix> -P ./${build-filename}
(Don't forget to configure pharos to look for rose in <prefix>
 using -DROSE_ROOT=<prefix> or by setting ROSE_ROOT in the cmake cache.)

If you wish to run a parallel build, pass a -DPARALLEL=<N> option
as well for an N-way build.

After building, you need to install rose, which you can do with the
following command:
  ${CMAKE_COMMAND} -P ./${install-filename}

This step is separate in case you need to install as another user.

After installation, re-run cmake on pharos so it can find the new
rose installation.

****************************************************************************
")
message(FATAL_ERROR "Configuration failed.  Exiting.")
