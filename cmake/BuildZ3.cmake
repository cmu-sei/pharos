find_package(Git REQUIRED)

message("")
message(STATUS "*** Could not locate a usable Z3 library ***")

if(Z3_ROOT)
  set(Z3_PREFIX ${Z3_ROOT})
else()
  set(Z3_PREFIX ${CMAKE_INSTALL_PREFIX})
endif()
set(Z3_SOURCE_DIR ${CMAKE_SOURCE_DIR}/z3)
set(Z3_BUILDROOT ${CMAKE_BINARY_DIR}/subbuild/z3)
set(Z3_BUILD_DIR ${Z3_BUILDROOT}/build)
file(MAKE_DIRECTORY ${Z3_BUILDROOT})
configure_file(${CMAKE_SOURCE_DIR}/cmake/z3-CMakeLists.txt ${Z3_BUILDROOT}/CMakeLists.txt
  @ONLY)
set(build-filename build-z3.cmake)
set(install-filename install-z3.cmake)

set(file ${CMAKE_BINARY_DIR}/${build-filename})
set(code [=[
set(args)
set(Z3_ROOT @Z3_ROOT@)
if(NOT Z3_ROOT)
  set(Z3_ROOT @CMAKE_INSTALL_PREFIX@)
endif()
set(args "-DZ3_PREFIX=${Z3_ROOT}")
set(buildargs)
if(PARALLEL)
  set(buildargs "--" "-j" ${PARALLEL})
endif()
execute_process(
  COMMAND @CMAKE_COMMAND@ ${args} .
  WORKING_DIRECTORY @Z3_BUILDROOT@
  RESULT_VARIABLE err)
if(NOT err EQUAL 0)
  message(FATAL_ERROR "Could not set up Z3 build")
endif()
execute_process(
  COMMAND @CMAKE_COMMAND@ --build . --target z3-build ${buildargs}
  WORKING_DIRECTORY @Z3_BUILDROOT@
  RESULT_VARIABLE err)
if(NOT err EQUAL 0)
  message(FATAL_ERROR "Could not build Z3")
endif()
message("
***************************************************************************
Z3 has successfully built and can now be installed.  You can do this with
the following command:
  ${CMAKE_COMMAND} -P ./@install-filename@
***************************************************************************
")
]=])
string(CONFIGURE "${code}" data @ONLY)
file(WRITE "${file}" "${data}")

set(file ${CMAKE_BINARY_DIR}/${install-filename})
set(code [=[
execute_process(
  COMMAND @CMAKE_COMMAND@ --build . --target z3-install
  WORKING_DIRECTORY @Z3_BUILDROOT@
  RESULT_VARIABLE err)
if(NOT err EQUAL 0)
  message(FATAL_ERROR "Could not install Z3")
endif()
message("
***************************************************************************
Now you should re-run cmake for the pharos project.  You may need to clean
the build in order to cmake to recognize the new files.   You can do this
by typing:

    rm -rf *

in the cmake build directory, and then re-running cmake, including the
-DZ3_ROOT=<location> option if needed.
***************************************************************************
")
]=])
string(CONFIGURE "${code}" data @ONLY)
file(WRITE "${file}" "${data}")

message("
************************************************************************
To build z3 for an install into ${Z3_ROOT}, run the following command:
  ${CMAKE_COMMAND} -P ./${build-filename}

To build for an install into a different location <prefix>, run:
  ${CMAKE_COMMAND} -DZ3_ROOT=<prefix> -P ./${build-filename}
(Don't forget to configure pharos to look for z3 in <prefix>
 using -DZ3_ROOT=<prefix> or by setting Z3_ROOT in the cmake cache.)

If you wish to run a parallel build, pass a -DPARALLEL=<N> option
as well for an N-way build.

After building, you need to install z3, which you can do with the
following command:
  ${CMAKE_COMMAND} -P ./${install-filename}

This step is separate in case you need to install as another user.

After installation, re-run cmake on pharos so it can find the new
z3 installation.

************************************************************************
")
message(FATAL_ERROR "Configuration failed.  Exiting.")

