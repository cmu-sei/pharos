# Make indempotent
set(_once ${_fxsb_once})
set(_fxsb_once TRUE CACHE BOOL "Idempotency check for FindXSB")
mark_as_advanced(_fxsb_once)

# Cache variables
set(XSB_ROOT "" CACHE PATH "The root directory of the XSB installation")
set(XSB_TAG "" CACHE STRING "XSB configuration tag")
set(XSB_REVISION "" CACHE STRING "Revision of XSB to download, if building from scratch")
set(XSB_REPOSITORY "https://svn.code.sf.net/p/xsb/src/trunk" CACHE STRING
  "SVN repository for xsb")
set(XSB_REPOSITORY_TYPE "SVN" CACHE STRING "Type of repository in XSB_REPOSITORY")
set_property(CACHE XSB_REPOSITORY PROPERTY STRINGS "SVN" "GIT")
mark_as_advanced(XSB_TAG XSB_REVISION XSB_REPOSITORY XSB_REPOSITORY_TYPE)

# Are we making a debug build?
set(_fxsb_debug FALSE)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(_fxsb_debug TRUE)
  if(NOT XSB_TAG)
    set_property(XSB_TAG CACHE PROPERTY VALUE "dbg")
  endif()
endif()

# Default value for XSB_INSTALL_DIR
set(XSB_INSTALL_DIR ${XSB_ROOT})

function(_fxsb_run_code file code output result)
  string(CONFIGURE "${code}" data)
  file(WRITE "${file}" "${data}")
  execute_process(
    COMMAND sh -e "${file}"
    OUTPUT_VARIABLE out
    RESULT_VARIABLE res
    ${ARGN})
  string(REGEX REPLACE "[ \n\t]+$" "" out "${out}")
  set("${output}" ${out} PARENT_SCOPE)
  set("${result}" ${res} PARENT_SCOPE)
endfunction(_fxsb_run_code)

# A function to get the version number from src dir of XSB
function(_fxsb_get_version VAR SRC_DIR)
  message(STATUS "Determining XSB version")
  set(code [=[#!/bin/sh
. ${SRC_DIR}/XSB/build/version.sh
if test -n "$xsb_beta_version" ; then
   echo "$xsb_major_version.$xsb_minor_version-b$xsb_beta_version"
else
   echo "$xsb_major_version.$xsb_minor_version.$xsb_patch_version"
fi
]=])
  _fxsb_run_code("${CMAKE_BINARY_DIR}/get_xsb_version.sh" "${code}" output result)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "Could not determine XSB version")
  endif()
  message(STATUS "Determining XSB version - ${output}")
  set("${VAR}" "${output}" PARENT_SCOPE)
endfunction(_fxsb_get_version)

# A function to determine the config directory name
function(_fxsb_get_arch VAR SRC_DIR)
  message(STATUS "Determining XSB configuration")
  set(code [=[#!/bin/sh
${SRC_DIR}/XSB/build/config.sub `${SRC_DIR}/XSB/build/config.guess`
]=])
  _fxsb_run_code("${CMAKE_BINARY_DIR}/get_xsb_arch.sh" "${code}" output result)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "Could not determine XSB architecture")
  endif()
  if(XSB_TAG)
    set(output "${output}-${XSB_TAG}")
  endif()
  set(${VAR} "${output}" PARENT_SCOPE)
  message(STATUS "Determining XSB configuration - ${output}")
endfunction(_fxsb_get_arch)

set(revision)
if(XSB_REPOSITORY_TYPE STREQUAL SVN)
  if(XSB_REVISION)
    set(revision SVN_REVISION "-r${XSB_REVISION}")
  endif()
elseif(XSB_REPOSITORY_TYPE STREQUAL GIT)
  if(XSB_REVISION)
    set(revision GIT_TAG "${XSB_REVISION}")
  endif()
else()
  message(FATAL_ERROR "Unknown XSB repository type ${XSB_REPOSITORY_TYPE}")
endif()

set(install_dir "${CMAKE_BINARY_DIR}/XSB")
set(source_dir "${CMAKE_BINARY_DIR}/src/XSB")

set(configure_args)
set(make_args)
if(_fxsb_debug)
  set(configure_args "--enable-dwarf-debug" "--disable-optimization")
endif()
if(XSB_TAG)
  set(make_args "--config-tag=${XSB_TAG}")
endif()

set(base_project
  xsb
  EXCLUDE_FROM_ALL 1
  SOURCE_DIR ${source_dir}
  STAMP_DIR ${CMAKE_BINARY_DIR}/xsbstamp
  BUILD_IN_SOURCE 1)
set(configure_project
  ${XSB_REPOSITORY_TYPE}_REPOSITORY ${XSB_REPOSITORY}
  ${revision}
  CONFIGURE_COMMAND cd XSB/build &&
  ./configure ${configure_args} "--prefix=${install_dir}" "CFLAGS=-fPIC"
  STEP_TARGETS configure)
set(build_project
  CONFIGURE_COMMAND "true"
  BUILD_COMMAND cd XSB/build && ./makexsb ${make_args}
  INSTALL_DIR "${install_dir}"
  INSTALL_COMMAND cd XSB/build && ./makexsb ${make_args} install
  STEP_TARGETS install)

set(code [=[
cmake_minimum_required(VERSION "${CMAKE_MINIMUM_REQUIRED_VERSION}")
project(xsb-build)
include(ExternalProject)
ExternalProject_Add(${base_project} ${configure_project})
]=])

set(xsb_project "${CMAKE_BINARY_DIR}/xsb-project")
file(MAKE_DIRECTORY ${xsb_project})
set(script "${xsb_project}/CMakeLists.txt")
string(CONFIGURE "${code}" data)
file(WRITE "${script}" "${data}")

if(NOT _once)
  message(STATUS "Downloading and configuring XSB")
  execute_process(
    COMMAND ${CMAKE_COMMAND} -Wno-dev .
    WORKING_DIRECTORY ${xsb_project}
    RESULT_VARIABLE SCRIPT_ERROR)
  if(NOT SCRIPT_ERROR EQUAL 0)
    message(FATAL_ERROR "Could not configure XSB")
  endif()
  execute_process(
    COMMAND ${CMAKE_COMMAND} --build . --target xsb-configure
    WORKING_DIRECTORY ${xsb_project}
    RESULT_VARIABLE SCRIPT_ERROR)
  if(NOT SCRIPT_ERROR EQUAL 0)
    message(FATAL_ERROR "Could not configure XSB")
  endif()
  message(STATUS "Downloading and configuring XSB - done")

  _fxsb_get_version(version ${source_dir})
  set(XSB_VERSION "${version}")
  set(XSB_INSTALL_DIR "${install_dir}/xsb-${version}")

  _fxsb_get_arch(arch ${source_dir})
  set(XSB_ARCH "" CACHE STRING "The architecture of the XSB installation")
  mark_as_advanced(XSB_ARCH)
  set(XSB_CONFIG_DIR "${XSB_INSTALL_DIR}/config/${arch}")
  set(XSB_SOURCE_CONFIG_DIR "${source_dir}/XSB/config/${arch}")
endif()

if(NOT TARGET xsb-install)
  include(ExternalProject)
  ExternalProject_Add(${base_project} ${build_project})
endif()

set(XSB_INCLUDE_DIRS "${XSB_CONFIG_DIR}" "${XSB_INSTALL_DIR}/emu" CACHE STRING
  "Include directories for XSB")
set(XSB_OBJECT_FILE "${XSB_CONFIG_DIR}/saved.o/xsb.o" CACHE FILEPATH
  "Location of xsb.o file")
mark_as_advanced(XSB_INCLUDE_DIRS XSB_OBJECT_FILE)

add_custom_command(OUTPUT "${XSB_OBJECT_FILE}"
  COMMAND true
  DEPENDS xsb-install)

# mwd: I cannot figure out how to attatch the .o file to the interface
# library proper in suct a way that target_link_libraries will work
# add_library(XSB::cinterf UNKNOWN IMPORTED)
# set_target_properties(XSB::cinterf PROPERTIES
#   INTERFACE_INCLUDE_DIRECTORIES "${XSB_INCLUDE_DIRS}")

set(_xsb_tag)
if(XSB_TAG)
  set(_xsb_tag "-${XSB_TAG}")
endif()

set(XSB_PROGRAM "${XSB_INSTALL_DIR}/bin/xsb${_xsb_tag}" CACHE FILEPATH
  "Location of xsb executable")
set(XSB_INSTALL_DIR ${XSB_INSTALL_DIR} CACHE PATH
  "Path to XSB install directory")
mark_as_advanced(XSB_PROGRAM XSB_INSTALL_DIR)

if(NOT _once)
  message(STATUS "Checking sizes of prolog_int and prolog_term")
  include(CheckTypeSize)
  set(_tmp_CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES})
  set(CMAKE_REQUIRED_INCLUDES "${source_dir}/XSB/emu" ${XSB_SOURCE_CONFIG_DIR})
  set(_tmp_CMAKE_EXTRA_INCLUDE_FILES ${CMAKE_EXTRA_INCLUDE_FILES})
  set(CMAKE_EXTRA_INCLUDE_FILES cinterf.h)
  check_type_size(prolog_int PINT_SIZE LANGUAGE CXX)
  check_type_size(prolog_term PTERM_SIZE LANGUAGE CXX)
  set(CMAKE_REQUIRED_INCLUDES ${_tmp_CMAKE_REQUIRED_INCLUDES})
  set(CMAKE_EXTRA_INCLUDE_FILES ${_tmp_CMAKE_EXTRA_INCLUDE_FILES})
  if (NOT PINT_SIZE OR NOT PTERM_SIZE)
    message(FATAL_ERROR "Could not determine XSB prolog sizes")
  endif()
  math(EXPR PINT_BIT_SIZE "${PINT_SIZE} * 8")
  math(EXPR PTERM_BIT_SIZE "${PTERM_SIZE} * 8")
  set(XSB_PINT_TYPE "std::int${PINT_BIT_SIZE}_t" CACHE STRING "prolog_int integer type")
  set(XSB_PTERM_TYPE "std::uint${PTERM_BIT_SIZE}_t" CACHE STRING "prolog_term integer type")
  mark_as_advanced(XSB_PINT_TYPE XSB_PTERM_TYPE)
  message(STATUS "Checking sizes of prolog_int and prolog_term - ${PINT_SIZE}, ${PTERM_SIZE}")
endif()
