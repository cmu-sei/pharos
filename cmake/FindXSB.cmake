get_property(_xsb_once GLOBAL PROPERTY XSB_ONCE)
if (_xsb_once)
  get_property(XSB_PINT_TYPE TARGET XSB::XSB PROPERTY PINT_TYPE)
  get_property(XSB_PTERM_TYPE TARGET XSB::XSB PROPERTY PTERM_TYPE)
  get_property(XSB_INSTALL_DIR TARGET XSB::XSB PROPERTY INSTALL_DIR)
  return()
endif()

macro(_fxsb_message arg)
  set(arg "${arg}")
  if(NOT XSB_FIND_QUIETLY OR arg STREQUAL "FATAL_ERROR")
    if (arg STREQUAL "DEBUG")
      if (XSB_DEBUG)
        message(STATUS ${ARGN})
      endif()
    else()
      message("${arg}" ${ARGN})
    endif()
  endif()
endmacro(_fxsb_message)

_fxsb_message(STATUS "Finding XSB")
set(XSB_ROOT "" CACHE PATH "The root directory of the XSB installation")

cmake_policy(SET CMP0057 NEW)

macro(_fxsb_subdirs result curdir)
  set(_dirs)
  get_filename_component(curdir "${curdir}" REALPATH)
  FILE(GLOB children RELATIVE "${curdir}" "${curdir}/*")
  foreach(child ${children})
    get_filename_component(_rdir "${curdir}/${child}" REALPATH)
    if(IS_DIRECTORY "${_rdir}")
      list(APPEND _dirs "${child}")
    endif()
  endforeach()
  set("${result}" "${_dirs}")
endmacro(_fxsb_subdirs)

macro(_fxsb_find_bindirs result curdir)
  set(_result)
  set(_candidates "${curdir}")
  while(_candidates)
    list(GET _candidates 0 _dir)
    list(REMOVE_AT _candidates 0)
    _fxsb_subdirs(_children "${_dir}")
    if("bin" IN_LIST _children)
      list(APPEND _result "${_dir}/bin")
    endif()
    foreach(child ${_children})
      list(APPEND _candidates "${_dir}/${child}")
    endforeach()
  endwhile()
  set("${result}" "${_result}")
endmacro(_fxsb_find_bindirs)

# Try to find the xsb interpreter.  Search within ${XSB_ROOT} if that is set.
set(_fxsb_hints)
if(XSB_ROOT AND (NOT XSB_PROGRAM))
  set(_fxsb_hints HINTS "${XSB_ROOT}/bin")
  _fxsb_find_bindirs(xsb_bin_dirs "${XSB_ROOT}")
  foreach(dir ${xsb_bin_dirs})
    if(EXISTS "${dir}/xsb" AND NOT IS_DIRECTORY "${dir}/xsb")
      list(APPEND _fxsb_hints "${dir}")
    endif()
  endforeach()
endif()
find_program(XSB_PROGRAM xsb ${_fxsb_hints} DOC "XSB executable")

if (XSB_PROGRAM)
  function(_fxsb_query_var var output)
    set(prog "xsb_configuration(${var}, X), writeln(X), halt")
    set(prog "catch(((${prog});true), E, true), halt.")
    execute_process(
      COMMAND "${XSB_PROGRAM}" --noprompt --nobanner --quietload -e "${prog}"
      OUTPUT_VARIABLE out
      RESULT_VARIABLE res)
    if (NOT res EQUAL 0)
      _fxsb_message(FATAL_ERROR "Could not query xsb variable ${var}")
    endif()
    string(REGEX REPLACE "[ \n\t]+$" "" out "${out}")
    set("${output}" ${out} PARENT_SCOPE)
  endfunction(_fxsb_query_var)

  macro(_fxsb_set_vars)
    foreach(var ${ARGN})
      _fxsb_query_var("${var}" result)
      string(TOUPPER "${var}" upper)
      set("XSB_${upper}" "${result}")
      _fxsb_message(DEBUG "XSB_${upper}: ${result}")
    endforeach()
  endmacro(_fxsb_set_vars)

  set(_fxsb_vars emudir config_dir install_dir)
  _fxsb_set_vars(${_fxsb_vars})

  set(XSB_INCLUDE_DIRS "${XSB_CONFIG_DIR}" "${XSB_EMUDIR}" CACHE STRING
    "Include directories for XSB")
  find_file(XSB_OBJECT_FILE xsb.o PATHS "${XSB_CONFIG_DIR}/saved.o" NO_DEFAULT_PATH DOC
    "Location of xsb.o file")
  mark_as_advanced(XSB_INCLUDE_DIRS XSB_OBJECT_FILE)

  _fxsb_message(DEBUG "Checking sizes of prolog_int and prolog_term")
  set(CMAKE_REQUIRED_QUIET true)
  include(CheckTypeSize)
  set(_tmp_CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES})
  set(CMAKE_REQUIRED_INCLUDES ${XSB_INCLUDE_DIRS})
  set(_tmp_CMAKE_EXTRA_INCLUDE_FILES ${CMAKE_EXTRA_INCLUDE_FILES})
  set(CMAKE_EXTRA_INCLUDE_FILES cinterf.h)
  check_type_size(prolog_int PINT_SIZE LANGUAGE CXX)
  check_type_size(prolog_term PTERM_SIZE LANGUAGE CXX)
  set(CMAKE_REQUIRED_INCLUDES ${_tmp_CMAKE_REQUIRED_INCLUDES})
  set(CMAKE_EXTRA_INCLUDE_FILES ${_tmp_CMAKE_EXTRA_INCLUDE_FILES})
  if (NOT PINT_SIZE OR NOT PTERM_SIZE)
    _fxsb_message(FATAL_ERROR "Could not determine XSB prolog sizes")
  endif()
  math(EXPR PINT_BIT_SIZE "${PINT_SIZE} * 8")
  math(EXPR PTERM_BIT_SIZE "${PTERM_SIZE} * 8")
  set(XSB_PINT_TYPE "std::int${PINT_BIT_SIZE}_t")
  set(XSB_PTERM_TYPE "std::uint${PTERM_BIT_SIZE}_t")
  _fxsb_message(DEBUG
    "Checking sizes of prolog_int and prolog_term - ${PINT_SIZE}, ${PTERM_SIZE}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(XSB
   "Could not find XSB Prolog, please set either XSB_PROGRAM or XSB_ROOT\n"
   XSB_PROGRAM XSB_INSTALL_DIR XSB_INCLUDE_DIRS XSB_OBJECT_FILE XSB_PINT_TYPE XSB_PTERM_TYPE)

if(NOT TARGET XSB::XSB)
  add_library(XSB::XSB SHARED IMPORTED GLOBAL)
  define_property(TARGET PROPERTY PINT_TYPE
    BRIEF_DOCS "Type of prolog integer"
    FULL_DOCS "Type of prolog integer")
  define_property(TARGET PROPERTY PTERM_TYPE
    BRIEF_DOCS "Type of prolog term"
    FULL_DOCS "Type of prolog term")
  define_property(TARGET PROPERTY INSTALL_DIR
    BRIEF_DOCS "Location of prolog installation"
    FULL_DOCS "Location of prolog installation")
endif()
set_target_properties(XSB::XSB PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${XSB_INCLUDE_DIRS}"
  IMPORTED_LOCATION "${XSB_OBJECT_FILE}"
  LINKER_LANGUAGE C
  PINT_TYPE "${XSB_PINT_TYPE}"
  PTERM_TYPE "${XSB_PTERM_TYPE}"
  INSTALL_DIR "${XSB_INSTALL_DIR}")

set_property(GLOBAL PROPERTY XSB_ONCE true)
