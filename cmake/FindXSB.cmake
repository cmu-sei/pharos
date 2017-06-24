set(_XSB_SEARCHES)

if(XSB_TAG)
  set(_XSB_TAG "-${XSB_TAG}")
else()
  set(_XSB_TAG "${XSB_TAG}")
endif()

# Search XSB_ROOT first if it is set
if(XSB_ROOT)
  set(_XSB_SEARCH_ROOT PATHS ${XSB_ROOT} NO_DEFAULT_PATH)
  list(APPEND _XSB_SEARCHES _XSB_SEARCH_ROOT)
endif()

foreach(search ${_XSB_SEARCHES})
  find_path(XSB_EMU_DIR NAMES cinterf.h ${${search}} PATH_SUFFIXES emu)
  find_path(XSB_CONFIG_DIR NAMES xsb_config.h ${${search}}
    PATH_SUFFIXES "config/${XSB_ARCH}${_XSB_TAG}")
  find_program(XSB_PROGRAM NAMES "xsb${_XSB_TAG}" ${${search}} PATH_SUFFIXES bin)
endforeach()

if(NOT XSB_OBJ)
  find_file(XSB_OBJ NAMES xsb.o PATHS ${XSB_CONFIG_DIR}
    NO_DEFAULT_PATH PATH_SUFFIXES saved.o)
endif()

get_filename_component(XSB_BIN ${XSB_PROGRAM} DIRECTORY)
get_filename_component(XSB_BIN ${XSB_BIN} REALPATH)
get_filename_component(_XSB_INSTALL_DIR ${XSB_BIN} DIRECTORY)
set(XSB_INSTALL_DIR ${_XSB_INSTALL_DIR} CACHE PATH "Path to XSB install directory")

mark_as_advanced(XSB_OBJ XSB_EMU_DIR XSB_CONFIG_DIR XSB_PROGRAM XSB_INSTALL_DIR)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(XSB DEFAULT_MSG
  XSB_EMU_DIR XSB_CONFIG_DIR XSB_OBJ)

if(XSB_FOUND)
  set(XSB_INCLUDE_DIRS ${XSB_EMU_DIR} ${XSB_CONFIG_DIR})
  include(CheckTypeSize)
  set(CMAKE_REQUIRED_INCLUDES ${XSB_INCLUDE_DIRS})
  set(CMAKE_EXTRA_INCLUDE_FILES cinterf.h)
  check_type_size(prolog_int PINT_SIZE LANGUAGE CXX)
  check_type_size(prolog_term PTERM_SIZE LANGUAGE CXX)
  unset(CMAKE_REQUIRED_INCLUDES)
  unset(CMAKE_EXTRA_INCLUDE_FILES)
  if (NOT PINT_SIZE OR NOT PTERM_SIZE)
    message(FATAL_ERROR "Could not determine prolog sizes")
  endif()
  math(EXPR PINT_BIT_SIZE "${PINT_SIZE} * 8")
  math(EXPR PTERM_BIT_SIZE "${PTERM_SIZE} * 8")
  set(XSB_PINT_TYPE "std::int${PINT_BIT_SIZE}_t")
  set(XSB_PTERM_TYPE "std::uint${PTERM_BIT_SIZE}_t")
endif()

