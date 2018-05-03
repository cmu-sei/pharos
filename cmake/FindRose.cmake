set(_ROSE_SEARCHES)

find_package(Z3)
if (NOT Z3_FOUND)
  include(BuildZ3)
  message(FATAL_ERROR "Should not get here")
endif()
if (Z3_VERSION AND (Z3_VERSION VERSION_LESS 4.6))
  message(WARNING "Foud Z3 version ${Z3_VERSION}, needed 4.6")
  include(BuildZ3)
endif()

set(Boost_USE_MULTITHREADED on)
find_package(Boost 1.60.0 REQUIRED
  COMPONENTS system thread program_options iostreams filesystem regex wave)
if (NOT Boost_FOUND OR (Boost_VERSION LESS 1.60))
  message(FATAL_ERROR "Could not find a usable version of boost")
endif()

find_package(YamlCpp 0.6 REQUIRED)

find_package(Threads)

# Search ROSE_ROOT first if it is set
if(ROSE_ROOT)
  set(_ROSE_SEARCH_ROOT PATHS ${ROSE_ROOT} NO_DEFAULT_PATH)
  list(APPEND _ROSE_SEARCHES _ROSE_SEARCH_ROOT)
endif()

set(ROSE_NAMES librose.so)

# Normal search.
set(_ROSE_SEARCH_NORMAL)
list(APPEND _ROSE_SEARCHES _ROSE_SEARCH_NORMAL)

foreach(search ${_ROSE_SEARCHES})
  find_path(ROSE_INCLUDE_DIR NAMES rose.h ${${search}} PATH_SUFFIXES include/rose)
  if(NOT ROSE_LIBRARY)
    find_library(ROSE_LIBRARY NAMES ${ROSE_NAMES} ${${search}} PATH_SUFFIXES lib)
  endif()
  find_program(ROSE_CONFIG NAMES rose-config ${${search}} PATH_SUFFIXES bin)
endforeach()

set(ROSE_VERSION)
if(ROSE_CONFIG)
  execute_process(
    COMMAND ${ROSE_CONFIG} -V
    ERROR_VARIABLE out
    RESULT_VARIABLE res)
  if (NOT res EQUAL 0)
    message(FATAL_ERROR "Cannot run ${ROSE_CONFIG} -V")
  endif()
  string(REGEX REPLACE "[ \n\t]+$" "" ROSE_VERSION "${out}")
endif()

mark_as_advanced(ROSE_LIBRARY ROSE_INCLUDE_DIR ROSE_CONFIG)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ROSE
  VERSION_VAR ROSE_VERSION
  REQUIRED_VARS ROSE_INCLUDE_DIR ROSE_LIBRARY)

if(ROSE_FOUND)

  set(ROSE_INCLUDE_DIRS ${ROSE_INCLUDE_DIR})

  if(NOT ROSE_LIBRARIES)
    set(ROSE_LIBRARIES ${ROSE_LIBRARY})
  endif()

  if(NOT TARGET Rose::Rose)
    add_library(Rose::Rose UNKNOWN IMPORTED)
    set_property(TARGET Rose::Rose PROPERTY INTERFACE_INCLUDE_DIRECTORIES
      ${ROSE_INCLUDE_DIR} ${Z3_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS} ${YAML_CPP_INCLUDE_DIR})
    set_property(TARGET Rose::Rose PROPERTY INTERFACE_SYSTEM_INCLUDE_DIRECTORIES
      ${ROSE_INCLUDE_DIR} ${Z3_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS} ${YAML_CPP_INCLUDE_DIR})
    set_property(TARGET Rose::Rose PROPERTY IMPORTED_LOCATION ${ROSE_LIBRARY})
    set_property(TARGET Rose::Rose PROPERTY INTERFACE_LINK_LIBRARIES
      ${ROSE_STATIC_LIBS} ${Boost_LIBRARIES} ${Z3_LIBRARIES}
      ${YAML_CPP_LIBRARY} ${CMAKE_DL_LIBS} Threads::Threads)
  endif()
endif()
