set(_ROSE_SEARCHES)

find_package(Z3 REQUIRED)

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

set(ROSE_NAMES ${CMAKE_SHARED_LIBRARY_PREFIX}rose${CMAKE_SHARED_LIBRARY_SUFFIX})

# Normal search.
set(_ROSE_SEARCH_NORMAL)
list(APPEND _ROSE_SEARCHES _ROSE_SEARCH_NORMAL)

foreach(search ${_ROSE_SEARCHES})
  find_path(ROSE_INCLUDE_DIR NAMES rose.h ${${search}} PATH_SUFFIXES include/rose)
  if(NOT ROSE_LIBRARY)
    find_library(ROSE_LIBRARY NAMES ${ROSE_NAMES} ${${search}} PATH_SUFFIXES lib)
  endif()
  find_path(SAWYER_INCLUDE_DIR NAMES Sawyer/Sawyer.h ${${search}}
    PATH_SUFFIXES include include/rose)
endforeach()

mark_as_advanced(ROSE_LIBRARY ROSE_INCLUDE_DIR SAWYER_INCLUDE_DIR)

if(ROSE_INCLUDE_DIR)
  file(STRINGS "${ROSE_INCLUDE_DIR}/rosePublicConfig.h" _ver_line
    REGEX "^#define ROSE_PACKAGE_VERSION  *\"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\""
    LIMIT_COUNT 1)
  string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+" ROSE_VERSION "${_ver_line}")
  unset(_ver_line)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Rose
  REQUIRED_VARS ROSE_INCLUDE_DIR SAWYER_INCLUDE_DIR ROSE_LIBRARY
  VERSION_VAR ROSE_VERSION)

if(ROSE_FOUND)

  set(ROSE_INCLUDE_DIRS ${ROSE_INCLUDE_DIR})

  if(NOT ROSE_LIBRARIES)
    set(ROSE_LIBRARIES ${ROSE_LIBRARY})
  endif()

  if(NOT TARGET Rose::Rose)
    add_library(Rose::Rose UNKNOWN IMPORTED)
    set_property(TARGET Rose::Rose PROPERTY INTERFACE_INCLUDE_DIRECTORIES
      ${ROSE_INCLUDE_DIR} ${Z3_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS} ${YamlCpp_INCLUDE_DIR}
      ${SAWYER_INCLUDE_DIR})
    set_property(TARGET Rose::Rose PROPERTY INTERFACE_SYSTEM_INCLUDE_DIRECTORIES
      ${ROSE_INCLUDE_DIR} ${Z3_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS} ${YamlCpp_INCLUDE_DIR}
      ${SAWYER_INCLUDE_DIR})
    set_property(TARGET Rose::Rose PROPERTY IMPORTED_LOCATION ${ROSE_LIBRARY})
    set_property(TARGET Rose::Rose PROPERTY INTERFACE_LINK_LIBRARIES
      ${Boost_LIBRARIES} ${Z3_LIBRARIES}
      ${YamlCpp_LIBRARY} ${CMAKE_DL_LIBS} Threads::Threads)
  endif()
endif()
