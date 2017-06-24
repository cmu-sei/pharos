set(_ROSE_SEARCHES)

find_package(Yices)

set(Boost_USE_MULTITHREADED on)
find_package(Boost 1.60.0 REQUIRED
  COMPONENTS system thread program_options iostreams filesystem regex wave)

find_package(yaml-cpp 0.5.3 PATHS ${yaml-cpp_ROOT}
  NO_DEFAULT_PATH PATH_SUFFIXES lib/cmake cmake)
find_package(yaml-cpp 0.5.3 REQUIRED PATH_SUFFIXES lib/cmake cmake)

find_package(Threads)

# Search ROSE_ROOT first if it is set
if(ROSE_ROOT)
  set(_ROSE_SEARCH_ROOT PATHS ${ROSE_ROOT} NO_DEFAULT_PATH)
  list(APPEND _ROSE_SEARCHES _ROSE_SEARCH_ROOT)
endif()

if(ROSE_STATIC)
  set(ROSE_NAMES librose.a)
elseif(ROSE_DYNAMIC)
  set(ROSE_NAMES librose.so)
else()
  set(ROSE_NAMES rose)
endif()

# Normal search.
set(_ROSE_SEARCH_NORMAL)
list(APPEND _ROSE_SEARCH _ROSE_SEARCH_NORMAL)

foreach(search ${_ROSE_SEARCHES})
  find_path(ROSE_INCLUDE_DIR NAMES rose.h ${${search}} PATH_SUFFIXES include/rose)
endforeach()

if(NOT ROSE_LIBRARY)
  foreach(search ${_ROSE_SEARCHES})
    find_library(ROSE_LIBRARY NAMES ${ROSE_NAMES} ${${search}} PATH_SUFFIXES lib)
  endforeach()
endif()

if(ROSE_STATIC)
  foreach(search ${_ROSE_SEARCHES})
    find_library(ROSE_HPDF_LIBRARY NAMES libhpdf.a ${${search}} PATH_SUFFIXES lib)
  endforeach()
  find_library(ROSE_GCRYPT_LIBRARY NAMES libgcrypt.a)
  find_library(ROSE_GPGERROR_LIBRARY NAMES libgpg-error.a)
  set(ROSE_STATIC_LIBS ${ROSE_GCRYPT_LIBRARY} ${ROSE_GPGERROR_LIBRARY} ${ROSE_HPDF_LIBRARY})
  set(_ROSE_STATIC_LIB_VARS ROSE_GCRYPT_LIBRARY ROSE_GPGERROR_LIBRARY ROSE_HPDF_LIBRARY)
endif()

unset(ROSE_NAMES)

mark_as_advanced(ROSE_LIBRARY ROSE_INCLUDE_DIR)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ROSE DEFAULT_MSG
  ROSE_INCLUDE_DIR ROSE_LIBRARY ${_ROSE_STATIC_LIB_VARS})

if(ROSE_FOUND)
  set(ROSE_INCLUDE_DIRS ${ROSE_INCLUDE_DIR})

  if(NOT ROSE_LIBRARIES)
    set(ROSE_LIBRARIES ${ROSE_LIBRARY})
  endif()

  if(NOT TARGET Rose::Rose)
    add_library(Rose::Rose UNKNOWN IMPORTED)
    set_property(TARGET Rose::Rose PROPERTY INTERFACE_INCLUDE_DIRECTORIES
      ${ROSE_INCLUDE_DIR} ${YICES_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS} ${YAML_CPP_INCLUDE_DIR})
    set_property(TARGET Rose::Rose PROPERTY INTERFACE_SYSTEM_INCLUDE_DIRECTORIES
      ${ROSE_INCLUDE_DIR} ${YICES_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS} ${YAML_CPP_INCLUDE_DIR})
    set_property(TARGET Rose::Rose PROPERTY IMPORTED_LOCATION ${ROSE_LIBRARY})
    set_property(TARGET Rose::Rose PROPERTY INTERFACE_LINK_LIBRARIES
      ${ROSE_STATIC_LIBS} ${Boost_LIBRARIES} ${YICES_LIBRARIES}
      ${YAML_CPP_LIBRARIES} ${CMAKE_DL_LIBS} Threads::Threads)
  endif()
endif()
