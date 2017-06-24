set(_YICES_SEARCHES)

# Search YICES_ROOT first if it is set
if(YICES_ROOT)
  set(_YICES_SEARCH_ROOT PATHS ${YICES_ROOT} NO_DEFAULT_PATH)
  list(APPEND _YICES_SEARCHES _YICES_SEARCH_ROOT)
endif()

if(YICES_STATIC)
  set(YICES_NAMES libyices.a)
elseif(YICES_DYNAMIC)
  set(YICES_NAMES libyices.so)
else()
  set(YICES_NAMES yices)
endif()

# Normal search.
set(_YICES_SEARCH_NORMAL)
list(APPEND _YICES_SEARCHES _YICES_SEARCH_NORMAL)

foreach(search ${_YICES_SEARCHES})
  find_path(YICES_INCLUDE_DIR NAMES yices_c.h ${${search}} PATH_SUFFIXES include)
endforeach()

if(NOT YICES_LIBRARY)
  foreach(search ${_YICES_SEARCHES})
    find_library(YICES_LIBRARY NAMES ${YICES_NAMES} ${${search}} PATH_SUFFIXES lib)
  endforeach()
endif()

unset(YICES_NAMES)

mark_as_advanced(YICES_LIBRARY YICES_INCLUDE_DIR)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(YICES DEFAULT_MSG
  YICES_INCLUDE_DIR YICES_LIBRARY)

if(YICES_FOUND)
  set(YICES_INCLUDE_DIRS ${YICES_INCLUDE_DIR})

  if(NOT YICES_LIBRARIES)
    set(YICES_LIBRARIES ${YICES_LIBRARY})
  endif()

  if(NOT TARGET Yices::Yices)
    add_library(Yices::Yices UNKNOWN IMPORTED)
    set_target_properties(Yices::Yices PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${YICES_INCLUDE_DIRS}"
      INTERFACE_LINK_LIBRARIES m
      IMPORTED_LOCATION "${YICES_LIBRARY}")
  endif()
endif()
