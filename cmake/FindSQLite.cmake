set(_SQLITE_SEARCHES)

# Search SQLITE_ROOT first if it is set
if(SQLITE_ROOT)
  set(_SQLITE_SEARCH_ROOT PATHS ${SQLITE_ROOT} NO_DEFAULT_PATH)
  list(APPEND _SQLITE_SEARCHES _SQLITE_SEARCH_ROOT)
endif()

if(SQLITE_STATIC)
  set(SQLITE_NAMES libsqlite3.a)
elseif(SQLITE_DYNAMIC)
  set(SQLITE_NAMES libsqlite3.so)
else()
  set(SQLITE_NAMES sqlite3)
endif()

# Normal search.
set(_SQLITE_SEARCH_NORMAL)
list(APPEND _SQLITE_SEARCHES _SQLITE_SEARCH_NORMAL)

foreach(search ${_SQLITE_SEARCHES})
  find_path(SQLITE_INCLUDE_DIR NAMES sqlite3.h ${${search}}
    PATH_SUFFIXES sqlite sqlite3)
endforeach()

if(NOT SQLITE_LIBRARY)
  foreach(search ${_SQLITE_SEARCHES})
    find_library(SQLITE_LIBRARY NAMES ${SQLITE_NAMES} ${${search}} PATH_SUFFIXES lib)
  endforeach()
endif()

unset(SQLITE_NAMES)

mark_as_advanced(SQLITE_LIBRARY SQLITE_INCLUDE_DIR)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SQLITE DEFAULT_MSG
  SQLITE_INCLUDE_DIR SQLITE_LIBRARY)

if(SQLITE_FOUND)
  set(SQLITE_INCLUDE_DIRS ${SQLITE_INCLUDE_DIR})

  if(NOT SQLITE_LIBRARIES)
    set(SQLITE_LIBRARIES ${SQLITE_LIBRARY})
  endif()

  if(NOT TARGET SQLite::SQLite)
    add_library(SQLite::SQLite UNKNOWN IMPORTED)
    set_target_properties(SQLite::SQLite PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${SQLITE_INCLUDE_DIRS}"
      IMPORTED_LOCATION "${SQLITE_LIBRARY}")
  endif()
endif()
