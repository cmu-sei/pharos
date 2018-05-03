set(Z3_ROOT  "" CACHE PATH "The root directory of the Z3 library")
set(fz3_options Z3 CONFIG)
if (Z3_FIND_REQUIRES)
  set(fz3_options ${fz3_options} REQUIRED)
else()
endif()
if (Z3_ROOT)
  set(fz3_options ${fz3_options} PATHS ${Z3_ROOT} NO_DEFAULT_PATH)
endif()
find_package(${fz3_options})
set(Z3_PREFIX ${PACKAGE_PREFIX_DIR}) # Hack
find_package(PackageHandleStandardArgs)
find_package_handle_standard_args(Z3 CONFIG_MODE)
# Z3 doesn't set the include directories correctl
if (Z3_FOUND)
  set_target_properties(z3::libz3 PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${Z3_CXX_INCLUDE_DIRS}")
endif()
