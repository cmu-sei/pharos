# pharos library sources
set(PHAROS_SOURCES
  apidb.cpp
  apigraph.cpp
  apisig.cpp
  calls.cpp
  cdg.cpp
  class.cpp
  config.cpp
  convention.cpp
  defuse.cpp
  demangle.cpp
  descriptors.cpp
  funcs.cpp
  globals.cpp
  imports.cpp
  jsonoo.cpp
  limit.cpp
  masm.cpp
  md5.cpp
  member.cpp
  method.cpp
  misc.cpp
  ooanalyzer.cpp
  oosolver.cpp
  options.cpp
  partitioner.cpp
  pdg.cpp
  prolog.cpp
  prologimpl.cpp
  revision.cpp
  riscops.cpp
  semantics.cpp
  sptrack.cpp
  state.cpp
  stkvar.cpp
  typedb.cpp
  types.cpp
  usage.cpp
  util.cpp
  vcall.cpp
  vftable.cpp
  xsb.cpp
  PHAROS_REVISION.ii
  config.yaml.ii
  )

# Packages needed by libpharos
find_package(XSB REQUIRED)
find_package(SQLite REQUIRED)
set(CURSES_NEED_NCURSES true)
find_package(Curses REQUIRED)
find_package(Threads)

set(Boost_USE_MULTITHREADED on)
find_package(Boost 1.60.0 REQUIRED
  COMPONENTS system chrono timer)

configure_file(xsb_types.hpp.in xsb_types.hpp)
configure_file(build.hpp.in build.hpp)

# Create pharos library
add_library(pharos STATIC ${PHAROS_SOURCES} ${XSB_OBJ})
target_link_libraries(pharos PUBLIC Threads::Threads Boost::chrono Boost::timer)
target_link_libraries(pharos INTERFACE
  Rose::Rose SQLite::SQLite ${CURSES_LIBRARIES})
# XSB include dirs
target_include_directories(pharos PRIVATE ${XSB_INCLUDE_DIRS})
# curses and Rose include dirs
target_include_directories(pharos SYSTEM PUBLIC
  ${CURSES_INCLUDE_DIRS}
  $<TARGET_PROPERTY:Rose::Rose,INTERFACE_INCLUDE_DIRECTORIES>)
# Set this directory as an include for targets that use the pharos library
target_include_directories(pharos INTERFACE
  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
  $<INSTALL_INTERFACE:include/libpharos>)
# Generated include files
target_include_directories(pharos PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
  $<INSTALL_INTERFACE:include/libpharos>)

# install target
install(TARGETS pharos EXPORT libpharos DESTINATION lib)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} DESTINATION include
  FILES_MATCHING PATTERN "*.hpp")
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} DESTINATION include
  FILES_MATCHING PATTERN "*.hpp")
install(EXPORT libpharos DESTINATION lib/cmake/libpharos
  EXPORT_LINK_INTERFACE_LIBRARIES)

# Create config.yaml
configure_file(config.yaml.in config.yaml)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/config.yaml"
  DESTINATION etc
  RENAME pharos.yaml)

# Generate PHAROS_REVISION in every build
add_custom_target(generate_pharos_revision ALL)
add_custom_command(
  TARGET generate_pharos_revision
  COMMAND ${CMAKE_COMMAND} -P "${CMAKE_CURRENT_SOURCE_DIR}/make_pharos_revision.cmake"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  BYPRODUCTS PHAROS_REVISION)
add_dependencies(pharos generate_pharos_revision)
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES PHAROS_REVISION)

# Copy PHAROS_REVISION to PHAROS_REVISION.ii if changed
add_custom_command(
  OUTPUT PHAROS_REVISION.ii
  COMMAND ${CMAKE_COMMAND} -E copy_if_different PHAROS_REVISION PHAROS_REVISION.ii
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  MAIN_DEPENDENCY PHAROS_REVISION)
set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/PHAROS_REVISION.ii"
  PROPERTIES HEADER_FILE_ONLY true)

# Generate config.yaml.ii from config.yaml
add_custom_command(
  OUTPUT config.yaml.ii
  COMMAND xxd -i config.yaml > "${CMAKE_CURRENT_BINARY_DIR}/config.yaml.ii"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  MAIN_DEPENDENCY "${CMAKE_CURRENT_BINARY_DIR}/config.yaml")
set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/config.yaml.ii"
  PROPERTIES HEADER_FILE_ONLY true)
