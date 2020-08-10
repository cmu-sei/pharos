set(PROLOG_FILES setup.pl progress_oosolver.pl report.pl util.pl validate.pl oojson.pl)
build_pharos_pod(ooprolog-man ooprolog.pod 1)

include(GetPrologDependencies)
set(ALL_PROLOG_FILES)
foreach(file ${PROLOG_FILES})
  get_prolog_dependencies(depends "${CMAKE_CURRENT_SOURCE_DIR}/${file}")
  list(APPEND ALL_PROLOG_FILES "${CMAKE_CURRENT_SOURCE_DIR}/${file}" ${depends})
endforeach()
list(REMOVE_DUPLICATES ALL_PROLOG_FILES)

install(FILES ${ALL_PROLOG_FILES} DESTINATION share/pharos/prolog/oorules)

install(PROGRAMS ooprolog.pl DESTINATION bin RENAME ooprolog)
