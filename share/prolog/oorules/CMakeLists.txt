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

# Prolog unit tests.  These exercise the rules directly with asserted facts, rather than
# replaying a binary's facts the way the ooprolog corpus tests do, so they are the only coverage
# for reasoning the MSVC corpus cannot reach.
set(PROLOG_UNIT_TESTS
  tests/vtt_tests.pl
  tests/vtt_slice_tests.pl
  tests/vftable_slot_tests.pl
  tests/constructor_tests.pl
  tests/class_relationship_tests.pl
  tests/itanium_rtti_tests.pl)

foreach(test_file ${PROLOG_UNIT_TESTS})
  get_filename_component(test_name "${test_file}" NAME_WE)
  add_test(NAME "ooprolog_unit_${test_name}"
    COMMAND "${SWIPL_EXECUTABLE}" -g "run_tests,halt(0)" -g "halt(1)"
            "${CMAKE_CURRENT_SOURCE_DIR}/${test_file}")
  set_tests_properties("ooprolog_unit_${test_name}" PROPERTIES LABELS ooprolog)
endforeach()
