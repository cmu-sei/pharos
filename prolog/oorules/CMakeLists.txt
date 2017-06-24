compile_prolog(setup.pl report.pl rulerun.pl)
add_custom_target(oorules ALL DEPENDS
  "${CMAKE_CURRENT_BINARY_DIR}/setup.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/report.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/rulerun.xwam")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/setup.xwam"
  DESTINATION share/pharos/prolog/oorules)
