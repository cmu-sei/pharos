compile_prolog(setup.pl progress_oosolver.pl report.pl rulerun.pl)
add_custom_target(oorules ALL DEPENDS
  "${CMAKE_CURRENT_BINARY_DIR}/setup.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/progress_oosolver.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/report.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/rulerun.xwam")
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/setup.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/progress_oosolver.xwam"
  DESTINATION share/pharos/prolog/oorules)
