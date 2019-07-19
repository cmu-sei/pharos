compile_prolog(setup.pl progress_oosolver.pl report.pl rulerun.pl util.pl validate.pl)
add_custom_target(oorules ALL DEPENDS
  "${CMAKE_CURRENT_BINARY_DIR}/setup.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/progress_oosolver.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/report.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/util.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/validate.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/rulerun.xwam")
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/setup.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/progress_oosolver.xwam"
  DESTINATION share/pharos/prolog/oorules)
file(COPY
  "${CMAKE_CURRENT_SOURCE_DIR}/oodebugrun"
  "${CMAKE_CURRENT_SOURCE_DIR}/oodebugrun-noguess"
  "${CMAKE_CURRENT_SOURCE_DIR}/oodebugrun-nortti"
  "${CMAKE_CURRENT_SOURCE_DIR}/oointeractive"
  "${CMAKE_CURRENT_SOURCE_DIR}/oorulerun"
  "${CMAKE_CURRENT_SOURCE_DIR}/oovalidate"
  "${CMAKE_CURRENT_SOURCE_DIR}/rtti_report"
  DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
