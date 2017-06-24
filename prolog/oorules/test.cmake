execute_process(
  COMMAND ${XSB_PROGRAM} --noprompt -e "[rulerun],run('${FACTS}')."
  OUTPUT_FILE "${OUTPUT_DIR}/${BASENAME}.unsorted.xsbresults"
  ERROR_VARIABLE error
  RESULT_VARIABLE res
)
if(NOT res EQUAL 0)
  message(FATAL_ERROR "Failure running XSB\n${error}")
endif()
execute_process(
  COMMAND ${CMAKE_COMMAND} -E env LANG=C sort
  INPUT_FILE "${OUTPUT_DIR}/${BASENAME}.unsorted.xsbresults"
  OUTPUT_FILE "${OUTPUT_DIR}/${BASENAME}.sorted.xsbresults")
if(NOT res EQUAL 0)
  message(FATAL_ERROR "Failure running sort")
endif()
execute_process(
  COMMAND diff -bwu ${GOOD_RESULTS} "${OUTPUT_DIR}/${BASENAME}.sorted.xsbresults"
  OUTPUT_FILE "${OUTPUT_DIR}/${BASENAME}.xsbresults.diff"
  RESULT_VARIABLE res
)
if(NOT res EQUAL 0)
  message(FATAL_ERROR "Regression test of ${FACTS} found differences")
endif()
