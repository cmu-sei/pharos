execute_process(
  COMMAND git rev-parse HEAD
  WORKING_DIRECTORY "${srcdir}"
  OUTPUT_VARIABLE out
  RESULT_VARIABLE result
  ERROR_QUIET
  OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT result EQUAL 0)
  set(out "unknown revision")
endif()
set(deco "%%**REVISION**%%")
file(WRITE "PHAROS_REVISION" "R\"${deco}(${out})${deco}\"")
