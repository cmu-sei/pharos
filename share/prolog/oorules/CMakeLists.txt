set(SWIPL_ROOT "" CACHE PATH "The root directory of the SWI Prolog installation")
set(_swipl_search)
if(SWPIL_ROOT)
  set(_swipl_search PATHS "${SWIPL_ROOT}/bin" NO_DEFAULT_PATH)
endif()
find_program(SWIPL_PROGRAM swipl ${_swipl_search} DOC "SWI Prolog runtime")
if(NOT SWIPL_PROGRAM)
  set(SWIPL_PROGRAM swipl)
endif()

compile_prolog(setup.P progress_oosolver.P report.P util.P validate.P)
add_custom_target(oorules ALL DEPENDS
  "${CMAKE_CURRENT_BINARY_DIR}/setup.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/progress_oosolver.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/report.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/util.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/validate.xwam")
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/setup.xwam"
  "${CMAKE_CURRENT_BINARY_DIR}/progress_oosolver.xwam"
  DESTINATION share/pharos/prolog/oorules)

macro(install_ooscript script_name)
  configure_file(${script_name}.in ${CMAKE_CURRENT_BINARY_DIR}/${script_name} @ONLY)
endmacro()

install_ooscript(oodebugrun)
install_ooscript(oodebugrun-swipl)
install_ooscript(oodebugrun-noguess)
install_ooscript(oodebugrun-nortti)
install_ooscript(oodebugrun-profile)
install_ooscript(oointeractive)
install_ooscript(oorulerun)
install_ooscript(oovalidate)
install_ooscript(rtti_report)
