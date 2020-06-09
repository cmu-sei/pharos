find_package(SWIPL)
set(SWIPL_COMMAND swipl)
if(SWIPL_FOUND)
  set(SWIPL_COMMAND ${SWIPL_PROGRAM})
endif()

set(PHAROS_OOLOGLEVEL 6 CACHE STRING "Default log level, set to 7 for trace")
mark_as_advanced(PHAROS_OOLOGLEVEL)

find_package(XSB REQUIRED)
function(compile_prolog)
  include(GetPrologDependencies)
  foreach(file ${ARGV})
    get_prolog_dependencies(depends "${CMAKE_CURRENT_SOURCE_DIR}/${file}")
    get_filename_component(name ${file} NAME_WE)
    set(xwam "${name}.xwam")
    set(log "${CMAKE_CURRENT_BINARY_DIR}/${name}.log")
    add_custom_command(
      OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/${xwam}" "${CMAKE_CURRENT_BINARY_DIR}/${xwam}"
      # The space after the ">" is critically important!
      COMMAND ${XSB_PROGRAM} -e "assert(logLevel(${PHAROS_OOLOGLEVEL})),[logging_instrumentation],catch(compile(${name}),X,(writeln(X),halt(-1))),halt." > ${log} 2>&1
      # Once the log file exists, look for ++Warning and ++Error since the XSB return code can't be trusted.
      COMMAND ! grep -e ^..Warning -e ^..Error ${log}
      COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/${xwam}" "${CMAKE_CURRENT_BINARY_DIR}/"
      DEPENDS ${depends}
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      VERBATIM)
  endforeach()
endfunction()

configure_file(helper.bash.in helper.bash @ONLY)

add_subdirectory(oorules)
