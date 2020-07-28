set(PROLOG_FILES setup.pl progress_oosolver.pl report.pl util.pl validate.pl oojson.pl)

include(GetPrologDependencies)
set(ALL_PROLOG_FILES)
foreach(file ${PROLOG_FILES})
  get_prolog_dependencies(depends "${CMAKE_CURRENT_SOURCE_DIR}/${file}")
  list(APPEND ALL_PROLOG_FILES "${CMAKE_CURRENT_SOURCE_DIR}/${file}" ${depends})
endforeach()
list(REMOVE_DUPLICATES ALL_PROLOG_FILES)

# Copy all Prolog source files to the build directory and install them too
foreach(file ${ALL_PROLOG_FILES})
get_filename_component(basename "${file}" NAME)
configure_file("${file}" "${CMAKE_CURRENT_BINARY_DIR}/${basename}" COPYONLY)
endforeach()
install(FILES ${ALL_PROLOG_FILES} DESTINATION share/pharos/prolog/oorules)

string(CONCAT SWIPL_HEADER
  "STACK_LIMIT=\${STACK_LIMIT:-200 000 000 000}\n"
  "TABLE_SPACE=\${TABLE_SPACE:-200 000 000 000}\n"
  "DIR=\"\$( cd \"\$( dirname \"\${BASH_SOURCE[0]}\" )\" >/dev/null 2>&1 && pwd )\"")

macro(install_ooscript script_name)
  configure_file(${script_name}.in ${CMAKE_CURRENT_BINARY_DIR}/${script_name} @ONLY)
  install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${script_name}
    DESTINATION share/pharos/prolog/oorules)
endmacro()

install_ooscript(oodebugrun)
install_ooscript(oodebugrun-noguess)
install_ooscript(oodebugrun-nortti)
install_ooscript(oovalidate)
install_ooscript(oojson)
