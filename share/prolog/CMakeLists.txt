find_package(XSB REQUIRED)
function(compile_prolog)
  include(GetPrologDependencies)
  foreach(file ${ARGV})
    get_prolog_dependencies(depends "${CMAKE_CURRENT_SOURCE_DIR}/${file}")
    get_filename_component(name ${file} NAME_WE)
    set(xwam "${name}.xwam")
    add_custom_command(
      OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/${xwam}" "${CMAKE_CURRENT_BINARY_DIR}/${xwam}"
      COMMAND ${XSB_PROGRAM} -e "catch(compile(${name}),X,halt(-1)),halt." > /dev/null 2>&1
      COMMAND ${CMAKE_COMMAND} -E
      copy "${CMAKE_CURRENT_SOURCE_DIR}/${xwam}" "${CMAKE_CURRENT_BINARY_DIR}/"
      DEPENDS ${depends} xsb-install
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      VERBATIM)
  endforeach()
endfunction()

add_subdirectory(oorules)
