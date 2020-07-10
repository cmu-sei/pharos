cmake_minimum_required(VERSION 3.10)

if(WIN32)
  if("${CMAKE_GENERATOR}" MATCHES "Visual Studio 9 2008")
    set(CMAKE_CXX_FLAGS_DEBUG "/Od /D \"WIN32\" /D_DEBUG\" /D_CONSOLE /D_UNICODE /D UNICODE /Gm /EHsc /RTC1 /MDd /W3 /c /ZI /TP" CACHE STRING "")
    # XXX: We don't have a 2008 Lite configuration
    # set(CMAKE_CXX_FLAGS_LITE "/O2 /Oi /GL /DWIN32 /DNDEBUG /D_CONSOLE /D_UNICODE /DUNICODE /FD /EHsc /MD /Gy /W3 /c /Zi /TP" CACHE STRING "")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/O2 /Oi /GL /DWIN32 /DNDEBUG /D_CONSOLE /D_UNICODE /DUNICODE /FD /EHsc /MD /Gy /W3 /c /Zi /TP" CACHE STRING "")
  elseif("${CMAKE_GENERATOR}" MATCHES "Visual Studio 10 2010")
    set(CMAKE_CXX_FLAGS_DEBUG "/ZI /nologo /W3 /WX- /Od /Oy- /DWIN32 /D_DEBUG /D_CONSOLE /D_UNICODE /DUNICODE /Gm /EHsc /RTC1 /MDd /GS /fp:precise /Zc:wchar_t /Zc:forScope /Gd /analyze- /errorReport:queue" CACHE STRING "")
    set(CMAKE_CXX_FLAGS_LITE "/Zi /nologo /W3 /WX- /O2 /Ob0 /Oy- /DWIN32 /DNDEBUG /D_CONSOLE /D_UNICODE /DUNICODE /Gm- /EHsc /GS /Gy /fp:precise /Zc:wchar_t /Zc:forScope /Gd /analyze- /errorReport:queue" CACHE STRING "")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/Zi /nologo /W3 /WX- /O2 /Oi /Oy- /GL /DWIN32 /DNDEBUG /D_CONSOLE /D_UNICODE /DUNICODE /Gm- /EHsc /MD /GS /Gy /fp:precise /Zc:wchar_t /Zc:forScope /Gd /analyze- /errorReport:queue" CACHE STRING "")
  else()
    message("Unsupported visual studio version. Using cmake defaults.")
  endif()

  cmake_policy(SET CMP0091 NEW)
endif()


# set the project name
project(PharosTests)

if(WIN32)
  # Add static option
  option(CMAKE_MSVC_STATIC "Statically link CRT" OFF)
  if(CMAKE_MSVC_STATIC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  else()
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
  endif()

  # Add a Lite configuration if we have one
  if(CMAKE_CONFIGURATION_TYPES)
    if(CMAKE_CXX_FLAGS_LITE)
      set(CMAKE_CONFIGURATION_TYPES Debug RelWithDebInfo Lite)

    else()
      set(CMAKE_CONFIGURATION_TYPES Debug RelWithDebInfo)
    endif()
    set(CMAKE_CONFIGURATION_TYPES "${CMAKE_CONFIGURATION_TYPES}" CACHE STRING
      "Reset the configurations to what we need"
      FORCE)
    set(CMAKE_EXE_LINKER_FLAGS_LITE "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO}")
  endif()
endif()

FILE(GLOB CXXPROGS *.cpp)

foreach(CXXFILE ${CXXPROGS})
  get_filename_component(EXENAME ${CXXFILE} NAME_WE)
  add_executable(${EXENAME} ${CXXFILE})
endforeach(CXXFILE)

set_property(TARGET oonewdel PROPERTY CXX_STANDARD 17)
