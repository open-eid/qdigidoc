cmake_minimum_required(VERSION 2.6)
project(EsteidShellExtension)

add_definitions(
    -D_UNICODE
    -DUNICODE
    -D_MERGE_PROXYSTUB
)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(SOURCES 
    ${CMAKE_CURRENT_BINARY_DIR}/EsteidShellExtension_i.c
    dllmain.cpp
    EsteidShellExtension.cpp
    EsteidShellExtension.def
    EsteidShlExt.cpp
    stdafx.cpp
    EsteidShellExtension.rc
    EsteidShellExtension.rgs
    EsteidShlExt.rgs
)

if(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
    set(MIDL_TARGET "x64")
else(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
    set(MIDL_TARGET "win32")
endif(${CMAKE_SIZEOF_VOID_P} EQUAL 8)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/EsteidShellExtension_i.h
           ${CMAKE_CURRENT_BINARY_DIR}/EsteidShellExtension_i.c
           ${CMAKE_CURRENT_BINARY_DIR}/EsteidShellExtension_p.c
    COMMAND Midl.Exe EsteidShellExtension.idl
                     /nologo
                     /I ${CMAKE_SOURCE_DIR}
                     /char signed
                     /env ${MIDL_TARGET}
                     /Oicf
                     /tlb EsteidShellExtension.tlb
                     /h EsteidShellExtension_i.h
                     /iid EsteidShellExtension_i.c
                     /proxy EsteidShellExtension_p.c
                     /no_robust
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM
)

add_library(EsteidShellExtension SHARED ${SOURCES})
install(TARGETS EsteidShellExtension DESTINATION lib)
