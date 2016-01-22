add_definitions(
    -D_UNICODE
    -DUNICODE
    -D_MERGE_PROXYSTUB
    -D_WINDLL
)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

if(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
    set(MIDL_TARGET "x64")
else(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
    set(MIDL_TARGET "win32")
endif(${CMAKE_SIZEOF_VOID_P} EQUAL 8)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/EsteidShellExtension_i.h
           ${CMAKE_CURRENT_BINARY_DIR}/EsteidShellExtension_i.c
           ${CMAKE_CURRENT_BINARY_DIR}/EsteidShellExtension_p.c
    COMMAND Midl.Exe ${CMAKE_CURRENT_SOURCE_DIR}/EsteidShellExtension.idl
                     /nologo /no_robust /char signed /Oicf /env ${MIDL_TARGET}
                     /I ${CMAKE_CURRENT_SOURCE_DIR}
                     /tlb EsteidShellExtension.tlb
                     /h EsteidShellExtension_i.h
                     /iid EsteidShellExtension_i.c
                     /proxy EsteidShellExtension_p.c
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM
)

add_library(EsteidShellExtension SHARED
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
install(TARGETS EsteidShellExtension DESTINATION ${CMAKE_INSTALL_BINDIR})

if(SIGNCERT)
	add_custom_command(TARGET EsteidShellExtension POST_BUILD
		COMMAND signtool.exe sign /a /v /s MY /n "${SIGNCERT}" /fd SHA256 /du http://installer.id.ee
                	/t http://timestamp.verisign.com/scripts/timstamp.dll $<TARGET_FILE:EsteidShellExtension>
	)
endif()
