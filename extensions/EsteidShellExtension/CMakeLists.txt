add_definitions(
    -D_UNICODE
    -DUNICODE
    -D_MERGE_PROXYSTUB
    -D_WINDLL
)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(MIDL_TARGET "x64")
    set(PLATFORM "x64")
else()
    set(MIDL_TARGET "win32")
    set(PLATFORM "x86")
endif()

foreach(CompilerFlag
    CMAKE_CXX_FLAGS
    CMAKE_CXX_FLAGS_DEBUG
    CMAKE_CXX_FLAGS_RELEASE
    CMAKE_CXX_FLAGS_MINSIZEREL
    CMAKE_CXX_FLAGS_RELWITHDEBINFO
    CMAKE_C_FLAGS
    CMAKE_C_FLAGS_DEBUG
    CMAKE_C_FLAGS_RELEASE
    CMAKE_C_FLAGS_MINSIZEREL
    CMAKE_C_FLAGS_RELWITHDEBINFO)
    string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
endforeach()

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
        /proxy EsteidShellExtension_p.c 2> nul
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

add_custom_target(msishellext DEPENDS EsteidShellExtension
    COMMAND "$ENV{WIX}bin\\candle.exe" -nologo -arch ${PLATFORM}
        -dMSI_VERSION=${VERSION} -dPlatform=${PLATFORM} -dShellExt=$<TARGET_FILE:EsteidShellExtension>
        ${CMAKE_CURRENT_SOURCE_DIR}/EsteidShellExtension.wxs
        ${CMAKE_SOURCE_DIR}/cmake/modules/WelcomeDlg2.wxs
        ${CMAKE_SOURCE_DIR}/cmake/modules/WixUI_Minimal2.wxs
    COMMAND "$ENV{WIX}bin\\light.exe" -nologo -ext WixUIExtension
        EsteidShellExtension.wixobj WelcomeDlg2.wixobj WixUI_Minimal2.wixobj
        -dWixUIDialogBmp=${CMAKE_SOURCE_DIR}/cmake/modules/dlgbmp.bmp
        -dWixUIBannerBmp=${CMAKE_SOURCE_DIR}/cmake/modules/banner.bmp
        -o "Digidoc3_ShellExt-${VERSION}$ENV{VER_SUFFIX}.${PLATFORM}.msi"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

if(SIGNCERT)
    add_custom_command(TARGET EsteidShellExtension POST_BUILD
        COMMAND signtool.exe sign /a /v /s MY /n "${SIGNCERT}" /fd SHA256 /du http://installer.id.ee
            /tr http://sha256timestamp.ws.symantec.com/sha256/timestamp /td SHA256 $<TARGET_FILE:EsteidShellExtension>
    )
    add_custom_command(TARGET msishellext POST_BUILD
        COMMAND signtool.exe sign /a /v /s MY /n "${SIGNCERT}" /fd SHA256 /du http://installer.id.ee
            /tr http://sha256timestamp.ws.symantec.com/sha256/timestamp /td SHA256
            "${CMAKE_BINARY_DIR}/Digidoc3_ShellExt-${VERSION}$ENV{VER_SUFFIX}.${PLATFORM}.msi"
    )
endif()
