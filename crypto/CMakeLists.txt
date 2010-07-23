SET( MOC_HEADERS
	CryptoDoc.h
	KeyDialog.h
	LdapSearch.h
	MainWindow.h
	Poller.h
	SettingsDialog.h
	TreeWidget.h
	)
QT4_WRAP_UI( UI_HEADERS
	ui/KeyAddDialog.ui
	ui/KeyDialog.ui
	ui/MainWindow.ui
	ui/SettingsDialog.ui
	)
SET( HEADERS
	${MOC_HEADERS}
	${UI_HEADERS}
	version.h
	)
QT4_WRAP_CPP( MOC_SOURCES ${MOC_HEADERS} )
SET( SOURCES
	${HEADERS}
	${MOC_SOURCES}
	main.cpp
	CryptoDoc.cpp
	KeyDialog.cpp
	LdapSearch.cpp
	MainWindow.cpp
	Poller.cpp
	SettingsDialog.cpp
	TreeWidget.cpp
	)

set(QM_DIR ${CMAKE_CURRENT_BINARY_DIR})
configure_file(${COMMON}/translations/common_tr.qrc.cmake ${QM_DIR}/common_tr.qrc)
configure_file(translations/tr.qrc.cmake ${QM_DIR}/tr.qrc)

QT4_ADD_RESOURCES( RC_SOURCES
	${COMMON_RCS}
	images/images.qrc
	${QM_DIR}/common_tr.qrc
	${QM_DIR}/tr.qrc
	)
QT4_ADD_TRANSLATION( QM_FILES
	${COMMON_TS}
	translations/et.ts
	translations/ru.ts
	)

INCLUDE_DIRECTORIES(
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${OPENSSL_INCLUDE_DIR}
	${LIBDIGIDOC_INCLUDE_DIR}
	${LDAP_INCLUDE_DIR}
	${LIBP11_INCLUDE_DIR}
	)

if(APPLE)
    set(APP_CONTENTS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mac")
 
    # xCode hacks
    include_directories(/usr/local/include/../include)

    # Bundle resources
    file(GLOB_RECURSE RESOURCE_FILES
        ${APP_CONTENTS_DIR}/Resources/*.icns
        ${APP_CONTENTS_DIR}/Resources/**/*.strings)

    foreach(_file ${RESOURCE_FILES})
        get_filename_component(_file_dir ${_file} PATH)
        file(RELATIVE_PATH _file_dir ${APP_CONTENTS_DIR}/Resources ${_file_dir})
        set_source_files_properties(${_file} PROPERTIES MACOSX_PACKAGE_LOCATION "Resources/${_file_dir}" )
    endforeach(_file)
endif(APPLE)

IF(WIN32)
	SET( SOURCES ${SOURCES} qdigidoccrypto.rc )
ENDIF(WIN32)

ADD_EXECUTABLE(
	qdigidoccrypto
	WIN32
	MACOSX_BUNDLE
	${SOURCES}
	${QM_FILES}
	${RC_SOURCES}
	${RESOURCE_FILES}
	)

if(APPLE)
    configure_file(
        ${APP_CONTENTS_DIR}/Info.plist.cmake
        ${APP_CONTENTS_DIR}/Info.plist
        @ONLY)

    set_target_properties(qdigidoccrypto
    	PROPERTIES
    	MACOSX_BUNDLE_INFO_PLIST ${APP_CONTENTS_DIR}/Info.plist)
    
    include_directories(/Developer/Headers/FlatCarbon)
    find_library(CARBON_LIBRARY Carbon)
    set(EXTRA_LIBRARIES ${CARBON_LIBRARY})
endif(APPLE)

TARGET_LINK_LIBRARIES( qdigidoccrypto
	${QT_QTMAIN_LIBRARY}
	${QT_QTCORE_LIBRARY}
	${QT_QTGUI_LIBRARY}
	${QT_QTNETWORK_LIBRARY}
	${LIBDIGIDOC_LIBRARY}
	${OPENSSL_LIBRARIES}
	${OPENSSLCRYPTO_LIBRARIES}
	${LDAP_LIBRARIES}
	${EXTRA_LIBRARIES}
	${LIBP11_LIBRARY}
	qdigidoccommon
)
install(TARGETS qdigidoccrypto DESTINATION ${BIN_INSTALL_DIR})

install(FILES qdigidoc-crypto.desktop DESTINATION ${SHARE_INSTALL_PREFIX}/applications)
install(FILES qdigidoc-crypto.xml DESTINATION ${SHARE_INSTALL_PREFIX}/mime/packages)

if(UNIX AND NOT APPLE)
    # Install icons
    foreach(RES 16 22 32 48 128)
        set(ICONDIR ${SHARE_INSTALL_PREFIX}/icons/hicolor/${RES}x${RES}/mimetypes/)
        set(SRC images/qdigidoc_crypto_document_${RES}x${RES}.png)
        set(TGT application-x-cdoc.png)
        install(
            FILES ${SRC}
            DESTINATION ${ICONDIR}
            RENAME ${TGT}
        )

        set(ICONDIR ${SHARE_INSTALL_PREFIX}/icons/hicolor/${RES}x${RES}/apps/)
        set(SRC images/crypto_${RES}x${RES}.png)
        set(TGT qdigidoc-crypto.png)
        install(
            FILES ${SRC}
            DESTINATION ${ICONDIR}
            RENAME ${TGT}
        )
    endforeach(RES)
endif(UNIX AND NOT APPLE)
