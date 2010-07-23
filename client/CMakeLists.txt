SET( MOC_HEADERS
	AccessCert.h
	DigiDoc.h
	MainWindow.h
	MobileDialog.h
	PrintSheet.h
	QSigner.h
	RegisterP12.h
	SettingsDialog.h
	SignatureDialog.h
	TreeWidget.h
	)
QT4_WRAP_UI( UI_HEADERS
	ui/MainWindow.ui
	ui/MobileDialog.ui
	ui/RegisterP12.ui
	ui/SettingsDialog.ui
	ui/SignatureDialog.ui
	)
SET( HEADERS
	${MOC_HEADERS}
	${UI_HEADERS}
	QMobileSigner.h
	version.h
	)
QT4_WRAP_CPP( MOC_SOURCES ${MOC_HEADERS} )
SET( SOURCES
	${HEADERS}
	${MOC_SOURCES}
	main.cpp
	AccessCert.cpp
	DigiDoc.cpp
	MainWindow.cpp
	MobileDialog.cpp
	PrintSheet.cpp
	QSigner.cpp
	QMobileSigner.cpp
	RegisterP12.cpp
	SettingsDialog.cpp
	SignatureDialog.cpp
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
	translations/en.ts
	translations/et.ts
	translations/ru.ts
	)

INCLUDE_DIRECTORIES(
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${OPENSSL_INCLUDE_DIR}
	${XERCESC_INCLUDE_DIR}
	${XSD_INCLUDE_DIR}
	${LIBDIGIDOCPP_INCLUDE_DIR}
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
    
    include_directories(/Developer/Headers/FlatCarbon)
    find_library(CARBON_LIBRARY Carbon)
    set(EXTRA_LIBRARIES ${CARBON_LIBRARY})
endif(APPLE)

if(MSVC)
	# disable warning C4290: C++ exception specification ignored
	add_definitions( -wd4290 )
	add_definitions( -wd4996 )
endif(MSVC)
IF(WIN32)
	SET( SOURCES ${SOURCES} qdigidocclient.rc )
ENDIF(WIN32)

ADD_EXECUTABLE(
	qdigidocclient
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

    set_target_properties(qdigidocclient
    	PROPERTIES
    	MACOSX_BUNDLE_INFO_PLIST ${APP_CONTENTS_DIR}/Info.plist)
endif(APPLE)

TARGET_LINK_LIBRARIES( qdigidocclient
	${QT_QTMAIN_LIBRARY}
	${QT_LIBRARIES}
	${LIBDIGIDOCPP_LIBRARY}
	${OPENSSL_LIBRARIES}
	${OPENSSLCRYPTO_LIBRARIES}
	${LIBP11_LIBRARY}
	${EXTRA_LIBRARIES}
	qdigidoccommon
)
install(TARGETS qdigidocclient DESTINATION ${BIN_INSTALL_DIR})

install(FILES qdigidoc-client.desktop DESTINATION ${SHARE_INSTALL_PREFIX}/applications)
install(FILES qdigidoc-client.xml DESTINATION ${SHARE_INSTALL_PREFIX}/mime/packages)

if(UNIX AND NOT APPLE)
    # Install icons
    foreach(RES 16 22 32 48 128)
        set(ICONDIR ${SHARE_INSTALL_PREFIX}/icons/hicolor/${RES}x${RES}/mimetypes/)
        foreach(TGT application-x-bdoc.png application-x-ddoc.png application-x-p12d.png)
            set(SRC images/qdigidoc_client_document_${RES}x${RES}.png)
            install(
                FILES ${SRC}
                DESTINATION ${ICONDIR}
                RENAME ${TGT}
            )
        endforeach(TGT)

        set(ICONDIR ${SHARE_INSTALL_PREFIX}/icons/hicolor/${RES}x${RES}/apps/)
        set(SRC images/digidoc_icon_${RES}x${RES}.png)
        set(TGT qdigidoc-client.png)
        install(
            FILES ${SRC}
            DESTINATION ${ICONDIR}
            RENAME ${TGT}
        )
    endforeach(RES)
endif(UNIX AND NOT APPLE)
