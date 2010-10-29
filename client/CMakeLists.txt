set( PROGNAME qdigidocclient )

set( BDOC_ENABLED false CACHE BOOL "Enable BDOC support" )
if( BDOC_ENABLED )
	add_definitions( -DBDOC_ENABLED )
endif( BDOC_ENABLED )

set( MOC_HEADERS
	AccessCert.h
	Application.h
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
set( HEADERS
	${MOC_HEADERS}
	${UI_HEADERS}
	QMobileSigner.h
	version.h
	)
QT4_WRAP_CPP( MOC_SOURCES ${MOC_HEADERS} )
set( SOURCES
	${HEADERS}
	${MOC_SOURCES}
	main.cpp
	AccessCert.cpp
	Application.cpp
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

if( APPLE )
	set( APP_CONTENTS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mac" )

	set( APPLE_GUI_BUNDLE_NAME ${PROGNAME} )
	set( APPLE_GUI_IDENTIFIER ${PROGNAME} )
	set( APPLE_GUI_INFO_STRING "${VERSION}, Copyright 2010 Estonian ID Card" )
	set( APPLE_GUI_COPYRIGHT "(C) 2010 Estonian ID Card" )
	set( APPLE_GUI_SHORT_VERSION_STRING ${VERSION} )
	set( APPLE_GUI_BUNDLE_VERSION ${SHORT_VERSION} )
	set( APPLE_GUI_LONG_VERSION_STRING Version ${VERSION} )
	set( APPLE_GUI_ICON Icon.icns )
	configure_file( mac/Info.plist.cmake mac/Info.plist )

	file( GLOB_RECURSE RESOURCE_FILES
		${APP_CONTENTS_DIR}/Resources/*.icns
		${APP_CONTENTS_DIR}/Resources/**/*.strings )

	foreach( _file ${RESOURCE_FILES} )
		get_filename_component( _file_dir ${_file} PATH )
		file( RELATIVE_PATH _file_dir ${APP_CONTENTS_DIR}/Resources ${_file_dir} )
		set_source_files_properties( ${_file} PROPERTIES MACOSX_PACKAGE_LOCATION "Resources/${_file_dir}" )
	endforeach( _file )

	find_library( COCOA_LIBRARY Cocoa )
	set( EXTRA_LIBRARIES ${COCOA_LIBRARY} )
endif( APPLE )

if(MSVC)
	# disable warning C4290: C++ exception specification ignored
	add_definitions( -wd4290 )
	add_definitions( -wd4996 )
endif(MSVC)
IF(WIN32)
	SET( SOURCES ${SOURCES} qdigidocclient.rc )
ENDIF(WIN32)

add_executable(
	${PROGNAME}
	WIN32
	MACOSX_BUNDLE
	${SOURCES}
	${QM_FILES}
	${RC_SOURCES}
	${RESOURCE_FILES}
	)

if( APPLE )
	set_target_properties( ${PROGNAME}
    	PROPERTIES
		MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_BINARY_DIR}/mac/Info.plist )
endif( APPLE )
if( WIN32 )
	set_target_properties( ${PROGNAME}
		PROPERTIES
		LINK_FLAGS "/MANIFESTDEPENDENCY:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' publicKeyToken='6595b64144ccf1df' language='*' processorArchitecture='*'\"" )
endif( WIN32 )

target_link_libraries( ${PROGNAME}
	${QT_QTMAIN_LIBRARY}
	${QT_LIBRARIES}
	${LIBDIGIDOCPP_LIBRARY}
	${OPENSSL_LIBRARIES}
	${OPENSSLCRYPTO_LIBRARIES}
	${EXTRA_LIBRARIES}
	${LIBP11_LIBRARY}
	${LIBDL_LIBRARIES}
	qdigidoccommon
	qtsingleapplication
)
install( TARGETS ${PROGNAME} DESTINATION ${BIN_INSTALL_DIR} )

if(UNIX AND NOT APPLE)
	install(FILES qdigidoc-client.desktop DESTINATION ${SHARE_INSTALL_PREFIX}/applications)
	install(FILES qdigidoc-client.xml DESTINATION ${SHARE_INSTALL_PREFIX}/mime/packages)

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
