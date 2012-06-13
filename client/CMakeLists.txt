set( PROGNAME qdigidocclient )

set( MOC_HEADERS
	AccessCert.h
	Application.h
	DigiDoc.h
	MainWindow.h
	MobileDialog.h
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
	PrintSheet.h
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
	RegisterP12.cpp
	SettingsDialog.cpp
	SignatureDialog.cpp
	TreeWidget.cpp
	)

configure_file(${COMMON}/translations/common_tr.qrc common_tr.qrc COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/breakpad/translations/breakpad.qrc breakpad.qrc COPYONLY)
configure_file(translations/tr.qrc tr.qrc COPYONLY)

QT4_ADD_RESOURCES( RC_SOURCES
	${COMMON_RCS}
	images/images.qrc
	${CMAKE_CURRENT_BINARY_DIR}/breakpad.qrc
	${CMAKE_CURRENT_BINARY_DIR}/common_tr.qrc
	${CMAKE_CURRENT_BINARY_DIR}/tr.qrc
	)

QT4_ADD_TRANSLATION( QM_FILES
	${COMMON_TS}
	${BREAKPAD_TS}
	translations/en.ts
	translations/et.ts
	translations/ru.ts
	)

include_directories(
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${OPENSSL_INCLUDE_DIR}
	${XERCESC_INCLUDE_DIR}
	${XSD_INCLUDE_DIR}
	${LIBDIGIDOCPP_INCLUDE_DIR}
	)

if( APPLE )
	include( VersionInfoMac )
	set( ADDITIONAL_LIBRARIES ${ADDITIONAL_LIBRARIES} "-framework Cocoa" )
endif( APPLE )
if( WIN32 )
	set( SOURCES ${SOURCES} ${PROGNAME}.rc )
	set( ADDITIONAL_LIBRARIES ${ADDITIONAL_LIBRARIES} ncrypt )
endif( WIN32 )

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
		MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/mac/Info.plist.cmake )
endif( APPLE )
if( WIN32 )
	set_target_properties( ${PROGNAME}
		PROPERTIES
		LINK_FLAGS "/MANIFESTDEPENDENCY:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' publicKeyToken='6595b64144ccf1df' language='*' processorArchitecture='*'\"" )
endif( WIN32 )

target_link_libraries( ${PROGNAME}
	qtsingleapplication
	qdigidoccommon
	${QT_QTMAIN_LIBRARY}
	${QT_LIBRARIES}
	${LIBDIGIDOCPP_LIBRARY}
	${OPENSSL_LIBRARIES}
	${ADDITIONAL_LIBRARIES}
)
if( DUMP_SYMS_EXECUTABLE )
	get_property( BINARY_PATH TARGET ${PROGNAME} PROPERTY LOCATION )
	add_custom_target( ${PROGNAME}.symbols ALL
		${DUMP_SYMS_EXECUTABLE} ${BINARY_PATH} > ${PROGNAME}.sym
		DEPENDS ${PROGNAME}
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	)
endif( DUMP_SYMS_EXECUTABLE )
install( TARGETS ${PROGNAME} DESTINATION ${CMAKE_INSTALL_BINDIR} )

if(UNIX AND NOT APPLE)
	install(FILES qdigidoc-client.desktop DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
	install(FILES qdigidoc-client.xml DESTINATION ${CMAKE_INSTALL_DATADIR}/mime/packages)

	# Install icons
	foreach(RES 16 22 32 48 128)
		set(ICONDIR ${CMAKE_INSTALL_DATADIR}/icons/hicolor/${RES}x${RES}/mimetypes/)
		foreach(TGT application-x-bdoc.png application-x-ddoc.png application-x-p12d.png)
			set(SRC images/qdigidoc_client_document_${RES}x${RES}.png)
			install(FILES ${SRC} DESTINATION ${ICONDIR} RENAME ${TGT})
		endforeach(TGT)

		set(ICONDIR ${CMAKE_INSTALL_DATADIR}/icons/hicolor/${RES}x${RES}/apps/)
		set(SRC images/digidoc_icon_${RES}x${RES}.png)
		set(TGT qdigidoc-client.png)
		install(FILES ${SRC} DESTINATION ${ICONDIR} RENAME ${TGT})
	endforeach(RES)
endif(UNIX AND NOT APPLE)
