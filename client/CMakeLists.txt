set_app_name( PROGNAME qdigidocclient )

QT4_WRAP_CPP( MOC_SOURCES
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

configure_file(${CMAKE_SOURCE_DIR}/breakpad/translations/breakpad.qrc breakpad.qrc COPYONLY)
configure_file(translations/tr.qrc tr.qrc COPYONLY)

QT4_ADD_RESOURCES( RC_SOURCES
	images/images.qrc
	${CMAKE_CURRENT_BINARY_DIR}/breakpad.qrc
	${CMAKE_CURRENT_BINARY_DIR}/tr.qrc
)

QT4_ADD_TRANSLATION( QM_FILES
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

add_executable( ${PROGNAME} WIN32 MACOSX_BUNDLE
	${PROGNAME}.rc
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
	${UI_HEADERS}
	${MOC_SOURCES}
	${QM_FILES}
	${RC_SOURCES}
	${RESOURCE_FILES}
)

if( APPLE )
	set_target_properties( ${PROGNAME}
		PROPERTIES
		LINK_FLAGS "-framework Security"
		MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/mac/Info.plist.cmake )
endif()
if( WIN32 )
	list( APPEND ADDITIONAL_LIBRARIES Setupapi )
	set_target_properties( ${PROGNAME}
		PROPERTIES
		LINK_FLAGS "/MANIFESTDEPENDENCY:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' publicKeyToken='6595b64144ccf1df' language='*' processorArchitecture='*'\"" )
endif()

target_link_libraries( ${PROGNAME}
	qdigidoccommon
	${QT_QTMAIN_LIBRARY}
	${QT_LIBRARIES}
	${LIBDIGIDOCPP_LIBRARY}
	${OPENSSL_LIBRARIES}
	${ADDITIONAL_LIBRARIES}
)
dump_syms( ${PROGNAME} )
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
		endforeach()

		set(ICONDIR ${CMAKE_INSTALL_DATADIR}/icons/hicolor/${RES}x${RES}/apps/)
		set(SRC images/digidoc_icon_${RES}x${RES}.png)
		set(TGT qdigidoc-client.png)
		install(FILES ${SRC} DESTINATION ${ICONDIR} RENAME ${TGT})
	endforeach()
endif()
