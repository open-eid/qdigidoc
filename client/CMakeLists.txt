find_package( LibDigiDocpp REQUIRED )

set_app_name( PROGNAME qdigidocclient )

QT4_WRAP_UI( UI_HEADERS
	ui/MainWindow.ui
	ui/MobileDialog.ui
	ui/RegisterP12.ui
	ui/SettingsDialog.ui
	ui/SignatureDialog.ui
)

configure_file( translations/tr.qrc tr.qrc COPYONLY )

QT4_ADD_RESOURCES( RC_SOURCES
	images/images.qrc
	${CMAKE_CURRENT_BINARY_DIR}/tr.qrc
)

if( APPSTORE )
	QT4_ADD_TRANSLATION( QM_FILES
		translations/mac/en.ts
		translations/mac/et.ts
		translations/mac/ru.ts
	)
else()
	QT4_ADD_TRANSLATION( QM_FILES
		translations/en.ts
		translations/et.ts
		translations/ru.ts
	)
endif()

include_directories(
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${OPENSSL_INCLUDE_DIR}
	${LIBDIGIDOCPP_INCLUDE_DIR}
)

if( APPLE )
	set( SOURCES TreeWidgetMac.mm )
	set_source_files_properties( ${SOURCES} PROPERTIES COMPILE_FLAGS "-fobjc-arc" )
endif()

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
	${QM_FILES}
	${RC_SOURCES}
	${RESOURCE_FILES}
	${SOURCES}
)

if( APPLE )
	set_target_properties( ${PROGNAME} PROPERTIES
		LINK_FLAGS "-framework Security -framework Quartz"
		MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/mac/Info.plist.cmake )
	find_program( LN NAMES "ln" )
	get_property( BINARY_PATH TARGET ${PROGNAME} PROPERTY LOCATION )
	get_filename_component( BINARY_DIR ${BINARY_PATH} PATH )
	execute_process( COMMAND ${LN} "-fs" ${PKCS11_MODULE} ${BINARY_DIR} )
endif()
if( WIN32 )
	set_target_properties( ${PROGNAME} PROPERTIES
		LINK_FLAGS "/MANIFESTDEPENDENCY:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' publicKeyToken='6595b64144ccf1df' language='*' processorArchitecture='*'\"" )
endif()
set_target_properties( ${PROGNAME} PROPERTIES AUTOMOC TRUE )

target_link_libraries( ${PROGNAME}
	qdigidoccommon
	${QT_QTMAIN_LIBRARY}
	${QT_LIBRARIES}
	${LIBDIGIDOCPP_LIBRARY}
	${ADDITIONAL_LIBRARIES}
)
dump_syms( ${PROGNAME} )
install( TARGETS ${PROGNAME} DESTINATION ${CMAKE_INSTALL_BINDIR} )

if(UNIX AND NOT APPLE)
	configure_file( qdigidocclient.1.cmake qdigidocclient.1 )
	install( FILES ${CMAKE_CURRENT_BINARY_DIR}/qdigidocclient.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 )
	install( FILES qdigidoc-client.desktop DESTINATION ${CMAKE_INSTALL_DATADIR}/applications )
	install( FILES qdigidoc-client.xml DESTINATION ${CMAKE_INSTALL_DATADIR}/mime/packages )

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
