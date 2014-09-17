set_app_name( PROGNAME qdigidocclient )

add_definitions( -DPKCS11_MODULE="${PKCS11_MODULE}" )
include_directories( ${CMAKE_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR} )

set( UI_FILES
	ui/MainWindow.ui
	ui/MobileDialog.ui
	ui/SettingsDialog.ui
	ui/SignatureDialog.ui
)

configure_file( translations/tr.qrc tr.qrc COPYONLY )
set( RC_FILES images/images.qrc certs/certs.qrc ${CMAKE_CURRENT_BINARY_DIR}/tr.qrc )
set( TS_FILES translations/en.ts translations/et.ts translations/ru.ts )

if( NOT Qt5Widgets_FOUND )
	qt4_add_translation( SOURCES ${TS_FILES} )
	qt4_add_resources( SOURCES ${RC_FILES} )
	qt4_wrap_ui( SOURCES ${UI_FILES} )
else()
	qt5_add_translation( SOURCES ${TS_FILES} )
	qt5_add_resources( SOURCES ${RC_FILES} )
	qt5_wrap_ui( SOURCES ${UI_FILES} )
endif()

if( APPLE )
	list( APPEND SOURCES TreeWidgetMac.mm )
	set_source_files_properties( TreeWidgetMac.mm PROPERTIES COMPILE_FLAGS "-fobjc-arc" )
elseif( WIN32 )
	list( APPEND SOURCES QCSP.cpp QCNG.cpp )
	list( APPEND ADDITIONAL_LIBRARIES NCrypt )
endif()

add_executable( ${PROGNAME} WIN32 MACOSX_BUNDLE
	${PROGNAME}.rc
	${SOURCES}
	${RESOURCE_FILES}
	main.cpp
	AccessCert.cpp
	Application.cpp
	CheckConnection.cpp
	DigiDoc.cpp
	FileDialog.cpp
	MainWindow.cpp
	MobileDialog.cpp
	PrintSheet.cpp
	QPKCS11.cpp
	QSigner.cpp
	SettingsDialog.cpp
	SignatureDialog.cpp
	TreeWidget.cpp
)

if( APPLE )
	set_target_properties( ${PROGNAME} PROPERTIES
		LINK_LIBRARIES "-framework Security;-framework Quartz"
		MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/mac/Info.plist.cmake
		INSTALL_RPATH "@loader_path/../Frameworks"
	)
	add_custom_command(TARGET ${PROGNAME} POST_BUILD
		COMMAND ln "-fs" ${PKCS11_MODULE} $<TARGET_FILE_DIR:${PROGNAME}>)
endif()

if( Qt5Widgets_FOUND )
	qt5_use_modules( ${PROGNAME} Widgets Network PrintSupport )
	if( WIN32 )
		qt5_use_modules( ${PROGNAME} WinExtras )
	endif()
endif()

target_link_libraries( ${PROGNAME}
	qdigidoccommon
	qdigidoccrypto
	${QT_QTMAIN_LIBRARY}
	${QT_LIBRARIES}
	${LIBDIGIDOCPP_LIBRARY}
	${LDAP_LIBRARIES}
	${ADDITIONAL_LIBRARIES}
)
add_manifest( ${PROGNAME} )
dump_syms( ${PROGNAME} )
install( TARGETS ${PROGNAME} DESTINATION ${CMAKE_INSTALL_BINDIR} )

if(UNIX AND NOT APPLE)
	configure_file( qdigidocclient.1.cmake qdigidocclient.1 )
	install( FILES ${CMAKE_CURRENT_BINARY_DIR}/qdigidocclient.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 )
	install( FILES qdigidoc-client.desktop DESTINATION ${CMAKE_INSTALL_DATADIR}/applications )
	install( FILES qdigidoc-client.xml DESTINATION ${CMAKE_INSTALL_DATADIR}/mime/packages )
	foreach(RES 16 22 32 48 128)
		foreach(TGT application-vnd.bdoc-1.0.png application-vnd.etsi.asic-e+zip.png application-x-ddoc.png application-x-p12d.png)
			install(
				FILES images/qdigidoc_client_document_${RES}x${RES}.png
				DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/${RES}x${RES}/mimetypes/
				RENAME ${TGT}
			)
		endforeach()
		install(
			FILES images/digidoc_icon_${RES}x${RES}.png
			DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/${RES}x${RES}/apps/
			RENAME qdigidoc-client.png
		)
	endforeach()
endif()
