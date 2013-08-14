if( UNIX AND NOT APPLE )
	find_package( Ldap REQUIRED )
endif()
find_package( LibDigiDoc REQUIRED )

set_app_name( PROGNAME qdigidoccrypto )

set( UI_FILES
	ui/CertAddDialog.ui
	ui/KeyDialog.ui
	ui/MainWindow.ui
	ui/SettingsDialog.ui
)

configure_file( translations/tr.qrc tr.qrc COPYONLY )
set( RC_FILES images/crypto_images.qrc ${CMAKE_CURRENT_BINARY_DIR}/tr.qrc )
set( TS_FILES translations/et.ts translations/ru.ts )

if( NOT Qt5Widgets_FOUND )
	qt4_add_translation( QM_FILES ${TS_FILES} )
	qt4_add_resources( RC_SOURCES ${RC_FILES} )
	qt4_wrap_ui( UI_HEADERS ${UI_FILES} )
else()
	qt5_add_translation( QM_FILES ${TS_FILES} )
	qt5_add_resources( RC_SOURCES ${RC_FILES} )
	qt5_wrap_ui( UI_HEADERS ${UI_FILES} )
endif()

include_directories(
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${OPENSSL_INCLUDE_DIR}
	${LIBDIGIDOC_INCLUDE_DIR}
	${LDAP_INCLUDE_DIR}
)

add_executable( ${PROGNAME} WIN32 MACOSX_BUNDLE
	${PROGNAME}.rc
	main.cpp
	Application.cpp
	CryptoDoc.cpp
	KeyDialog.cpp
	LdapSearch.cpp
	MainWindow.cpp
	Poller.cpp
	SettingsDialog.cpp
	TreeWidget.cpp
	${UI_HEADERS}
	${QM_FILES}
	${RC_SOURCES}
	${RESOURCE_FILES}
)

if( APPLE )
	set_target_properties( ${PROGNAME} PROPERTIES
		LINK_FLAGS "-framework LDAP"
		MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/mac/Info.plist.cmake )
endif()
if( WIN32 )
	list( APPEND ADDITIONAL_LIBRARIES Wldap32 )
endif()
set_target_properties( ${PROGNAME} PROPERTIES AUTOMOC TRUE )
if( Qt5Widgets_FOUND )
	qt5_use_modules( ${PROGNAME} Widgets Network )
endif()

target_link_libraries( ${PROGNAME}
	qdigidoccommon
	${QT_QTMAIN_LIBRARY}
	${Qt5Core_QTMAIN_LIBRARIES}
	${QT_LIBRARIES}
	${LIBDIGIDOC_LIBRARY}
	${LDAP_LIBRARIES}
	${ADDITIONAL_LIBRARIES}
)
add_manifest( ${PROGNAME} )
dump_syms( ${PROGNAME} )
if( APPLE )
	install( TARGETS ${PROGNAME} DESTINATION ${CMAKE_INSTALL_BINDIR}/qdigidocclient.app/Contents/MacOS/ )
else()
	install( TARGETS ${PROGNAME} DESTINATION ${CMAKE_INSTALL_BINDIR} )
endif()

if(UNIX AND NOT APPLE)
	configure_file( qdigidoccrypto.1.cmake qdigidoccrypto.1 )
	install( FILES ${CMAKE_CURRENT_BINARY_DIR}/qdigidoccrypto.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 )
	install( FILES qdigidoc-crypto.desktop DESTINATION ${CMAKE_INSTALL_DATADIR}/applications )
	install( FILES qdigidoc-crypto.xml DESTINATION ${CMAKE_INSTALL_DATADIR}/mime/packages )

	# Install icons
	foreach(RES 16 22 32 48 128)
		set(ICONDIR ${CMAKE_INSTALL_DATADIR}/icons/hicolor/${RES}x${RES}/mimetypes/)
		set(SRC images/qdigidoc_crypto_document_${RES}x${RES}.png)
		set(TGT application-x-cdoc.png)
		install(FILES ${SRC} DESTINATION ${ICONDIR} RENAME ${TGT})

		set(ICONDIR ${CMAKE_INSTALL_DATADIR}/icons/hicolor/${RES}x${RES}/apps/)
		set(SRC images/crypto_${RES}x${RES}.png)
		set(TGT qdigidoc-crypto.png)
		install(FILES ${SRC} DESTINATION ${ICONDIR} RENAME ${TGT})
	endforeach()
endif()
