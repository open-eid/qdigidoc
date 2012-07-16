set( PROGNAME qdigidoccrypto )

set( MOC_HEADERS
	Application.h
	CryptoDoc.h
	KeyDialog.h
	LdapSearch.h
	MainWindow.h
	Poller.h
	SettingsDialog.h
	TreeWidget.h
	)
QT4_WRAP_UI( UI_HEADERS
	ui/CertAddDialog.ui
	ui/KeyDialog.ui
	ui/MainWindow.ui
	ui/SettingsDialog.ui
	)
set( HEADERS
	${MOC_HEADERS}
	${UI_HEADERS}
	version.h
	)
QT4_WRAP_CPP( MOC_SOURCES ${MOC_HEADERS} )
set( SOURCES
	${HEADERS}
	${MOC_SOURCES}
	main.cpp
	Application.cpp
	CryptoDoc.cpp
	KeyDialog.cpp
	LdapSearch.cpp
	MainWindow.cpp
	Poller.cpp
	SettingsDialog.cpp
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
	translations/et.ts
	translations/ru.ts
	)

include_directories(
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${OPENSSL_INCLUDE_DIR}
	${LIBDIGIDOC_INCLUDE_DIR}
	${LDAP_INCLUDE_DIR}
	)

if( APPLE )
	include( VersionInfoMac )
	set( ADDITIONAL_LIBRARIES ${ADDITIONAL_LIBRARIES} "-framework LDAP" )
endif( APPLE )
if( WIN32 )
	set( SOURCES ${SOURCES} ${PROGNAME}.rc )
	set( ADDITIONAL_LIBRARIES ${ADDITIONAL_LIBRARIES} Setupapi Wldap32 )
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
	qdigidoccommon
	${QT_QTMAIN_LIBRARY}
	${QT_LIBRARIES}
	${LIBDIGIDOC_LIBRARY}
	${OPENSSL_LIBRARIES}
	${LDAP_LIBRARIES}
	${ADDITIONAL_LIBRARIES}
)
dump_syms( ${PROGNAME} )
install( TARGETS ${PROGNAME} DESTINATION ${CMAKE_INSTALL_BINDIR} )

if(UNIX AND NOT APPLE)
	install(FILES qdigidoc-crypto.desktop DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
	install(FILES qdigidoc-crypto.xml DESTINATION ${CMAKE_INSTALL_DATADIR}/mime/packages)

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
	endforeach(RES)
endif(UNIX AND NOT APPLE)
