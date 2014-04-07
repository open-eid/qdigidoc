if( UNIX AND NOT APPLE )
	find_package( Ldap REQUIRED )
endif()

set( PROGNAME qdigidoccrypto )

set( UI_FILES
	ui/CertAddDialog.ui
	ui/KeyDialog.ui
	ui/MainWindow.ui
)

configure_file( translations/crypto_tr.qrc crypto_tr.qrc COPYONLY )
set( RC_FILES images/crypto_images.qrc ${CMAKE_CURRENT_BINARY_DIR}/crypto_tr.qrc )
set( TS_FILES translations/crypto_et.ts translations/crypto_ru.ts )

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
	${LDAP_INCLUDE_DIR}
)

add_library( ${PROGNAME} STATIC
	CryptoDoc.cpp
	KeyDialog.cpp
	LdapSearch.cpp
	MainWindow.cpp
	TreeWidget.cpp
	${UI_HEADERS}
	${QM_FILES}
	${RC_SOURCES}
	${RESOURCE_FILES}
)

if( APPLE )
	set( LDAP_LIBRARIES "-framework LDAP" )
endif()
if( WIN32 )
	set( LDAP_LIBRARIES Wldap32 )
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
	${LDAP_LIBRARIES}
	${ADDITIONAL_LIBRARIES}
)

if(UNIX AND NOT APPLE)
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
