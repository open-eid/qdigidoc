if( UNIX AND NOT APPLE )
	find_package( Ldap REQUIRED )
endif()

set( PROGNAME qdigidoccrypto )

configure_file( translations/crypto_tr.qrc crypto_tr.qrc COPYONLY )
set( RC_FILES images/crypto_images.qrc ${CMAKE_CURRENT_BINARY_DIR}/crypto_tr.qrc )
set( TS_FILES translations/crypto_et.ts translations/crypto_ru.ts )
set( UI_FILES ui/CertAddDialog.ui ui/KeyDialog.ui ui/MainWindow.ui )

if( NOT Qt5Widgets_FOUND )
	qt4_add_translation( QM_FILES ${TS_FILES} )
	qt4_add_resources( RC_SOURCES ${RC_FILES} )
	qt4_wrap_ui( UI_HEADERS ${UI_FILES} )
else()
	qt5_add_translation( QM_FILES ${TS_FILES} )
	qt5_add_resources( RC_SOURCES ${RC_FILES} )
	qt5_wrap_ui( UI_HEADERS ${UI_FILES} )
	list( APPEND QT_LIBRARIES Qt5::Widgets Qt5::Network )
endif()

include_directories(
	${CMAKE_SOURCE_DIR}
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
	set_source_files_properties( CryptoDoc.cpp PROPERTIES COMPILE_FLAGS "-Wno-deprecated-declarations" )
endif()
if( WIN32 )
	set( LDAP_LIBRARIES Wldap32 )
endif()

target_link_libraries( ${PROGNAME}
	qdigidoccommon
	${QT_LIBRARIES}
	${LDAP_LIBRARIES}
)

if(UNIX AND NOT APPLE)
	install( FILES qdigidoc-crypto.desktop DESTINATION ${CMAKE_INSTALL_DATADIR}/applications )
	install( FILES qdigidoc-cypto.appdata.xml DESTINATION ${CMAKE_INSTALL_DATADIR}/appdata )	
	install( FILES qdigidoc-crypto.xml DESTINATION ${CMAKE_INSTALL_DATADIR}/mime/packages )
	foreach(RES 16 22 32 48 128)
		install(
			FILES images/qdigidoc_crypto_document_${RES}x${RES}.png
			DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/${RES}x${RES}/mimetypes/
			RENAME application-x-cdoc.png
		)
		install(
			FILES images/crypto_${RES}x${RES}.png
			DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/${RES}x${RES}/apps/
			RENAME qdigidoc-crypto.png
		)
	endforeach()
endif()
