configure_file( translations/crypto_tr.qrc crypto_tr.qrc COPYONLY )
qt5_add_translation( SOURCES translations/crypto_et.ts translations/crypto_ru.ts )
qt5_add_resources( SOURCES images/crypto_images.qrc ${CMAKE_CURRENT_BINARY_DIR}/crypto_tr.qrc )
qt5_wrap_ui( SOURCES CertAddDialog.ui KeyDialog.ui MainWindow.ui )

if( APPLE )
	set( LDAP_LIBRARIES "-framework LDAP" )
	set_source_files_properties( LdapSearch.cpp PROPERTIES COMPILE_FLAGS "-Wno-deprecated-declarations" )
elseif( WIN32 )
	set( LDAP_LIBRARIES Wldap32 )
else()
	find_package( Ldap REQUIRED )
endif()

add_library(qdigidoccrypto STATIC
	CryptoDoc.cpp
	KeyDialog.cpp
	LdapSearch.cpp
	MainWindow.cpp
	TreeWidget.cpp
	${SOURCES}
)

target_include_directories( qdigidoccrypto PRIVATE ${CMAKE_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR} ${LDAP_INCLUDE_DIR} )
target_link_libraries( qdigidoccrypto qdigidoccommon ${LDAP_LIBRARIES} )

if(UNIX AND NOT APPLE)
	set_target_properties( qdigidoccrypto PROPERTIES COMPILE_DEFINITIONS "DATADIR=\"${CMAKE_INSTALL_FULL_DATADIR}\"" )
	install( FILES qdigidoc-crypto.desktop DESTINATION ${CMAKE_INSTALL_DATADIR}/applications )
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
