cmake_minimum_required( VERSION 2.8 )
project( qdigidoc )
set( MAJOR_VER 3 )
set( MINOR_VER 5 )
set( RELEASE_VER 0 )

set( CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules" )

include( InstallSettings )
include( VersionInfo )

find_package( Ldap REQUIRED )
find_package( LibDigiDoc REQUIRED )
find_package( LibDigiDocpp REQUIRED )
find_package( OpenSSL REQUIRED )
find_package( LibP11 REQUIRED )
find_package( PKCS11 )
find_package( Qt4 4.4.0 COMPONENTS QtCore QtGui QtNetwork QtXml REQUIRED )
find_package( XercesC REQUIRED )
find_package( XSD REQUIRED )

add_definitions( -DPKCS11_MODULE="${PKCS11_MODULE}" )

set( COMMON ${CMAKE_SOURCE_DIR}/common )
set( COMMON_RCS
	${COMMON}/images/common_images.qrc
	)
set( COMMON_TS
	${COMMON}/translations/common_en.ts
	${COMMON}/translations/common_et.ts
	${COMMON}/translations/common_ru.ts
	${COMMON}/translations/qt_et.ts
	${COMMON}/translations/qt_ru.ts
	)

include( ${QT_USE_FILE} )
add_subdirectory( qtsingleapplication )
add_subdirectory( common )
add_definitions( -DQT_NO_KEYWORDS )
add_subdirectory( client )
add_subdirectory( crypto )
