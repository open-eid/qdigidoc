cmake_minimum_required( VERSION 2.6 )
project( qdigidoc )

set( CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules" )

include( InstallSettings )

if(PKCS11_MODULE)
    add_definitions(-DPKCS11_MODULE="${PKCS11_MODULE}")
endif(PKCS11_MODULE)

find_package( Ldap REQUIRED )
find_package( LibDigiDoc REQUIRED )
find_package( LibDigiDocpp REQUIRED )
find_package( LibP11 REQUIRED )
find_package( OpenSSL REQUIRED )
find_package( OpenSSLCrypto REQUIRED )
find_package( Qt4 REQUIRED )
find_package( XercesC REQUIRED )
find_package( XSD REQUIRED )

set( QT_MIN_VERSION 4.4.0 )
set( QT_USE_QTNETWORK true )
set( QT_USE_QTWEBKIT true )
set( QT_USE_QTXML true )

include( ${QT_USE_FILE} )

find_package(Subversion)
if (Subversion_FOUND AND EXISTS ${PROJECT_SOURCE_DIR}/.svn)
    Subversion_WC_INFO(${PROJECT_SOURCE_DIR} PROJECT)
    message(STATUS "Current SVN revision is ${PROJECT_WC_REVISION}")
    add_definitions(-DBUILD_VER=${PROJECT_WC_REVISION})
else (Subversion_FOUND AND EXISTS ${PROJECT_SOURCE_DIR}/.svn)
    add_definitions(-DBUILD_VER=0)
endif (Subversion_FOUND AND EXISTS ${PROJECT_SOURCE_DIR}/.svn)

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

add_definitions( -DQT_NO_KEYWORDS )
add_subdirectory( common )
add_subdirectory( client )
add_subdirectory( crypto )
