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
if( ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION} LESS 2.8 )
find_package( OpenSSLCrypto REQUIRED )
endif( ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION} LESS 2.8 )
find_package( Qt4 4.4.0 COMPONENTS QtCore QtGui QtNetwork QtWebkit QtXml REQUIRED )
find_package( XercesC REQUIRED )
find_package( XSD REQUIRED )
find_package( Subversion )

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

if( LIBP11_TOKEN_FLAGS )
add_definitions( -DLIBP11_TOKEN_FLAGS )
endif( LIBP11_TOKEN_FLAGS )

include( ${QT_USE_FILE} )
add_subdirectory( qtsingleapplication )
add_subdirectory( common )
add_definitions( -DQT_NO_KEYWORDS )
add_subdirectory( client )
add_subdirectory( crypto )
