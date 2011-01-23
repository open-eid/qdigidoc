cmake_minimum_required( VERSION 2.6 )
project( qdigidoc )

set( CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules" )

include( InstallSettings )

find_package( Ldap REQUIRED )
find_package( LibDigiDoc REQUIRED )
find_package( LibDigiDocpp REQUIRED )
find_package( LibP11 REQUIRED )
find_package( OpenSSL REQUIRED )
if( ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION} LESS 2.8 )
find_package( OpenSSLCrypto REQUIRED )
endif( ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION} LESS 2.8 )
find_package( PKCS11 )
find_package( Qt4 4.4.0 COMPONENTS QtCore QtGui QtNetwork QtWebkit QtXml REQUIRED )
find_package( XercesC REQUIRED )
find_package( XSD REQUIRED )
find_package( Subversion )
if( UNIX )
	find_package( LibDL REQUIRED )
endif( UNIX )

set( MAJOR_VER 3 )
set( MINOR_VER 3 )
set( RELEASE_VER 0 )

if( Subversion_FOUND AND EXISTS ${PROJECT_SOURCE_DIR}/.svn )
	Subversion_WC_INFO( ${PROJECT_SOURCE_DIR} PROJECT )
	message( STATUS "Current SVN revision is ${PROJECT_WC_REVISION}" )
	set( BUILD_VER ${PROJECT_WC_REVISION} )
else( Subversion_FOUND AND EXISTS ${PROJECT_SOURCE_DIR}/.svn )
	set( BUILD_VER 0 )
endif( Subversion_FOUND AND EXISTS ${PROJECT_SOURCE_DIR}/.svn )

set( SHORT_VERSION ${BUILD_VER} )
set( VERSION ${MAJOR_VER}.${MINOR_VER}.${RELEASE_VER}.${BUILD_VER} )

add_definitions( -DMAJOR_VER=${MAJOR_VER} -DMINOR_VER=${MINOR_VER} -DRELEASE_VER=${RELEASE_VER} -DBUILD_VER=${BUILD_VER} )
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
