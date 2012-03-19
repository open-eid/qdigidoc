cmake_minimum_required( VERSION 2.8 )
project( qdigidoc )

set( CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules" )

include( InstallSettings )
include( VersionInfo )

find_package( Ldap REQUIRED )
find_package( LibDigiDoc REQUIRED )
find_package( LibDigiDocpp REQUIRED )
find_package( OpenSSL REQUIRED )
find_package( PKCS11 )
find_package( Qt4 4.6.0 COMPONENTS QtCore QtGui QtNetwork REQUIRED )
find_package( XSD REQUIRED )

add_definitions( -DPKCS11_MODULE="${PKCS11_MODULE}" )

include( ${QT_USE_FILE} )
add_subdirectory( qtsingleapplication )
add_subdirectory( common )
include( common/resources.cmake )
add_subdirectory( client )
add_subdirectory( crypto )
