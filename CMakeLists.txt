cmake_minimum_required( VERSION 2.8 )
project( qdigidoc )

set( CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules" )
set( CMAKE_FIND_ROOT_PATH ${CMAKE_OSX_SYSROOT} )

include( GNUInstallDirs )
include( VersionInfo )

find_package( Qt4 4.8.0 COMPONENTS QtCore QtGui QtNetwork REQUIRED )
include( ${QT_USE_FILE} )

if( APPLE )
	set( APPSTORE true CACHE BOOL "AppStore build" )
endif()
if( APPSTORE )
	add_definitions(-DAPPSTORE)
endif()
add_subdirectory( common )
include( breakpad/BreakPad.cmake )
add_subdirectory( client )
add_subdirectory( crypto )
