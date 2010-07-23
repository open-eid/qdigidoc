# - Try to find Gecko
# Once done this will define
#
#  GECKO_FOUND - System has Gecko
#  GECKO_INCLUDE_DIR - The Gecko include directory
#  GECKO_IDL_DIR - The Gecko idl include directory
#  GECKO_DEFINITIONS - Compiler switches required for using Gecko
#  GECKO_XPIDL_EXECUTABLE - The idl compiler xpidl coming with Gecko


IF (GECKO_INCLUDE_DIR AND GECKO_IDL_DIR AND GECKO_XPIDL_EXECUTABLE)
   # in cache already
   SET(Gecko_FIND_QUIETLY TRUE)
ENDIF (GECKO_INCLUDE_DIR AND GECKO_IDL_DIR AND GECKO_XPIDL_EXECUTABLE)

IF (NOT WIN32)
   # use pkg-config to get the directories and then use these values
   # in the FIND_PATH() and FIND_LIBRARY() calls
   FIND_PACKAGE(PkgConfig)
   PKG_CHECK_MODULES(PC_LIBXUL libxul)
   SET(GECKO_DEFINITIONS ${PC_LIBXUL_CFLAGS_OTHER})

   # Use FindPkgConfig internal function _pkgconfig_invoke to get sdkdir
   _pkgconfig_invoke(libxul "PC_LIBXUL" SDKDIR "" --variable=sdkdir)
ENDIF (NOT WIN32)

IF (MSVC)
   SET(GECKO_DEFINITIONS "/Zc:wchar_t-")
ENDIF (MSVC)

SET(XULRUNNER_SDK_SEARCH_DIRS
   /build/Win32/xulrunner-sdk
   ${PROJECT_SOURCE_DIR}/xulrunner-sdk
   ${PROJECT_SOURCE_DIR}/../xulrunner-sdk
   )

FIND_PATH(GECKO_STABLE_INCLUDE_DIR nsISupports.h
   HINTS
   ${PC_LIBXUL_INCLUDE_DIRS}
   ${XULRUNNER_SDK_SEARCH_DIRS}
   PATH_SUFFIXES sdk/include
   )

FIND_PATH(GECKO_NSPR4_INCLUDE_DIR prcpucfg.h
   HINTS
   ${PC_LIBXUL_INCLUDE_DIRS}
   ${XULRUNNER_SDK_SEARCH_DIRS}
   PATH_SUFFIXES sdk/include nspr4
   )

FIND_PATH(GECKO_XPCOM_INCLUDE_DIR xpcom-config.h
   HINTS
   ${PC_LIBXUL_SDKDIR}
   ${XULRUNNER_SDK_SEARCH_DIRS}
   PATH_SUFFIXES sdk/include
   )

SET(GECKO_INCLUDE_DIR ${GECKO_STABLE_INCLUDE_DIR} ${GECKO_NSPR4_INCLUDE_DIR} ${GECKO_XPCOM_INCLUDE_DIR})
LIST(REMOVE_DUPLICATES GECKO_INCLUDE_DIR)


FIND_PATH(GECKO_IDL_DIR nsIDOMWindow.idl
   HINTS
   ${PC_LIBXUL_SDKDIR}
   ${XULRUNNER_SDK_SEARCH_DIRS}
   PATH_SUFFIXES idl
   )

FIND_PROGRAM(GECKO_XPIDL_EXECUTABLE xpidl
   HINTS
   ${PC_LIBXUL_LIBDIR}
   ${PC_LIBXUL_SDKDIR}
   ${XULRUNNER_SDK_SEARCH_DIRS}
   PATH_SUFFIXES bin
   )

INCLUDE(FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set GECKO_FOUND to TRUE if 
# all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Gecko DEFAULT_MSG GECKO_INCLUDE_DIR GECKO_IDL_DIR GECKO_XPIDL_EXECUTABLE)

MARK_AS_ADVANCED(GECKO_INCLUDE_DIR GECKO_IDL_DIR GECKO_XPIDL_EXECUTABLE)
