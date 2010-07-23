# - Find LibDigiDocpp
# Find the native LibDigiDocpp includes and library
#
#  LIBDIGIDOCPP_INCLUDE_DIR - where to find winscard.h, wintypes.h, etc.
#  LIBDIGIDOCPP_CONF        - where is digidocpp.conf file
#  LIBDIGIDOCPP_LIBRARIES   - List of libraries when using LibDigiDocpp.
#  LIBDIGIDOCPP_FOUND       - True if LibDigiDocpp found.


IF (LIBDIGIDOCPP_INCLUDE_DIR)
  # Already in cache, be silent
  SET(LIBDIGIDOCPP_FIND_QUIETLY TRUE)
ENDIF (LIBDIGIDOCPP_INCLUDE_DIR)

FIND_PATH(LIBDIGIDOCPP_INCLUDE_DIR digidocpp/BDoc.h /usr/include /usr/local/include)
FIND_FILE(LIBDIGIDOCPP_CONF digidocpp.conf /etc/digidocpp /usr/local/etc/digidocpp)
FIND_LIBRARY(LIBDIGIDOCPP_LIBRARY NAMES digidocpp)

# handle the QUIETLY and REQUIRED arguments and set LIBDIGIDOCPP_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibDigiDocpp DEFAULT_MSG LIBDIGIDOCPP_LIBRARY LIBDIGIDOCPP_INCLUDE_DIR)

IF(LIBDIGIDOCPP_FOUND)
  SET( LIBDIGIDOCPP_LIBRARIES ${LIBDIGIDOCPP_LIBRARY} )
ELSE(LIBDIGIDOCPP_FOUND)
  SET( LIBDIGIDOCPP_LIBRARIES )
ENDIF(LIBDIGIDOCPP_FOUND)

MARK_AS_ADVANCED(LIBDIGIDOCPP_LIBRARY LIBDIGIDOCPP_INCLUDE_DIR LIBDIGIDOCPP_CONF)
