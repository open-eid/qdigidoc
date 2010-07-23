# - Find XSD
# Find XSD includes and executable
#
#  XSD_INCLUDE_DIR - Where to find xsd include sub-directory.
#  XSD_EXECUTABLE  - XSD compiler.
#  XSD_FOUND       - True if XSD found.


IF (XSD_INCLUDE_DIR)
  # Already in cache, be silent.
  SET(XSD_FIND_QUIETLY TRUE)
ENDIF (XSD_INCLUDE_DIR)

FIND_PATH(XSD_INCLUDE_DIR xsd/cxx/parser/elements.hxx)

SET(XSD_NAMES xsdcxx xsdgen xsd)
FIND_PROGRAM(XSD_EXECUTABLE NAMES ${XSD_NAMES} )

# Handle the QUIETLY and REQUIRED arguments and set XSD_FOUND to
# TRUE if all listed variables are TRUE.
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(XSD DEFAULT_MSG XSD_EXECUTABLE XSD_INCLUDE_DIR)

MARK_AS_ADVANCED( XSD_EXECUTABLE XSD_INCLUDE_DIR )
