include_directories(
	${OPENSSL_INCLUDE_DIR}
	${XERCESC_INCLUDE_DIR}
	${XSD_INCLUDE_DIR}
	${LIBDIGIDOCPP_INCLUDE_DIR}
)
set( RESOURCES bdoc.icns ddoc.icns )
add_library( DigiDocQL MODULE
	${RESOURCES}
	Info.plist
	main.c
	GenerateThumbnailForURL.c
	GeneratePreviewForURL.mm
)
set_source_files_properties( GeneratePreviewForURL.mm PROPERTIES COMPILE_FLAGS "-fobjc-arc" )
set_source_files_properties( ${RESOURCES} PROPERTIES MACOSX_PACKAGE_LOCATION Resources )
set_source_files_properties( Info.plist PROPERTIES MACOSX_PACKAGE_LOCATION . )
set_target_properties( DigiDocQL PROPERTIES
	BUNDLE YES
	BUNDLE_EXTENSION qlgenerator
	XCODE_ATTRIBUTE_WRAPPER_EXTENSION qlgenerator
	MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/Info.plist
	COMPILE_FLAGS "-Wno-unused-parameter"
	LINK_FLAGS "-F/Library/Frameworks -fobjc-arc -framework QuickLook -framework digidocpp -framework Cocoa"
)
install( DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/DigiDocQL.qlgenerator
	DESTINATION ${CMAKE_INSTALL_BINDIR}/qdigidocclient.app/Contents/Library/QuickLook
)
