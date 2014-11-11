set(SERVICES_INSTALL_DIR "${CMAKE_INSTALL_DATADIR}/kde4/services" CACHE PATH "Install dir for KDE service (desktop, protocol, ...) files")

install(FILES qdigidoc-signer.desktop DESTINATION "${SERVICES_INSTALL_DIR}")
