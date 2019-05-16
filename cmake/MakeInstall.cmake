# -------------------------------------------------------------------------------------------------- #
# инсталляция библиотеки (только для UNIX)
if( CMAKE_HOST_UNIX )
  if( LIBAKRYPT_SHARED_LIB )
    install( TARGETS akrypt-shared
             LIBRARY DESTINATION lib
             ARCHIVE DESTINATION lib
           )
  endif()
  if( LIBAKRYPT_STATIC_LIB )
    install( TARGETS akrypt-static
             LIBRARY DESTINATION lib
             ARCHIVE DESTINATION lib
           )
  endif()
  install( FILES ${MAIN_HEADER} DESTINATION include )
  install( FILES ${HEADERS} DESTINATION include )
  if( LIBAKRYPT_CONST_CRYPTO_PARAMS )
  else()
    install( FILES libakrypt.conf DESTINATION ${LIBAKRYPT_CONF} )
  endif()

  if( LIBAKRYPT_AKRYPT )
    # настройка и инсталяция инструментальных средств
    install( CODE "execute_process( COMMAND strip -s akrypt${LIBAKRYPT_EXT} )" )
    install( TARGETS akrypt${LIBAKRYPT_EXT} RUNTIME DESTINATION bin )
    #  install( FILES akrypt/akrypt.1 DESTINATION man/man1 )
    #  find_file( AKRYPT_MSGFMT msgfmt )
    #  if( AKRYPT_MSGFMT )
    #    install( CODE "execute_process( COMMAND msgfmt ${CMAKE_SOURCE_DIR}/akrypt/akrypt.po -o ${CMAKE_BINARY_DIR}/akrypt.mo )" )
    #    install( FILES ${CMAKE_BINARY_DIR}/akrypt.mo DESTINATION /usr/share/locale/ru/LC_MESSAGES )
    #  endif()
  endif()

# ручная деинсталляция
  if( ${CMAKE_INSTALL_PREFIX} )
  else()
   set( CMAKE_INSTALL_PREFIX "/usr/local" )
  endif()
  file( WRITE ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh "#/bin/bash\n" )
  file( APPEND ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh "rm -fv ${CMAKE_INSTALL_PREFIX}/lib/libakrypt-static.a\n" )
  file( APPEND ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh "rm -fv ${CMAKE_INSTALL_PREFIX}/lib/libakrypt-shared.*\n" )
  file( APPEND ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh "rm -fv ${CMAKE_INSTALL_PREFIX}/include/libakrypt.h\n" )
  file( APPEND ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh "rm -fv ${CMAKE_INSTALL_PREFIX}/include/ak_*\n" )
  file( APPEND ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh "rm -fv ${LIBAKRYPT_CONF}/libakrypt.conf\n" )
  if( LIBAKRYPT_AKRYPT )
    file( APPEND ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh "rm -fv ${CMAKE_INSTALL_PREFIX}/bin/akrypt${LIBAKRYPT_EXT}\n" )
  endif()

  execute_process( COMMAND chmod +x ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh )
  add_custom_target( uninstall ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh )

  message("-- Install script is done (now \"make install\" & \"make uninstall\" enabled)" )
  message("-- Install path ${CMAKE_INSTALL_PREFIX}" )
endif()

# -------------------------------------------------------------------------------------------------- #
