# -------------------------------------------------------------------------------------------------- #
# инсталляция библиотеки (только для UNIX)
if( CMAKE_HOST_UNIX )
  install( TARGETS akrypt
           LIBRARY DESTINATION lib
           ARCHIVE DESTINATION lib
         )

  install( FILES ${MAIN_HEADER} DESTINATION include )

  # если нужны заголовки внутреннего инфтерфейса
  if( LIBAKRYPT_INSTALL_HEADERS )
    install( FILES ${HEADERS} DESTINATION include )
  endif()

  if( LIBAKRYPT_CONST_CRYPTO_PARAMS )
  else()
    install( FILES libakrypt.conf DESTINATION ${LIBAKRYPT_CONF} )
  endif()

  if( LIBAKRYPT_AKTOOL )
    # настройка и инсталяция инструментальных средств
    install( CODE "execute_process( COMMAND strip -s aktool${LIBAKRYPT_EXT} )" )
    install( TARGETS aktool${LIBAKRYPT_EXT} RUNTIME DESTINATION bin )
    install( FILES aktool/aktool.1 DESTINATION share/man/man1 ) # проверить, что freebsd использует тот же путь
                                                                # в случае необходимости, исправить путь для деинсталляции
#    find_file( AKRYPT_MSGFMT msgfmt )
#    if( AKRYPT_MSGFMT )
#      install( CODE "execute_process( COMMAND msgfmt ${CMAKE_SOURCE_DIR}/akrypt/akrypt.po -o ${CMAKE_BINARY_DIR}/akrypt.mo )" )
#      if( BSD )
#        install( FILES ${CMAKE_BINARY_DIR}/akrypt.mo DESTINATION /usr/local/share/locale/ru/LC_MESSAGES )
#      else()
#        install( FILES ${CMAKE_BINARY_DIR}/akrypt.mo DESTINATION /usr/share/locale/ru/LC_MESSAGES )
#      endif()
#    endif()
  endif()

# ручная деинсталляция
  if( CMAKE_INSTALL_PREFIX )
  else()
   set( CMAKE_INSTALL_PREFIX "/usr/local" )
  endif()
  file( WRITE ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh "#/bin/bash\n" )
  file( APPEND ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh "rm -fv ${CMAKE_INSTALL_PREFIX}/lib/libakrypt*\n" )
  file( APPEND ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh "rm -fv ${CMAKE_INSTALL_PREFIX}/include/libakrypt.h\n" )
  file( APPEND ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh "rm -fv ${CMAKE_INSTALL_PREFIX}/include/ak_*\n" )
  file( APPEND ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh "rm -fv ${LIBAKRYPT_CONF}/libakrypt.conf\n" )
  if( LIBAKRYPT_AKTOOL )
    file( APPEND ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh "rm -fv ${CMAKE_INSTALL_PREFIX}/bin/aktool${LIBAKRYPT_EXT}\n" )
    file( APPEND ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh "rm -fv ${CMAKE_INSTALL_PREFIX}/share/man/man1/aktool.1\n" )

#    if( BSD )
#      file( APPEND ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh "rm -fv /usr/local/share/locale/ru/LC_MESSAGES/akrypt.mo\n" )
#    elseif()
#      file( APPEND ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh "rm -fv /usr/share/locale/ru/LC_MESSAGES/akrypt.mo\n" )
#    endif()
  endif()

  execute_process( COMMAND chmod +x ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh )
  add_custom_target( uninstall ${CMAKE_BINARY_DIR}/make-uninstall-${FULL_VERSION}.sh )

  message("-- Install script is done (now \"make install\" & \"make uninstall\" enabled)" )
  message("-- Install prefix is ${CMAKE_INSTALL_PREFIX}" )
endif()

# -------------------------------------------------------------------------------------------------- #
